"""Single-authority IPv4 leases. No network calls inside SQLite transactions."""
import ipaddress
import json
import re
import time
import uuid


class Refused(ValueError):
    pass


def require(value, message):
    if not value:
        raise Refused(message)


def identity(value):
    try:
        require(str(uuid.UUID(value)) == value, 'Нужен канонический UUID')
    except (TypeError, AttributeError, ValueError) as exc:
        raise Refused('Нужен канонический UUID') from exc
    return value


class Ipam:
    def __init__(self, db, config=None, clock=time.time):
        self.db, self.config, self.clock = db, config or {}, clock
        self.db.executescript('''
            CREATE TABLE IF NOT EXISTS ipv4_pool (id TEXT PRIMARY KEY, spec TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS ipv4_lease (
                id TEXT PRIMARY KEY, generation INTEGER NOT NULL UNIQUE,
                pool_id TEXT NOT NULL, address TEXT NOT NULL, account TEXT NOT NULL,
                reference TEXT NOT NULL, order_id INTEGER, client_id INTEGER,
                state TEXT NOT NULL, payment_pending INTEGER NOT NULL DEFAULT 0,
                expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL);
            CREATE UNIQUE INDEX IF NOT EXISTS ipv4_active_address ON ipv4_lease(address)
                WHERE state != 'released';
            CREATE UNIQUE INDEX IF NOT EXISTS ipv4_active_reference ON ipv4_lease(reference)
                WHERE state != 'released';
        ''')
        self.addresses = []
        if not self.config:
            return
        c = self.config
        network = ipaddress.IPv4Network(c['cidr'])
        blocked = ('0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16','172.16.0.0/12','192.168.0.0/16','224.0.0.0/4','240.0.0.0/4')
        require(not any(network.overlaps(ipaddress.IPv4Network(cidr)) for cidr in blocked), 'Пул IPv4 не может быть приватным, локальным или multicast')
        require(16 <= network.prefixlen <= 30, 'Нужна IPv4 подсеть /16–/30')
        require(re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', c['pool_id']), 'Некорректный pool_id')
        require(re.fullmatch(r'vmbr[0-9]+', c['bridge']), 'Некорректный public bridge')
        excluded = {str(ipaddress.IPv4Address(x)) for x in [c['gateway'], c['host_ip'], *c.get('reserved', [])]}
        require(all(ipaddress.IPv4Address(x) in network for x in excluded), 'Служебный IP вне подсети')
        require(c['gateway'] != c['host_ip'], 'Адрес хоста совпал со шлюзом')
        self.addresses = [str(ip) for ip in network.hosts() if str(ip) not in excluded]
        require(self.addresses, 'В подсети нет клиентских адресов')
        spec = json.dumps({k: v for k, v in c.items() if k != 'enabled'}, sort_keys=True)
        with self.db:
            prior = self.db.execute('SELECT * FROM ipv4_pool').fetchall()
            require(not prior or len(prior) == 1 and prior[0]['id'] == c['pool_id'] and prior[0]['spec'] == spec,
                    'Изменение IPv4-пула требует отдельной миграции')
            self.db.execute('INSERT OR IGNORE INTO ipv4_pool VALUES (?,?)', (c['pool_id'], spec))

    def _expire(self):
        self.db.execute("UPDATE ipv4_lease SET state='released' WHERE state='held' AND payment_pending=0 AND expires_at<=?", (int(self.clock()),))

    @staticmethod
    def info(row):
        return {key: row[key] for key in ('id', 'generation', 'address', 'state', 'expires_at', 'order_id', 'client_id', 'account', 'reference', 'pool_id')}

    def _owned(self, account, reference, lease_id):
        identity(account); identity(reference); identity(lease_id)
        row = self.db.execute('SELECT * FROM ipv4_lease WHERE id=?', (lease_id,)).fetchone()
        require(row and row['account'] == account and row['reference'] == reference, 'Аренда адреса не принадлежит заказу')
        return row

    def capacity(self, unavailable=()):
        occupied = self.db.execute("SELECT * FROM ipv4_lease WHERE state!='released' AND NOT(state='held' AND payment_pending=0 AND expires_at<=?)", (int(self.clock()),)).fetchall()
        counts = {state: sum(row['state'] == state for row in occupied) for state in ('held', 'assigned', 'releasing', 'reconcile_required')}
        return {'enabled': self.config.get('enabled') is True, 'poolId': self.config.get('pool_id'),
                'total': len(self.addresses), 'free': len(set(self.addresses)-{row['address'] for row in occupied}-set(unavailable)), **counts,
                'observedAt': int(self.clock())}

    def reserve(self, account, reference, unavailable=()):
        identity(account); identity(reference)
        require(self.config.get('enabled') is True, 'Выдача IPv4 выключена')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self._expire()
            require(not self.db.execute('SELECT 1 FROM ipv4_lease WHERE reference=? AND account!=?', (reference, account)).fetchone(), 'Reference принадлежит другому клиенту')
            prior = self.db.execute("SELECT * FROM ipv4_lease WHERE reference=? AND state!='released'", (reference,)).fetchone()
            if prior:
                require(prior['state'] in ('held', 'assigned'), 'Адрес требует сверки')
                require(prior['state']=='assigned' or prior['address'] not in unavailable, 'Адрес занят сторонней VM')
                self.db.commit()
                return self.info(prior)
            used = {r[0] for r in self.db.execute("SELECT address FROM ipv4_lease WHERE state!='released'")}
            available = [ip for ip in self.addresses if ip not in used and ip not in unavailable]
            require(available, 'Нет свободных публичных IPv4')
            generation = self.db.execute('SELECT COALESCE(MAX(generation),0)+1 FROM ipv4_lease').fetchone()[0]
            lease_id, now = str(uuid.uuid4()), int(self.clock())
            self.db.execute('INSERT INTO ipv4_lease(id,generation,pool_id,address,account,reference,state,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?,?)',
                            (lease_id, generation, self.config['pool_id'], available[0], account, reference, 'held', now+900, now))
            row = self.db.execute('SELECT * FROM ipv4_lease WHERE id=?', (lease_id,)).fetchone()
            self.db.commit()
            return self.info(row)
        except BaseException:
            self.db.rollback()
            raise

    def payment_pending(self, account, reference, lease_id):
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            self._expire()
            row = self._owned(account, reference, lease_id)
            require(row['state'] in ('held', 'assigned'), 'Резерв IPv4 истёк или требует сверки')
            self.db.execute('UPDATE ipv4_lease SET payment_pending=1 WHERE id=?', (lease_id,))
        return self.info(self._owned(account, reference, lease_id))

    def release_hold(self, account, reference, lease_id, resolved=False):
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            row = self._owned(account, reference, lease_id)
            if row['state'] == 'released':
                return True
            if row['state'] != 'held' or row['payment_pending'] and not resolved:
                return False
            self.db.execute("UPDATE ipv4_lease SET state='released' WHERE id=?", (lease_id,))
        return True

    def bind(self, account, reference, lease_id, order, client):
        require(type(order) is int and order > 0 and type(client) is int and client > 0, 'Некорректный заказ')
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            self._expire()
            row = self._owned(account, reference, lease_id)
            require(row['state'] in ('held', 'assigned') and (row['order_id'] in (None, order)) and row['client_id'] in (None, client), 'Резерв истёк или принадлежит другой VM')
            self.db.execute("UPDATE ipv4_lease SET state='assigned',order_id=?,client_id=? WHERE id=?", (order, client, lease_id))
        return self.info(self._owned(account, reference, lease_id))

    def for_order(self, order, client, active=True):
        suffix = " AND state!='released'" if active else ''
        row = self.db.execute('SELECT * FROM ipv4_lease WHERE order_id=? AND client_id=?'+suffix+' ORDER BY generation DESC LIMIT 1', (order, client)).fetchone()
        return self.info(row) if row else None

    def release_assigned(self, order, client, lease_id, isolated):
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            row = self.db.execute('SELECT * FROM ipv4_lease WHERE id=?', (lease_id,)).fetchone()
            require(row and row['order_id'] == order and row['client_id'] == client, 'Неизвестное владение IPv4')
            if row['state'] == 'released':
                return
            require(isolated is True, 'Нет подтверждения изоляции прежней VM')
            self.db.execute("UPDATE ipv4_lease SET state='released' WHERE id=?", (lease_id,))
