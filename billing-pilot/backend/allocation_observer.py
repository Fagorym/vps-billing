"""Read-only allocation identity and root filesystem observations; no Engine/IPAM init."""
from contextlib import contextmanager, closing
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import time
import uuid

from infrastructure_observer import InfrastructureObserver, require, fingerprint
from infrastructure_disk_history import DiskHistory, STORE_PATH, RETENTION_SECONDS, valid_pair

DISK_ACTIONS = ('disk_usage', 'disk_history')


class DiskReadDeadline(BaseException):
    """A wall-clock timeout must bypass expected QGA OSError handling."""
    pass


class AllocationIdentity:
    def marker(self, row):
        return f'safehost-billing:v1:order:{row["order_id"]}:client:{row["client_id"]}:' + fingerprint(json.loads(row['spec']))

    def vmid(self, row):
        return self.c['vm_first'] + row['slot']


    def owned_config(self, row, guests=None, *, configs=None):
        vmid = self.vmid(row)
        guest = (guests if guests is not None else self.pve.guests()).get(vmid)
        require(guest is not None and guest['node'] == self.c['node'] and guest['type'] == 'qemu',
                'Управляемая VM не найдена на заданном узле')
        cfg = self.pve.config(vmid) if configs is None else configs.get(vmid)
        require(cfg is not None, 'Управляемая конфигурация VM не найдена')
        require(cfg.get('description') == self.marker(row) and not cfg.get('template'),
                'VMID занят чужой VM или изменена метка владельца')
        require(not cfg.get('lock'), 'VM заблокирована; повторите после завершения задачи')
        require('bridge=' + self.c['bridge'] in cfg.get('net0', '').split(','), 'Изменилась сеть VM')
        stored = self.db.execute('SELECT phase FROM allocation WHERE order_id=?', (row['order_id'],)).fetchone()
        effective_phase = stored['phase'] if stored else row['phase']
        public = json.loads(row['spec']).get('network_mode') == 'public_ipv4'
        extra_nets = {k for k in cfg if re.fullmatch(r'net[1-9]\d*', k)}
        require(extra_nets <= ({'net1'} if public else set()), 'У VM появилась дополнительная сеть')
        if public and row['phase'] != 'reserved':
            lease = self.ipam.for_order(row['order_id'], row['client_id'])
            detached = effective_phase in ('archiving', 'purging', 'canceling', 'restoring') and 'net1' not in cfg and 'ipconfig1' not in cfg
            if lease and not detached:
                require(cfg.get('net1') == self.public_nic(row, lease, down=True) or cfg.get('net1') == self.public_nic(row, lease), 'Изменилась публичная сеть VM')
                expected = f'ip={lease["address"]}/{self.public_prefix()},gw={self.c["public_network"]["gateway"]}'
                require(cfg.get('ipconfig1') == expected, 'Изменилась публичная адресация VM')
            elif not lease:
                require(not extra_nets and not cfg.get('ipconfig1'), 'Освобождённый адрес остался у VM')
            require(cfg.get('net0') == self.private_nic(row), 'Изменилась приватная сеть VM')
        require(not cfg.get('hookscript'), 'У VM появился сторонний lifecycle hook')
        require(not any(re.fullmatch(r'(?:unused|tpmstate)\d+', k) for k in cfg), 'У VM появились неучтённые тома')
        if row['phase'] != 'reserved':
            ip = str(ipaddress.ip_address(self.c['ip_first']) + row['slot'])
            fields = dict(part.split('=', 1) for part in cfg.get('ipconfig0', '').split(',') if '=' in part)
            expected_private = {'ip': ip + '/24'} if public else {'ip': ip + '/24', 'gw': self.c['gateway']}
            require(fields == expected_private, 'Изменилась адресация VM')
            require(not any(re.fullmatch(r'ipconfig[1-9]\d*', k) and (not public or k != 'ipconfig1') for k in cfg), 'У VM появилась дополнительная адресация')
        for disk in ('scsi0', 'efidisk0', 'ide2'):
            if disk in cfg:
                require(re.fullmatch(re.escape(self.c['storage']) + ':vm-' + str(vmid) + r'-[a-z0-9-]+',
                                     cfg[disk].split(',')[0]), 'VM использует неожиданный том')
        require(not any(re.fullmatch(r'(?:scsi|sata|virtio|ide)\d+', k) and k not in ('scsi0', 'ide2')
                        for k in cfg), 'У VM появились дополнительные диски')
        return cfg

    def public_prefix(self):
        return ipaddress.IPv4Network(self.c['public_network']['cidr']).prefixlen

    def mac(self, row, nic):
        blob = uuid.uuid5(uuid.NAMESPACE_OID, f'safehost:{row["order_id"]}:{row["client_id"]}:{nic}').bytes
        return ':'.join(f'{x:02x}' for x in b'\x02' + blob[:5])

    def private_nic(self, row):
        return f'virtio={self.mac(row, 0)},bridge={self.c["bridge"]},firewall=0'

    def public_nic(self, row, lease, down=False):
        return f'virtio={self.mac(row, 1)},bridge={self.c["public_network"]["bridge"]},firewall=0' + (',link_down=1' if down else '')
class ReadOnlyLeases:
    def __init__(self, db):self.db = db

    def for_order(self, order, client):
        return self.db.execute("SELECT * FROM ipv4_lease WHERE order_id=? AND client_id=? AND state!='released' ORDER BY generation DESC LIMIT 1",
                               (order, client)).fetchone()


class CustomerDiskHistory(DiskHistory):
    @contextmanager
    def customer_writer(self):
        # Keep the infrastructure table and its global user_version unchanged.
        with self.writer() as db:
            db.execute('CREATE TABLE IF NOT EXISTS customer_sample (identitySha256 TEXT NOT NULL,timestamp INTEGER NOT NULL,usedBytes INTEGER,totalBytes INTEGER,PRIMARY KEY(identitySha256,timestamp))')
            db.execute('CREATE INDEX IF NOT EXISTS customer_retention ON customer_sample(timestamp)')
            db.execute('CREATE TABLE IF NOT EXISTS collector_cursor (name TEXT PRIMARY KEY,lastOrder INTEGER NOT NULL)')
            yield db

    def record_customer(self, entry, tick, used, total, *, now):
        require(type(tick) is int and tick >= 0 and tick % 60 == 0 and tick == int(now)//60*60, 'Некорректная минута наблюдения')
        require((used is None and total is None) or valid_pair(used,total), 'Некорректные размеры диска')
        if entry['identitySha256'] is None:return
        with self.customer_writer() as db:
            db.execute('INSERT OR IGNORE INTO customer_sample VALUES(?,?,?,?)',(entry['identitySha256'],tick,used,total))
            db.execute('DELETE FROM customer_sample WHERE timestamp<=?',(int(now)-RETENTION_SECONDS,))

    def prune_customers(self, now):
        if not self.checked():return
        with closing(sqlite3.connect(self.path.as_uri()+'?mode=rw',uri=True,timeout=.5)) as db, db:
            if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='customer_sample'").fetchone():
                db.execute('DELETE FROM customer_sample WHERE timestamp<=?',(int(now)-RETENTION_SECONDS,))
        self.checked()

    def read_customer(self, entry, start, end):
        if entry['identitySha256'] is None or not self.checked():return {}
        with closing(sqlite3.connect(self.path.as_uri()+'?mode=ro',uri=True,timeout=.5)) as db:
            db.execute('PRAGMA query_only=ON')
            require(db.execute('PRAGMA user_version').fetchone()[0]==1,'Неизвестная версия истории диска')
            if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='customer_sample'").fetchone():return {}
            rows=db.execute('SELECT timestamp,usedBytes,totalBytes FROM customer_sample WHERE identitySha256=? AND timestamp>? AND timestamp<=? ORDER BY timestamp LIMIT 10081',
                            (entry['identitySha256'],start,end)).fetchall()
        self.checked()
        require(len(rows)<=10080,'Слишком много точек истории диска')
        result={}
        for tick,used,total in rows:
            require(type(tick) is int and tick%60==0 and tick not in result
                    and ((used is None and total is None) or valid_pair(used,total)),'Повреждена история диска')
            result[tick]=(used,total)
        return result

    def customer_order(self, candidates):
        if not candidates:return []
        with self.customer_writer() as db:
            row=db.execute("SELECT lastOrder FROM collector_cursor WHERE name='customer'").fetchone()
        last=row[0] if row else 0
        return sorted(candidates,key=lambda pair:(pair[1]<=last,pair[1]))

    def attempted(self, order):
        with self.customer_writer() as db:
            db.execute("INSERT INTO collector_cursor VALUES('customer',?) ON CONFLICT(name) DO UPDATE SET lastOrder=excluded.lastOrder",(order,))


class AllocationObserver(AllocationIdentity, InfrastructureObserver):
    @contextmanager
    def allocations(self):
        parent=self.state.lstat();path=self.state/'allocations.sqlite';metadata=path.lstat()
        require(stat.S_ISDIR(parent.st_mode) and parent.st_uid==os.geteuid() and stat.S_IMODE(parent.st_mode)==0o700
                and stat.S_ISREG(metadata.st_mode) and metadata.st_uid==os.geteuid() and stat.S_IMODE(metadata.st_mode)==0o600,
                'Небезопасный allocator для наблюдения')
        with closing(sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=.5)) as db:
            db.row_factory=sqlite3.Row;db.execute('PRAGMA query_only=ON')
            yield db

    @staticmethod
    def target(client,order):
        require(type(client) is int and 0<client<2147483647 and type(order) is int and 0<order<2147483647,
                'Нужны целочисленные order_id и client_id')

    def candidates(self):
        registry=self.infrastructure_registry()
        with self.allocations() as db:
            rows=db.execute('SELECT client_id,order_id,slot FROM allocation ORDER BY order_id LIMIT ?', (self.c['slots']+1,)).fetchall()
        require(len(rows)<=self.c['slots'],'Некорректное число allocation')
        return [(row['client_id'],row['order_id']) for row in rows if self.c['vm_first']+row['slot'] not in registry]

    def identity(self,client,order,reader):
        self.target(client,order)
        snapshot=reader.identity()
        require(isinstance(snapshot,dict),'Некорректная конфигурация VPS')
        with self.allocations() as db:
            row=db.execute('SELECT * FROM allocation WHERE order_id=?',(order,)).fetchone()
            require(row is not None and row['client_id']==client,'VPS этого клиента не найден')
            require(type(row['slot']) is int and 0<=row['slot']<self.c['slots'],'Некорректный слот VPS')
            vmid=self.vmid(row)
            require(vmid not in self.infrastructure_registry(),'Служебная VM доступна через реестр владельца')
            checker=AllocationIdentity();checker.c=self.c;checker.pve=self.pve;checker.db=db;checker.ipam=ReadOnlyLeases(db)
            cfg=checker.owned_config(row,guests={vmid:snapshot.get('guest')},configs={vmid:snapshot.get('config')})
            lease=checker.ipam.for_order(order,client) if json.loads(row['spec']).get('network_mode')=='public_ipv4' else None
            entry={'client_id':client,'order_id':order,'vmid':vmid,'node':self.c['node'],'mountpoint':'/',
                   'allocation':dict(row),'lease':dict(lease) if lease else None,
                   'configSha256':fingerprint({key:value for key,value in cfg.items() if key!='digest'})}
        created=row['created_at'];valid_generation=False
        try:
            instant=datetime.fromisoformat(created)
            valid_generation=instant.tzinfo is not None and 0<=instant.timestamp()<=time.time()
        except (ValueError,TypeError):pass
        entry['identitySha256']=fingerprint({key:entry[key] for key in ('client_id','order_id','vmid','node','configSha256')} |
            {key:row[key] for key in ('slot','created_at','spec')}) if valid_generation else None
        return entry,snapshot.get('guest')

    def bound(self,client,order):
        self.target(client,order)
        with self.allocations() as db:
            row=db.execute('SELECT * FROM allocation WHERE order_id=?',(order,)).fetchone()
            require(row is not None and row['client_id']==client,'VPS этого клиента не найден')
            require(type(row['slot']) is int and 0<=row['slot']<self.c['slots'],'Некорректный слот VPS')
            vmid=self.vmid(row)
            require(vmid not in self.infrastructure_registry(),'Служебная VM доступна через реестр владельца')
            return vmid

    @staticmethod
    def public_identity(entry):
        return {key:entry[key] for key in ('client_id','order_id','vmid','node','mountpoint')}

    def observe_disk(self,client,order):
        vmid=self.bound(client,order)
        with self.pve.metrics_reader(vmid,'day') as reader:
            entry,guest=self.identity(client,order,reader)
            require(entry['vmid']==vmid,'Изменился слот VPS перед чтением диска')
            result=self.public_identity(entry)|{'usedBytes':None,'totalBytes':None,'observedAt':None}
            offline=entry['allocation']['phase']!='ready' or guest.get('status')=='stopped'
            fs=None
            if not offline:
                try:fs=self.pve.guest_fs(vmid)
                except (OSError,ValueError,TypeError,AttributeError,subprocess.TimeoutExpired):pass
            after,_=self.identity(client,order,reader)
            require(after==entry,'Изменилась идентичность VPS во время чтения диска')
        if isinstance(fs,(tuple,list)) and len(fs)==2 and valid_pair(*fs):
            result.update(usedBytes=fs[0],totalBytes=fs[1],observedAt=datetime.now(timezone.utc).isoformat())
        return result,entry

    def disk_usage(self,client,order):return self.observe_disk(client,order)[0]

    def disk_history(self,client,order,timeframe,*,store=None,clock=time.time):
        periods={'day':86400,'week':604800}
        require(isinstance(timeframe,str) and timeframe in periods,'Недопустимый период истории диска')
        vmid=self.bound(client,order);end=int(clock())//60*60;start=end-periods[timeframe]
        with self.pve.metrics_reader(vmid,'day') as reader:
            entry,_=self.identity(client,order,reader)
            require(entry['vmid']==vmid,'Изменился слот VPS перед чтением истории')
            rows=(store or CustomerDiskHistory(STORE_PATH)).read_customer(entry,start,end)
            after,_=self.identity(client,order,reader)
            require(after==entry,'Изменилась идентичность VPS во время чтения истории')
        result=self.public_identity(entry)|{'timeframe':timeframe,'start':start,'end':end,'step':60,
            'points':[{'timestamp':tick,'usedBytes':rows.get(tick,(None,None))[0],'totalBytes':rows.get(tick,(None,None))[1]}
                      for tick in range(start+60,end+1,60)]}
        require(len(json.dumps({'ok':True,'result':result}).encode())<1048576,'История диска слишком велика')
        return result

    def handle_disk(self,request):
        require(request.get('action') in DISK_ACTIONS,'Недопустимая операция диска')
        if request['action']=='disk_usage':
            require(request.get('timeframe') is None,'Текущему диску не нужен период')
            return self.disk_usage(request.get('client_id'),request.get('order_id'))
        return self.disk_history(request.get('client_id'),request.get('order_id'),request.get('timeframe'))
