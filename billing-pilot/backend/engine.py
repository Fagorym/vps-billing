#!/usr/bin/python3
"""Restricted SSH command. Only owned VMs, no arbitrary commands or deletion."""
import base64
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
import struct
import subprocess
import sys

from cryptography.fernet import Fernet, InvalidToken


class Refused(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Refused(message)


def ssh_key(value):
    require(isinstance(value, str) and len(value) < 1000 and '\n' not in value and '\r' not in value,
            'Нужен один публичный Ed25519 SSH-ключ')
    parts = value.strip().split()
    require(len(parts) >= 2 and parts[0] == 'ssh-ed25519', 'Поддерживается ssh-ed25519')
    try:
        blob = base64.b64decode(parts[1], validate=True)
        require(len(blob) == 51 and struct.unpack('>I', blob[:4])[0] == 11
                and blob[4:15] == b'ssh-ed25519' and struct.unpack('>I', blob[15:19])[0] == 32,
                'Некорректный Ed25519 ключ')
    except (ValueError, struct.error) as exc:
        raise Refused('Некорректный Ed25519 ключ') from exc
    return ' '.join(parts[:2])


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def run(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=900)
    require(result.returncode == 0, 'Proxmox отклонил операцию; смотрите журнал хоста')
    return result.stdout


def declared_ips(pve, node, exclude=None):
    """Both QEMU and LXC declared addresses; called again at purchase, not just deploy."""
    used = set()
    for vmid, guest in pve.guests().items():
        if vmid == exclude or guest['node'] != node or guest['type'] not in ('qemu', 'lxc'):
            continue
        cfg = pve.config(vmid, guest['type'])
        fields = ('ipconfig',) if guest['type'] == 'qemu' else ('net',)
        for key, value in cfg.items():
            if key.startswith(fields):
                match = re.search(r'(?:^|,)ip=([0-9.]+)(?:/|,|$)', str(value))
                if match:
                    used.add(match[1])
    return used


class Proxmox:
    def __init__(self, config):
        self.c = config

    def api(self, path, **params):
        args = ['/usr/bin/pvesh', 'get', path, '--output-format', 'json']
        for name, value in params.items():
            args += ['--' + name, str(value)]
        return json.loads(run(args))

    def guests(self):
        return {int(v['vmid']): v for v in self.api('/cluster/resources', type='vm')}

    def config(self, vmid, kind='qemu'):
        return self.api(f'/nodes/{self.c["node"]}/{kind}/{vmid}/config')

    def command(self, verb, vmid, *args):
        return run(['/usr/sbin/qm', verb, str(vmid), *map(str, args)])

    def check_capacity(self, plan):
        node = self.api(f'/nodes/{self.c["node"]}/status')
        reserved = sum(int(v.get('maxmem', 0)) for v in self.guests().values()
                       if v['node'] == self.c['node'] and not v.get('template'))
        require(reserved + plan['memory_mb'] * 1048576 <= node['memory']['total'] - 2 * 1073741824,
                'Недостаточно RAM с резервом 2 GiB для хоста')
        storage = self.api(f'/nodes/{self.c["node"]}/storage/{self.c["storage"]}/status')
        require(int(storage['avail']) >= (plan['disk_gb'] + 5) * 1073741824,
                'Недостаточно места на local-lvm')

    def status(self, vmid):
        return self.api(f'/nodes/{self.c["node"]}/qemu/{vmid}/status/current')['status']

    def cloudinit_update(self, vmid):
        return run(['/usr/sbin/qm', 'cloudinit', 'update', str(vmid)])

    def resize(self, vmid, gb):
        run(['/usr/sbin/qm', 'disk', 'resize', str(vmid), 'scsi0', str(gb) + 'G'])


class Engine:
    def __init__(self, config, state, snippets, pve=None):
        self.c = config
        self.state = Path(state)
        self.snippets = Path(snippets)
        self.state.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.pve = pve or Proxmox(config)
        self.db = sqlite3.connect(self.state / 'allocations.sqlite', timeout=30)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('''CREATE TABLE IF NOT EXISTS allocation (
            order_id INTEGER PRIMARY KEY, client_id INTEGER NOT NULL,
            slot INTEGER NOT NULL UNIQUE, spec TEXT NOT NULL,
            phase TEXT NOT NULL DEFAULT 'reserved')''')
        self.db.execute('''CREATE TABLE IF NOT EXISTS credential (
            order_id INTEGER PRIMARY KEY, encrypted BLOB NOT NULL, password_hash TEXT NOT NULL)''')
        self.db.commit()
        config_hash = self.state / 'config.sha256'
        digest = fingerprint(config)
        if config_hash.exists():
            require(config_hash.read_text().strip() == digest,
                    'Конфигурация пула изменилась; нужна отдельная миграция')
        else:
            require(not self.db.execute('SELECT 1 FROM allocation').fetchone(), 'Потерян config.sha256')
            config_hash.write_text(digest + '\n')

    def marker(self, row):
        return f'safehost-billing:v1:order:{row["order_id"]}:client:{row["client_id"]}:' + fingerprint(json.loads(row['spec']))

    def vmid(self, row):
        return self.c['vm_first'] + row['slot']

    def owned_config(self, row):
        vmid = self.vmid(row)
        guest = self.pve.guests().get(vmid)
        require(guest is not None and guest['node'] == self.c['node'] and guest['type'] == 'qemu',
                'Управляемая VM не найдена на заданном узле')
        cfg = self.pve.config(vmid)
        require(cfg.get('description') == self.marker(row) and not cfg.get('template'),
                'VMID занят чужой VM или изменена метка владельца')
        require(not cfg.get('lock'), 'VM заблокирована; повторите после завершения задачи')
        require('bridge=' + self.c['bridge'] in cfg.get('net0', '').split(','), 'Изменилась сеть VM')
        require(not any(re.fullmatch(r'net[1-9]\d*', k) for k in cfg), 'У VM появилась дополнительная сеть')
        for disk in ('scsi0', 'efidisk0', 'ide2'):
            if disk in cfg:
                require(re.fullmatch(re.escape(self.c['storage']) + ':vm-' + str(vmid) + r'-[a-z0-9-]+',
                                     cfg[disk].split(',')[0]), 'VM использует неожиданный том')
        require(not any(re.fullmatch(r'(?:scsi|sata|virtio|ide)\d+', k) and k not in ('scsi0', 'ide2')
                        for k in cfg), 'У VM появились дополнительные диски')
        return cfg

    def reserve(self, order, client, spec):
        row = self.db.execute('SELECT * FROM allocation WHERE order_id=?', (order,)).fetchone()
        if row:
            require(row['client_id'] == client and json.loads(row['spec']) == spec,
                    'Заказ уже закреплён за другим клиентом, тарифом или SSH-ключом')
            return row
        used = {r[0] for r in self.db.execute('SELECT slot FROM allocation')}
        guests = self.pve.guests()
        ips = declared_ips(self.pve, self.c['node'])
        slots = [i for i in range(self.c['slots']) if i not in used and self.c['vm_first'] + i not in guests
                 and str(ipaddress.ip_address(self.c['ip_first']) + i) not in ips]
        require(slots, 'Нет свободных слотов VPS; отменённые слоты не переиспользуются')
        credential = self.new_password(order, client) if spec['ssh_key'] is None else None
        self.db.execute('INSERT INTO allocation(order_id,client_id,slot,spec) VALUES(?,?,?,?)',
                        (order, client, slots[0], json.dumps(spec, sort_keys=True)))
        if credential is not None:
            self.db.execute('INSERT INTO credential(order_id,encrypted,password_hash) VALUES(?,?,?)',
                            (order, *credential))
        self.db.commit()  # Reservation survives a lost SSH response or an interrupted clone.
        return self.db.execute('SELECT * FROM allocation WHERE order_id=?', (order,)).fetchone()

    def cipher(self):
        key = self.state / 'credential.key'
        require(not key.is_symlink(), 'Ключ шифрования не должен быть symlink')
        if not key.exists():
            require(not self.db.execute('SELECT 1 FROM credential LIMIT 1').fetchone(),
                    'Потерян ключ выдачи паролей; восстановите credential.key из резервной копии')
            with os.fdopen(os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as file:
                file.write(Fernet.generate_key())
        try:
            return Fernet(key.read_bytes())
        except (ValueError, TypeError) as exc:
            raise Refused('Повреждён ключ выдачи паролей; нужна резервная копия') from exc

    def new_password(self, order, client):
        cipher = self.cipher()
        password = 'V1!' + secrets.token_urlsafe(24)
        process = subprocess.run([shutil.which('openssl') or '/usr/bin/openssl', 'passwd', '-6', '-stdin'],
                                 input=password + '\n', capture_output=True, text=True, timeout=15)
        hashed = process.stdout.strip()
        require(process.returncode == 0 and hashed.startswith('$6$'), 'Не удалось подготовить пароль VPS')
        value = json.dumps({'order_id': order, 'client_id': client, 'password': password}).encode()
        return cipher.encrypt(value), hashed

    def initial_password(self, row):
        require(row['phase'] == 'ready' and self.pve.status(self.vmid(row)) == 'running',
                'Пароль доступен только у активного VPS')
        require(json.loads(row['spec'])['ssh_key'] is None, 'Этот VPS использует SSH-ключ')
        credential = self.db.execute('SELECT encrypted FROM credential WHERE order_id=?', (row['order_id'],)).fetchone()
        require(credential is not None, 'Не найден начальный пароль; нужна проверка администратором')
        try:
            value = json.loads(self.cipher().decrypt(credential['encrypted']))
        except (InvalidToken, ValueError) as exc:
            raise Refused('Начальный пароль повреждён; нужна резервная копия') from exc
        require(value['order_id'] == row['order_id'] and value['client_id'] == row['client_id'],
                'Пароль не принадлежит этому заказу')
        return {'user': 'vpsadmin', 'password': value['password']}

    def phase(self, row, value):
        self.db.execute('UPDATE allocation SET phase=? WHERE order_id=?', (value, row['order_id']))
        self.db.commit()

    def create(self, row):
        require(row['phase'] != 'cancelled', 'Заказ отменён; диск сохранён, новая активация запрещена')
        require(row['phase'] != 'suspended', 'VPS приостановлен; используйте unsuspend')
        vmid, spec = self.vmid(row), json.loads(row['spec'])
        plan = self.c['plans'][spec['plan']]
        if vmid not in self.pve.guests():
            require(row['phase'] == 'reserved', 'Ранее созданная VM исчезла; автоматическое восстановление запрещено')
            ip = str(ipaddress.ip_address(self.c['ip_first']) + row['slot'])
            require(ip not in declared_ips(self.pve, self.c['node']), 'IP закреплённого слота занят другой VM или LXC')
            template = self.pve.config(self.c['template_id'])
            require(template.get('template') and template.get('description') == self.c['template_marker'],
                    'Шаблон не принадлежит proxmox-pilot')
            self.pve.check_capacity(plan)
            self.pve.command('clone', self.c['template_id'], vmid, '--full', '1', '--storage', self.c['storage'],
                             '--name', f'vps-order-{row["order_id"]}', '--description', self.marker(row))
        cfg = self.owned_config(row)
        if row['phase'] == 'ready':
            return self.info(row)  # An activation retry must never reboot or reconfigure a guest.
        require(self.pve.status(vmid) == 'stopped', 'Незавершённая VM запущена; нужна проверка администратором')
        require('scsi0' in cfg, 'Клонирование не завершено; проверьте задачу Proxmox')
        ip = str(ipaddress.ip_address(self.c['ip_first']) + row['slot'])
        cloud = {'hostname': f'vps-order-{row["order_id"]}', 'manage_etc_hosts': True,
                 'users': [{'name': 'vpsadmin', 'groups': ['adm', 'sudo'], 'shell': '/bin/bash',
                            'sudo': 'ALL=(ALL) NOPASSWD:ALL', 'lock_passwd': True,
                            'ssh_authorized_keys': [spec['ssh_key']]}],
                 'disable_root': True, 'ssh_pwauth': False, 'package_update': True,
                 'packages': ['qemu-guest-agent'], 'runcmd': [['systemctl', 'enable', '--now', 'qemu-guest-agent']]}
        if spec['ssh_key'] is None:
            credential = self.db.execute('SELECT password_hash FROM credential WHERE order_id=?', (row['order_id'],)).fetchone()
            require(credential is not None, 'Не найден пароль закреплённого VPS; нужна проверка администратором')
            cloud['users'][0]['ssh_authorized_keys'] = []
            # Ubuntu's set_passwords runs before SSH, and expires the hash before enabling password auth.
            cloud['chpasswd'] = {'expire': True, 'users': [
                {'name': 'vpsadmin', 'type': 'hash', 'password': credential['password_hash']}]}
            cloud['ssh_pwauth'] = True
            cloud['write_files'] = [{'path': '/etc/ssh/sshd_config.d/00-safehost-password.conf',
                                     'owner': 'root:root', 'permissions': '0644',
                                     'content': 'KbdInteractiveAuthentication no\nPermitRootLogin no\n'}]
        self.snippets.mkdir(parents=True, exist_ok=True)
        snippet = f'safehost-billing-{vmid}.yaml'
        temp = self.snippets / (snippet + '.tmp')
        with os.fdopen(os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), 'w') as file:
            file.write('#cloud-config\n' + json.dumps(cloud, ensure_ascii=False) + '\n')
        temp.chmod(0o600)
        temp.replace(self.snippets / snippet)
        self.pve.command('set', vmid, '--cores', plan['cores'], '--memory', plan['memory_mb'],
                         '--cpu', 'host', '--sockets', '1', '--onboot', '1', '--protection', '1',
                         '--ciuser', 'vpsadmin', '--ciupgrade', '0', '--nameserver', self.c['dns'],
                         '--ipconfig0', f'ip={ip}/24,gw={self.c["gateway"]}',
                         '--cicustom', 'user=local:snippets/' + snippet)
        size = re.search(r'(?:^|,)size=([0-9.]+)([GMT])(?:,|$)', cfg['scsi0'])
        require(size, 'Не удалось прочитать размер диска')
        gb = float(size[1]) * {'M': 1/1024, 'G': 1, 'T': 1024}[size[2]]
        require(gb <= plan['disk_gb'], 'Диск больше тарифа; уменьшение запрещено')
        if gb < plan['disk_gb']:
            self.pve.resize(vmid, plan['disk_gb'])
        self.pve.cloudinit_update(vmid)
        # Persist configured phase before start: a lost response is recoverable on retry.
        self.phase(row, 'configured')
        self.pve.command('start', vmid)
        self.phase(row, 'ready')
        return self.info(row)

    def info(self, row):
        self.owned_config(row)
        current = self.db.execute('SELECT phase FROM allocation WHERE order_id=?', (row['order_id'],)).fetchone()[0]
        return {'vmid': self.vmid(row), 'public_ip': self.c['public_ip'],
                'private_ip': str(ipaddress.ip_address(self.c['ip_first']) + row['slot']),
                'ssh_port': self.c['ssh_port_first'] + row['slot'], 'user': 'vpsadmin',
                'auth_mode': 'password' if json.loads(row['spec'])['ssh_key'] is None else 'key',
                'phase': current, 'status': self.pve.status(self.vmid(row)),
                'ssh': f'ssh -p {self.c["ssh_port_first"] + row["slot"]} vpsadmin@{self.c["public_ip"]}'}

    def handle(self, request):
        require(isinstance(request, dict), 'Ожидается JSON object')
        action = request.get('action')
        require(action in ('create', 'status', 'password', 'suspend', 'unsuspend', 'cancel'), 'Недопустимая операция')
        order, client = request.get('order_id'), request.get('client_id')
        require(type(order) is int and 1 <= order < 2147483647 and type(client) is int and 1 <= client < 2147483647,
                'Нужны целочисленные order_id и client_id')
        if action == 'create':
            require(request.get('plan') in self.c['plans'], 'Неизвестный тариф')
            key = request.get('ssh_key', '')
            require(key is None or isinstance(key, str), 'Некорректный публичный SSH-ключ')
            spec = {'plan': request['plan'], 'ssh_key': ssh_key(key) if key and key.strip() else None}
            row = self.reserve(order, client, spec)
            if row['phase'] == 'configured':
                self.owned_config(row)
                if self.pve.status(self.vmid(row)) == 'stopped':
                    self.pve.command('start', self.vmid(row))
                self.phase(row, 'ready')
                return self.info(row)
            return self.create(row)
        row = self.db.execute('SELECT * FROM allocation WHERE order_id=?', (order,)).fetchone()
        require(row is not None and row['client_id'] == client, 'VPS этого клиента не найден')
        self.owned_config(row)
        if action == 'password':
            return self.initial_password(row)
        if action == 'status':
            return self.info(row)
        require(row['phase'] != 'cancelled' or action == 'cancel', 'Заказ отменён; операция запрещена')
        require(row['phase'] in ('ready', 'suspended', 'cancelled'), 'Создание не завершено; сначала повторите активацию')
        require(action != 'unsuspend' or row['phase'] != 'cancelled', 'Заказ отменён; запуск запрещён')
        desired = 'running' if action == 'unsuspend' else 'stopped'
        # Cancel/suspend disables autostart too: rebooting the host must not lift suspension.
        self.pve.command('set', self.vmid(row), '--onboot', '1' if action == 'unsuspend' else '0')
        if self.pve.status(self.vmid(row)) != desired:
            self.pve.command('start' if desired == 'running' else 'stop', self.vmid(row))
        self.phase(row, {'suspend': 'suspended', 'unsuspend': 'ready', 'cancel': 'cancelled'}[action])
        return self.info(row)


def main():
    os.umask(0o077)
    # SSH_ORIGINAL_COMMAND is deliberately ignored. stdin is the only protocol.
    config = json.loads(Path('/etc/safehost-billing/config.json').read_text())
    state = Path('/var/lib/safehost-billing')
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (state / 'operation.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        raw = sys.stdin.buffer.read(8193)
        require(len(raw) <= 8192, 'Запрос слишком большой')
        engine = Engine(config, state, '/var/lib/vz/snippets')
        try:
            result = engine.handle(json.loads(raw))
        finally:
            engine.db.close()
    print(json.dumps({'ok': True, 'result': result}, ensure_ascii=False))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, sqlite3.Error, subprocess.TimeoutExpired) as exc:
        print(json.dumps({'ok': False, 'error': str(exc)}, ensure_ascii=False))
        sys.exit(1)
