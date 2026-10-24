#!/usr/bin/python3
"""Restricted SSH command. Only marked owned VMs, no arbitrary commands."""
import base64
import fcntl
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import shutil
import sqlite3
import stat
import struct
import subprocess
import sys
from datetime import datetime, timezone
from contextlib import contextmanager, nullcontext
import uuid

from cryptography.fernet import Fernet, InvalidToken
sys.path.insert(0, str(Path(__file__).resolve().parent))
from ipam import Ipam, Refused as IpamRefused

DEFAULT_OS = 'Ubuntu 24.04'
SUPPORTED_OS = (DEFAULT_OS, 'Ubuntu 22.04', 'Ubuntu 26.04', 'Debian 13',
                'Debian 12', 'AlmaLinux 9', 'AlmaLinux 10')
METRICS_ACTIONS = ('metrics', 'infrastructure_metrics', 'infrastructure_disk')
RESTART_SUPERSEDING_PHASES = ('stopped', 'suspended', 'blocked', 'archiving', 'archived',
                            'canceling', 'cancelled', 'purging', 'deleted')


class Refused(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Refused(message)


def selected_os(value):
    name = DEFAULT_OS if value is None else value
    require(isinstance(name, str) and name in SUPPORTED_OS, 'Неизвестная операционная система')
    return name


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
    return 'ssh-ed25519 ' + base64.b64encode(blob).decode('ascii')


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def validated_boot_id(value):
    require(isinstance(value, str) and re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', value),
            'Не удалось проверить запуск VPS')
    return value


def run(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=900)
    if result.returncode != 0:
        raise OSError('Сбой выполнения команды Proxmox; смотрите журнал хоста')
    return result.stdout


@contextmanager
def metrics_deadline(seconds=15):
    def expired(signum, frame):
        raise TimeoutError('Истёк срок получения метрик')
    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def declared_ips(pve, node, exclude=None, *, configs=None):
    """Both QEMU and LXC declared addresses; called again at purchase, not just deploy."""
    used = set()
    observed_configs = configs if configs is not None else pve.network_configs(node, exclude)
    for guest in observed_configs:
        cfg = guest['config']
        fields = ('ipconfig',) if guest['type'] == 'qemu' else ('net',)
        for key, value in cfg.items():
            if key.startswith(fields):
                match = re.search(r'(?:^|,)ip=([0-9.]+)(?:/|,|$)', str(value))
                if match:
                    used.add(match[1])
    return used


class MetricsReader:
    def __init__(self, process):
        self.process = process

    def read(self, action):
        self.process.stdin.write(json.dumps(action) + '\n')
        self.process.stdin.flush()
        line = self.process.stdout.readline(1048577)
        if not line.endswith('\n') or len(line) > 1048576:
            raise OSError('Некорректный ответ источника метрик')
        try:
            return json.loads(line)
        except ValueError as exc:
            raise OSError('Некорректный ответ источника метрик') from exc

    def identity(self):
        return self.read('identity')

    def history(self):
        return self.read('history')


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

    @contextmanager
    def metrics_reader(self, vmid, timeframe):
        # Load the canonical API once per request. No persistent process or shared history cache.
        script = r'''
$| = 1;
my ($node, $vmid, $timeframe) = @ARGV;
while (my $line = <STDIN>) {
    my $action = decode_json($line);
    my $result;
    if ($action eq 'identity') {
        PVE::Cluster::cfs_update();
        my $guest = PVE::Cluster::get_vmlist()->{ids}->{$vmid};
        $result = {guest => $guest, config => undef};
        if ($guest && $guest->{node} eq $node && $guest->{type} eq 'qemu') {
            $result->{config} = PVE::API2::Qemu->vm_config({node => $node, vmid => 0 + $vmid});
        }
    } elsif ($action eq 'history') {
        $result = PVE::API2::Qemu->rrddata({
            node => $node, vmid => 0 + $vmid, timeframe => $timeframe, cf => 'AVERAGE',
        });
    } else { die 'Invalid metrics read'; }
    print encode_json($result)."\n";
}
'''
        with subprocess.Popen([
            '/usr/bin/perl', '-MPVE::API2::Qemu', '-MJSON::PP', '-e', script,
            self.c['node'], str(vmid), timeframe,
        ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True) as process:
            try:
                yield MetricsReader(process)
            finally:
                # Includes validation failures, partial output and the outer metrics deadline.
                if process.poll() is None:
                    process.kill()

    def current_configs(self, node, exclude=None):
        # One canonical Proxmox read avoids a separate pvesh startup per VM.
        script = r'''
PVE::Cluster::cfs_update();
my ($node, $exclude) = @ARGV;
my $vms = PVE::Cluster::get_vmlist();
my @rows;
for my $id (sort {$a <=> $b} keys %{$vms->{ids}}) {
    my $guest = $vms->{ids}{$id};
    next if $guest->{node} ne $node || "$id" eq $exclude;
    my $config;
    if ($guest->{type} eq 'qemu') {
        $config = PVE::QemuConfig->load_current_config($id, 0);
    } elsif ($guest->{type} eq 'lxc') {
        $config = PVE::LXC::Config->load_current_config($id, 0);
    } else { next; }
    push @rows, {vmid => 0 + $id, type => $guest->{type}, config => $config};
}
print encode_json(\@rows);
'''
        return json.loads(subprocess.check_output([
            '/usr/bin/perl', '-MPVE::QemuConfig', '-MPVE::LXC::Config', '-MJSON::PP',
            '-e', script, node, '' if exclude is None else str(exclude)
        ], text=True, timeout=10))

    def network_configs(self, node, exclude=None):
        return [{'type': guest['type'], 'config': {
                    key: value for key, value in guest['config'].items()
                    if key.startswith('ipconfig' if guest['type'] == 'qemu' else 'net')}}
                for guest in self.current_configs(node, exclude)]

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

    def ready(self, vmid, ip, os_name=DEFAULT_OS):
        try:
            command = ['cloud-init', 'status', '--format', 'json']
            if os_name in ('AlmaLinux 9', 'AlmaLinux 10'):
                command.insert(0, '/usr/local/libexec/safehost-qga-exec')
            result = subprocess.run(['/usr/sbin/qm', 'guest', 'exec', str(vmid), '--timeout', '10',
                                     '--', *command],
                                    capture_output=True, text=True, timeout=15)
            if result.returncode != 0:
                return False
            guest = json.loads(result.stdout)
            cloud = json.loads(guest.get('out-data', '{}'))
            if guest.get('exitcode') != 0 or cloud.get('status') != 'done':
                return False
            with socket.create_connection((ip, 22), timeout=2) as connection:
                return connection.recv(128).startswith(b'SSH-2.0-')
        except (OSError, ValueError, subprocess.TimeoutExpired):
            return False

    def network_guard(self, row, lease, config):
        from guest_network import install_guard
        install_guard(row, lease, config)

    def guest_command(self, vmid, command, os_name):
        if os_name in ('AlmaLinux 9', 'AlmaLinux 10'):
            command = ['/usr/local/libexec/safehost-qga-exec', *command]
        result = subprocess.run(['/usr/sbin/qm', 'guest', 'exec', str(vmid), '--timeout', '10', '--', *command],
                                capture_output=True, text=True, timeout=15)
        if result.returncode != 0:
            raise OSError('Guest agent ещё не готов')
        response = json.loads(result.stdout)
        if response.get('exitcode') != 0:
            raise OSError('Не удалось выполнить гостевую операцию')
        return response.get('out-data', '')

    def boot_id(self, vmid, os_name=DEFAULT_OS):
        value = self.guest_command(vmid, ['/usr/bin/python3', '-c',
            "from pathlib import Path;print(Path('/proc/sys/kernel/random/boot_id').read_text().strip())"], os_name).strip()
        return validated_boot_id(value)

    def graceful_reboot(self, vmid, os_name=DEFAULT_OS):
        self.guest_command(vmid, ['/usr/bin/systemctl', '--no-block', 'reboot'], os_name)

    def remove_network_guard(self, vmid):
        from guest_network import remove_guard
        remove_guard(vmid)

    def apply_public_network(self, row, lease, config):
        from guest_network import apply_guest
        apply_guest(row, lease, config)

    def public_ready(self, ip):
        try:
            with socket.create_connection((ip, 22), timeout=2) as connection:
                return connection.recv(128).startswith(b'SSH-2.0-')
        except OSError:
            return False

    def guest_fs(self, vmid):
        try:
            result = subprocess.run(['/usr/sbin/qm', 'guest', 'cmd', str(vmid), 'get-fsinfo'],
                                    capture_output=True, text=True, timeout=3)
            if result.returncode == 0:
                filesystems = json.loads(result.stdout)
                root = next((fs for fs in filesystems if fs.get('mountpoint') == '/'), None)
                if root and all(type(root.get(k)) is int for k in ('used-bytes', 'total-bytes')):
                    return root['used-bytes'], root['total-bytes']
        except (OSError, ValueError, TypeError, subprocess.TimeoutExpired):
            pass
        return None


class Engine:
    def __init__(self, config, state, snippets, pve=None, *, db_timeout=30):
        self.c = config
        self.state = Path(state)
        self.snippets = Path(snippets)
        self.state.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.pve = pve or Proxmox(config)
        self.db = sqlite3.connect(self.state / 'allocations.sqlite', timeout=db_timeout)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('''CREATE TABLE IF NOT EXISTS allocation (
            order_id INTEGER PRIMARY KEY, client_id INTEGER NOT NULL,
            slot INTEGER NOT NULL UNIQUE, spec TEXT NOT NULL,
            phase TEXT NOT NULL DEFAULT 'reserved')''')
        self.db.execute('''CREATE TABLE IF NOT EXISTS credential (
            order_id INTEGER PRIMARY KEY, encrypted BLOB NOT NULL, password_hash TEXT NOT NULL)''')
        self.db.execute('BEGIN IMMEDIATE')
        columns = {r[1] for r in self.db.execute('PRAGMA table_info(allocation)')}
        for name in ('reason', 'created_at'):
            if name not in columns:
                self.db.execute(f'ALTER TABLE allocation ADD COLUMN {name} TEXT')
        self.db.execute('''CREATE TABLE IF NOT EXISTS retired_allocation (
            order_id INTEGER PRIMARY KEY, client_id INTEGER NOT NULL, slot INTEGER NOT NULL,
            spec TEXT NOT NULL, phase TEXT NOT NULL, reason TEXT, created_at TEXT)''')
        self.db.execute('''CREATE TABLE IF NOT EXISTS admin_operation (
            id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, order_id INTEGER NOT NULL,
            state TEXT NOT NULL, result TEXT)''')
        self.db.execute('''CREATE TABLE IF NOT EXISTS owner_restart (
            id TEXT PRIMARY KEY, order_id INTEGER NOT NULL, client_id INTEGER NOT NULL,
            owner TEXT NOT NULL, before_boot_id TEXT NOT NULL, state TEXT NOT NULL,
            after_boot_id TEXT)''')
        self.db.execute("CREATE UNIQUE INDEX IF NOT EXISTS owner_restart_pending ON owner_restart(order_id) WHERE state='dispatched'")
        self.db.commit()
        config_hash = self.state / 'config.sha256'
        digest = fingerprint(config)
        if config_hash.exists():
            require(config_hash.read_text().strip() == digest,
                    'Конфигурация пула изменилась; нужна отдельная миграция')
        else:
            require(not self.db.execute('SELECT 1 FROM allocation').fetchone(), 'Потерян config.sha256')
            config_hash.write_text(digest + '\n')
        self.ipam = Ipam(self.db, config.get("public_network"))

    def marker(self, row):
        return f'safehost-billing:v1:order:{row["order_id"]}:client:{row["client_id"]}:' + fingerprint(json.loads(row['spec']))

    def vmid(self, row):
        return self.c['vm_first'] + row['slot']

    def infrastructure_registry(self):
        """Root state, independent of the immutable provisioning configuration seal."""
        path = self.state / 'infrastructure.json'
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            return {}
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.geteuid()
                and metadata.st_mode & 0o077 == 0 and metadata.st_size <= 131072,
                'Небезопасный реестр служебных VM')
        def unique_fields(pairs):
            result = {}
            for key, value in pairs:
                require(key not in result, 'Повторное поле в реестре служебных VM')
                result[key] = value
            return result
        try:
            document = json.loads(path.read_text(), object_pairs_hook=unique_fields)
        except (OSError, ValueError) as exc:
            raise Refused('Некорректный реестр служебных VM') from exc
        require(isinstance(document, dict) and set(document) == {'version', 'servers'}
                and type(document['version']) is int and document['version'] == 1
                and isinstance(document['servers'], list) and len(document['servers']) <= 100,
                'Некорректный реестр служебных VM')
        registry = {}
        fields = {'vmid', 'node', 'account', 'name', 'os', 'address', 'publicIpv4', 'configSha256'}
        for entry in document['servers']:
            require(isinstance(entry, dict) and set(entry) == fields, 'Некорректная служебная VM')
            require(type(entry['vmid']) is int and 0 < entry['vmid'] < 2147483647
                    and entry['vmid'] not in registry and isinstance(entry['node'], str)
                    and entry['node'].strip() and entry['node'] == self.c['node'],
                    'Некорректный VMID или узел служебной VM')
            require(isinstance(entry['name'], str) and 1 <= len(entry['name'].strip()) <= 254
                    and not any(ord(character) < 32 for character in entry['name']),
                    'Нужно имя служебной VM')
            require(isinstance(entry['account'], str)
                    and re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', entry['account'])
                    and uuid.UUID(entry['account']).int != 0, 'Нужен UUID владельца служебной VM')
            selected_os(entry['os'])
            require(isinstance(entry['os'], str) and type(entry['publicIpv4']) is bool
                    and isinstance(entry['configSha256'], str)
                    and re.fullmatch(r'[0-9a-f]{64}', entry['configSha256']),
                    'Некорректная идентичность служебной VM')
            try:
                require(isinstance(entry['address'], str), 'Нужен IPv4 служебной VM')
                ipaddress.IPv4Address(entry['address'])
            except ValueError as exc:
                raise Refused('Некорректный IPv4 служебной VM') from exc
            registry[entry['vmid']] = entry
        return registry

    def assert_mutable(self, row):
        require(self.vmid(row) not in self.infrastructure_registry(),
                'Служебная VM доступна только для чтения')

    def infrastructure_info(self, entry, *, guests, configs):
        vmid = entry['vmid']
        guest, cfg = guests.get(vmid), configs.get(vmid)
        self.infrastructure_config(entry, guest, cfg)
        addresses = set()
        for key, value in cfg.items():
            if re.fullmatch(r'ipconfig\d+', key):
                match = re.search(r'(?:^|,)ip=([0-9.]+)(?:/|,|$)', str(value))
                if match:
                    addresses.add(match[1])
        require(entry['address'] in addresses, 'Не подтверждён адрес служебной VM')
        require(guest.get('status') in ('running', 'stopped'), 'Неизвестное состояние служебной VM')
        require(all(type(cfg.get(field)) in (int, str) and str(cfg[field]).isdigit()
                    and int(cfg[field]) > 0 for field in ('cores', 'memory')),
                'Не подтверждены ресурсы служебной VM')
        disk = re.search(r'(?:^|,)size=(\d+(?:\.\d+)?)([KMGT])(?:,|$)', str(cfg.get('scsi0', '')))
        require(disk is not None, 'Не подтверждён SSD служебной VM')
        disk_gb = float(disk[1]) * {'K': 1 / 1048576, 'M': 1 / 1024, 'G': 1, 'T': 1024}[disk[2]]
        require(math.isfinite(disk_gb) and disk_gb > 0, 'Не подтверждён SSD служебной VM')
        return {key: entry[key] for key in ('vmid', 'node', 'account', 'name', 'os', 'address', 'publicIpv4')} | {
            'status': guest['status'], 'phase': 'ready' if guest['status'] == 'running' else 'stopped',
            'cores': int(cfg['cores']), 'memoryMb': int(cfg['memory']),
            'diskGb': int(disk_gb) if disk_gb.is_integer() else disk_gb, 'observedAt': self.now()}

    @staticmethod
    def infrastructure_config(entry, guest, cfg):
        require(isinstance(guest, dict) and guest.get('node') == entry['node']
                and guest.get('type') == 'qemu' and isinstance(cfg, dict),
                'Служебная VM отсутствует на заданном узле')
        require(not cfg.get('template') and not cfg.get('lock')
                and fingerprint({key: value for key, value in cfg.items() if key != 'digest'}) == entry['configSha256'],
                'Изменилась защищённая конфигурация служебной VM')

    def template(self, os_name):
        templates = self.c.get('templates', {})
        require(isinstance(templates, dict), 'Некорректный каталог шаблонов ОС')
        configured = templates.get(os_name)
        if os_name not in templates and os_name == DEFAULT_OS:
            configured = {key: self.c.get(key) for key in ('template_id', 'template_marker')}
        require(isinstance(configured, dict), 'Шаблон выбранной ОС ещё не настроен')
        template_id, marker = configured.get('template_id'), configured.get('template_marker')
        require(type(template_id) is int and template_id > 0 and isinstance(marker, str) and marker.strip(),
                'Некорректная конфигурация шаблона ОС')
        guest = self.pve.guests().get(template_id)
        require(guest is not None and guest['node'] == self.c['node'] and guest['type'] == 'qemu',
                'Шаблон выбранной ОС не найден на заданном узле')
        template = self.pve.config(template_id)
        require(template.get('template') and template.get('description') == marker and not template.get('lock'),
                'Шаблон ОС не принадлежит proxmox-pilot или заблокирован')
        return template_id

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

    def isolate_public(self, row):
        self.assert_mutable(row)
        lease = self.ipam.for_order(row['order_id'], row['client_id'])
        if not lease:
            return
        require(self.pve.status(self.vmid(row)) == 'stopped', 'Нужно подтверждённо остановить VM')
        cfg = self.pve.config(self.vmid(row))
        if 'net1' in cfg or 'ipconfig1' in cfg:
            self.pve.command('set', self.vmid(row), '--delete', 'net1,ipconfig1')
        cfg = self.pve.config(self.vmid(row))
        require('net1' not in cfg and 'ipconfig1' not in cfg and self.pve.status(self.vmid(row)) == 'stopped', 'Не удалось изолировать публичный адрес')
        self.pve.network_guard(row, {**lease, 'state': 'released'}, self.c)
        self.ipam.release_assigned(row['order_id'], row['client_id'], lease['id'], isolated=True)

    def restore_public(self, row):
        self.assert_mutable(row)
        spec = json.loads(row['spec'])
        vmid = self.vmid(row)
        try:
            lease = self.ipam.reserve(spec['account'], spec['reference'], declared_ips(self.pve, self.c['node'], exclude=vmid))
            lease = self.ipam.bind(spec['account'], spec['reference'], lease['id'], row['order_id'], row['client_id'])
            self.pve.command('set', vmid, '--net1', self.public_nic(row, lease, down=True),
                             '--ipconfig1', f'ip={lease["address"]}/{self.public_prefix()},gw={self.c["public_network"]["gateway"]}')
            self.pve.network_guard(row, lease, self.c)
            # Boot needs carrier to finish network-online. The installed bridge
            # guard already drops every source except the newly assigned IP,
            # including the archived address until netplan is repaired.
            self.pve.command('set', vmid, '--net1', self.public_nic(row, lease))
            if self.pve.status(vmid) != 'running':
                self.pve.command('start', vmid)
            self.pve.apply_public_network(row, lease, self.c)
            require(self.pve.ready(vmid, str(ipaddress.ip_address(self.c['ip_first']) + row['slot']), spec.get('os', DEFAULT_OS))
                    and self.pve.public_ready(lease['address']), 'Сеть восстанавливаемой VM ещё не готова')
            self.pve.command('set', vmid, '--onboot', '1')
            self.phase(row, 'ready')
        except (ValueError, OSError, subprocess.SubprocessError) as error:
            # Retain the lease if stopping/detaching itself fails; a retry must
            # verify isolation before returning any address to the pool.
            self.stop_vm(row)
            self.isolate_public(row)
            self.phase(row, 'archived')
            raise OSError('Восстановление сети отложено; VM сохранена в архиве') from error

    def reserve(self, order, client, spec):
        require(not self.db.execute('SELECT 1 FROM retired_allocation WHERE order_id=?', (order,)).fetchone(),
                'Заказ удалён; повторная выдача запрещена')
        row = self.db.execute('SELECT * FROM allocation WHERE order_id=?', (order,)).fetchone()
        if row:
            self.assert_mutable(row)
            require(row['client_id'] == client and json.loads(row['spec']) == spec,
                    'Заказ уже закреплён за другим клиентом, тарифом или SSH-ключом')
            return row
        # Refuse an unavailable/unowned OS before allocating a slot or a password.
        self.template(spec.get('os', DEFAULT_OS))
        used = {r[0] for r in self.db.execute('SELECT slot FROM allocation')}
        guests = self.pve.guests()
        infrastructure = self.infrastructure_registry()
        ips = declared_ips(self.pve, self.c['node'])
        slots = [i for i in range(self.c['slots']) if i not in used and self.c['vm_first'] + i not in guests
                 and self.c['vm_first'] + i not in infrastructure
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
        self.assert_mutable(row)
        require(row['phase'] == 'ready' and self.pve.status(self.vmid(row)) == 'running',
                'Пароль доступен только у активного VPS')
        require(not self.pending_restart(row), 'Перезагрузка VPS ещё не завершена')
        spec = json.loads(row['spec'])
        require(spec['ssh_key'] is None, 'Этот VPS использует SSH-ключ')
        ip = str(ipaddress.ip_address(self.c['ip_first']) + row['slot'])
        require(self.pve.ready(self.vmid(row), ip, spec.get('os', DEFAULT_OS)), 'SSH ещё не готов; повторите запрос')
        if spec.get('network_mode') == 'public_ipv4':
            lease = self.ipam.for_order(row['order_id'], row['client_id'])
            require(lease and self.pve.public_ready(lease['address']), 'Публичный SSH ещё не готов')
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
        self.assert_mutable(row)
        self.db.execute('UPDATE allocation SET phase=? WHERE order_id=?', (value, row['order_id']))
        if value in RESTART_SUPERSEDING_PHASES:
            self.db.execute("UPDATE owner_restart SET state='interrupted' WHERE order_id=? AND state='dispatched'", (row['order_id'],))
        self.db.commit()

    @staticmethod
    def now():
        return datetime.now(timezone.utc).isoformat()

    def allocation_plan(self, spec):
        plan = dict(self.c['plans'][spec['plan']])
        size = spec.get('disk_gb', plan['disk_gb'])
        maximum = {'mini': 40, 'small': 80, 'medium': 120}[spec['plan']]
        require(type(size) is int and plan['disk_gb'] <= size <= maximum
                and (size - plan['disk_gb']) % 5 == 0, 'Недопустимый объём SSD')
        plan['disk_gb'] = size
        return plan

    def capacity(self, plan, restoring=None):
        guests = self.pve.guests()
        excluded = set()
        target_memory = plan['memory_mb'] * 1048576
        for row in self.db.execute('SELECT * FROM allocation'):
            vmid = self.vmid(row)
            if (row['phase'] == 'archived' and guests.get(vmid, {}).get('status') == 'stopped') or (restoring and row['order_id'] == restoring['order_id']):
                if vmid in guests:
                    cfg = self.owned_config(row, guests)
                    if restoring and row['order_id'] == restoring['order_id']:
                        memory = cfg.get('memory')
                        require(type(memory) in (int, str) and str(memory).isdigit() and int(memory) > 0,
                                'Не удалось проверить фактическую RAM восстанавливаемой VM')
                        target_memory = int(memory) * 1048576
                    excluded.add(vmid)
        reserved = sum(int(v.get('maxmem', 0)) for vmid, v in guests.items()
                       if v['node'] == self.c['node'] and not v.get('template') and vmid not in excluded)
        node = self.pve.api(f'/nodes/{self.c["node"]}/status')
        require(reserved + target_memory <= node['memory']['total'] - 2 * 1073741824,
                'Недостаточно RAM с резервом 2 GiB для хоста')
        if restoring is None:
            storage = self.pve.api(f'/nodes/{self.c["node"]}/storage/{self.c["storage"]}/status')
            require(int(storage['avail']) >= (plan['disk_gb'] + 5) * 1073741824, 'Недостаточно места на диске')

    def stop_vm(self, row):
        self.assert_mutable(row)
        vmid = self.vmid(row)
        self.pve.command('set', vmid, '--onboot', '0')
        if self.pve.status(vmid) == 'running':
            try:
                self.pve.command('shutdown', vmid, '--timeout', '30')
            except (Refused, OSError, subprocess.TimeoutExpired):
                pass
            if self.pve.status(vmid) != 'stopped':
                self.pve.command('stop', vmid)

    def power(self, row, start, phase=None):
        self.assert_mutable(row)
        self.owned_config(row)
        if start:
            lease = self.ipam.for_order(row['order_id'], row['client_id'])
            if lease:
                self.pve.network_guard(row, lease, self.c)
            self.pve.command('set', self.vmid(row), '--onboot', '1')
            if self.pve.status(self.vmid(row)) != 'running':
                self.pve.command('start', self.vmid(row))
        else:
            self.stop_vm(row)
        self.phase(row, phase or ('ready' if start else 'stopped'))
        return self.info(row)

    def pending_restart(self, row):
        return self.db.execute("SELECT * FROM owner_restart WHERE order_id=? AND state='dispatched'",
                               (row['order_id'],)).fetchone()

    def is_ready(self, row, info):
        owned_running = info['ownership'] == 'owned' and info['phase'] == 'ready' and info['status'] == 'running'
        if not owned_running:
            return False
        os_name = json.loads(row['spec']).get('os', DEFAULT_OS)
        guest_ready = self.pve.ready(self.vmid(row), info['private_ip'], os_name)
        if not guest_ready:
            return False
        public_ready = info['network_mode'] != 'public_ipv4' or bool(info['public_ip']) and self.pve.public_ready(info['public_ip'])
        return public_ready

    def owner_restart(self, row, request):
        self.assert_mutable(row)
        value = request.get('operation_id')
        require(isinstance(value, str), 'Нужен UUID операции')
        try:
            operation = str(uuid.UUID(value))
        except ValueError as exc:
            raise Refused('Нужен UUID операции') from exc
        require(row['phase'] == 'ready', 'Перезагрузка доступна только у активного VPS')
        require(not self.db.execute("SELECT 1 FROM admin_operation WHERE order_id=? AND state='pending'", (row['order_id'],)).fetchone(),
                'Административная операция ещё выполняется')
        os_name = json.loads(row['spec']).get('os', DEFAULT_OS)
        dispatched = False
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            prior = self.db.execute('SELECT * FROM owner_restart WHERE id=?', (operation,)).fetchone()
            if prior:
                require((prior['order_id'], prior['client_id'], prior['owner']) ==
                        (row['order_id'], row['client_id'], self.marker(row)), 'UUID операции уже закреплён за другим VPS')
            else:
                require(not self.pending_restart(row), 'Предыдущая перезагрузка ещё не завершена')
                require(self.pve.status(self.vmid(row)) == 'running', 'Перезагрузка доступна только у запущенного VPS')
                require(self.is_ready(row, self.info(row)), 'SSH ещё не готов; перезагрузка не отправлена')
                before = validated_boot_id(self.pve.boot_id(self.vmid(row), os_name))
                self.db.execute('INSERT INTO owner_restart VALUES(?,?,?,?,?,?,NULL)',
                                (operation, row['order_id'], row['client_id'], self.marker(row), before, 'dispatched'))
                dispatched = True
        # The durable fence precedes dispatch. A crash in this gap deliberately
        # requires investigation: neither this UUID nor another UUID may reboot again.
        if dispatched:
            try:
                self.pve.graceful_reboot(self.vmid(row), os_name)
            except (OSError, ValueError, subprocess.SubprocessError):
                pass  # A missing reply cannot prove whether the guest accepted reboot.
        elif prior['state'] == 'dispatched' and self.pve.status(self.vmid(row)) == 'running':
            try:
                current = validated_boot_id(self.pve.boot_id(self.vmid(row), os_name))
                info = self.info(row)
                info['phase'] = 'ready'
                if current != prior['before_boot_id'] and self.is_ready(row, info):
                    with self.db:
                        self.db.execute("UPDATE owner_restart SET state='done',after_boot_id=? WHERE id=?", (current, operation))
            except (OSError, ValueError, subprocess.SubprocessError):
                pass
        result = self.info(row)
        result['ready'] = self.is_ready(row, result)
        return result

    def admin(self, row, request):
        self.assert_mutable(row)
        command = request.get('command')
        require(command in ('start', 'stop', 'block', 'unblock', 'archive', 'restore', 'purge'), 'Недопустимая операция')
        try:
            operation = str(uuid.UUID(request.get('operation_id', '')))
        except (ValueError, TypeError, AttributeError) as exc:
            raise Refused('Нужен UUID операции') from exc
        reason = request.get('reason')
        require(isinstance(reason, str) and 3 <= len(reason.strip()) <= 500, 'Укажите причину операции')
        actor = request.get('actor')
        require(isinstance(actor, dict) and isinstance(actor.get('email'), str) and '@' in actor['email'], 'Нужен оператор')
        try:
            uuid.UUID(actor.get('account', ''))
        except (ValueError, TypeError, AttributeError) as exc:
            raise Refused('Нужен UUID оператора') from exc
        digest = fingerprint(request)
        prior = self.db.execute('SELECT * FROM admin_operation WHERE id=?', (operation,)).fetchone()
        if prior:
            require(prior['fingerprint'] == digest, 'UUID операции уже использован с другими данными')
            if prior['state'] == 'done':
                return json.loads(prior['result'])
            require(prior['state'] != 'failed', 'Операция отклонена; создайте новую операцию')
        else:
            self.db.execute('INSERT INTO admin_operation(id,fingerprint,order_id,state) VALUES(?,?,?,?)',
                            (operation, digest, row['order_id'], 'pending'))
            self.db.commit()
        try:
            result = self.admin_effect(row, command, request)
        except Refused:
            self.db.execute('UPDATE admin_operation SET state=? WHERE id=?', ('failed', operation))
            self.db.commit()
            raise
        self.db.execute('UPDATE admin_operation SET state=?,result=? WHERE id=?', ('done', json.dumps(result), operation))
        self.db.commit()
        return result

    def admin_effect(self, row, command, request):
        self.assert_mutable(row)
        phase = row['phase']
        if command == 'purge':
            require(type(request.get('confirm_vmid')) is int and request['confirm_vmid'] == self.vmid(row),
                    'Подтвердите точный VMID')
            if phase == 'deleted':
                return self.info(row)
            guests = self.pve.guests()
            if self.vmid(row) in guests:
                self.owned_config(row, guests)
                self.phase(row, 'purging')
                self.stop_vm(row)
                self.owned_config(row)
                self.pve.command('set', self.vmid(row), '--protection', '0')
                self.pve.command('destroy', self.vmid(row), '--purge', '1')
            else:
                require(phase == 'purging', 'VM исчезла; автоматическое удаление неизвестных дисков запрещено')
            lease = self.ipam.for_order(row['order_id'], row['client_id'])
            if lease:
                require(self.vmid(row) not in self.pve.guests(), 'Физическое удаление VM не подтверждено')
                self.ipam.release_assigned(row['order_id'], row['client_id'], lease['id'], isolated=True)
            if json.loads(row['spec']).get('network_mode') == 'public_ipv4':
                self.pve.remove_network_guard(self.vmid(row))
            # The slot cannot be reused until this atomic retirement and credential cleanup.
            (self.snippets / f'safehost-billing-{self.vmid(row)}.yaml').unlink(missing_ok=True)
            with self.db:
                self.db.execute('INSERT OR IGNORE INTO retired_allocation VALUES(?,?,?,?,?,?,?)',
                                (row['order_id'], row['client_id'], row['slot'], row['spec'], 'deleted',
                                 request['reason'].strip(), row['created_at']))
                self.db.execute('DELETE FROM credential WHERE order_id=?', (row['order_id'],))
                self.db.execute('DELETE FROM allocation WHERE order_id=?', (row['order_id'],))
            retired = self.db.execute('SELECT * FROM retired_allocation WHERE order_id=?', (row['order_id'],)).fetchone()
            return self.info(retired)
        require(phase != 'deleted', 'Заказ удалён')
        self.owned_config(row)
        if command in ('start', 'unblock'):
            allowed = ('ready', 'stopped', 'blocked', 'suspended') if command == 'unblock' else ('ready', 'stopped')
            require(phase in allowed, 'Запуск запрещён состоянием заказа')
            result = self.power(row, True)
        elif command in ('stop', 'block'):
            require(phase in ('ready', 'stopped', 'blocked', 'suspended'), 'Остановка запрещена состоянием заказа')
            target = 'blocked' if command == 'block' or phase in ('blocked', 'suspended') else 'stopped'
            result = self.power(row, False, target)
        elif command == 'archive':
            require(phase in ('ready', 'stopped', 'blocked', 'suspended', 'cancelled', 'archived', 'archiving'),
                    'Создание не завершено')
            self.phase(row, 'archiving')
            self.stop_vm(row)
            self.isolate_public(row)
            self.phase(row, 'archived')
            result = self.info(row)
        else:
            require(phase in ('archived', 'restoring'), 'Восстановление доступно только из архива')
            self.capacity(self.allocation_plan(json.loads(row['spec'])), restoring=row)
            self.phase(row, 'restoring')
            if json.loads(row['spec']).get('network_mode') == 'public_ipv4':
                self.restore_public(row)
                result = self.info(row)
            else:
                result = self.power(row, True)
        self.db.execute('UPDATE allocation SET reason=? WHERE order_id=?', (request['reason'].strip(), row['order_id']))
        self.db.commit()
        return self.info(row)

    def create(self, row):
        self.assert_mutable(row)
        require(row['phase'] != 'cancelled', 'Заказ отменён; диск сохранён, новая активация запрещена')
        require(row['phase'] in ('reserved', 'configured', 'ready'), 'Повторная активация запрещена состоянием VPS')
        vmid, spec = self.vmid(row), json.loads(row['spec'])
        lease = None
        if spec.get('network_mode') == 'public_ipv4':
            # Bind before cloning. An expired or forged reservation cannot create a VM.
            lease = self.ipam.for_order(row['order_id'], row['client_id'])
            if not lease:
                lease = self.ipam.bind(spec['account'], spec['reference'], spec['lease_id'], row['order_id'], row['client_id'])
        if lease:
            require(lease['address'] not in declared_ips(self.pve, self.c['node'], exclude=vmid), 'Публичный IP занят сторонней VM')
        plan = self.allocation_plan(spec)
        if vmid not in self.pve.guests():
            require(row['phase'] == 'reserved', 'Ранее созданная VM исчезла; автоматическое восстановление запрещено')
            ip = str(ipaddress.ip_address(self.c['ip_first']) + row['slot'])
            require(ip not in declared_ips(self.pve, self.c['node']), 'IP закреплённого слота занят другой VM или LXC')
            template_id = self.template(spec.get('os', DEFAULT_OS))
            self.capacity(plan)
            self.pve.command('clone', template_id, vmid, '--full', '1', '--storage', self.c['storage'],
                             '--name', f'vps-order-{row["order_id"]}', '--description', self.marker(row))
        cfg = self.owned_config(row)
        if not row['created_at'] and row['phase'] == 'reserved':
            self.db.execute('UPDATE allocation SET created_at=? WHERE order_id=?', (self.now(), row['order_id']))
            self.db.commit()
        if row['phase'] == 'ready':
            return self.info(row)  # An activation retry must never reboot or reconfigure a guest.
        require(self.pve.status(vmid) == 'stopped', 'Незавершённая VM запущена; нужна проверка администратором')
        require('scsi0' in cfg, 'Клонирование не завершено; проверьте задачу Proxmox')
        ip = str(ipaddress.ip_address(self.c['ip_first']) + row['slot'])
        alma = selected_os(spec.get('os')) in ('AlmaLinux 9', 'AlmaLinux 10')
        cloud = {'hostname': f'vps-order-{row["order_id"]}', 'manage_etc_hosts': True,
                 'users': [{'name': 'vpsadmin', 'groups': ['wheel'] if alma else ['adm', 'sudo'], 'shell': '/bin/bash',
                            'sudo': 'ALL=(ALL) NOPASSWD:ALL', 'lock_passwd': True,
                            'ssh_authorized_keys': [spec['ssh_key']]}],
                 'disable_root': True, 'ssh_pwauth': False, 'package_update': True,
                 'packages': ['qemu-guest-agent'], 'runcmd': [['systemctl', 'enable', '--now', 'qemu-guest-agent']]}
        if spec['ssh_key'] is None:
            credential = self.db.execute('SELECT password_hash FROM credential WHERE order_id=?', (row['order_id'],)).fetchone()
            require(credential is not None, 'Не найден пароль закреплённого VPS; нужна проверка администратором')
            del cloud['users'][0]['ssh_authorized_keys']
            # Cloud-init sets and expires the password before enabling SSH password auth.
            cloud['chpasswd'] = {'expire': True, 'users': [
                {'name': 'vpsadmin', 'type': 'hash', 'password': credential['password_hash']}]}
            # Ubuntu 22.04 cloud-init may exclude hashed users from expire=true.
            # Enforce expiry before cloud-init can report this guest ready.
            cloud['runcmd'].insert(0, ['chage', '-d', '0', 'vpsadmin'])
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
                         '--ipconfig0', f'ip={ip}/24' + ('' if lease else f',gw={self.c["gateway"]}'),
                         '--cicustom', 'user=local:snippets/' + snippet)
        if lease:
            self.pve.command('set', vmid, '--net0', self.private_nic(row), '--net1', self.public_nic(row, lease),
                             '--ipconfig1', f'ip={lease["address"]}/{self.public_prefix()},gw={self.c["public_network"]["gateway"]}')
            self.pve.network_guard(row, lease, self.c)
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

    def info(self, row, *, guests=None, configs=None):
        infrastructure = self.infrastructure_registry().get(self.vmid(row))
        if infrastructure:
            self.infrastructure_info(infrastructure,
                                     guests=self.pve.guests() if guests is None else guests,
                                     configs={self.vmid(row): self.pve.config(self.vmid(row))} if configs is None else configs)
        current_row = self.db.execute('SELECT * FROM allocation WHERE order_id=?', (row['order_id'],)).fetchone()
        current = current_row['phase'] if current_row else 'deleted'
        reason = current_row['reason'] if current_row else row['reason']
        ownership, status = 'deleted', 'stopped'
        if current != 'deleted':
            observed_guests = self.pve.guests() if guests is None else guests
            if self.vmid(row) not in observed_guests:
                ownership, current, reason = 'missing', 'missing', 'Управляемая VM отсутствует на узле'
            else:
                try:
                    self.owned_config(row, guests, configs=configs)
                    status = self.pve.status(self.vmid(row)) if guests is None else guests[self.vmid(row)]['status']
                    ownership = 'owned'
                except Refused:
                    ownership, current, reason = 'foreign', 'missing', 'VMID занят чужой VM или изменены её защищённые параметры'
        if current in ('suspended', 'blocked'):
            current = 'blocked'
        elif current == 'ready' and self.pending_restart(row):
            current = 'preparing'
        elif current == 'ready' and status == 'stopped':
            current = 'stopped'
        public = json.loads(row['spec']).get('network_mode') == 'public_ipv4'
        lease = self.ipam.for_order(row['order_id'], row['client_id']) if public else None
        endpoint = ownership == 'owned' and current not in ('archived', 'archiving', 'deleted', 'cancelled', 'missing')
        host = lease['address'] if public and lease and endpoint else None if public else self.c['public_ip']
        port = 22 if public and host else 0 if public else self.c['ssh_port_first'] + row['slot']
        return {'infrastructure': infrastructure is not None,
                'network_mode': 'public_ipv4' if public else 'nat', 'lease_id': lease['id'] if lease else None,
                'lease_generation': lease['generation'] if lease else None,
                'vmid': self.vmid(row), 'public_ip': host,
                'private_ip': str(ipaddress.ip_address(self.c['ip_first']) + row['slot']),
                'ssh_port': port, 'user': 'vpsadmin',
                'auth_mode': 'password' if json.loads(row['spec'])['ssh_key'] is None else 'key',
                'phase': current, 'status': status, 'reason': reason, 'ownership': ownership,
                'ssh': f'ssh -p {port} vpsadmin@{host}' if host and endpoint else None}

    def metrics(self, row, timeframe):
        duration, step = self.metrics_period(timeframe)
        require(row['phase'] not in ('deleted', 'missing'), 'История VPS недоступна')
        now = int(datetime.now(timezone.utc).timestamp())
        # RRD files survive VMID reuse. Exclude the bucket crossing allocation creation too.
        require(isinstance(row['created_at'], str), 'Неизвестна дата создания VPS; история недоступна')
        created = datetime.fromisoformat(row['created_at']).timestamp()
        cutoff = max(now - duration, created + step)
        vmid = self.vmid(row)
        def identity(snapshot):
            infrastructure = self.infrastructure_registry().get(vmid)
            if infrastructure:
                self.infrastructure_config(infrastructure, snapshot.get('guest'), snapshot.get('config'))
            self.owned_config(row, guests={vmid: snapshot.get('guest')}, configs={vmid: snapshot.get('config')})
        return self.read_metrics(vmid, timeframe, duration=duration, now=now, cutoff=cutoff, identity=identity)

    @staticmethod
    def metrics_period(timeframe):
        periods = {'day': (86400, 60), 'week': (604800, 1800)}
        require(isinstance(timeframe, str) and timeframe in periods, 'Недопустимый период метрик')
        return periods[timeframe]

    @staticmethod
    def metrics_since(entry, observed_now):
        value = entry.get('metricsSince')
        require(isinstance(value, str) and re.fullmatch(
            r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)', value),
            'Нужна доверенная UTC граница истории служебной VM')
        try:
            registered = datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()
        except (ValueError, OverflowError, OSError) as exc:
            raise Refused('Некорректная граница истории служебной VM') from exc
        require(math.isfinite(registered) and 0 <= registered <= observed_now,
                'Граница истории служебной VM вне допустимого времени')
        return registered

    def infrastructure_metrics_registry(self, registry, observed_now):
        """Optional root metadata: only infrastructure history depends on this file."""
        path = self.state / 'infrastructure-metrics.json'
        try:
            directory, metadata = self.state.lstat(), path.lstat()
            private_directory = (stat.S_ISDIR(directory.st_mode) and directory.st_uid == os.geteuid()
                                 and directory.st_mode & 0o777 == 0o700)
            private_file = (stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.geteuid()
                            and metadata.st_mode & 0o777 == 0o600 and metadata.st_size <= 131072)
            require(private_directory and private_file, 'Небезопасный реестр истории служебных VM')
            def unique_fields(pairs):
                result = {}
                for key, value in pairs:
                    require(key not in result, 'Повторное поле в реестре истории служебных VM')
                    result[key] = value
                return result
            document = json.loads(path.read_text(), object_pairs_hook=unique_fields)
        except (OSError, ValueError) as exc:
            raise Refused('Недоступен реестр истории служебных VM') from exc
        require(isinstance(document, dict) and set(document) == {'version', 'servers'}
                and type(document['version']) is int and document['version'] == 1
                and isinstance(document['servers'], list) and len(document['servers']) <= 100,
                'Некорректный реестр истории служебных VM')
        entries = {}
        identity_fields = ('vmid', 'node', 'account', 'configSha256')
        fields = {*identity_fields, 'metricsSince'}
        for entry in document['servers']:
            valid_fields = isinstance(entry, dict) and set(entry) == fields
            require(valid_fields, 'Некорректная запись истории служебной VM')
            vmid = entry['vmid']
            require(type(vmid) is int and vmid in registry and vmid not in entries,
                    'Некорректный или повторный VMID истории служебной VM')
            bound_identity = all(entry[field] == registry[vmid][field] for field in identity_fields)
            require(bound_identity, 'История не соответствует регистрации служебной VM')
            self.metrics_since(entry, observed_now)
            entries[vmid] = entry
        return entries

    @staticmethod
    def owned_infrastructure(registry, account, vmid, node):
        valid_account = isinstance(account, str) and re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', account)
        valid_vm = type(vmid) is int and 0 < vmid < 2147483647 and isinstance(node, str) and bool(node.strip())
        require(valid_account and valid_vm, 'Некорректный владелец, VMID или узел служебной VM')
        entry = registry.get(vmid)
        owned = entry is not None and entry['account'] == account and entry['node'] == node
        require(owned, 'Служебная VM этого владельца не найдена')
        return entry

    def infrastructure_disk(self, account, vmid, node):
        entry = self.owned_infrastructure(self.infrastructure_registry(), account, vmid, node)
        result = {key: entry[key] for key in ('vmid', 'node', 'account')}
        result.update(mountpoint='/', usedBytes=None, totalBytes=None, observedAt=None)
        with self.pve.metrics_reader(vmid, 'day') as reader:
            def identity():
                snapshot = reader.identity()
                require(isinstance(snapshot, dict), 'Некорректная конфигурация служебной VM')
                current = self.infrastructure_registry().get(vmid)
                require(current == entry, 'Изменилась регистрация служебной VM во время чтения диска')
                self.infrastructure_config(current, snapshot.get('guest'), snapshot.get('config'))
            identity()
            try:
                fs = self.pve.guest_fs(vmid)
            except (OSError, ValueError, TypeError, AttributeError, subprocess.TimeoutExpired):
                fs = None
            identity()
        valid_shape = isinstance(fs, (tuple, list)) and len(fs) == 2
        if valid_shape:
            used, total = fs
            valid_bytes = type(used) is int and type(total) is int and 0 <= used <= total and 0 < total <= 2**53 - 1
            if valid_bytes:
                result.update(usedBytes=used, totalBytes=total, observedAt=datetime.now(timezone.utc).isoformat())
        return result

    def infrastructure_metrics(self, account, vmid, node, timeframe):
        duration, step = self.metrics_period(timeframe)
        registry = self.infrastructure_registry()
        entry = self.owned_infrastructure(registry, account, vmid, node)
        observed_now = datetime.now(timezone.utc).timestamp()
        metadata = self.infrastructure_metrics_registry(registry, observed_now).get(vmid)
        require(metadata is not None, 'Не зарегистрирована история служебной VM')
        registered = self.metrics_since(metadata, observed_now)
        now = int(observed_now)
        cutoff = max(now - duration, registered + step)
        def identity(snapshot):
            current_registry = self.infrastructure_registry()
            current = current_registry.get(vmid)
            require(current == entry, 'Изменилась регистрация служебной VM во время чтения метрик')
            current_metadata = self.infrastructure_metrics_registry(
                current_registry, datetime.now(timezone.utc).timestamp()).get(vmid)
            require(current_metadata == metadata, 'Изменилась граница истории служебной VM во время чтения метрик')
            self.infrastructure_config(current, snapshot.get('guest'), snapshot.get('config'))
        return self.read_metrics(vmid, timeframe, duration=duration, now=now, cutoff=cutoff, identity=identity)

    def read_metrics(self, vmid, timeframe, *, duration, now, cutoff, identity):
        with self.pve.metrics_reader(vmid, timeframe) as reader:
            def check_identity():
                snapshot = reader.identity()
                require(isinstance(snapshot, dict), 'Некорректная конфигурация метрик')
                identity(snapshot)
            check_identity()
            rows = reader.history()
            check_identity()
        require(isinstance(rows, list) and len(rows) <= 2000, 'Некорректная история метрик')

        def number(value, maximum=None):
            if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                return None
            return value if maximum is None or value <= maximum else None

        points = {}
        for sample in rows:
            require(isinstance(sample, dict), 'Некорректная точка метрик')
            timestamp = sample.get('time')
            if type(timestamp) is not int or not cutoff <= timestamp <= now:
                continue
            cpu = number(sample.get('cpu'), 1)
            used, total = number(sample.get('mem')), number(sample.get('maxmem'))
            points[timestamp] = {
                'timestamp': timestamp, 'cpuPercent': None if cpu is None else cpu * 100,
                'memoryUsedBytes': None if used is None else int(used),
                'memoryTotalBytes': None if total is None else int(total),
                'networkInBytesPerSecond': number(sample.get('netin')),
                'networkOutBytesPerSecond': number(sample.get('netout')),
            }
        return {'timeframe': timeframe, 'start': now - duration, 'end': now,
                'points': [points[key] for key in sorted(points)]}

    def monitor(self):
        # Request-local observations only; actions and readiness still read fresh state.
        guests = self.pve.guests()
        configs = self.pve.current_configs(self.c['node'])
        qemu_configs = {guest['vmid']: guest['config'] for guest in configs if guest['type'] == 'qemu'}
        registry = self.infrastructure_registry()
        infrastructure = [self.infrastructure_info(entry, guests=guests, configs=qemu_configs)
                          for entry in registry.values()]
        excluded = set()
        servers = []
        rows = list(self.db.execute('SELECT * FROM allocation')) + list(self.db.execute('SELECT * FROM retired_allocation'))
        for row in rows:
            info = self.info(row, guests=guests, configs=qemu_configs)
            plan = self.allocation_plan(json.loads(row['spec']))
            metrics = dict.fromkeys(('cpuFraction', 'memoryUsedBytes', 'memoryTotalBytes', 'guestDiskUsedBytes', 'guestDiskTotalBytes'))
            if info['ownership'] == 'owned':
                guest = guests[self.vmid(row)]
                metrics.update(cpuFraction=guest.get('cpu'), memoryUsedBytes=guest.get('mem'), memoryTotalBytes=guest.get('maxmem'))
                fs = self.pve.guest_fs(self.vmid(row)) if info['status'] == 'running' else None
                if fs:
                    metrics.update(guestDiskUsedBytes=fs[0], guestDiskTotalBytes=fs[1])
                if row['phase'] == 'archived' and info['status'] == 'stopped':
                    excluded.add(self.vmid(row))
            servers.append({**info, 'orderId': row['order_id'], 'clientId': row['client_id'], 'node': self.c['node'],
                            'plan': json.loads(row['spec'])['plan'], 'cores': plan['cores'], 'memoryMb': plan['memory_mb'],
                            'diskGb': plan['disk_gb'], 'createdAt': row['created_at'], 'metrics': metrics})
        node = self.pve.api(f'/nodes/{self.c["node"]}/status')
        # A fresh pvesh process has no previous CPU sample and reports zero.
        # Cluster resources contain the interval measured by pvestatd instead.
        node_samples = self.pve.api('/cluster/resources', type='node')
        node_sample = next((sample for sample in node_samples
                            if sample.get('node') == self.c['node'] and sample.get('status') == 'online'), {})
        storage = self.pve.api(f'/nodes/{self.c["node"]}/storage/{self.c["storage"]}/status')
        reserved = [v for vmid, v in guests.items() if v['node'] == self.c['node'] and not v.get('template') and vmid not in excluded]
        occupied = {r['slot'] for r in self.db.execute('SELECT slot FROM allocation')}
        ips = declared_ips(self.pve, self.c['node'], configs=configs)
        free_slots = sum(i not in occupied and self.c['vm_first'] + i not in guests
                         and self.c['vm_first'] + i not in registry
                         and str(ipaddress.ip_address(self.c['ip_first']) + i) not in ips
                         for i in range(self.c['slots']))
        host = {'node': self.c['node'], 'cpuFraction': node_sample.get('cpu'), 'cpuCores': node.get('cpuinfo', {}).get('cpus'),
                'memoryUsedBytes': node['memory']['used'], 'memoryTotalBytes': node['memory']['total'],
                'memoryReservedBytes': sum(int(v.get('maxmem', 0)) for v in reserved),
                'vcpuReserved': sum(int(v.get('maxcpu', 0)) for v in reserved), 'storageUsedBytes': storage.get('used'),
                'storageTotalBytes': storage['total'], 'storageFreeBytes': storage['avail'], 'slotsFree': free_slots}
        return {'hosts': [host], 'servers': servers, 'infrastructure': infrastructure,
                'publicIpv4': self.ipam.capacity(ips)}

    def handle(self, request):
        require(isinstance(request, dict), 'Ожидается JSON object')
        action = request.get('action')
        require(action in ('create', 'status', 'readiness', 'password', 'suspend', 'unsuspend', 'cancel',
                           'owner_start', 'owner_stop', 'owner_restart', 'mutation_guard', 'admin', 'monitor', 'network_capacity', 'network_reserve', 'network_payment_pending', 'network_release_hold') + METRICS_ACTIONS, 'Недопустимая операция')
        # A present but invalid root registry must never silently remove protection.
        self.infrastructure_registry()
        if action.startswith('network_'):
            try:
                if action == 'network_capacity':
                    return self.ipam.capacity(declared_ips(self.pve, self.c['node']))
                if action == 'network_reserve':
                    self.template(selected_os(request.get('os')))
                    return self.ipam.reserve(request.get('account'), request.get('reference'), declared_ips(self.pve, self.c['node']))
                if action == 'network_payment_pending':
                    return self.ipam.payment_pending(request.get('account'), request.get('reference'), request.get('lease_id'))
                if action == 'network_release_hold':
                    return {'released': self.ipam.release_hold(request.get('account'), request.get('reference'), request.get('lease_id'), request.get('resolved') is True)}
                raise Refused('Недопустимая сетевая операция')
            except IpamRefused as exc:
                raise Refused(str(exc)) from exc
        if action == 'monitor':
            return self.monitor()
        if action == 'infrastructure_disk':
            return self.infrastructure_disk(request.get('account'), request.get('vmid'), request.get('node'))
        if action == 'infrastructure_metrics':
            return self.infrastructure_metrics(request.get('account'), request.get('vmid'), request.get('node'), request.get('timeframe'))
        order, client = request.get('order_id'), request.get('client_id')
        require(type(order) is int and 1 <= order < 2147483647 and type(client) is int and 1 <= client < 2147483647,
                'Нужны целочисленные order_id и client_id')
        if action == 'mutation_guard':
            row = self.db.execute('SELECT * FROM allocation WHERE order_id=?', (order,)).fetchone()
            if row is None:
                row = self.db.execute('SELECT * FROM retired_allocation WHERE order_id=?', (order,)).fetchone()
            if row is not None:
                require(row['client_id'] == client, 'VPS этого клиента не найден')
                self.assert_mutable(row)
            return {'mutable': True}
        if action == 'create':
            os_name = selected_os(request.get('os'))
            require(request.get('plan') in self.c['plans'], 'Неизвестный тариф')
            key = request.get('ssh_key', '')
            require(key is None or isinstance(key, str), 'Некорректный публичный SSH-ключ')
            spec = {'plan': request['plan'], 'ssh_key': ssh_key(key) if key and key.strip() else None}
            # Preserve the historical default spec JSON and its ownership fingerprint.
            if os_name != DEFAULT_OS:
                spec['os'] = os_name
            requested_disk = request.get('disk_gb')
            if requested_disk is not None:
                spec['disk_gb'] = requested_disk
            selected_plan = self.allocation_plan(spec)
            # Base-size requests retain the historical idempotency fingerprint.
            if selected_plan['disk_gb'] == self.c['plans'][request['plan']]['disk_gb']:
                spec.pop('disk_gb', None)
            mode = request.get('network_mode', 'nat')
            require(mode in ('nat', 'public_ipv4'), 'Неизвестный режим сети')
            if mode == 'public_ipv4':
                spec.update(network_mode=mode, account=request.get('account'), reference=request.get('reference'), lease_id=request.get('lease_id'))
                # Validate identity and active hold before persisting allocation/credential.
                lease = self.ipam._owned(spec['account'], spec['reference'], spec['lease_id'])
                require(lease['state'] in ('held', 'assigned') and (lease['state'] == 'assigned' or lease['payment_pending'] or lease['expires_at'] > self.ipam.clock()), 'IPv4 резерв недействителен')
            row = self.reserve(order, client, spec)
            if row['phase'] == 'configured':
                self.owned_config(row)
                if self.pve.status(self.vmid(row)) == 'stopped':
                    self.pve.command('start', self.vmid(row))
                self.phase(row, 'ready')
                return self.info(row)
            return self.create(row)
        row = self.db.execute('SELECT * FROM allocation WHERE order_id=?', (order,)).fetchone()
        if row is None:
            row = self.db.execute('SELECT * FROM retired_allocation WHERE order_id=?', (order,)).fetchone()
        if action == 'cancel' and row is None:
            return {'phase': 'cancelled', 'status': 'stopped'}
        require(row is not None and row['client_id'] == client, 'VPS этого клиента не найден')
        if action not in ('status', 'readiness', 'metrics'):
            self.assert_mutable(row)
        if action == 'metrics':
            return self.metrics(row, request.get('timeframe'))
        if action == 'cancel' and row['phase'] == 'deleted':
            return self.info(row)
        if action in ('status', 'readiness'):
            info = self.info(row)
            if action == 'readiness':
                info['ready'] = self.is_ready(row, info)
            return info
        if action == 'admin':
            return self.admin(row, request)
        require(row['phase'] != 'deleted', 'Заказ удалён')
        self.owned_config(row)
        if action == 'password':
            return self.initial_password(row)
        if action == 'owner_restart':
            return self.owner_restart(row, request)
        if action == 'cancel' and row['phase'] in ('archived', 'archiving'):
            return self.power(row, False, 'archived')
        if action in ('owner_start', 'owner_stop'):
            require(row['phase'] in ('ready', 'stopped'), 'VPS заблокирован, архивирован или удалён')
            require(not self.db.execute('SELECT 1 FROM admin_operation WHERE order_id=? AND state=?', (order, 'pending')).fetchone(),
                    'Административная операция ещё выполняется')
            return self.power(row, action == 'owner_start')
        require(row['phase'] != 'cancelled' or action == 'cancel', 'Заказ отменён; операция запрещена')
        require(row['phase'] in ('ready', 'stopped', 'suspended', 'blocked', 'cancelled', 'canceling'), 'Создание не завершено или VPS архивирован')
        require(action != 'unsuspend' or row['phase'] not in ('cancelled', 'blocked'),
                'Терминальный заказ или административная блокировка; запуск запрещён')
        # Native billing resume can lift its own suspension, never an explicit
        # audited admin block. Native suspend must preserve a pre-existing block.
        target = {'suspend': 'blocked' if row['phase'] == 'blocked' else 'suspended',
                  'unsuspend': 'ready', 'cancel': 'cancelled'}[action]
        if action == 'cancel':
            self.phase(row, 'canceling')
            self.stop_vm(row)
            self.isolate_public(row)
        return self.power(row, action == 'unsuspend', target)


def main():
    os.umask(0o077)
    # SSH_ORIGINAL_COMMAND is deliberately ignored. stdin is the only protocol.
    state = Path('/var/lib/safehost-billing')
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    raw = sys.stdin.buffer.read(8193)
    require(len(raw) <= 8192, 'Запрос слишком большой')
    request = json.loads(raw)
    require(isinstance(request, dict), 'Ожидается JSON object')
    with (state / 'operation.lock').open('a') as lock:
        read_only = request.get('action') in ('status', 'readiness', 'password', 'monitor', 'mutation_guard', 'network_capacity') + METRICS_ACTIONS
        # A pre-effect guard must wait for source cutover, rather than turn lock
        # contention into a terminal policy denial in the financial/admin queue.
        lock_mode = fcntl.LOCK_SH if request.get('action') == 'mutation_guard' else (
            fcntl.LOCK_SH | fcntl.LOCK_NB if read_only else fcntl.LOCK_EX)
        try:
            fcntl.flock(lock, lock_mode)
        except BlockingIOError as exc:
            raise Refused('Выполняется изменение VPS; повторите запрос') from exc
        is_metrics = request.get('action') in METRICS_ACTIONS
        with metrics_deadline() if is_metrics else nullcontext():
            # Config and its seal are replaced under this same lock during migrations.
            config = json.loads(Path('/etc/safehost-billing/config.json').read_text())
            engine = Engine(config, state, '/var/lib/vz/snippets', db_timeout=1) if is_metrics else Engine(config, state, '/var/lib/vz/snippets')
            try:
                result = engine.handle(request)
            finally:
                engine.db.close()
    print(json.dumps({'ok': True, 'result': result}, ensure_ascii=False))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, sqlite3.Error, subprocess.TimeoutExpired) as exc:
        print(json.dumps({'ok': False, 'error': str(exc), 'code': 'refused' if isinstance(exc, Refused) else 'temporary'}, ensure_ascii=False))
        sys.exit(1)
