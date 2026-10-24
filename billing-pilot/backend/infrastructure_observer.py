"""Standalone read-only infrastructure identity and QGA observation. No allocator import."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import time
import uuid
from datetime import datetime, timezone
from contextlib import contextmanager

DEFAULT_OS = 'Ubuntu 24.04'
SUPPORTED_OS = (DEFAULT_OS, 'Ubuntu 22.04', 'Ubuntu 26.04', 'Debian 13',
                'Debian 12', 'AlmaLinux 9', 'AlmaLinux 10')


class Refused(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Refused(message)


def selected_os(value):
    name = DEFAULT_OS if value is None else value
    require(isinstance(name, str) and name in SUPPORTED_OS, 'Неизвестная операционная система')
    return name


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


@contextmanager
def metrics_deadline(seconds=15, *, exception=TimeoutError):
    def expired(signum, frame):
        raise exception('Истёк срок получения метрик')
    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


class InfrastructureObserver:
    def __init__(self, state, pve):
        self.state, self.pve, self.c = Path(state), pve, pve.c

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

    @staticmethod
    def infrastructure_config(entry, guest, cfg):
        require(isinstance(guest, dict) and guest.get('node') == entry['node']
                and guest.get('type') == 'qemu' and isinstance(cfg, dict),
                'Служебная VM отсутствует на заданном узле')
        require(not cfg.get('template') and not cfg.get('lock')
                and fingerprint({key: value for key, value in cfg.items() if key != 'digest'}) == entry['configSha256'],
                'Изменилась защищённая конфигурация служебной VM')

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

    def check_identity(self, entry, reader):
        snapshot = reader.identity()
        require(isinstance(snapshot, dict), 'Некорректная конфигурация служебной VM')
        current = self.infrastructure_registry().get(entry['vmid'])
        require(current == entry, 'Изменилась регистрация служебной VM во время чтения истории')
        self.infrastructure_config(current, snapshot.get('guest'), snapshot.get('config'))

    def infrastructure_disk_history(self, account, vmid, node, timeframe, *, store=None, clock=None):
        from infrastructure_disk_history import DiskHistory
        periods = {'day': 86400, 'week': 604800}
        require(isinstance(timeframe, str) and timeframe in periods, 'Недопустимый период истории диска')
        entry = self.owned_infrastructure(self.infrastructure_registry(), account, vmid, node)
        end = int((clock or time.time)()) // 60 * 60
        start = end - periods[timeframe]
        with self.pve.metrics_reader(vmid, 'day') as reader:
            self.check_identity(entry, reader)
            rows = (store or DiskHistory()).read(entry, start, end)
            self.check_identity(entry, reader)
        result = {key: entry[key] for key in ('vmid', 'node', 'account')}
        result.update(mountpoint='/', timeframe=timeframe, start=start, end=end, step=60,
                      points=[{'timestamp': tick, 'usedBytes': rows.get(tick, (None, None))[0],
                               'totalBytes': rows.get(tick, (None, None))[1]} for tick in range(start + 60, end + 1, 60)])
        require(len(json.dumps({'ok': True, 'result': result}).encode()) < 1048576, 'История диска слишком велика')
        return result
