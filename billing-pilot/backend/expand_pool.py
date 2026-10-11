#!/usr/bin/python3
"""Root-only 5 -> 10 migration. Never changes VMs, allocations or billing data."""
import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import sqlite3
import subprocess
import tempfile
import uuid


class Refused(ValueError):
    pass


def require(value, message):
    if not value:
        raise Refused(message)


def fingerprint(config):
    return hashlib.sha256(json.dumps(config, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def atomic_write(path, data, mode=0o600):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix='.' + path.name + '.')
    try:
        with os.fdopen(fd, 'w') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def rules(config, start, end):
    result = []
    for slot in range(start, end):
        ip = str(ipaddress.ip_address(config['ip_first']) + slot)
        port = str(config['ssh_port_first'] + slot)
        public = config['public_ip']
        result.extend([
            ('nat', 'BILL_DNAT', '-i', 'vmbr0', '-d', public + '/32', '-p', 'tcp', '--dport', port,
             '-j', 'DNAT', '--to-destination', ip + ':22'),
            ('nat', 'BILL_SNAT', '-s', ip + '/32', '-o', 'vmbr0', '-j', 'MASQUERADE'),
            ('filter', 'BILL_FWD', '-i', 'vmbr1', '-o', 'vmbr0', '-s', ip + '/32', '-m', 'conntrack',
             '--ctstate', 'NEW,ESTABLISHED,RELATED', '-j', 'ACCEPT'),
            ('filter', 'BILL_FWD', '-i', 'vmbr0', '-o', 'vmbr1', '-d', ip + '/32', '-m', 'conntrack',
             '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'),
            ('filter', 'BILL_FWD', '-i', 'vmbr0', '-o', 'vmbr1', '-d', ip + '/32', '-p', 'tcp', '--dport', '22',
             '-m', 'conntrack', '--ctstate', 'NEW', '--ctorigdst', public, '--ctorigdstport', port, '-j', 'ACCEPT')])
    return result


def parents():
    return [('nat', 'PREROUTING', '-j', 'BILL_DNAT'), ('nat', 'POSTROUTING', '-j', 'BILL_SNAT'),
            ('filter', 'FORWARD', '-j', 'BILL_FWD')]


def validate_script(config, script):
    static = []
    for line in script.splitlines():
        if line.startswith('ipt -t ') and ' -A ' in line:
            tokens = shlex.split(line)
            require(tokens[3] == '-A', 'Неверная команда в новом NAT')
            static.append((tokens[2], tokens[4], *tokens[5:]))
    billing = {**config, 'ip_first': '10.10.10.11', 'ssh_port_first': 2223}
    expected = rules(billing, 0, 1) + rules(config, 0, config['slots'])
    require(len(static) == len(expected) and set(static) == set(expected),
            'Сохранённый NAT должен содержать все десять слотов и VM биллинга')


def port_matches(line, port):
    tokens = shlex.split(line)
    for option in ('--dport', '--destination-port', '--dports', '--destination-ports'):
        if option in tokens:
            index = tokens.index(option)
            if '!' in tokens[:index + 1]:
                return True  # Negated selectors: fail conservatively.
            for part in tokens[index + 1].split(','):
                bounds = part.split(':')
                low = int(bounds[0] or 0)
                high = int(bounds[-1] or 65535)
                if low <= port <= high:
                    return True
            return False
    return '-j DNAT' in line or '-j REDIRECT' in line


def owned_dnat(line, config, slot):
    tokens = shlex.split(line)
    if len(tokens) % 2 or '!' in tokens:
        return False
    pairs = list(zip(tokens[::2], tokens[1::2]))
    pairs = [pair for pair in pairs if pair != ('-m', 'tcp')]
    rule = rules(config, slot, slot + 1)[0]
    wanted = [('-A', rule[1]), *zip(rule[2::2], rule[3::2])]
    return sorted(pairs) == sorted(wanted)


class System:
    def output(self, *args):
        return subprocess.check_output(args, text=True, timeout=60)

    def guests(self, config):
        return {int(v['vmid']): v for v in json.loads(self.output(
            '/usr/bin/pvesh', 'get', '/cluster/resources', '--type', 'vm', '--output-format', 'json'))}

    def guest_config(self, config, vmid, kind):
        return json.loads(self.output('/usr/bin/pvesh', 'get',
                         f'/nodes/{config["node"]}/{kind}/{vmid}/config', '--output-format', 'json'))

    def listener_ports(self):
        return {int(line.split()[3].rsplit(':', 1)[1]) for line in self.output('/usr/bin/ss', '-ltnH').splitlines()}

    def nat_dump(self):
        return self.output('/usr/sbin/iptables', '-w', '10', '-t', 'nat', '-S')

    def snapshot(self):
        return self.output('/usr/sbin/iptables-save')

    def has_rule(self, rule):
        table, chain, *args = rule
        result = subprocess.run(['/usr/sbin/iptables', '-w', '10', '-t', table, '-C', chain, *args],
                                capture_output=True, timeout=30)
        require(result.returncode in (0, 1), 'Не удалось проверить NAT')
        return result.returncode == 0

    def add_rule(self, rule):
        table, chain, *args = rule
        self.output('/usr/sbin/iptables', '-w', '10', '-t', table, '-A', chain, *args)

    def shell_check(self, path):
        self.output('/bin/sh', '-n', str(path))

    def preflight(self, old, new, start):
        for rule in [*rules(old, 0, old['slots']), *parents()]:
            require(self.has_rule(rule), 'Исходные NAT-правила изменены; сначала восстановите сеть')
        guests = self.guests(old)
        used_ips = set()
        for vmid, guest in guests.items():
            if guest['node'] != old['node'] or guest['type'] not in ('qemu', 'lxc'):
                continue
            cfg = self.guest_config(old, vmid, guest['type'])
            fields = ('ipconfig',) if guest['type'] == 'qemu' else ('net',)
            for key, value in cfg.items():
                if key.startswith(fields):
                    match = re.search(r'(?:^|,)ip=([0-9.]+)(?:/|,|$)', str(value))
                    if match:
                        used_ips.add(match[1])
        listeners = self.listener_ports()
        nat = self.nat_dump()
        for slot in range(start, new['slots']):
            ip = str(ipaddress.ip_address(new['ip_first']) + slot)
            port = new['ssh_port_first'] + slot
            require(new['vm_first'] + slot not in guests, 'Новый VMID занят')
            require(ip not in used_ips, 'Новый IP занят: ' + ip)
            require(port not in listeners, 'Новый SSH-порт занят: ' + str(port))
            for line in nat.splitlines():
                if line.startswith('-A ') and port_matches(line, port):
                    require(owned_dnat(line, new, slot) and self.has_rule(rules(new, slot, slot + 1)[0]),
                            'Новый SSH-порт занят чужим NAT: ' + str(port))


def expand(config_path, state, desired, nat_path, staged_nat, system=None):
    config_path, state, nat_path, staged_nat = map(Path, (config_path, state, nat_path, staged_nat))
    system = system or System()
    require(state.is_dir(), 'Пилот ещё не установлен')
    pending_path = state / 'pool-expansion.pending.json'
    seal_path = state / 'config.sha256'
    with (state / 'operation.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        current = json.loads(config_path.read_text())
        seal = seal_path.read_text().strip()
        pending = json.loads(pending_path.read_text()) if pending_path.exists() else None
        old = pending['old'] if pending else current
        new = {**old, 'slots': desired['slots']}
        require(type(new['slots']) is int and new['slots'] == 10 and old['slots'] in (5, 10),
                'Эта миграция разрешает только расширение 5 → 10')
        supplied = {k: v for k, v in desired.items() if k != 'template_marker'}
        require(supplied == {k: v for k, v in new.items() if k != 'template_marker'},
                'Кроме slots конфигурацию менять нельзя')
        if pending:
            require(pending['new'] == new and current in (old, new) and seal in (fingerprint(old), fingerprint(new)),
                    'Журнал миграции или конфигурация изменены; нужна ручная проверка')
        else:
            require(seal == fingerprint(current), 'Повреждена контрольная сумма конфигурации')
        require('# managed-by: safehost-billing:v1' in nat_path.read_text(), 'Чужой NAT-скрипт')
        require('# managed-by: safehost-billing:v1' in staged_nat.read_text(), 'Неверный новый NAT-скрипт')
        validate_script(new, staged_nat.read_text())
        system.shell_check(staged_nat)
        db = sqlite3.connect('file:' + str(state / 'allocations.sqlite') + '?mode=ro', uri=True)
        try:
            require(db.execute('PRAGMA quick_check').fetchone()[0] == 'ok', 'Повреждено состояние пула')
            require(all(0 <= slot < current['slots'] for (slot,) in db.execute('SELECT slot FROM allocation')),
                    'Резервы слотов выходят за границы пула')
            complete = current == new and seal == fingerprint(new)
            system.preflight(old if not complete else new, new, old['slots'] if not complete else new['slots'])
            if complete:
                require(nat_path.read_bytes() == staged_nat.read_bytes(), 'Сохранённый NAT не соответствует пулу')
                if pending:
                    pending_path.unlink()
                return {'changed': False, 'slots': new['slots']}
            if not pending:
                backup = state / 'backups' / ('pool-5-to-10-' + uuid.uuid4().hex)
                backup.mkdir(mode=0o700, parents=True)
                backup.parent.chmod(0o700)
                for source, name in [(config_path, 'config.json'), (seal_path, 'config.sha256'), (nat_path, 'nat.sh'),
                                     (state / 'credential.key', 'credential.key'),
                                     (Path('/usr/local/lib/safehost-billing/engine.py'), 'engine.py')]:
                    if source.exists():
                        shutil.copyfile(source, backup / name)
                        (backup / name).chmod(0o600)
                with sqlite3.connect(backup / 'allocations.sqlite') as saved:
                    db.backup(saved)
                (backup / 'allocations.sqlite').chmod(0o600)
                atomic_write(backup / 'iptables.save', system.snapshot())
                pending = {'old': old, 'new': new, 'backup': str(backup),
                           'nat_sha256': hashlib.sha256(staged_nat.read_bytes()).hexdigest()}
                atomic_write(pending_path, json.dumps(pending, sort_keys=True) + '\n')
            require(pending['nat_sha256'] == hashlib.sha256(staged_nat.read_bytes()).hexdigest(),
                    'Новый NAT изменён после начала миграции')
            # Append only: current SSH/HTTPS and unrelated chains are never flushed.
            for rule in rules(new, old['slots'], new['slots']):
                if not system.has_rule(rule):
                    system.add_rule(rule)
            atomic_write(nat_path, staged_nat.read_text(), 0o750)
            atomic_write(config_path, json.dumps(new, sort_keys=True, indent=2) + '\n')
            atomic_write(seal_path, fingerprint(new) + '\n')
            pending_path.unlink()
            return {'changed': True, 'slots': new['slots'], 'backup': pending['backup']}
        finally:
            db.close()


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('--desired', required=True)
    parser.add_argument('--nat-script', required=True)
    args = parser.parse_args()
    require(os.geteuid() == 0, 'Расширение выполняется только администратором хоста')
    result = expand('/etc/safehost-billing/config.json', '/var/lib/safehost-billing',
                    json.loads(Path(args.desired).read_text()), '/usr/local/sbin/safehost-billing-nat', args.nat_script)
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
