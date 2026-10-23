"""Root-only bridge guards and guest-agent network changes for owned public VMs."""
import base64
import configparser
import inspect
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time
import uuid
import zlib


SERVICE_ACCESS_DIRECTORY = Path('/etc/safehost-billing/service-access')
POLICY_OWNER_UID = 0


def service_https_peers(row, address, network, vmid):
    """Operator-only access; bind exceptions to the current allocation identity."""
    try:
        descriptor = os.open(SERVICE_ACCESS_DIRECTORY/f'{vmid}.json',
                             os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return ()
    with os.fdopen(descriptor) as stream:
        info = os.fstat(stream.fileno())
        trusted_file = stat.S_ISREG(info.st_mode) and info.st_uid == POLICY_OWNER_UID
        private_mode = stat.S_IMODE(info.st_mode) == 0o600
        if not trusted_file or not private_mode or info.st_size > 4096:
            raise ValueError('Небезопасная служебная сетевая политика')
        policy = json.load(stream)
    identity_matches = all(type(policy.get(key)) is int and policy[key] == row[key]
                           for key in ('order_id', 'client_id'))
    if not identity_matches or policy.get('address') != address:
        raise ValueError('Служебная политика не соответствует аренде IPv4')
    peers = policy.get('https_peers')
    if not isinstance(peers, list) or len(peers) > 16:
        raise ValueError('Неверный список служебных HTTPS-адресов')
    parsed = [ipaddress.IPv4Address(peer) for peer in peers]
    if not all(network.network_address < peer < network.broadcast_address
               and str(peer) != address for peer in parsed):
        raise ValueError('Служебный HTTPS-адрес вне допустимой подсети')
    return tuple(dict.fromkeys(str(peer) for peer in parsed))


def mac(row, nic):
    blob = uuid.uuid5(uuid.NAMESPACE_OID, f'safehost:{row["order_id"]}:{row["client_id"]}:{nic}').bytes
    return ':'.join(f'{x:02x}' for x in b'\x02' + blob[:5])


def values(row, lease, config):
    c = config['public_network']
    network = ipaddress.IPv4Network(c['cidr'])
    address = ipaddress.IPv4Address(lease['address'])
    forbidden = [c['host_ip'], c['gateway'], *c.get('reserved', [])]
    if address not in network.hosts() or str(address) in forbidden or not 0 <= row['slot'] < 10000:
        raise ValueError('IPv4 не принадлежит клиентскому пулу')
    if not re.fullmatch(r'vmbr\d+', c['bridge']):
        raise ValueError('Неизвестный bridge')
    private = str(ipaddress.IPv4Address(config['ip_first']) + row['slot'])
    gateway = str(ipaddress.IPv4Address(config['gateway']))
    vmid = config['vm_first'] + row['slot']
    if type(vmid) is not int or not 1 <= vmid < 1000000000:
        raise ValueError('Неизвестный VMID')
    return c, network, str(address), private, gateway, vmid


def guest_config(row, lease, config):
    c, network, address, private, _, _ = values(row, lease, config)
    return {'network': {'version': 2, 'renderer': 'networkd', 'ethernets': {
        'private': {'match': {'macaddress': mac(row, 0)}, 'set-name': 'shpriv0',
                    'addresses': [private+'/24'], 'dhcp4': False, 'dhcp6': False, 'link-local': []},
        'public': {'match': {'macaddress': mac(row, 1)}, 'set-name': 'shpub0',
                   'addresses': [f'{address}/{network.prefixlen}'], 'dhcp4': False, 'dhcp6': False, 'link-local': [],
                   'routes': [{'to': 'default', 'via': c['gateway']}],
                   'nameservers': {'addresses': [str(ipaddress.IPv4Address(config.get('dns','1.1.1.1')))]}}
    }}}


def guard(row, lease, config):
    c, network, address, private, gateway, vmid = values(row, lease, config)
    https_peers = service_https_peers(row, address, network, vmid)
    # Provider routers may query ARP from reserved addresses, not the virtual gateway.
    arp_peers = [ipaddress.IPv4Address(peer) for peer in
                 [c['gateway'], c['host_ip'], *c.get('reserved', []), *https_peers]]
    if not all(network.network_address < peer < network.broadcast_address for peer in arp_peers):
        raise ValueError('Служебный ARP-адрес вне подсети')
    arp_destinations = ', '.join(dict.fromkeys(str(peer) for peer in arp_peers))
    service_rules = ''
    if https_peers:
        destinations = ', '.join(https_peers)
        service_rules = f'''
        ether type ip ip daddr {{ {destinations} }} tcp dport 443 accept
        ether type ip ip daddr {{ {destinations} }} tcp sport 443 ct state established,related accept
        ether type ip ip daddr {{ {destinations} }} drop'''
    # Hook both paths: private packets to the host traverse input, not forward.
    # prerouting/postrouting cover them as well as peer traffic. Only the public
    # NIC is exposed; the private NIC serves host-initiated SSH readiness.
    private_rules = f'''
        ether saddr != {mac(row,0)} drop
        ether type arp arp saddr ether != {mac(row,0)} drop
        ether type arp arp saddr ip {private} arp daddr ip {gateway} accept
        ether type ip ip saddr {private} ip daddr {gateway} tcp sport 22 ct state established,related accept
        drop'''
    public_rules = f'''
        ether saddr != {mac(row,1)} drop
        ether type arp arp saddr ether != {mac(row,1)} drop
        ether type arp arp saddr ip {address} arp daddr ip {{ {arp_destinations} }} accept
        ether type ip ip saddr {address} ip daddr {c['host_ip']} tcp sport 22 ct state established,related accept
        ether type ip ip saddr != {address} drop{service_rules}
        ether type ip ip daddr {{ {c['host_ip']}, 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 }} drop
        ether type ip accept
        drop'''
    if lease.get('state') == 'released':
        public_rules = '\n        drop'
    public_out = f'ether type arp arp daddr ip {address} accept\n        ether type ip ip daddr {address} accept' if lease.get('state') != 'released' else ''
    return f'''table bridge safehost_{vmid} {{
    chain private_in {{{private_rules}
    }}
    chain public_in {{{public_rules}
    }}
    chain ingress {{ type filter hook prerouting priority -150; policy accept;
        iifname "tap{vmid}i0" jump private_in
        iifname "tap{vmid}i1" jump public_in
    }}
    chain private_out {{
        ether type arp arp saddr ip {gateway} arp daddr ip {private} accept
        ether type ip ip saddr {gateway} ip daddr {private} tcp dport 22 ct state new,established,related accept
        drop
    }}
    chain public_out {{
        {public_out}
        drop
    }}
    chain egress {{ type filter hook postrouting priority 300; policy accept;
        oifname "tap{vmid}i0" jump private_out
        oifname "tap{vmid}i1" jump public_out
    }}
}}
'''


def install_guard(row, lease, config):
    script = guard(row, lease, config)
    vmid = config['vm_first'] + row['slot']
    folder = Path('/etc/safehost-billing/networks')
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    target = folder / f'{vmid}.nft'
    # The operator installs the boot prerequisite before enabling the pool.
    subprocess.run(['/usr/bin/systemctl','is-active','--quiet','safehost-public-networks.service'], check=True, timeout=10)
    exists = subprocess.run(['/usr/sbin/nft','list','table','bridge',f'safehost_{vmid}'], capture_output=True, timeout=10)
    payload = (f'delete table bridge safehost_{vmid}\n' if exists.returncode == 0 else '') + script
    # nft applies the batch atomically: no rule-free interval.
    subprocess.run(['/usr/sbin/nft','--check','-f','-'], input=payload, text=True, capture_output=True, check=True, timeout=10)
    temp = target.with_suffix('.tmp')
    temp.write_text(script); temp.chmod(0o600); temp.replace(target)
    subprocess.run(['/usr/sbin/nft','-f','-'], input=payload, text=True, capture_output=True, check=True, timeout=10)


def write_guest_config(config, root=Path('/')):
    folder = root/'etc/netplan'
    files = list(folder.glob('*.yaml')) + list(folder.glob('*.yml'))
    if any(f.name != '50-cloud-init.yaml' for f in files):
        raise ValueError('Посторонняя конфигурация netplan; требуется ручная сверка')
    folder.mkdir(parents=True, exist_ok=True)
    target = folder/'50-cloud-init.yaml'
    if target.is_symlink():
        raise ValueError('Небезопасная конфигурация netplan')
    temp = folder/'safehost-network.tmp'
    temp.write_text(json.dumps(config)); temp.chmod(0o600); temp.replace(target)
    disabled = root/'etc/cloud/cloud.cfg.d/99-safehost-network.cfg'
    disabled.parent.mkdir(parents=True, exist_ok=True)
    disabled.write_text('network: {config: disabled}\n')


def network_manager_config(row, lease, config):
    interfaces = guest_config(row, lease, config)['network']['ethernets']
    profiles = {}
    for nic, name in enumerate(('private', 'public')):
        interface = interfaces[name]
        address = str(ipaddress.IPv4Interface(interface['addresses'][0]))
        public = name == 'public'
        if public:
            address += ',' + str(ipaddress.IPv4Address(interface['routes'][0]['via']))
        identity = uuid.uuid5(uuid.NAMESPACE_OID, 'safehost-network:' + mac(row, nic))
        profiles[f'safehost-{name}.nmconnection'] = (
            '# Managed by safehost billing.\n'
            f'[connection]\nid=safehost-{name}\nuuid={identity}\ntype=ethernet\nautoconnect=true\n'
            f'[ethernet]\nmac-address={mac(row, nic)}\n'
            f'[ipv4]\nmethod=manual\naddress1={address}\nnever-default={str(not public).lower()}\n'
            'ignore-auto-dns=true\n' +
            ('dns=' + ';'.join(interface['nameservers']['addresses']) + ';\n' if public else '') +
            '[ipv6]\nmethod=disabled\n')
    return profiles


def write_network_manager_config(config, root=Path('/')):
    """Replace only our profiles or unmodified cloud-init profile structures."""
    def checked(relative):
        target = root/relative
        for part in (target, *target.parents):
            if part.is_symlink():
                raise ValueError('Небезопасный путь конфигурации сети')
            if part != target and part.exists() and not part.is_dir():
                raise ValueError('Небезопасный каталог конфигурации сети')
            if part == root:
                break
        return target

    def parse(text):
        result = configparser.ConfigParser(interpolation=None)
        result.optionxform = str
        result.read_string(text)
        if result.defaults():
            raise ValueError('Посторонние настройки профиля сети')
        return {section: dict(result[section]) for section in result.sections()}

    expected = {name: parse(text) for name, text in config.items()}
    macs = {profile['ethernet']['mac-address'] for profile in expected.values()}
    uuids = set()
    folder = checked('etc/NetworkManager/system-connections')
    disabled = checked('etc/cloud/cloud.cfg.d/99-safehost-network.cfg')
    if disabled.exists() and (not disabled.is_file() or disabled.read_text() != 'network: {config: disabled}\n'):
        raise ValueError('Небезопасная конфигурация cloud-init')
    for relative in ('run/NetworkManager/system-connections', 'usr/lib/NetworkManager/system-connections'):
        other = checked(relative)
        for path in list(other.iterdir()) if other.exists() else []:
            checked(str(path.relative_to(root)))
            if relative.startswith('usr/') or path.name != 'lo.nmconnection' or not path.is_file():
                raise ValueError('Посторонние профили NetworkManager')
            loopback = parse(path.read_text())
            connection = loopback.get('connection', {})
            identity = connection.pop('uuid', '')
            uuid.UUID(identity)
            if not connection.pop('timestamp', '').isdigit():
                raise ValueError('Изменён loopback NetworkManager')
            stock_loopback = {
                'connection': {'id': 'lo', 'type': 'loopback', 'interface-name': 'lo'},
                'loopback': {}, 'proxy': {},
                'ipv4': {'address1': '127.0.0.1/8', 'method': 'manual'},
                'ipv6': {'addr-gen-mode': 'default', 'address1': '::1/128', 'method': 'manual'},
                '.nmmeta': {'nm-generated': 'true', 'volatile': 'true', 'external': 'true'}}
            if loopback != stock_loopback:
                raise ValueError('Изменён loopback NetworkManager')
            uuids.add(identity)
    legacy = checked('etc/sysconfig/network-scripts')
    netplan = checked('etc/netplan')
    if list(legacy.glob('ifcfg-*')) or list(netplan.glob('*.yaml')) or list(netplan.glob('*.yml')):
        raise ValueError('Посторонняя конфигурация сети')
    cloud_profiles = []
    seen_macs = set()
    for path in list(folder.iterdir()) if folder.exists() else []:
        checked(str(path.relative_to(root)))
        if not path.is_file():
            raise ValueError('Небезопасный профиль NetworkManager')
        text = path.read_text()
        profile = parse(text)
        if path.name in expected:
            if not text.startswith('# Managed by safehost billing.\n'):
                raise ValueError('Изменён владелец профиля NetworkManager')
            previous = {section: dict(settings) for section, settings in profile.items()}
            for key in ('address1', 'dns'):
                if key in previous.get('ipv4', {}):
                    previous['ipv4'][key] = expected[path.name]['ipv4'].get(key)
            if previous != expected[path.name]:
                raise ValueError('Изменён профиль safehost NetworkManager')
            uuids.add(profile['connection']['uuid'])
        else:
            match = re.fullmatch(r'cloud-init-([a-zA-Z0-9_.:-]+)\.nmconnection', path.name)
            allowed = {
                'connection': {'id', 'uuid', 'type', 'interface-name', 'autoconnect-priority'},
                'user': {'org.freedesktop.NetworkManager.origin'},
                'ethernet': {'mac-address'},
                'ipv4': {'method', 'address1', 'may-fail', 'gateway', 'dns', 'dns-search'},
                'ipv6': {'method', 'may-fail'}}
            if not match or not text.startswith('# Generated by cloud-init.'):
                raise ValueError('Посторонний профиль NetworkManager')
            required = {'connection', 'ethernet', 'ipv4'}
            if not required <= set(profile) or set(profile) - set(allowed) or any(set(settings) - allowed[key] for key, settings in profile.items()):
                raise ValueError('Посторонние настройки cloud-init NetworkManager')
            connection = profile['connection']
            cloud_identity = (connection.get('id'), connection.get('type'))
            if cloud_identity != ('cloud-init ' + match[1], 'ethernet') or connection.get('interface-name', match[1]) != match[1]:
                raise ValueError('Изменён профиль cloud-init NetworkManager')
            if 'user' in profile and profile['user'] != {'org.freedesktop.NetworkManager.origin': 'cloud-init'}:
                raise ValueError('Изменён источник профиля NetworkManager')
            uuid.UUID(connection['uuid'])
            if connection.get('autoconnect-priority', '120') != '120':
                raise ValueError('Изменён приоритет cloud-init NetworkManager')
            if profile['ethernet'].get('mac-address', '').lower() not in macs:
                raise ValueError('Посторонний MAC в cloud-init NetworkManager')
            if profile['ipv4'].get('method') != 'manual' or profile.get('ipv6', {}).get('method', 'disabled') not in ('disabled', 'ignore'):
                raise ValueError('Неожиданный режим адресации cloud-init NetworkManager')
            address, *gateway = profile['ipv4']['address1'].split(',')
            ipaddress.IPv4Interface(address)
            if gateway:
                ipaddress.IPv4Address(','.join(gateway))
            if 'gateway' in profile['ipv4']:
                if gateway:
                    raise ValueError('Двойной gateway в cloud-init NetworkManager')
                ipaddress.IPv4Address(profile['ipv4']['gateway'])
            for address in profile['ipv4'].get('dns', '').split(';'):
                if address:
                    ipaddress.IPv4Address(address)
            for domain in filter(None, profile['ipv4'].get('dns-search', '').split(';')):
                labels = domain.rstrip('.').split('.')
                if len(domain) > 253 or any(not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label) for label in labels):
                    raise ValueError('Неверный домен поиска DNS')
            for section in ('ipv4', 'ipv6'):
                if profile.get(section, {}).get('may-fail', 'false') != 'false':
                    raise ValueError('Изменён профиль cloud-init NetworkManager')
            cloud_profiles.append(path)
            uuids.add(connection['uuid'])
        hardware = profile['ethernet']['mac-address'].lower()
        # A retry may see our first atomic write beside the old cloud profile.
        profile_kind = 'safehost' if path.name in expected else 'cloud-init'
        if (hardware, profile_kind) in seen_macs:
            raise ValueError('Повторный профиль NetworkManager для MAC')
        seen_macs.add((hardware, profile_kind))
    observed = subprocess.run(['/usr/bin/nmcli', '-t', '-f', 'UUID,TYPE', 'connection', 'show'],
                              check=True, capture_output=True, text=True, timeout=10)
    for line in observed.stdout.splitlines():
        identity, kind = line.split(':', 1)
        if identity not in uuids:
            raise ValueError('Посторонний активный профиль NetworkManager')

    def replace(target, text):
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', dir=target.parent, prefix='.safehost-', delete=False) as stream:
                temporary = stream.name
                stream.write(text)
            os.replace(temporary, target)
        finally:
            if temporary and os.path.exists(temporary):
                os.unlink(temporary)

    for name, text in config.items():
        replace(folder/name, text)
    replace(disabled, 'network: {config: disabled}\n')
    for path in cloud_profiles:
        path.unlink()
    subprocess.run(['/usr/bin/nmcli', 'connection', 'reload'], check=True, timeout=10)
    for profile in expected.values():
        subprocess.run(['/usr/bin/nmcli', '--wait', '15', 'connection', 'up', 'uuid', profile['connection']['uuid']],
                       check=True, timeout=20)


def wait_guest_agent(vmid):
    deadline = time.monotonic() + 180
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise OSError('Guest agent не запустился после восстановления VM')
        try:
            result = subprocess.run(['/usr/sbin/qm', 'guest', 'cmd', str(vmid), 'ping'],
                                    capture_output=True, timeout=min(10, remaining))
            if result.returncode == 0:
                return
        except subprocess.TimeoutExpired:
            pass
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise OSError('Guest agent не запустился после восстановления VM')
        time.sleep(min(2, remaining))


def apply_guest(row, lease, config):
    desired = guest_config(row, lease, config)
    # Execute reviewed host source over the agent channel. A guest-owned helper
    # is not trusted for host isolation; nft enforces the lease independently.
    selected = json.loads(row['spec']).get('os') if 'spec' in row.keys() else None
    if selected in ('AlmaLinux 9', 'AlmaLinux 10'):
        source = 'import configparser,ipaddress,os,re,subprocess,tempfile,uuid\nfrom pathlib import Path\n' + inspect.getsource(write_network_manager_config)
        program = source + '\nwrite_network_manager_config(' + repr(network_manager_config(row, lease, config)) + ')\n'
        encoded = base64.b85encode(zlib.compress(program.encode(), 9)).decode('ascii')
        program = 'import base64,zlib;exec(zlib.decompress(base64.b85decode(' + repr(encoded) + ')))'
    else:
        source = 'import json,subprocess\nfrom pathlib import Path\n' + inspect.getsource(write_guest_config)
        program = source + '\nwrite_guest_config(' + repr(desired) + ')\nsubprocess.run(["/usr/sbin/netplan","generate"],check=True,timeout=20)\nsubprocess.run(["/usr/sbin/netplan","apply"],check=True,timeout=30)\n'
        encoded = base64.b64encode(program.encode()).decode('ascii')
        program = 'import base64;exec(base64.b64decode(' + repr(encoded) + '))'
    # Send only reviewed source and network values in a bounded ASCII argument.
    vmid = config['vm_first'] + row['slot']
    # A restored VM cold-boots with the public link isolated. Wait for QGA,
    # not public SSH: the network being repaired cannot be its prerequisite.
    wait_guest_agent(vmid)
    command = ['/usr/bin/python3', '-c', program]
    if selected in ('AlmaLinux 9', 'AlmaLinux 10'):
        command.insert(0, '/usr/local/libexec/safehost-qga-exec')
    result = subprocess.run(['/usr/sbin/qm','guest','exec',str(vmid),'--timeout','60','--',*command], capture_output=True, text=True, check=True, timeout=70)
    response = json.loads(result.stdout)
    if response.get('exitcode') != 0:
        raise ValueError('Не удалось применить сеть через guest agent')


def remove_guard(vmid):
    table = f'safehost_{int(vmid)}'
    result = subprocess.run(['/usr/sbin/nft','list','tables'],capture_output=True,text=True,check=True,timeout=10)
    if f'table bridge {table}' in result.stdout.splitlines():
        subprocess.run(['/usr/sbin/nft','delete','table','bridge',table],capture_output=True,check=True,timeout=10)
    (Path('/etc/safehost-billing/networks')/f'{int(vmid)}.nft').unlink(missing_ok=True)
