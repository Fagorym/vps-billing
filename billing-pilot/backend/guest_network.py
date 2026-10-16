"""Root-only bridge guards and guest-agent network changes for owned public VMs."""
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import time
import uuid


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
    c, _, address, private, gateway, vmid = values(row, lease, config)
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
        ether type arp arp saddr ip {address} arp daddr ip {{ {c['gateway']}, {c['host_ip']} }} accept
        ether type ip ip saddr {address} ip daddr {c['host_ip']} tcp sport 22 ct state established,related accept
        ether type ip ip saddr != {address} drop
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
    source = Path(__file__).read_text()
    program = source + '\nwrite_guest_config(' + repr(desired) + ')\nsubprocess.run(["/usr/sbin/netplan","generate"],check=True,timeout=20)\nsubprocess.run(["/usr/sbin/netplan","apply"],check=True,timeout=30)\n'
    vmid = config['vm_first'] + row['slot']
    # A restored VM cold-boots with the public link isolated. Wait for QGA,
    # not public SSH: the network being repaired cannot be its prerequisite.
    wait_guest_agent(vmid)
    result = subprocess.run(['/usr/sbin/qm','guest','exec',str(vmid),'--timeout','60','--','/usr/bin/python3','-c',program], capture_output=True, text=True, check=True, timeout=70)
    response = json.loads(result.stdout)
    if response.get('exitcode') != 0:
        raise ValueError('Не удалось применить сеть через guest agent')


def remove_guard(vmid):
    table = f'safehost_{int(vmid)}'
    result = subprocess.run(['/usr/sbin/nft','list','tables'],capture_output=True,text=True,check=True,timeout=10)
    if f'table bridge {table}' in result.stdout.splitlines():
        subprocess.run(['/usr/sbin/nft','delete','table','bridge',table],capture_output=True,check=True,timeout=10)
    (Path('/etc/safehost-billing/networks')/f'{int(vmid)}.nft').unlink(missing_ok=True)
