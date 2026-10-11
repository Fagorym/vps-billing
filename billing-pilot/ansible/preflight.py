import argparse
import ipaddress
import json
from pathlib import Path
import re
import subprocess

def output(*args):
    return subprocess.check_output(args, text=True)

parser = argparse.ArgumentParser()
parser.add_argument('--slots', type=int, choices=(5, 10), default=10)
slots = parser.parse_args().slots
ports = [2223, *range(22220, 22220 + slots)]
pool_ips = {'10.10.10.11', *(str(ipaddress.ip_address('10.10.10.20') + i) for i in range(slots))}
nat = output('iptables-save', '-t', 'nat')
rules = nat + output('iptables-save', '-t', 'filter')
own_script = Path('/usr/local/sbin/safehost-billing-nat')
if any(chain in rules for chain in (':BILL_DNAT ', ':BILL_SNAT ', ':BILL_FWD ')):
    assert own_script.exists() and '# managed-by: safehost-billing:v1' in own_script.read_text(), 'Чужие BILL_* цепочки'
for port in ports:
    assert not output('ss', '-H', '-lnt', 'sport', '=', ':' + str(port)).strip(), 'Порт занят: ' + str(port)
    for line in nat.splitlines():
        if re.search(r'--dport\s+' + str(port) + r'(?:\s|$)', line):
            assert line.startswith('-A BILL_DNAT '), 'Порт занят чужим NAT: ' + str(port)
guests = json.loads(output('pvesh', 'get', '/cluster/resources', '--type', 'vm', '--output-format', 'json'))
for guest in guests:
    if guest['node'] != 'pve1' or guest['type'] not in ('qemu', 'lxc'):
        continue
    cfg = json.loads(output('pvesh', 'get', f'/nodes/pve1/{guest["type"]}/{guest["vmid"]}/config', '--output-format', 'json'))
    managed = cfg.get('description', '').startswith('safehost-billing:v1:') or int(guest['vmid']) == 101
    fields = ('ipconfig',) if guest['type'] == 'qemu' else ('net',)
    for value in [v for k,v in cfg.items() if k.startswith(fields)]:
        match = re.search(r'(?:^|,)ip=([0-9.]+)/', value)
        assert not match or match[1] not in pool_ips or managed, 'IP пула занят чужой VM: ' + (match[1] if match else '')
print('NAT ports and pool IPs verified')
