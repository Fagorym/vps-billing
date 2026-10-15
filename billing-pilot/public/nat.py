#!/usr/bin/python3
# managed-by: safehost-billing-public:v1
"""Only add web forwarding for VM 101; refuse foreign rules and listeners."""
from pathlib import Path
import shlex
import json
import ipaddress
import subprocess
import sys

MARKER = 'managed-by: safehost-billing-public:v1'
INSTALLED = Path('/usr/local/lib/safehost-billing/public-nat.py')
CHAINS = {'nat': 'BILL_WEB_DNAT', 'filter': 'BILL_WEB_FWD'}


def run(*args, check=True):
    return subprocess.run(args, text=True, capture_output=True, check=check)


def includes_web_port(tokens):
    for option in ('--dport', '--dports'):
        if option not in tokens:
            continue
        for item in tokens[tokens.index(option) + 1].split(','):
            ends = item.split(':')
            low, high = int(ends[0]), int(ends[-1])
            if any(low <= port <= high for port in (80, 443)):
                return True
    return False


def preflight():
    owned = INSTALLED.exists() and MARKER in INSTALLED.read_text()
    if INSTALLED.exists() and not owned:
        raise RuntimeError('Foreign public NAT script')
    for port in (80, 443):
        if run('ss', '-H', '-ltn', 'sport', '=', ':' + str(port)).stdout.strip():
            raise RuntimeError(f'Public port {port} has a host listener')
    for table, chain in CHAINS.items():
        rules = run('iptables-save', '-t', table).stdout
        if ':' + chain + ' ' in rules and not owned:
            raise RuntimeError('Foreign chain: ' + chain)
        if table == 'nat':
            for line in rules.splitlines():
                if line.startswith('-A ') and includes_web_port(shlex.split(line)):
                    if not line.startswith('-A ' + chain + ' '):
                        raise RuntimeError('Existing NAT uses web ports: ' + line)


def ensure(table, chain, rule):
    prefix = ['iptables', '-w', '10', '-t', table]
    if run(*prefix, '-C', chain, *rule, check=False).returncode:
        run(*prefix, '-A', chain, *rule)


def apply():
    public = str(ipaddress.IPv4Address(json.loads(Path('/etc/safehost-billing/config.json').read_text())['public_ip']))
    preflight()
    for table, chain in CHAINS.items():
        if run('iptables', '-w', '10', '-t', table, '-S', chain, check=False).returncode:
            run('iptables', '-w', '10', '-t', table, '-N', chain)
    for port in (80, 443):
        ensure('nat', CHAINS['nat'], ['-i', 'vmbr0', '-d', public + '/32', '-p', 'tcp',
               '--dport', str(port), '-j', 'DNAT', '--to-destination', f'10.10.10.11:{port}'])
        ensure('filter', CHAINS['filter'], ['-i', 'vmbr0', '-o', 'vmbr1', '-d', '10.10.10.11/32',
               '-p', 'tcp', '--dport', str(port), '-m', 'conntrack', '--ctstate', 'NEW',
               '--ctorigdst', public, '--ctorigdstport', str(port), '-j', 'ACCEPT'])
    ensure('filter', CHAINS['filter'], ['-i', 'vmbr0', '-o', 'vmbr1', '-d', '10.10.10.11/32',
           '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'])
    ensure('filter', CHAINS['filter'], ['-i', 'vmbr1', '-o', 'vmbr0', '-s', '10.10.10.11/32',
           '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'])
    for table, parent in [('nat', 'PREROUTING'), ('filter', 'FORWARD')]:
        prefix = ['iptables', '-w', '10', '-t', table]
        if run(*prefix, '-C', parent, '-j', CHAINS[table], check=False).returncode:
            run(*prefix, '-I', parent, '1', '-j', CHAINS[table])
    print('Web NAT: 80/443 -> VM 101')


if __name__ == '__main__':
    if sys.argv[1:] == ['--check']:
        preflight()
        print('Public ports available; existing SSH forwarding preserved')
    elif not sys.argv[1:]:
        apply()
    else:
        sys.exit('Usage: public-nat.py [--check]')
