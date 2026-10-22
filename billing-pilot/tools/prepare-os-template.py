#!/usr/bin/env python3
"""Prepare a new, owned cloud-init template; never modify an existing customer VM."""
import argparse
import fcntl
import os
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def atomic(path, payload):
    temporary = path.with_name(path.name + '.next')
    with temporary.open('wb') as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.chmod(0o600)
    os.replace(temporary, path)
    descriptor = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def save_proof(path, proof):
    atomic(path, (json.dumps(proof, indent=2) + '\n').encode())


def run(argv, timeout=900):
    return subprocess.check_output(argv, text=True, stderr=subprocess.STDOUT, timeout=timeout)


def config(vmid):
    path = Path('/etc/pve/qemu-server') / f'{vmid}.conf'
    return json.loads(run(['pvesh', 'get', f'/nodes/pve1/qemu/{vmid}/config', '--output-format', 'json'])) if path.exists() else None


def owned(item):
    current = config(item['vmid'])
    if current is not None and current.get('description') != item['marker']:
        raise RuntimeError('VMID belongs to another resource; refusing to modify it')
    return current


def qm(item, verb, *args):
    if verb != 'create':
        require(owned(item) is not None, 'Owned VM is missing')
    if verb in ('disk', 'guest', 'cloudinit'):
        command, *rest = args
        return run(['qm', verb, str(command), str(item['vmid']), *map(str, rest)])
    return run(['qm', verb, str(item['vmid']), *map(str, args)])


def status(item):
    return json.loads(run(['pvesh', 'get', f'/nodes/pve1/qemu/{item["vmid"]}/status/current', '--output-format', 'json']))['status']


def guest(item, argv):
    response = json.loads(qm(item, 'guest', 'exec', '--timeout', '30', '--', *argv))
    if response.get('exitcode') != 0:
        raise RuntimeError('Guest validation failed; private provisioning logs retained')
    return response.get('out-data', '')


def prepare(item, stage):
    vmid = item['vmid']
    require(vmid in (9001, 9002, 9003), 'VMID outside the dedicated OS template range')
    require(item['os'] in ('Ubuntu 22.04', 'Ubuntu 26.04', 'Debian 13'), 'Unsupported OS')
    require(item['marker'].startswith('safehost-os-template:v1:'), 'Invalid ownership marker')
    image = Path(item['image'])
    with image.open('rb') as source:
        require(hashlib.file_digest(source, item['algorithm']).hexdigest() == item['checksum'], 'Image checksum mismatch')
    proof_path = stage / f'{vmid}.json'
    proof = json.loads(proof_path.read_text()) if proof_path.exists() else {}
    current = owned(item)
    if proof:
        require(current is not None, 'Previously prepared VM is missing; refusing automatic recreation')
        require(all(proof.get(key) == value for key, value in {'os': item['os'], 'vmid': vmid, 'marker': item['marker'], 'imageChecksum': item['checksum'], 'vmgenid': current.get('vmgenid')}.items()) and bool(current.get('vmgenid')), 'Proof belongs to another VM generation or image')
    if current and current.get('template'):
        require(proof.get('bootVerified') and proof.get('cleaned') and 'scsi0' in current, 'Template has no verified boot/root disk')
        proof['template'] = True
        save_proof(proof_path, proof)
        return proof
    ip = f'10.10.10.{240 + vmid - 9001}'
    for path in Path('/etc/pve/qemu-server').glob('*.conf'):
        if path.stem != str(vmid):
            require(not re.search(r'ip=' + re.escape(ip) + r'(?:/|,|\s|$)', path.read_text()), 'Bootstrap IP occupied')
    for path in Path('/etc/pve/lxc').glob('*.conf'):
        require(not re.search(r'ip=' + re.escape(ip) + r'(?:/|,|\s|$)', path.read_text()), 'Bootstrap IP occupied')
    cloud = {'hostname': f'safehost-template-{vmid}', 'manage_etc_hosts': True,
             'users': [{'name': 'vpsadmin', 'groups': ['adm', 'sudo'], 'shell': '/bin/bash',
                        'sudo': 'ALL=(ALL) NOPASSWD:ALL', 'lock_passwd': True}],
             'disable_root': True, 'ssh_pwauth': False, 'package_update': True,
             'packages': ['qemu-guest-agent', 'netplan.io', 'python3', 'sudo', 'openssh-server'],
             'runcmd': [['systemctl', 'enable', '--now', 'qemu-guest-agent']]}
    snippet = Path('/var/lib/vz/snippets') / f'safehost-os-bootstrap-{vmid}.yaml'
    atomic(snippet, ('#cloud-config\n' + json.dumps(cloud) + '\n').encode())
    if current is None:
        node = json.loads(run(['pvesh', 'get', '/nodes/pve1/status', '--output-format', 'json']))
        guests = json.loads(run(['pvesh', 'get', '/cluster/resources', '--type', 'vm', '--output-format', 'json']))
        reserved = sum(int(g.get('maxmem', 0)) for g in guests if not g.get('template'))
        require(reserved + 2 * 1073741824 <= node['memory']['total'] - 2 * 1073741824, 'RAM reserve would be exceeded')
        storage = json.loads(run(['pvesh', 'get', '/nodes/pve1/storage/local-lvm/status', '--output-format', 'json']))
        require(storage['avail'] > 25 * 1073741824, 'Insufficient template storage')
        qm(item, 'create', '--name', 'safehost-' + item['os'].lower().replace(' ', '-').replace('.', '-'),
           '--memory', '2048', '--cores', '2', '--cpu', 'host', '--bios', 'ovmf', '--machine', 'q35',
           '--scsihw', 'virtio-scsi-single', '--serial0', 'socket', '--vga', 'serial0', '--agent', 'enabled=1',
           '--net0', 'virtio,bridge=vmbr1,firewall=0', '--efidisk0', 'local-lvm:1,efitype=4m,pre-enrolled-keys=0',
           '--ide2', 'local-lvm:cloudinit', '--onboot', '0', '--protection', '1', '--description', item['marker'])
        current = owned(item)
    current_status = status(item)
    if current_status == 'stopped' and not proof.get('bootVerified'):
        if 'scsi0' not in current:
            unused = [k for k in current if re.fullmatch(r'unused[0-9]+', k)]
            if not unused:
                qm(item, 'disk', 'import', str(image), 'local-lvm')
                current = owned(item)
                unused = [k for k in current if re.fullmatch(r'unused[0-9]+', k)]
            require(len(unused) == 1, 'Unexpected number of imported disks')
            volume = current[unused[0]].split(',')[0]
            require(volume.startswith(f'local-lvm:vm-{vmid}-disk-'), 'Imported disk belongs to another VM')
            qm(item, 'set', '--scsi0', volume + ',discard=on,iothread=1')
        current = owned(item)
        match = re.search(r'(?:^|,)size=([0-9.]+)([GMT])(?:,|$)', current['scsi0'])
        require(match is not None, 'Cannot read root disk size')
        size = float(match[1]) * {'M': 1/1024, 'G': 1, 'T': 1024}[match[2]]
        require(size <= 20, 'Refusing to shrink root disk')
        if size < 20:
            qm(item, 'disk', 'resize', 'scsi0', '20G')
        qm(item, 'set', '--boot', 'order=scsi0', '--ciuser', 'vpsadmin', '--ciupgrade', '0', '--nameserver', '1.1.1.1',
           '--ipconfig0', f'ip={ip}/24,gw=10.10.10.1', '--cicustom', 'user=local:snippets/' + snippet.name)
        qm(item, 'cloudinit', 'update')
        qm(item, 'start')
    if not proof.get('bootVerified'):
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            try:
                state = json.loads(guest(item, ['cloud-init', 'status', '--format', 'json']))
                if state.get('status') == 'done':
                    break
                if state.get('status') == 'error':
                    raise RuntimeError('Cloud-init reported an error')
            except (subprocess.CalledProcessError, ValueError, RuntimeError):
                pass
            time.sleep(5)
        else:
            raise RuntimeError('Template bootstrap timeout; owned VM preserved for diagnosis')
        check = '''import json,subprocess
from pathlib import Path
values=dict(line.split('=',1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
if not Path('/usr/sbin/netplan').exists():raise RuntimeError('netplan missing')
if not all(p.name=='50-cloud-init.yaml' for p in Path('/etc/netplan').glob('*.yaml')):raise RuntimeError('Unexpected static network configuration')
for executable in ['netplan','python3','sudo','sshd']:subprocess.run(['sh','-c','command -v '+executable],check=True,stdout=subprocess.DEVNULL)
subprocess.run(['netplan','generate'],check=True,stdout=subprocess.DEVNULL)
print(json.dumps({'id':values['ID'].strip('"'),'version':values['VERSION_ID'].strip('"')}))
'''
        observed = json.loads(guest(item, ['python3', '-c', check]))
        require(observed == {'id': 'debian' if item['os'].startswith('Debian') else 'ubuntu', 'version': item['version']}, 'Booted OS differs from requested image')
        current = owned(item)
        require(bool(current.get('vmgenid')), 'VM generation identity is missing')
        proof = {'os': item['os'], 'vmid': vmid, 'marker': item['marker'], 'imageChecksum': item['checksum'],
                 'bootVerified': True, 'vmgenid': current['vmgenid'], 'observed': observed, 'preparedAt': time.time()}
        save_proof(proof_path, proof)
    if not proof.get('cleaned'):
        clean = '''import subprocess
from pathlib import Path
subprocess.run(['cloud-init','clean','--logs','--seed','--machine-id'],check=True)
for path in Path('/etc/ssh').glob('ssh_host_*'):
 if path.is_file():path.unlink()
for name in ['/etc/netplan/50-cloud-init.yaml','/etc/network/interfaces.d/50-cloud-init']:
 Path(name).unlink(missing_ok=True)
'''
        guest(item, ['python3', '-c', clean])
        proof['cleaned'] = True
        save_proof(proof_path, proof)
    if status(item) == 'running':
        qm(item, 'shutdown', '--timeout', '60')
    require(status(item) == 'stopped', 'Template must be stopped')
    require('scsi0' in owned(item), 'Template has no root disk')
    qm(item, 'set', '--delete', 'cicustom,ipconfig0')
    qm(item, 'template')
    proof['template'] = True
    save_proof(proof_path, proof)
    return proof


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('manifest', type=Path)
    parser.add_argument('--stage', type=Path, default=Path('/root/safehost-os-20261023'))
    args = parser.parse_args()
    os.umask(0o077)
    args.stage.mkdir(mode=0o700, parents=True, exist_ok=True)
    with Path('/run/lock/safehost-os-template.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for item in json.loads(args.manifest.read_text()):
            print(json.dumps(prepare(item, args.stage)), flush=True)


if __name__ == '__main__':
    main()
