#!/usr/bin/env python3
"""Prepare a new, owned cloud-init template; never modify an existing customer VM."""
import argparse
import fcntl
import os
import hashlib
import inspect
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
    if item['os'] in ('AlmaLinux 9', 'AlmaLinux 10'):
        argv = ['/usr/local/libexec/safehost-qga-exec', *argv]
    response = json.loads(qm(item, 'guest', 'exec', '--timeout', '30', '--', *argv))
    if response.get('exitcode') != 0:
        raise RuntimeError('Guest validation failed; private provisioning logs retained')
    return response.get('out-data', '')


def enable_guest_exec(root=Path('/')):
    """Keep vendor RPC restrictions, permitting only the two execution RPCs we use."""
    path = root / 'etc/sysconfig/qemu-ga'
    if path.is_symlink():
        raise ValueError('Unsafe guest agent configuration')
    source = path.read_text()
    settings = re.findall(r'^FILTER_RPC_ARGS=.*$', source, re.MULTILINE)
    if len(settings) != 1:
        raise ValueError('Unexpected guest agent filter configuration')
    match = re.fullmatch(r'FILTER_RPC_ARGS="--(allow|block)-rpcs=([a-z0-9,-]*)"', settings[0])
    if not match:
        raise ValueError('Unexpected guest agent RPC filter')
    mode, entries = match.groups()
    commands = entries.split(',') if entries else []
    if not all(re.fullmatch(r'guest-[a-z0-9-]+', command) for command in commands):
        raise ValueError('Unexpected guest agent RPC name')
    required = ('guest-exec', 'guest-exec-status')
    if mode == 'allow':
        commands += [command for command in required if command not in commands]
    else:
        commands = [command for command in commands if command not in required]
    updated = f'FILTER_RPC_ARGS="--{mode}-rpcs={",".join(commands)}"'
    if updated != settings[0]:
        path.write_text(source.replace(settings[0], updated, 1))


def reset_machine_identity(root=Path('/')):
    # Older cloud-init removes this file. Keep a bind-mount target for systemd
    # during early read-only boot, while still requesting a fresh identity.
    path = root / 'etc/machine-id'
    if path.is_symlink():
        raise ValueError('Unsafe template machine identity')
    path.write_text('uninitialized\n')
    path.chmod(0o644)


def prepare(item, stage):
    vmid = item['vmid']
    templates = {'Ubuntu 22.04': 9001, 'Ubuntu 26.04': 9002, 'Debian 13': 9003,
                 'Debian 12': 9004, 'AlmaLinux 9': 9005, 'AlmaLinux 10': 9006}
    require(isinstance(item['os'], str) and templates.get(item['os']) == vmid,
            'OS/VMID outside the dedicated template mapping')
    alma = item['os'] in ('AlmaLinux 9', 'AlmaLinux 10')
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
             'users': [{'name': 'vpsadmin', 'groups': ['wheel'] if alma else ['adm', 'sudo'], 'shell': '/bin/bash',
                        'sudo': 'ALL=(ALL) NOPASSWD:ALL', 'lock_passwd': True}],
             'disable_root': True, 'ssh_pwauth': False, 'package_update': True,
             'packages': ['qemu-guest-agent', 'NetworkManager' if alma else 'netplan.io', 'python3', 'sudo', 'openssh-server'],
             'runcmd': [['systemctl', 'enable', '--now', 'qemu-guest-agent']]}
    if alma:
        setup = 'import re\nfrom pathlib import Path\n' + inspect.getsource(enable_guest_exec) + '\nenable_guest_exec()\n'
        cloud['packages'].append('policycoreutils-python-utils')
        # SELinux transitions only through its dedicated entrypoint type; the
        # standard boolean alone does not permit commands from virt_qemu_ga_t.
        cloud['runcmd'] = [['semanage', 'fcontext', '-a', '-t', 'virt_qemu_ga_unconfined_exec_t',
                           '/usr/local/libexec/safehost-qga-exec'],
                          ['restorecon', '/usr/local/libexec/safehost-qga-exec'],
                          ['setsebool', '-P', 'virt_qemu_ga_run_unconfined', 'on'],
                          ['python3', '-c', setup], *cloud['runcmd'],
                          ['systemctl', 'restart', 'qemu-guest-agent']]
        cloud['write_files'] = [
            {'path': '/usr/local/libexec/safehost-qga-exec', 'permissions': '0755',
             'content': '#!/bin/sh\nexec "$@"\n'},
            {'path': '/etc/cloud/cloud.cfg.d/90-safehost-network-renderer.cfg', 'permissions': '0644',
             'content': 'system_info:\n  network:\n    renderers: [network-manager]\n'},
            {'path': '/etc/NetworkManager/conf.d/90-safehost.conf', 'permissions': '0644',
             'content': '[main]\nno-auto-default=*\n'},
        ]
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
os_id=values['ID'].strip('"')
driver='nmcli' if os_id=='almalinux' else 'netplan'
for executable in [driver,'python3','sudo','sshd']:subprocess.run(['sh','-c','command -v '+executable],check=True,stdout=subprocess.DEVNULL)
if driver=='netplan':
 if not all(p.name=='50-cloud-init.yaml' for p in Path('/etc/netplan').glob('*.yaml')):raise RuntimeError('Unexpected static network configuration')
 subprocess.run(['netplan','generate'],check=True,stdout=subprocess.DEVNULL)
else:
 subprocess.run(['systemctl','is-active','--quiet','NetworkManager'],check=True)
 if subprocess.check_output(['getenforce'],text=True).strip()!='Enforcing':raise RuntimeError('SELinux enforcement changed')
 if subprocess.check_output(['getsebool','virt_qemu_ga_run_unconfined'],text=True).strip()!='virt_qemu_ga_run_unconfined --> on':raise RuntimeError('Guest management policy is unavailable')
print(json.dumps({'id':os_id,'version':values['VERSION_ID'].strip('"')}))
'''
        observed = json.loads(guest(item, ['python3', '-c', check]))
        expected_id = 'almalinux' if alma else 'debian' if item['os'].startswith('Debian') else 'ubuntu'
        expected_version = observed['version'].split('.')[0] if alma else observed['version']
        require(observed['id'] == expected_id and expected_version == item['version'], 'Booted OS differs from requested image')
        current = owned(item)
        require(bool(current.get('vmgenid')), 'VM generation identity is missing')
        proof = {'os': item['os'], 'vmid': vmid, 'marker': item['marker'], 'imageChecksum': item['checksum'],
                 'bootVerified': True, 'vmgenid': current['vmgenid'], 'observed': observed, 'preparedAt': time.time()}
        save_proof(proof_path, proof)
    if not proof.get('cleaned'):
        clean = 'from pathlib import Path\n' + inspect.getsource(reset_machine_identity) + '\n' + '''import subprocess
from pathlib import Path
subprocess.run(['cloud-init','clean','--logs','--seed','--machine-id'],check=True)
reset_machine_identity()
for path in Path('/etc/ssh').glob('ssh_host_*'):
 if path.is_file():path.unlink()
for name in ['/etc/netplan/50-cloud-init.yaml','/etc/network/interfaces.d/50-cloud-init']:
 Path(name).unlink(missing_ok=True)
release=dict(line.split('=',1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
if release['ID'].strip('"')=='almalinux':
 for folder,pattern in [('/etc/NetworkManager/system-connections','cloud-init-*.nmconnection'),('/etc/sysconfig/network-scripts','ifcfg-*')]:
  for path in Path(folder).glob(pattern):
   if path.name=='ifcfg-lo':continue
   if path.is_symlink() or 'cloud-init' not in path.read_text():raise RuntimeError('Unexpected template network profile')
   path.unlink()
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
