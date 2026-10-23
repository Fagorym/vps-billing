import base64
import copy
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest
import fcntl
import io
import threading
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('engine', ROOT / 'backend/engine.py')
engine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(engine)
KEY = 'ssh-ed25519 ' + base64.b64encode(struct.pack('>I', 11) + b'ssh-ed25519' + struct.pack('>I', 32) + bytes(range(32))).decode()


def nat_configuration():
    config = json.loads((ROOT / 'config.json').read_text())
    config.pop('public_network', None)
    config['template_marker'] = 'proxmox-pilot:v1:template:test'
    return config


class FakePVE:
    def __init__(self, config):
        self.c = config
        self.vms = {9000: {'template': 1, 'description': config['template_marker'],
                           'net0': 'virtio=00:00:00:00:00:00,bridge=vmbr1', 'scsi0': 'local-lvm:base-9000-disk-0,size=4G'}}
        self.states = {9000: 'stopped'}
        self.calls = []
        self.is_ready = True
        self.crash_after_clone = False
        self.crash_after_start = False

    def ready(self, vmid, ip, os_name=engine.DEFAULT_OS):
        return self.is_ready

    def guests(self):
        return {i: {'vmid': i, 'node': 'pve1', 'type': v.get('_type', 'qemu'), 'template': v.get('template', 0),
                    'maxmem': int(v.get('memory', 0)) * 1048576, 'maxcpu': int(v.get('cores', 0)),
                    'status': self.states.get(i, 'stopped'), 'cpu': 0.125, 'mem': 4096} for i,v in self.vms.items()}

    def guest_fs(self, vmid):
        return None

    def config(self, vmid, kind='qemu'):
        return copy.deepcopy(self.vms[vmid])

    @contextmanager
    def metrics_reader(self, vmid, timeframe):
        def identity():
            guest = self.guests().get(vmid)
            config = self.config(vmid) if guest and guest['type'] == 'qemu' else None
            return {'guest': guest, 'config': config}
        yield SimpleNamespace(identity=identity, history=lambda: self.api(
            f'/nodes/{self.c["node"]}/qemu/{vmid}/rrddata', timeframe=timeframe, cf='AVERAGE'))

    def network_configs(self, node, exclude=None):
        return [{'type':guest['type'],'config':self.config(vmid,guest['type'])}
                for vmid,guest in self.guests().items()
                if vmid!=exclude and guest['node']==node and guest['type'] in ('qemu','lxc')]

    def check_capacity(self, plan):
        pass

    def api(self, path, **params):
        if path == '/cluster/resources' and params == {'type': 'node'}:
            return [{'node': self.c['node'], 'status': 'online', 'cpu': 0.2}]
        if '/storage/' in path:
            return {'avail': 100 * 1073741824, 'total': 200 * 1073741824, 'used': 100 * 1073741824}
        return {'memory': {'total': 64 * 1073741824, 'used': 1073741824}, 'cpu': 0.2, 'cpuinfo': {'cpus': 8}}

    def status(self, vmid):
        return self.states[vmid]

    def cloudinit_update(self, vmid):
        self.command('cloudinit', vmid, 'update')

    def resize(self, vmid, gb):
        self.calls.append(('resize', vmid, gb))
        self.vms[vmid]['scsi0'] = f'local-lvm:vm-{vmid}-disk-0,size={gb}G'

    def command(self, verb, vmid, *args):
        self.calls.append((verb, vmid, *args))
        if verb == 'clone':
            new_id = int(args[0])
            self.vms[new_id] = {'description': args[-1], 'net0': 'virtio=00:00:00:00:00:00,bridge=vmbr1',
                                'scsi0': f'local-lvm:vm-{new_id}-disk-0,size=4G'}
            self.states[new_id] = 'stopped'
            if self.crash_after_clone:
                self.crash_after_clone = False
                raise OSError('lost clone response')
        elif verb == 'set':
            if '--delete' in args:
                for key in args[args.index('--delete') + 1].split(','):
                    self.vms[vmid].pop(key, None)
                return
            self.vms[vmid].update(dict(zip((s.removeprefix('--') for s in args[::2]), args[1::2])))
        elif verb in ('start', 'stop'):
            self.states[vmid] = 'running' if verb == 'start' else 'stopped'
            if verb == 'start' and self.crash_after_start:
                self.crash_after_start = False
                raise OSError('lost start response')
        elif verb == 'shutdown':
            self.states[vmid] = 'stopped'
        elif verb == 'destroy':
            del self.vms[vmid]
            del self.states[vmid]


class CLILockingContracts(unittest.TestCase):
    def test_waiting_mutation_loads_config_after_acquiring_the_command_lock(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = root / 'config.json'
            config.write_text('{"generation":"before"}')
            state = root / 'state'
            state.mkdir()
            attempted = threading.Event()
            observed = []
            failures = []
            original_flock = fcntl.flock
            def flock(file, mode):
                if threading.current_thread() is not threading.main_thread():
                    attempted.set()
                return original_flock(file, mode)
            def path(value):
                return config if value == '/etc/safehost-billing/config.json' else state if value == '/var/lib/safehost-billing' else Path(value)
            def create_engine(current_config, *args):
                observed.append(current_config)
                return SimpleNamespace(db=SimpleNamespace(close=lambda: None), handle=lambda request: {'status': 'stopped'})
            def invoke():
                try:
                    engine.main()
                except BaseException as error:
                    failures.append(error)
            with (state / 'operation.lock').open('a') as held:
                original_flock(held, fcntl.LOCK_SH)
                with patch.object(engine, 'Path', side_effect=path), patch.object(engine, 'Engine', side_effect=create_engine), \
                     patch.object(engine.fcntl, 'flock', side_effect=flock), \
                     patch.object(engine.sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(b'{"action":"suspend"}'))), \
                     patch.object(engine.sys, 'stdout', io.StringIO()):
                    task = threading.Thread(target=invoke, daemon=True)
                    task.start()
                    try:
                        self.assertTrue(attempted.wait(timeout=2))
                        config.write_text('{"generation":"after"}')
                    finally:
                        original_flock(held, fcntl.LOCK_UN)
                        task.join(timeout=2)
                    self.assertFalse(task.is_alive())
            self.assertEqual(failures, [])
            self.assertEqual(observed, [{'generation': 'after'}])

    def invoke_while_locked(self, held_mode, action):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = root / 'config.json'
            config.write_text('{}')
            state = root / 'state'
            state.mkdir()
            outcome = []
            fake = SimpleNamespace(db=SimpleNamespace(close=lambda: None), handle=lambda request: {'status': 'running'})
            def path(value):
                return config if value == '/etc/safehost-billing/config.json' else state if value == '/var/lib/safehost-billing' else Path(value)
            def invoke():
                try:
                    engine.main()
                    outcome.append(None)
                except Exception as error:
                    outcome.append(type(error))
            with (state / 'operation.lock').open('a') as held:
                fcntl.flock(held, held_mode)
                with patch.object(engine, 'Path', side_effect=path), patch.object(engine, 'Engine', return_value=fake), \
                     patch.object(engine.sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(json.dumps({'action': action}).encode()))), \
                     patch.object(engine.sys, 'stdout', io.StringIO()):
                    task = threading.Thread(target=invoke, daemon=True)
                    task.start()
                    try:
                        task.join(timeout=0.5)
                        completed = not task.is_alive()
                    finally:
                        fcntl.flock(held, fcntl.LOCK_UN)
                        task.join(timeout=2)
                self.assertFalse(task.is_alive())
            return completed, outcome

    def test_status_does_not_queue_behind_another_read(self):
        completed, outcome = self.invoke_while_locked(fcntl.LOCK_SH, 'status')
        self.assertTrue(completed, 'A read was queued behind a read')
        self.assertEqual(outcome, [None])

    def test_password_fails_fast_while_a_mutation_is_running(self):
        completed, outcome = self.invoke_while_locked(fcntl.LOCK_EX, 'password')
        self.assertTrue(completed, 'Password lookup waited for a mutation')
        self.assertEqual(outcome, [engine.Refused])

    def test_capacity_fails_fast_while_a_mutation_is_running(self):
        completed, outcome = self.invoke_while_locked(fcntl.LOCK_EX, 'network_capacity')
        self.assertTrue(completed, 'Capacity lookup waited for a mutation')
        self.assertEqual(outcome, [engine.Refused])

    def test_mutation_still_waits_for_existing_readers(self):
        completed, outcome = self.invoke_while_locked(fcntl.LOCK_SH, 'suspend')
        self.assertFalse(completed)
        self.assertEqual(outcome, [None])


class CLIContracts(unittest.TestCase):
    def test_cloudinit_update_uses_nested_qm_subcommand(self):
        # Proxmox CLI: qm cloudinit update <vmid>, unlike qm start <vmid>.
        with patch.object(engine, 'run', return_value='') as command:
            engine.Proxmox({}).cloudinit_update(1100)
        command.assert_called_once_with(['/usr/sbin/qm', 'cloudinit', 'update', '1100'])

    def test_readiness_uses_selinux_entrypoint_only_for_exact_alma_os(self):
        cases = {None: [], 'Ubuntu 24.04': [], 'Debian 12': [], 'Debian 13': [],
                 'AlmaLinux 9 custom': [],
                 'AlmaLinux 9': ['/usr/local/libexec/safehost-qga-exec'],
                 'AlmaLinux 10': ['/usr/local/libexec/safehost-qga-exec']}
        reply = SimpleNamespace(returncode=0, stdout=json.dumps({'exitcode': 0, 'out-data': '{"status":"done"}'}))
        for os_name, entrypoint in cases.items():
            with self.subTest(os=os_name), patch.object(engine.subprocess, 'run', return_value=reply) as command, \
                    patch.object(engine.socket, 'create_connection') as ssh:
                ssh.return_value.__enter__.return_value.recv.return_value = b'SSH-2.0-OpenSSH'
                pve = engine.Proxmox({})
                self.assertTrue(pve.ready(1100, '10.10.10.20') if os_name is None else pve.ready(1100, '10.10.10.20', os_name))
                command.assert_called_once_with(['/usr/sbin/qm', 'guest', 'exec', '1100', '--timeout', '10', '--',
                    *entrypoint, 'cloud-init', 'status', '--format', 'json'], capture_output=True, text=True, timeout=15)
                ssh.assert_called_once_with(('10.10.10.20', 22), timeout=2)


class EngineTests(unittest.TestCase):
    def test_readiness_requires_cloud_init_and_ssh_and_owner(self):
        self.handle('create')
        self.pve.is_ready = False
        self.assertFalse(self.handle('readiness')['ready'])
        self.pve.is_ready = True
        self.assertTrue(self.handle('readiness')['ready'])
        with self.assertRaises(engine.Refused):
            self.handle('readiness', client_id=3)
        self.handle('suspend')
        self.assertFalse(self.handle('readiness')['ready'])

    def test_password_and_readiness_pass_frozen_os_to_guest_probe(self):
        self.add_os_templates()
        for order, os_name in enumerate((None, 'AlmaLinux 9', 'AlmaLinux 10'), 1):
            with self.subTest(os=os_name):
                request = {'order_id': order, 'ssh_key': ''}
                if os_name is not None:
                    request['os'] = os_name
                created = self.handle('create', **request)
                for action in ('password', 'readiness'):
                    with self.subTest(action=action), patch.object(self.pve, 'ready', return_value=True) as ready:
                        result = self.handle(action, order_id=order, os='Debian 12')
                        self.assertTrue(result['ready'] if action == 'readiness' else result['password'])
                        ready.assert_called_once_with(created['vmid'], created['private_ip'], os_name or engine.DEFAULT_OS)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.config = nat_configuration()
        self.pve = FakePVE(self.config)
        self.e = engine.Engine(self.config, Path(self.temp.name) / 'state', Path(self.temp.name) / 'snippets', self.pve)
        self.req = {'action': 'create', 'order_id': 1, 'client_id': 2, 'plan': 'mini', 'ssh_key': KEY}

    def tearDown(self):
        self.e.db.close()
        self.temp.cleanup()

    def handle(self, action, **kwargs):
        return self.e.handle({**self.req, 'action': action, **kwargs})

    def add_os_templates(self):
        self.config['templates'] = {}
        for template_id, os_name in enumerate(('Ubuntu 22.04', 'Ubuntu 26.04', 'Debian 13',
                                               'Debian 12', 'AlmaLinux 9', 'AlmaLinux 10'), 9001):
            marker = f'proxmox-pilot:v1:template:test-{template_id}'
            self.config['templates'][os_name] = {'template_id': template_id, 'template_marker': marker}
            self.pve.vms[template_id] = {**self.pve.vms[9000], 'description': marker}
            self.pve.states[template_id] = 'stopped'

    def test_selected_os_clones_its_owned_template_and_freezes_spec(self):
        self.add_os_templates()
        for order, os_name, template_id in ((1, 'Ubuntu 24.04', 9000), (2, 'Ubuntu 22.04', 9001),
                                             (3, 'Ubuntu 26.04', 9002), (4, 'Debian 13', 9003),
                                             (5, 'Debian 12', 9004), (6, 'AlmaLinux 9', 9005),
                                             (7, 'AlmaLinux 10', 9006)):
            with self.subTest(os=os_name):
                first = self.handle('create', order_id=order, os=os_name, disk_gb=25)
                row = self.e.db.execute('SELECT * FROM allocation WHERE order_id=?', (order,)).fetchone()
                expected_spec = {'plan': 'mini', 'ssh_key': KEY, 'disk_gb': 25}
                if os_name != 'Ubuntu 24.04':
                    expected_spec['os'] = os_name
                self.assertEqual(json.loads(row['spec']), expected_spec)
                self.assertIn(('clone', template_id, first['vmid'], '--full', '1', '--storage', self.config['storage'],
                               '--name', f'vps-order-{order}', '--description', self.e.marker(row)), self.pve.calls)
                calls = list(self.pve.calls)
                self.assertEqual(self.handle('create', order_id=order, os=os_name, disk_gb=25), first)
                with self.assertRaises(engine.Refused):
                    self.handle('create', order_id=order, os='Debian 13' if os_name != 'Debian 13' else 'Ubuntu 24.04', disk_gb=25)
                self.assertEqual(self.pve.calls, calls)

    def test_alma_creation_uses_wheel_and_retains_initial_password_expiry(self):
        self.add_os_templates()
        for order, os_name in enumerate(('AlmaLinux 9', 'AlmaLinux 10'), 1):
            with self.subTest(os=os_name):
                server = self.handle('create', order_id=order, os=os_name, ssh_key=None)
                snippet = Path(self.temp.name) / 'snippets' / f'safehost-billing-{server["vmid"]}.yaml'
                cloud = json.loads(snippet.read_text().split('\n', 1)[1])
                self.assertEqual(cloud['users'][0]['groups'], ['wheel'])
                self.assertEqual(cloud['users'][0]['sudo'], 'ALL=(ALL) NOPASSWD:ALL')
                self.assertTrue(cloud['chpasswd']['expire'])
                self.assertIn(['chage', '-d', '0', 'vpsadmin'], cloud['runcmd'])
                self.assertTrue(cloud['disable_root'])

    def test_default_os_replays_historic_spec_without_template_or_mutation(self):
        first = self.handle('create')
        row = self.e.db.execute('SELECT * FROM allocation').fetchone()
        self.assertEqual(json.loads(row['spec']), {'plan': 'mini', 'ssh_key': KEY})
        marker = self.pve.config(first['vmid'])['description']
        del self.pve.vms[9000]
        calls = list(self.pve.calls)
        self.assertEqual(self.handle('create', os='Ubuntu 24.04'), first)
        self.assertEqual(self.handle('create', os=None), first)
        self.assertEqual(self.handle('create'), first)
        self.assertEqual(self.pve.calls, calls)
        self.assertEqual(self.pve.config(first['vmid'])['description'], marker)
        self.assertEqual(self.e.owned_config(row)['description'], marker)

    def test_nondefault_os_retry_uses_frozen_spec_after_interrupted_clone(self):
        self.add_os_templates()
        self.pve.crash_after_clone = True
        with self.assertRaises(OSError):
            self.handle('create', os='Debian 13')
        del self.pve.vms[9003]
        self.assertEqual(self.handle('create', os='Debian 13')['vmid'], 1100)
        self.assertEqual([call[1] for call in self.pve.calls if call[0] == 'clone'], [9003])
        calls = list(self.pve.calls)
        with self.assertRaises(engine.Refused):
            self.handle('create')
        self.assertEqual(self.pve.calls, calls)

    def test_invalid_or_unavailable_os_fails_before_allocation_and_credentials(self):
        for os_name in ('Debian 13', 'Debian 12', 'AlmaLinux 9', 'AlmaLinux 10',
                        'Ubuntu 22.04', 'Ubuntu 26.04', 'Ubuntu 20.04', '', 13, {}):
            with self.subTest(os=os_name), self.assertRaises(engine.Refused):
                self.handle('create', os=os_name, ssh_key='')
        self.add_os_templates()
        for field, value in (('description', 'foreign'), ('template', 0), ('_type', 'lxc')):
            saved = self.pve.vms[9003].copy()
            self.pve.vms[9003][field] = value
            with self.subTest(field=field), self.assertRaises(engine.Refused):
                self.handle('create', os='Debian 13', ssh_key='')
            self.pve.vms[9003] = saved
        del self.pve.vms[9003]
        with self.assertRaises(engine.Refused):
            self.handle('create', os='Debian 13', ssh_key='')
        self.assertEqual(self.pve.calls, [])
        self.assertEqual(self.e.db.execute('SELECT count(*) FROM allocation').fetchone()[0], 0)
        self.assertEqual(self.e.db.execute('SELECT count(*) FROM credential').fetchone()[0], 0)
        self.assertFalse((Path(self.temp.name) / 'state/credential.key').exists())

    def test_configured_default_template_is_used_and_request_cannot_override_inventory(self):
        self.add_os_templates()
        marker = 'proxmox-pilot:v1:template:test-default'
        self.config['templates']['Ubuntu 24.04'] = {'template_id': 9004, 'template_marker': marker}
        self.pve.vms[9004] = {**self.pve.vms[9000], 'description': marker}
        first = self.handle('create', os='Ubuntu 24.04', template_id=9000, template_marker=self.config['template_marker'])
        self.assertEqual([call[1] for call in self.pve.calls if call[0] == 'clone'], [9004])
        self.assertEqual(self.handle('create'), first)

    def test_malformed_template_catalog_fails_closed_without_using_default(self):
        for configured in (None, {}, {'template_id': True, 'template_marker': 'owned'},
                           {'template_id': 9000, 'template_marker': ''}, {'template_id': '9000', 'template_marker': 'owned'}):
            self.config['templates'] = {'Ubuntu 24.04': configured}
            with self.subTest(configured=configured), self.assertRaises(engine.Refused):
                self.handle('create', ssh_key='')
        self.config['templates'] = []
        with self.assertRaises(engine.Refused):
            self.handle('create', ssh_key='')
        self.assertEqual(self.pve.calls, [])
        self.assertEqual(self.e.db.execute('SELECT count(*) FROM allocation').fetchone()[0], 0)
        self.assertEqual(self.e.db.execute('SELECT count(*) FROM credential').fetchone()[0], 0)

    def test_password_checks_ssh_readiness_in_the_same_request(self):
        self.handle('create', ssh_key='')
        self.pve.is_ready = False
        with self.assertRaises(engine.Refused):
            self.handle('password')
        self.pve.is_ready = True
        self.assertEqual(self.handle('password')['user'], 'vpsadmin')

    def test_selected_ssd_is_resized_and_retries_keep_the_same_disk(self):
        first = self.handle('create', disk_gb=25)
        self.assertIn(('resize', first['vmid'], 25), self.pve.calls)
        calls = list(self.pve.calls)
        self.assertEqual(self.handle('create', disk_gb=25), first)
        self.assertEqual(self.pve.calls, calls)
        with self.assertRaises(engine.Refused):
            self.handle('create', disk_gb=30)
        with self.assertRaises(engine.Refused):
            self.handle('create')

    def test_invalid_ssd_is_rejected_without_allocating_a_vm(self):
        for size in [0, 19, 21, 45, True, '25']:
            with self.subTest(size=size), self.assertRaises(engine.Refused):
                self.handle('create', disk_gb=size)
        self.assertEqual(self.pve.calls, [])
        self.assertEqual(self.e.db.execute('SELECT count(*) FROM allocation').fetchone()[0], 0)

    def test_paid_activation_is_idempotent(self):
        first = self.handle('create')
        calls = list(self.pve.calls)
        self.assertEqual(self.handle('create'), first)
        self.assertEqual(self.pve.calls, calls)
        self.assertEqual(first['ssh_port'], 22220)
        cloud = json.loads((Path(self.temp.name) / 'snippets/safehost-billing-1100.yaml').read_text().split('\n', 1)[1])
        self.assertFalse(cloud['ssh_pwauth'])
        self.assertEqual(cloud['users'][0]['ssh_authorized_keys'], [KEY])

    def test_interrupted_clone_resumes_same_vmid(self):
        self.pve.crash_after_clone = True
        with self.assertRaises(OSError):
            self.handle('create')
        self.assertEqual(self.handle('create')['vmid'], 1100)
        self.assertEqual(sum(c[0] == 'clone' for c in self.pve.calls), 1)

    def test_lost_start_response_resumes_without_reboot(self):
        self.pve.crash_after_start = True
        with self.assertRaises(OSError):
            self.handle('create')
        self.assertEqual(self.handle('create')['phase'], 'ready')
        self.assertEqual(sum(c[0] == 'start' for c in self.pve.calls), 1)

    def test_other_client_cannot_manage_order(self):
        self.handle('create')
        for action in ('status', 'suspend', 'unsuspend', 'cancel', 'create'):
            with self.subTest(action=action), self.assertRaises(engine.Refused):
                self.handle(action, client_id=3)

    def test_cannot_change_plan_or_ssh_key_on_retry(self):
        self.handle('create')
        with self.assertRaises(engine.Refused):
            self.handle('create', plan='medium')

    def test_cancel_is_terminal_and_preserves_disk(self):
        self.handle('create')
        self.handle('cancel')
        for action in ('create', 'unsuspend', 'suspend'):
            with self.subTest(action=action), self.assertRaises(engine.Refused):
                self.handle(action)
        self.assertEqual(self.handle('cancel')['phase'], 'cancelled')
        self.assertIn('scsi0', self.pve.vms[1100])
        self.assertEqual(self.pve.vms[1100]['onboot'], '0')

    def test_suspend_and_resume(self):
        self.handle('create')
        self.assertEqual(self.handle('suspend')['status'], 'stopped')
        self.assertEqual(self.pve.vms[1100]['onboot'], '0')
        self.assertEqual(self.handle('unsuspend')['status'], 'running')
        self.assertEqual(self.pve.vms[1100]['onboot'], '1')

    def test_foreign_vmid_is_skipped(self):
        self.pve.vms[1100] = {'description': 'foreign'}
        self.pve.states[1100] = 'stopped'
        self.assertEqual(self.handle('create')['vmid'], 1101)
        self.assertEqual(self.pve.vms[1100], {'description': 'foreign'})

    def test_foreign_qemu_or_lxc_ip_is_skipped_at_purchase(self):
        self.pve.vms[777] = {'ipconfig0': 'ip=10.10.10.20/24,gw=10.10.10.1'}
        self.pve.vms[778] = {'_type': 'lxc', 'net0': 'name=eth0,bridge=vmbr1,ip=10.10.10.21/24'}
        self.assertEqual(self.handle('create')['vmid'], 1102)
        self.assertEqual(self.pve.vms[777]['ipconfig0'], 'ip=10.10.10.20/24,gw=10.10.10.1')

    def test_marker_or_volume_drift_blocks_operations(self):
        self.handle('create')
        for field, value in [('description', 'changed'), ('scsi0', 'local-lvm:vm-777-disk-0,size=20G')]:
            saved = self.pve.vms[1100][field]
            self.pve.vms[1100][field] = value
            with self.assertRaises(engine.Refused):
                self.handle('cancel')
            self.pve.vms[1100][field] = saved

    def test_pool_exhaustion_does_not_recycle_cancelled_vps(self):
        for i in range(self.config['slots']):
            self.handle('create', order_id=i+1)
            self.handle('cancel', order_id=i+1)
        with self.assertRaises(engine.Refused):
            self.handle('create', order_id=self.config['slots'] + 1)

    def test_deleted_ready_vm_is_not_recreated(self):
        self.handle('create')
        del self.pve.vms[1100]
        with self.assertRaises(engine.Refused):
            self.handle('create')

    def test_bad_key_or_action_has_no_side_effects(self):
        for data in ({'ssh_key': 'ssh-ed25519 eA=='}, {'action': 'delete'}, {'order_id': True}, {'plan': 'x'}):
            with self.subTest(data=data), self.assertRaises(engine.Refused):
                self.e.handle({**self.req, **data})
        self.assertFalse(self.pve.calls)

    def test_empty_key_creates_password_vps_without_leaking_credentials(self):
        info = self.handle('create', ssh_key='')
        secret = self.handle('password')['password']
        self.assertEqual(info['auth_mode'], 'password')
        self.assertGreaterEqual(len(secret), 28)
        self.assertNotIn('password', info)
        self.assertNotIn('password', self.handle('status'))
        snippet = Path(self.temp.name) / 'snippets/safehost-billing-1100.yaml'
        cloud = json.loads(snippet.read_text().split('\n', 1)[1])
        self.assertTrue(cloud['ssh_pwauth'])
        self.assertNotIn('ssh_authorized_keys', cloud['users'][0])
        self.assertTrue(cloud['users'][0]['lock_passwd'])
        self.assertNotIn('hashed_passwd', cloud['users'][0])
        self.assertTrue(cloud['chpasswd']['expire'])
        account = cloud['chpasswd']['users'][0]
        self.assertEqual((account['name'], account['type']), ('vpsadmin', 'hash'))
        self.assertTrue(account['password'].startswith('$6$'))
        self.assertEqual(cloud['runcmd'], [
            ['chage', '-d', '0', 'vpsadmin'],
            ['systemctl', 'enable', '--now', 'qemu-guest-agent'],
        ])
        self.assertNotIn(secret, snippet.read_text())
        stored = self.e.db.execute('SELECT * FROM credential').fetchone()
        self.assertNotIn(secret, str(dict(stored)))
        self.assertEqual(snippet.stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.e.state / 'credential.key').stat().st_mode & 0o777, 0o600)

    def test_password_survives_interrupted_clone_and_activation_retries(self):
        self.pve.crash_after_clone = True
        with self.assertRaises(OSError):
            self.handle('create', ssh_key='')
        encrypted = self.e.db.execute('SELECT encrypted FROM credential').fetchone()[0]
        self.handle('create', ssh_key='')
        password = self.handle('password')['password']
        calls = list(self.pve.calls)
        self.handle('create', ssh_key='')
        self.assertEqual(self.handle('password')['password'], password)
        self.assertEqual(self.e.db.execute('SELECT encrypted FROM credential').fetchone()[0], encrypted)
        self.assertEqual(calls, self.pve.calls)
        self.e.db.close()
        self.e = engine.Engine(self.config, self.e.state, self.e.snippets, self.pve)
        self.assertEqual(self.handle('password')['password'], password)

    def test_password_is_unique_and_unavailable_to_other_clients(self):
        self.handle('create', ssh_key='')
        first = self.handle('password')['password']
        self.handle('create', order_id=2, ssh_key='')
        self.assertNotEqual(self.handle('password', order_id=2)['password'], first)
        with self.assertRaises(engine.Refused):
            self.handle('password', client_id=3)
        self.handle('suspend')
        with self.assertRaises(engine.Refused):
            self.handle('password')
        self.handle('unsuspend')
        self.assertEqual(self.handle('password')['password'], first)
        self.handle('cancel')
        with self.assertRaises(engine.Refused):
            self.handle('password')

    def test_missing_encryption_key_does_not_replace_existing_credentials(self):
        self.handle('create', ssh_key='')
        key = self.e.state / 'credential.key'
        key.unlink()
        with self.assertRaises(engine.Refused):
            self.handle('password')
        with self.assertRaises(engine.Refused):
            self.handle('create', order_id=2, ssh_key='')
        self.assertFalse(key.exists())

    def test_key_only_vps_keeps_existing_access(self):
        info = self.handle('create')
        self.assertEqual(info['auth_mode'], 'key')
        self.assertFalse((self.e.state / 'credential.key').exists())
        with self.assertRaises(engine.Refused):
            self.handle('password')
        with self.assertRaises(engine.Refused):
            self.handle('create', ssh_key='')


if __name__ == '__main__':
    unittest.main()
