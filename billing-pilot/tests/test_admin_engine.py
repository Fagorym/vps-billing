import json
from pathlib import Path
import tempfile
import unittest
import uuid
from types import SimpleNamespace
from unittest.mock import patch

from test_engine import engine, FakePVE, KEY, ROOT


class AdminPVE(FakePVE):
    def __init__(self, config):
        super().__init__(config)
        self.total_ram = 64 * 1073741824
        self.lose_destroy = False

    def guests(self):
        return {vmid: {**guest, 'maxmem': int(self.vms[vmid].get('memory', 0)) * 1048576,
                       'maxcpu': int(self.vms[vmid].get('cores', 0)),
                       'status': self.states[vmid], 'cpu': 0.125, 'mem': 4096}
                for vmid, guest in super().guests().items()}

    def api(self, path, **params):
        if path.endswith('/storage/local-lvm/status'):
            return {'avail': 100 * 1073741824, 'total': 200 * 1073741824, 'used': 100 * 1073741824}
        return {'memory': {'total': self.total_ram, 'used': 1073741824}, 'cpu': 0.2, 'cpuinfo': {'cpus': 8}}

    def guest_fs(self, vmid):
        return None

    def command(self, verb, vmid, *args):
        if verb in ('shutdown', 'destroy'):
            self.calls.append((verb, vmid, *args))
            if verb == 'shutdown':
                self.states[vmid] = 'stopped'
            else:
                del self.vms[vmid]
                del self.states[vmid]
                if self.lose_destroy:
                    self.lose_destroy = False
                    raise OSError('Lost destroy response')
            return
        return super().command(verb, vmid, *args)


class AdminEngineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.config = json.loads((ROOT / 'config.json').read_text())
        self.config['template_marker'] = 'proxmox-pilot:v1:template:test'
        self.pve = AdminPVE(self.config)
        self.e = engine.Engine(self.config, Path(self.temp.name) / 'state', Path(self.temp.name) / 'snippets', self.pve)
        self.request = {'order_id': 1, 'client_id': 2, 'plan': 'mini', 'ssh_key': ''}
        self.e.handle({**self.request, 'action': 'create'})

    def tearDown(self):
        self.e.db.close()
        self.temp.cleanup()

    def admin(self, command, **extra):
        return self.e.handle({**self.request, 'action': 'admin', 'command': command,
                              'operation_id': str(uuid.uuid4()), 'reason': 'Administrator requested operation',
                              'actor': {'account': '11111111-1111-4111-8111-111111111111', 'email': 'admin@example.test'}, **extra})

    def owner(self, action):
        return self.e.handle({**self.request, 'action': action})

    def test_owner_stop_start_cannot_lift_administrative_block(self):
        self.owner('owner_stop')
        self.assertEqual(self.owner('status')['phase'], 'stopped')
        self.owner('owner_start')
        self.admin('block')
        for action in ('owner_start', 'owner_stop', 'password'):
            with self.subTest(action=action), self.assertRaises(engine.Refused):
                self.owner(action)
        self.assertEqual(self.owner('status')['phase'], 'blocked')
        self.admin('unblock')
        self.assertEqual(self.owner('readiness')['phase'], 'ready')

    def test_native_lifecycle_cannot_release_explicit_admin_block(self):
        self.admin('block')
        before = list(self.pve.calls)
        with self.assertRaises(engine.Refused):
            self.owner('unsuspend')
        self.assertEqual(self.owner('status')['phase'], 'blocked')
        self.assertEqual(self.pve.states[1100], 'stopped')
        self.assertEqual(self.pve.calls, before)
        # A repeated native suspension must not downgrade the administrative gate.
        self.owner('suspend')
        with self.assertRaises(engine.Refused):
            self.owner('unsuspend')
        self.admin('unblock')
        self.assertEqual(self.owner('readiness')['phase'], 'ready')
        # Existing native FOSS suspension/resume remains usable on its own state.
        self.owner('suspend')
        self.assertEqual(self.e.db.execute('SELECT phase FROM allocation WHERE order_id=1').fetchone()[0], 'suspended')
        self.assertEqual(self.owner('unsuspend')['status'], 'running')
        self.admin('archive')
        with self.assertRaises(engine.Refused):
            self.owner('unsuspend')
        self.assertEqual(self.owner('status')['phase'], 'archived')

    def test_archive_keeps_disk_and_password_and_restore_checks_capacity(self):
        before = self.e.db.execute('SELECT encrypted FROM credential').fetchone()[0]
        self.admin('archive')
        self.assertEqual(self.owner('status')['phase'], 'archived')
        self.assertIn('scsi0', self.pve.vms[1100])
        self.assertEqual(self.pve.vms[1100]['onboot'], '0')
        with self.assertRaises(engine.Refused):
            self.owner('owner_start')
        self.pve.total_ram = 2 * 1073741824
        with self.assertRaises(engine.Refused):
            self.admin('restore')
        self.assertEqual(self.owner('status')['phase'], 'archived')
        self.pve.total_ram = 4 * 1073741824
        self.admin('restore')
        self.assertEqual(self.owner('readiness')['phase'], 'ready')
        self.assertEqual(self.e.db.execute('SELECT encrypted FROM credential').fetchone()[0], before)
        self.assertEqual(sum(c[0] == 'clone' for c in self.pve.calls), 1)

    def test_purge_requires_matching_confirmation_and_foreign_vm_is_never_touched(self):
        before = list(self.pve.calls)
        with self.assertRaises(engine.Refused):
            self.admin('purge', confirm_vmid=1101)
        self.assertEqual(self.pve.calls, before)
        self.pve.vms[1100]['description'] = 'foreign'
        with self.assertRaises(engine.Refused):
            self.admin('purge', confirm_vmid=1100)
        self.assertEqual(self.pve.calls, before)

    def test_destroy_response_loss_recovers_same_allocation(self):
        operation = str(uuid.uuid4())
        self.pve.lose_destroy = True
        with self.assertRaises(OSError):
            self.admin('purge', operation_id=operation, confirm_vmid=1100)
        self.assertNotIn(1100, self.pve.vms)
        self.assertEqual(self.admin('purge', operation_id=operation, confirm_vmid=1100)['phase'], 'deleted')
        self.assertEqual(sum(c[0] == 'destroy' for c in self.pve.calls), 1)
        self.assertEqual(self.e.db.execute('SELECT COUNT(*) FROM credential').fetchone()[0], 0)
        self.assertFalse((Path(self.temp.name) / 'snippets/safehost-billing-1100.yaml').exists())

    def test_retired_order_cannot_touch_reused_slot_and_purge_replay_has_no_effect(self):
        operation = str(uuid.uuid4())
        self.admin('purge', operation_id=operation, confirm_vmid=1100)
        second = self.e.handle({**self.request, 'action': 'create', 'order_id': 3})
        self.assertEqual(second['vmid'], 1100)
        before = list(self.pve.calls)
        self.assertEqual(self.owner('status')['phase'], 'deleted')
        self.assertEqual(self.admin('purge', operation_id=operation, confirm_vmid=1100)['phase'], 'deleted')
        for action in ('owner_start', 'create'):
            with self.subTest(action=action), self.assertRaises(engine.Refused):
                self.owner(action)
        self.assertEqual(self.pve.calls, before)
        self.assertEqual(self.pve.states[1100], 'running')

    def test_admin_operation_id_cannot_be_rebound(self):
        operation = str(uuid.uuid4())
        self.admin('stop', operation_id=operation)
        before = list(self.pve.calls)
        self.admin('stop', operation_id=operation)
        self.assertEqual(self.pve.calls, before)
        with self.assertRaises(engine.Refused):
            self.admin('start', operation_id=operation)

    def test_monitoring_keeps_unmanaged_capacity_and_releases_archived_reservation(self):
        password = self.owner('password')['password']
        self.pve.vms[101] = {'memory': 4096, 'cores': 2, 'description': 'billing'}
        self.pve.states[101] = 'running'
        self.admin('archive')
        report = self.e.handle({'action': 'monitor'})
        self.assertEqual(report['hosts'][0]['memoryReservedBytes'], 4096 * 1048576)
        self.assertEqual(report['hosts'][0]['vcpuReserved'], 2)
        self.assertEqual(report['hosts'][0]['slotsFree'], self.config['slots'] - 1)
        self.assertIsNone(report['servers'][0]['metrics']['guestDiskUsedBytes'])
        self.assertNotIn('password', report['servers'][0])
        self.assertNotIn(password, json.dumps(report))

    def test_missing_and_foreign_drift_are_reported_without_recreating(self):
        del self.pve.vms[1100]
        self.assertEqual(self.owner('status')['ownership'], 'missing')
        with self.assertRaises(engine.Refused):
            self.owner('owner_start')
        self.pve.vms[1100] = {'description': 'foreign'}
        self.assertEqual(self.owner('status')['ownership'], 'foreign')
        self.assertEqual(sum(c[0] == 'clone' for c in self.pve.calls), 1)

    def test_purge_refuses_untracked_disks_network_and_hooks_before_effects(self):
        config = dict(self.pve.vms[1100])
        for key, value in [('unused0', 'local-lvm:vm-999-disk-0'),
                           ('tpmstate0', 'local-lvm:vm-1100-disk-3'),
                           ('hookscript', 'local:snippets/foreign.pl'),
                           ('ipconfig0', 'ip=10.10.10.99/24,gw=10.10.10.1')]:
            with self.subTest(key=key):
                self.pve.vms[1100] = {**config, key: value}
                before = list(self.pve.calls)
                with self.assertRaises(engine.Refused):
                    self.admin('purge', confirm_vmid=1100)
                self.assertEqual(self.pve.calls, before)

    def test_stop_gracefully_shuts_down_then_forces_only_after_timeout(self):
        command = self.pve.command
        def timeout_shutdown(verb, vmid, *args):
            if verb == 'shutdown':
                self.pve.calls.append((verb, vmid, *args))
                raise OSError('Guest shutdown timeout')
            return command(verb, vmid, *args)
        self.pve.command = timeout_shutdown
        self.owner('owner_stop')
        effects = [c[0] for c in self.pve.calls if c[0] in ('shutdown','stop')]
        self.assertEqual(effects, ['shutdown','stop'])
        self.assertIn(('shutdown',1100,'--timeout','30'), self.pve.calls)
        self.assertEqual(self.pve.states[1100], 'stopped')

    def test_monitoring_free_slots_include_foreign_declared_ips(self):
        self.pve.vms[101] = {'ipconfig0':'ip=10.10.10.21/24,gw=10.10.10.1'}
        self.pve.states[101] = 'running'
        self.assertEqual(self.e.handle({'action':'monitor'})['hosts'][0]['slotsFree'], self.config['slots']-2)

    def test_archived_vm_started_outside_adapter_keeps_ram_reservation(self):
        self.admin('archive')
        self.pve.states[1100] = 'running'
        report = self.e.handle({'action':'monitor'})
        self.assertEqual(report['hosts'][0]['memoryReservedBytes'], 1024 * 1048576)
        self.assertEqual(report['hosts'][0]['vcpuReserved'], 1)
        self.pve.total_ram = 3 * 1073741824
        before = sum(c[0] == 'clone' for c in self.pve.calls)
        with self.assertRaises(engine.Refused):
            self.e.handle({**self.request,'action':'create','order_id':3})
        self.assertEqual(sum(c[0] == 'clone' for c in self.pve.calls), before)

    def test_restore_checks_actual_configured_ram_after_external_change(self):
        self.admin('archive')
        self.pve.vms[1100]['memory'] = 4096
        self.pve.total_ram = 5 * 1073741824
        before = list(self.pve.calls)
        with self.assertRaises(engine.Refused):
            self.admin('restore')
        self.assertEqual(self.owner('status')['phase'], 'archived')
        self.assertEqual(self.pve.states[1100], 'stopped')
        self.assertEqual(self.pve.calls, before)
        self.pve.total_ram = 6 * 1073741824
        self.assertEqual(self.admin('restore')['phase'], 'ready')
        self.assertEqual(self.pve.vms[1100]['memory'], 4096)

    def test_failed_qm_start_keeps_restore_retryable_with_same_operation_id(self):
        self.admin('archive')
        operation = str(uuid.uuid4())
        command = self.pve.command
        def failed_start(verb, vmid, *args):
            if verb == 'start':
                with patch.object(engine.subprocess, 'run', return_value=SimpleNamespace(returncode=1,stdout='')):
                    return engine.run(['/usr/sbin/qm','start',str(vmid)])
            return command(verb, vmid, *args)
        self.pve.command = failed_start
        with self.assertRaises(OSError):
            self.admin('restore', operation_id=operation)
        self.assertEqual(self.owner('status')['phase'], 'restoring')
        receipt = self.e.db.execute('SELECT state FROM admin_operation WHERE id=?', (operation,)).fetchone()
        self.assertEqual(receipt['state'], 'pending')
        self.pve.command = command
        self.assertEqual(self.admin('restore', operation_id=operation)['phase'], 'ready')
        self.assertEqual(self.pve.states[1100], 'running')
        self.assertEqual(sum(c[0] == 'clone' for c in self.pve.calls), 1)
