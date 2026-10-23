import copy
import json
from pathlib import Path
import tempfile
import unittest
import uuid

from test_engine import engine, nat_configuration
from test_admin_engine import AdminPVE


OWNER = '9ac2de9e-e907-42f1-b28d-e65a2c1552a8'


class InfrastructureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.config = nat_configuration()
        self.pve = AdminPVE(self.config)
        self.e = engine.Engine(self.config, Path(self.temp.name) / 'state', Path(self.temp.name) / 'snippets', self.pve)
        self.ordinary = {'order_id': 11, 'client_id': 2, 'plan': 'mini', 'ssh_key': ''}
        self.service = {'order_id': 12, 'client_id': 16, 'plan': 'medium', 'ssh_key': ''}
        self.e.handle({**self.ordinary, 'action': 'create'})
        self.e.handle({**self.service, 'action': 'create'})
        self.pve.vms[101] = {'name': 'billing', 'description': 'Existing billing VM', 'cores': 2, 'memory': 4096,
                             'ipconfig0': 'ip=10.10.10.11/24,gw=10.10.10.1',
                             'scsi0': 'local-lvm:vm-101-disk-0,size=40G'}
        self.pve.states[101] = 'running'
        self.document = {'version': 1, 'servers': [self.entry(101, '10.10.10.11'), self.entry(1101, '10.10.10.21')]}
        self.save_registry()

    def tearDown(self):
        self.e.db.close()
        self.temp.cleanup()

    def entry(self, vmid, address):
        return {'vmid': vmid, 'node': 'pve1', 'account': OWNER, 'name': f'safehost service {vmid}',
                'os': 'Ubuntu 24.04', 'address': address, 'publicIpv4': False,
                'configSha256': engine.fingerprint(self.pve.vms[vmid])}

    def save_registry(self):
        path = self.e.state / 'infrastructure.json'
        path.write_text(json.dumps(self.document))
        path.chmod(0o600)

    def test_observations_use_actual_resources_and_leave_technical_identity_intact(self):
        allocation = dict(self.e.db.execute('SELECT * FROM allocation WHERE order_id=12').fetchone())
        config = copy.deepcopy(self.pve.vms)
        calls = list(self.pve.calls)
        report = self.e.handle({'action': 'monitor'})
        rows = {row['vmid']: row for row in report['infrastructure']}
        self.assertEqual(set(rows), {101, 1101})
        self.assertEqual((rows[101]['cores'], rows[101]['memoryMb'], rows[101]['diskGb']), (2, 4096, 40))
        self.assertEqual((rows[1101]['cores'], rows[1101]['memoryMb'], rows[1101]['diskGb']), (4, 4096, 80))
        self.assertEqual(rows[101]['account'], OWNER)
        self.assertTrue(rows[101]['observedAt'].endswith('+00:00'))
        self.assertEqual(set(rows[101]), {'vmid', 'node', 'account', 'name', 'os', 'address', 'publicIpv4',
                                         'status', 'phase', 'cores', 'memoryMb', 'diskGb', 'observedAt'})
        self.assertEqual(dict(self.e.db.execute('SELECT * FROM allocation WHERE order_id=12').fetchone()), allocation)
        self.assertEqual(self.pve.vms, config)
        self.assertEqual(self.pve.calls, calls)
        self.assertEqual(self.e.db.execute('SELECT COUNT(*) FROM allocation').fetchone()[0], 2)
        self.assertTrue(self.e.handle({**self.service, 'action': 'status'})['infrastructure'])

    def test_all_mutations_and_password_are_refused_before_effects(self):
        before = list(self.pve.calls)
        snapshot = list(self.e.db.iterdump())
        actions = ('create', 'password', 'suspend', 'unsuspend', 'cancel', 'owner_start', 'owner_stop', 'owner_restart', 'mutation_guard')
        for action in actions:
            with self.subTest(action=action), self.assertRaisesRegex(engine.Refused, 'только для чтения'):
                self.e.handle({**self.service, 'action': action})
        for command in ('start', 'stop', 'block', 'unblock', 'archive', 'restore', 'purge'):
            with self.subTest(command=command), self.assertRaisesRegex(engine.Refused, 'только для чтения'):
                self.e.handle({**self.service, 'action': 'admin', 'command': command,
                               'operation_id': str(uuid.uuid4()), 'confirm_vmid': 1101,
                               'reason': 'Read-only infrastructure', 'actor': {'account': OWNER, 'email': 'owner@example.test'}})
        self.assertEqual(self.pve.calls, before)
        self.assertEqual(list(self.e.db.iterdump()), snapshot)

    def test_direct_dangerous_methods_protect_in_pool_and_external_vmids(self):
        row = dict(self.e.db.execute('SELECT * FROM allocation WHERE order_id=12').fetchone())
        before = list(self.pve.calls)
        for vmid in (101, 1101):
            target = {**row, 'slot': vmid - self.config['vm_first']}
            calls = (lambda: self.e.create(target), lambda: self.e.stop_vm(target),
                     lambda: self.e.power(target, True), lambda: self.e.phase(target, 'ready'),
                     lambda: self.e.admin(target, {}), lambda: self.e.admin_effect(target, 'purge', {}),
                     lambda: self.e.isolate_public(target), lambda: self.e.restore_public(target),
                     lambda: self.e.initial_password(target),
                     lambda: self.e.owner_restart(target, {'operation_id': str(uuid.uuid4())}))
            for call in calls:
                with self.subTest(vmid=vmid, method=call), self.assertRaisesRegex(engine.Refused, 'только для чтения'):
                    call()
        self.assertEqual(self.pve.calls, before)

    def test_config_drift_never_unlocks_a_protected_vmid_or_fakes_health(self):
        original = copy.deepcopy(self.pve.vms[1101])
        for field, value in (('description', 'foreign'), ('template', 1), ('lock', 'backup'),
                             ('cores', 8), ('scsi0', 'local-lvm:vm-999-disk-0,size=80G')):
            with self.subTest(field=field):
                self.pve.vms[1101] = {**original, field: value}
                with self.assertRaises(engine.Refused):
                    self.e.handle({'action': 'monitor'})
                with self.assertRaises(engine.Refused):
                    self.e.handle({**self.service, 'action': 'status'})
                with self.assertRaisesRegex(engine.Refused, 'только для чтения'):
                    self.e.handle({**self.service, 'action': 'cancel'})
        self.pve.vms[1101] = original

    def test_missing_protected_vmid_is_not_reused_for_a_new_order(self):
        self.e.db.execute('DELETE FROM allocation WHERE order_id=12')
        self.e.db.commit()
        del self.pve.vms[1101]
        del self.pve.states[1101]
        result = self.e.handle({**self.ordinary, 'order_id': 20, 'action': 'create'})
        self.assertEqual(result['vmid'], 1102)

    def test_api_digest_does_not_change_identity_and_stopped_is_observed(self):
        self.pve.vms[101]['digest'] = 'api-digest'
        self.pve.states[101] = 'stopped'
        row = self.e.handle({'action': 'monitor'})['infrastructure'][0]
        self.assertEqual((row['status'], row['phase']), ('stopped', 'stopped'))

    def test_malformed_registry_and_insecure_permissions_fail_closed(self):
        original = copy.deepcopy(self.document)
        invalid = [None, {'version': True, 'servers': []}, {'version': 1, 'servers': {}},
                   {'version': 1, 'servers': [self.document['servers'][0]] * 2}]
        for field, value in (('account', ''), ('account', '00000000-0000-0000-0000-000000000000'),
                             ('configSha256', ''), ('node', 'other'), ('publicIpv4', 1), ('name', ''), ('address', 'bad')):
            document = copy.deepcopy(original)
            document['servers'][0][field] = value
            invalid.append(document)
        before = list(self.pve.calls)
        for document in invalid:
            with self.subTest(document=document):
                self.document = document
                self.save_registry()
                with self.assertRaises(engine.Refused):
                    self.e.handle({**self.ordinary, 'action': 'owner_stop'})
        self.document = original
        self.save_registry()
        (self.e.state / 'infrastructure.json').chmod(0o644)
        with self.assertRaises(engine.Refused):
            self.e.handle({**self.ordinary, 'action': 'owner_stop'})
        self.assertEqual(self.pve.calls, before)

    def test_ordinary_umami_vm_keeps_power_password_and_native_lifecycle(self):
        self.assertEqual(self.e.handle({**self.ordinary, 'action': 'mutation_guard'}), {'mutable': True})
        self.assertTrue(self.e.handle({**self.ordinary, 'action': 'password'})['password'])
        self.assertEqual(self.e.handle({**self.ordinary, 'action': 'owner_stop'})['status'], 'stopped')
        self.assertEqual(self.e.handle({**self.ordinary, 'action': 'owner_start'})['status'], 'running')
        self.assertEqual(self.e.handle({**self.ordinary, 'action': 'suspend'})['phase'], 'blocked')
        self.assertEqual(self.e.handle({**self.ordinary, 'action': 'unsuspend'})['status'], 'running')
        self.assertEqual(self.e.handle({**self.ordinary, 'action': 'cancel'})['phase'], 'cancelled')

    def test_broken_json_duplicate_fields_and_symlinks_do_not_disable_protection(self):
        path = self.e.state / 'infrastructure.json'
        for content in ('{', '{"version":1,"version":1,"servers":[]}'):
            with self.subTest(content=content):
                path.write_text(content)
                with self.assertRaises(engine.Refused):
                    self.e.handle({**self.service, 'action': 'owner_stop'})
        self.save_registry()
        target = self.e.state / 'other.json'
        path.rename(target)
        path.symlink_to(target)
        with self.assertRaises(engine.Refused):
            self.e.handle({**self.service, 'action': 'owner_stop'})


if __name__ == '__main__':
    unittest.main()
