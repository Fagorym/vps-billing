import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from jinja2 import Template

from test_engine import engine, FakePVE, KEY, ROOT, nat_configuration

spec = importlib.util.spec_from_file_location('expand_pool', ROOT / 'backend/expand_pool.py')
pool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pool)


class FakeSystem(pool.System):
    def __init__(self, config, pve):
        self.pve = pve
        self.listeners = set()
        self.extra_nat = ''
        self.rules = set(pool.rules(config, 0, config['slots']))
        self.rules.update(pool.parents())
        self.added = []

    def guests(self, config):
        return self.pve.guests()

    def guest_config(self, config, vmid, kind):
        return self.pve.config(vmid, kind)

    def listener_ports(self):
        return self.listeners

    def nat_dump(self):
        return self.extra_nat

    def has_rule(self, rule):
        return rule in self.rules

    def add_rule(self, rule):
        self.rules.add(rule)
        self.added.append(rule)

    def snapshot(self):
        return 'before rules'

    def shell_check(self, path):
        pass


class ExpansionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.c = nat_configuration()
        self.c.update(slots=5, template_marker='proxmox-pilot:v1:template:test')
        self.desired = {**self.c, 'slots': 10}
        self.config = self.root / 'config.json'
        self.config.write_text(json.dumps(self.c))
        self.state = self.root / 'state'
        self.nat = self.root / 'nat.sh'
        self.nat.write_text('#!/bin/sh\n# managed-by: safehost-billing:v1\n# five slots\n')
        self.staged = self.root / 'staged.sh'
        entries = [{'ip': '10.10.10.11', 'port': 2223}]
        entries += [{'ip': '10.10.10.' + str(20 + i), 'port': 22220 + i} for i in range(10)]
        self.staged.write_text(Template((ROOT / 'ansible/nat.sh.j2').read_text()).render(
            engine=self.desired, billing_nat=entries))
        self.pve = FakePVE(self.c)
        self.e = engine.Engine(self.c, self.state, self.root / 'snippets', self.pve)
        self.system = FakeSystem(self.c, self.pve)

    def tearDown(self):
        self.e.db.close()
        self.temp.cleanup()

    def expand(self, desired=None):
        return pool.expand(self.config, self.state, desired or self.desired, self.nat, self.staged, self.system)

    def create(self, order, **kwargs):
        return self.e.handle({'action': 'create', 'order_id': order, 'client_id': 2,
                              'plan': 'mini', 'ssh_key': KEY, **kwargs})

    def rows(self):
        return [tuple(r) for r in self.e.db.execute('SELECT * FROM allocation ORDER BY order_id')]

    def test_five_to_ten_preserves_orders_credentials_and_vm_state(self):
        for order in range(1, 6):
            self.create(order, ssh_key='' if order == 1 else KEY)
        password = self.e.handle({'action': 'password', 'order_id': 1, 'client_id': 2})
        self.e.handle({'action': 'suspend', 'order_id': 2, 'client_id': 2})
        self.e.handle({'action': 'cancel', 'order_id': 3, 'client_id': 2})
        before = self.rows()
        credentials = [tuple(r) for r in self.e.db.execute('SELECT * FROM credential')]
        vm_state = copy.deepcopy((self.pve.vms, self.pve.states, self.pve.calls))
        self.assertTrue(self.expand()['changed'])
        self.assertEqual(self.rows(), before)
        self.assertEqual([tuple(r) for r in self.e.db.execute('SELECT * FROM credential')], credentials)
        self.assertEqual((self.pve.vms, self.pve.states, self.pve.calls), vm_state)
        self.e.db.close()
        self.e = engine.Engine(self.desired, self.state, self.root / 'snippets', self.pve)
        self.assertEqual(self.e.handle({'action': 'password', 'order_id': 1, 'client_id': 2}), password)
        for order in range(6, 11):
            info = self.create(order)
            self.assertEqual((info['vmid'], info['ssh_port']), (1099 + order, 22219 + order))
        with self.assertRaises(engine.Refused):
            self.create(11)
        self.assertEqual(len(self.system.added), 25)
        backups = list((self.state / 'backups').iterdir())
        self.assertEqual(len(backups), 1)
        self.assertTrue((backups[0] / 'allocations.sqlite').exists())
        self.assertEqual((backups[0] / 'credential.key').read_bytes(), (self.state / 'credential.key').read_bytes())

    def test_repeat_has_no_extra_rules_or_backups(self):
        self.expand()
        rules = set(self.system.rules)
        self.assertFalse(self.expand()['changed'])
        self.assertEqual(self.system.rules, rules)
        self.assertEqual(len(self.system.added), 25)
        self.assertEqual(len(list((self.state / 'backups').iterdir())), 1)

    def test_conflicts_and_config_changes_refuse_before_mutation(self):
        for conflict in ('vmid', 'qemu_ip', 'lxc_ip', 'listener', 'nat_range', 'nat_multiport', 'wrong_owned_nat',
                         'shrink', 'gateway', 'seal'):
            with self.subTest(conflict=conflict):
                desired = dict(self.desired)
                self.pve.vms.pop(1105, None)
                self.pve.vms.pop(777, None)
                self.system.listeners.clear()
                self.system.extra_nat = ''
                (self.state / 'config.sha256').write_text(engine.fingerprint(self.c) + '\n')
                if conflict == 'vmid':
                    self.pve.vms[1105] = {'description': 'foreign'}
                elif conflict in ('qemu_ip', 'lxc_ip'):
                    self.pve.vms[777] = ({'ipconfig0': 'ip=10.10.10.25/24'} if conflict == 'qemu_ip' else
                                         {'_type': 'lxc', 'net0': 'ip=10.10.10.25/24,name=eth0'})
                elif conflict == 'listener':
                    self.system.listeners.add(22225)
                elif conflict == 'nat_range':
                    self.system.extra_nat = '-A FOREIGN -p tcp --dport 22200:22300 -j DNAT --to-destination 1.2.3.4'
                elif conflict == 'nat_multiport':
                    self.system.extra_nat = '-A FOREIGN -p tcp -m multiport --dports 22,22229 -j REDIRECT'
                elif conflict == 'wrong_owned_nat':
                    self.system.rules.add(pool.rules(self.desired, 5, 6)[0])
                    self.system.extra_nat = '-A BILL_DNAT -p tcp --dport 22225 -j DNAT --to-destination 10.10.10.99:22'
                elif conflict == 'shrink':
                    desired['slots'] = 4
                elif conflict == 'gateway':
                    desired['gateway'] = '10.10.10.2'
                else:
                    (self.state / 'config.sha256').write_text('wrong\n')
                with self.assertRaises(pool.Refused):
                    self.expand(desired)
                self.assertEqual(json.loads(self.config.read_text()), self.c)
                self.assertFalse(self.system.added)
                self.assertFalse((self.state / 'backups').exists())

    def test_missing_old_nat_rule_refuses_without_flushing_chains(self):
        self.system.rules.remove(pool.rules(self.c, 0, 1)[0])
        with self.assertRaises(pool.Refused):
            self.expand()
        self.assertFalse(self.system.added)

    def test_incomplete_persistent_nat_is_refused_before_mutation(self):
        self.staged.write_text('#!/bin/sh\n# managed-by: safehost-billing:v1\n')
        with self.assertRaises(pool.Refused):
            self.expand()
        self.assertFalse(self.system.added)
        self.assertEqual(json.loads(self.config.read_text()), self.c)

    def test_interruption_between_config_and_seal_recovers_on_retry(self):
        original = pool.atomic_write
        def interrupted(path, data, mode=0o600):
            if path == self.state / 'config.sha256':
                raise OSError('interrupted before seal')
            return original(path, data, mode)
        with patch.object(pool, 'atomic_write', side_effect=interrupted), self.assertRaises(OSError):
            self.expand()
        with self.assertRaises(engine.Refused):
            engine.Engine(self.desired, self.state, self.root / 'snippets', self.pve)
        self.assertTrue(self.expand()['changed'])
        self.assertEqual(json.loads(self.config.read_text()), self.desired)
        self.assertEqual((self.state / 'config.sha256').read_text().strip(), engine.fingerprint(self.desired))
        self.assertEqual(len(self.system.added), 25)
        self.assertEqual(len(list((self.state / 'backups').iterdir())), 1)

    def test_unrelated_config_tampering_is_not_recovered(self):
        original = pool.atomic_write
        def interrupted(path, data, mode=0o600):
            if path == self.state / 'config.sha256':
                raise OSError('interrupted before seal')
            return original(path, data, mode)
        with patch.object(pool, 'atomic_write', side_effect=interrupted), self.assertRaises(OSError):
            self.expand()
        tampered = {**self.desired, 'vm_first': 1200}
        self.config.write_text(json.dumps(tampered))
        with self.assertRaises(pool.Refused):
            self.expand()
        self.assertEqual(json.loads(self.config.read_text()), tampered)


if __name__ == '__main__':
    unittest.main()
