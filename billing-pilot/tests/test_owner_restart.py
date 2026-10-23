import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_engine import engine, FakePVE, KEY, nat_configuration

OPERATION = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
NEXT_BOOT = '22222222-2222-4222-8222-222222222222'


class OwnerRestartTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.config = nat_configuration()
        self.pve = FakePVE(self.config)
        self.state = Path(self.temporary.name)/'state'
        self.snippets = Path(self.temporary.name)/'snippets'
        self.client = engine.Engine(self.config, self.state, self.snippets, self.pve)
        self.create = {'action': 'create', 'order_id': 1, 'client_id': 2, 'plan': 'mini', 'ssh_key': KEY}
        self.vm = self.client.handle(self.create)
        self.restart = {'action': 'owner_restart', 'order_id': 1, 'client_id': 2, 'operation_id': OPERATION}
        self.pve.calls.clear()

    def tearDown(self):
        self.client.db.close()
        self.temporary.cleanup()

    def reboots(self):
        return [call for call in self.pve.calls if call[0] == 'guest-reboot']

    def test_restart_waits_for_new_boot_and_ssh_before_ready_then_replay_is_safe(self):
        before = self.pve.config(self.vm['vmid'])
        self.assertEqual(self.client.handle(self.restart)['phase'], 'preparing')
        self.assertEqual(self.client.handle(self.restart)['phase'], 'preparing')
        self.assertFalse(self.client.handle({**self.restart, 'action': 'readiness'})['ready'])
        self.pve.boot_id_value = NEXT_BOOT
        self.pve.is_ready = False
        self.assertEqual(self.client.handle(self.restart)['phase'], 'preparing')
        self.pve.is_ready = True
        self.assertEqual(self.client.handle(self.restart)['phase'], 'ready')
        self.assertTrue(self.client.handle(self.restart)['ready'])
        self.assertEqual(len(self.reboots()), 1)
        self.assertEqual(self.pve.config(self.vm['vmid']), before)

    def test_lost_dispatch_reply_never_reboots_twice(self):
        def lost_reply(*args):
            self.pve.calls.append(('guest-reboot', *args))
            raise OSError('Lost QGA response')
        with patch.object(self.pve, 'graceful_reboot', side_effect=lost_reply):
            self.assertEqual(self.client.handle(self.restart)['phase'], 'preparing')
        self.client.db.close()
        self.client = engine.Engine(self.config, self.state, self.snippets, self.pve)
        self.assertEqual(self.client.handle(self.restart)['phase'], 'preparing')
        self.pve.boot_id_value = NEXT_BOOT
        self.assertEqual(self.client.handle(self.restart)['phase'], 'ready')
        self.assertEqual(len(self.reboots()), 1)

    def test_process_crash_after_fence_never_redispatches_even_before_effect(self):
        with patch.object(self.pve, 'graceful_reboot', side_effect=SystemExit('process crash')) as dispatch:
            with self.assertRaises(SystemExit):
                self.client.handle(self.restart)
            dispatch.assert_called_once()
        self.client.db.close()
        self.client = engine.Engine(self.config, self.state, self.snippets, self.pve)
        with patch.object(self.pve, 'graceful_reboot') as dispatch:
            self.assertEqual(self.client.handle(self.restart)['phase'], 'preparing')
            dispatch.assert_not_called()

    def test_pending_restart_rejects_another_operation_uuid(self):
        self.client.handle(self.restart)
        with self.assertRaises(engine.Refused):
            self.client.handle({**self.restart, 'operation_id': NEXT_BOOT})
        self.assertEqual(len(self.reboots()), 1)

    def test_known_pending_restart_stays_preparing_while_guest_is_stopped(self):
        self.client.handle(self.restart)
        self.pve.states[self.vm['vmid']] = 'stopped'
        self.assertEqual(self.client.handle({**self.restart, 'action': 'readiness'})['phase'], 'preparing')
        pending = self.client.handle(self.restart)
        self.assertEqual((pending['phase'], pending['status'], pending['ready']), ('preparing', 'stopped', False))
        with self.assertRaises(engine.Refused):
            self.client.handle({**self.restart, 'operation_id': NEXT_BOOT})
        self.assertEqual(len(self.reboots()), 1)
        self.pve.states[self.vm['vmid']] = 'running'
        self.pve.boot_id_value = NEXT_BOOT
        self.assertTrue(self.client.handle(self.restart)['ready'])
        self.assertEqual(len(self.reboots()), 1)

    def test_old_uuid_replay_after_a_newer_restart_never_dispatches_again(self):
        self.client.handle(self.restart)
        self.pve.boot_id_value = NEXT_BOOT
        self.client.handle(self.restart)
        newer = {**self.restart, 'operation_id': NEXT_BOOT}
        self.client.handle(newer)
        self.pve.boot_id_value = '33333333-3333-4333-8333-333333333333'
        self.client.handle(newer)
        self.client.db.close()
        self.client = engine.Engine(self.config, self.state, self.snippets, self.pve)
        self.assertEqual(self.client.handle(self.restart)['phase'], 'ready')
        self.assertEqual(len(self.reboots()), 2)

    def test_changed_boot_is_not_accepted_without_a_valid_identity(self):
        self.client.handle(self.restart)
        self.pve.boot_id_value = 'invalid'
        self.assertEqual(self.client.handle(self.restart)['phase'], 'preparing')
        self.assertEqual(len(self.reboots()), 1)

    def test_key_comments_canonicalize_without_changing_owner_fingerprint(self):
        same = self.client.handle({**self.create, 'ssh_key': '  '+KEY+'\tworkstation comment  '})
        self.assertEqual(same, self.vm)
        self.assertTrue(self.client.handle({**self.create, 'action': 'readiness'})['ready'])
        with self.assertRaises(engine.Refused):
            self.client.handle({**self.create, 'action': 'password'})

    def test_restart_uuid_is_bound_to_owned_order(self):
        self.client.handle(self.restart)
        second = self.client.handle({**self.create, 'order_id': 3})
        for changed in ({'client_id': 7}, {'order_id': 3}, {'operation_id': None}, {'operation_id': 'wrong'}):
            with self.subTest(changed=changed), self.assertRaises(engine.Refused):
                self.client.handle({**self.restart, **changed})
        self.assertEqual(len(self.reboots()), 1)
        self.assertEqual(self.pve.status(second['vmid']), 'running')

    def test_restart_refuses_offline_blocked_terminal_or_foreign_vps(self):
        for phase in ('stopped', 'blocked', 'suspended', 'archived', 'deleted', 'cancelled', 'reserved'):
            with self.subTest(phase=phase):
                self.client.db.execute('UPDATE allocation SET phase=? WHERE order_id=1', (phase,))
                self.client.db.commit()
                with self.assertRaises(engine.Refused):
                    self.client.handle(self.restart)
        self.client.db.execute("UPDATE allocation SET phase='ready' WHERE order_id=1")
        self.client.db.commit()
        self.pve.states[self.vm['vmid']] = 'stopped'
        with self.assertRaises(engine.Refused):
            self.client.handle(self.restart)
        self.pve.states[self.vm['vmid']] = 'running'
        self.pve.vms[self.vm['vmid']]['description'] = 'foreign'
        with self.assertRaises(engine.Refused):
            self.client.handle(self.restart)
        self.assertEqual(self.reboots(), [])

    def test_restart_does_not_bypass_admin_operation_or_unready_ssh(self):
        self.client.db.execute('INSERT INTO admin_operation VALUES(?,?,?,?,?)', (NEXT_BOOT, 'test', 1, 'pending', None))
        self.client.db.commit()
        with self.assertRaises(engine.Refused):
            self.client.handle(self.restart)
        self.client.db.execute('DELETE FROM admin_operation')
        self.client.db.commit()
        self.pve.is_ready = False
        with self.assertRaises(engine.Refused):
            self.client.handle(self.restart)
        self.assertEqual(self.reboots(), [])

    def test_invalid_boot_identity_refuses_before_dispatch(self):
        self.pve.boot_id_value = 'invalid'
        with self.assertRaises(engine.Refused):
            self.client.handle(self.restart)
        self.assertEqual(self.reboots(), [])

    def test_admin_block_can_interrupt_pending_restart_and_replay_cannot_unblock(self):
        self.client.handle(self.restart)
        self.client.db.execute("UPDATE allocation SET phase='blocked' WHERE order_id=1")
        self.client.db.commit()
        self.pve.boot_id_value = NEXT_BOOT
        with self.assertRaises(engine.Refused):
            self.client.handle(self.restart)
        self.assertEqual(self.client.handle({**self.restart, 'action': 'status'})['phase'], 'blocked')
        self.assertEqual(len(self.reboots()), 1)

    def assert_authoritative_stop_supersedes_restart(self, stop, restore):
        self.client.handle(self.restart)
        self.client.handle(stop)
        journal = self.client.db.execute('SELECT state FROM owner_restart WHERE id=?', (OPERATION,)).fetchone()
        self.assertEqual(journal['state'], 'interrupted')
        self.client.handle(restore)
        self.assertTrue(self.client.handle(self.restart)['ready'])
        self.assertEqual(len(self.reboots()), 1)
        self.client.handle({**self.restart, 'operation_id': NEXT_BOOT})
        self.assertEqual(len(self.reboots()), 2)

    def test_owner_stop_supersedes_restart_without_reusing_old_uuid(self):
        self.assert_authoritative_stop_supersedes_restart(
            {**self.restart, 'action': 'owner_stop'}, {**self.restart, 'action': 'owner_start'})

    def test_billing_suspend_supersedes_restart_without_reusing_old_uuid(self):
        self.assert_authoritative_stop_supersedes_restart(
            {**self.restart, 'action': 'suspend'}, {**self.restart, 'action': 'unsuspend'})

    def test_admin_block_then_unblock_allows_new_uuid_and_retains_old_fence(self):
        admin = {**self.restart, 'action': 'admin', 'reason': 'Reviewed administrative stop',
                 'actor': {'account': OPERATION, 'email': 'operator@example.test'}}
        self.assert_authoritative_stop_supersedes_restart(
            {**admin, 'command': 'block', 'operation_id': NEXT_BOOT},
            {**admin, 'command': 'unblock', 'operation_id': '33333333-3333-4333-8333-333333333333'})

    def test_native_guest_boot_identity_and_reboot_use_only_graceful_os_command(self):
        for os_name in ('Ubuntu 24.04', 'Debian 12', 'AlmaLinux 9', 'AlmaLinux 10'):
            with self.subTest(os=os_name), patch.object(engine.subprocess, 'run') as run:
                pve = engine.Proxmox(self.config)
                run.return_value = SimpleNamespace(returncode=0, stdout=json.dumps({'exitcode': 0, 'out-data': NEXT_BOOT+'\n'}))
                self.assertEqual(pve.boot_id(9108, os_name), NEXT_BOOT)
                prefix = ['/usr/local/libexec/safehost-qga-exec'] if os_name.startswith('AlmaLinux') else []
                self.assertEqual(run.call_args.args[0][7:9+len(prefix)], [*prefix, '/usr/bin/python3', '-c'])
                run.return_value = SimpleNamespace(returncode=0, stdout=json.dumps({'exitcode': 0}))
                pve.graceful_reboot(9108, os_name)
                self.assertEqual(run.call_args.args[0][7:], [*prefix, '/usr/bin/systemctl', '--no-block', 'reboot'])


if __name__ == '__main__':
    unittest.main()
