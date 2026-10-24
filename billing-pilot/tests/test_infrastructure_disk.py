import copy
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import json
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, call, patch

from test_engine import engine
import test_engine as engine_tests
import test_infrastructure as infrastructure

OWNER = infrastructure.OWNER


@dataclass(frozen=True)
class DriftCase:
    target: str
    change: dict[str, object] | None
    timeout: bool = False


@dataclass(frozen=True)
class FilesystemCommandCase:
    output: object
    expected: tuple[int, int] | None = None
    returncode: int = 0
    timeout: bool = False


class InfrastructureDiskTests(unittest.TestCase):
    tearDown = infrastructure.InfrastructureTests.tearDown
    entry = infrastructure.InfrastructureTests.entry
    save_registry = infrastructure.InfrastructureTests.save_registry

    def setUp(self):
        infrastructure.InfrastructureTests.setUp(self)
        self.readers = []
        self.original_reader = self.pve.metrics_reader
        self.reader_patch = patch.object(self.pve, 'metrics_reader', side_effect=self.reader_scope)
        self.reader_calls = self.reader_patch.start()
        self.addCleanup(self.reader_patch.stop)

    @contextmanager
    def reader_scope(self, vmid, timeframe):
        with self.original_reader(vmid, timeframe) as reader:
            tracked = SimpleNamespace(identity=Mock(wraps=reader.identity),
                                      history=Mock(side_effect=AssertionError('RRD history is forbidden')))
            self.readers.append(tracked)
            yield tracked

    def disk(self, **extra):
        return self.e.handle({'action': 'infrastructure_disk', 'account': OWNER, 'vmid': 101,
                              'node': 'pve1', **extra})

    def assert_unavailable(self, result):
        self.assertEqual((result['usedBytes'], result['totalBytes'], result['observedAt']), (None, None, None))
        self.assertEqual(set(result), {'vmid', 'node', 'account', 'mountpoint', 'usedBytes', 'totalBytes', 'observedAt'})
        self.assertEqual((result['vmid'], result['node'], result['account'], result['mountpoint']), (101, 'pve1', OWNER, '/'))

    def test_service_disks_are_readonly_with_one_identity_reader_and_no_history_or_sidecar(self):
        registry = self.e.state / 'infrastructure.json'
        sidecar = self.e.state / 'infrastructure-metrics.json'
        sidecar.write_bytes(b'{malformed history metadata is irrelevant to disk')
        sidecar.chmod(0o600)
        before = (registry.read_bytes(), sidecar.read_bytes(), list(self.e.db.iterdump()),
                  copy.deepcopy(self.pve.vms), list(self.pve.calls))
        with patch.object(self.pve, 'guest_fs', return_value=(0, 2**53 - 1)) as fs, \
             patch.object(self.pve, 'api', side_effect=AssertionError('RRD/API reads are forbidden')), \
             patch.object(self.e, 'monitor', side_effect=AssertionError('Full monitor is forbidden')), \
             patch.object(self.e, 'infrastructure_metrics_registry', side_effect=AssertionError('Sidecar is unrelated')), \
             patch.object(self.pve, 'current_configs', side_effect=AssertionError('Full config scan is forbidden')):
            for vmid in (101, 1101):
                with self.subTest(vmid=vmid):
                    result = self.disk(vmid=vmid)
                    self.assertEqual((result['vmid'], result['node'], result['account'], result['mountpoint']), (vmid, 'pve1', OWNER, '/'))
                    self.assertEqual((result['usedBytes'], result['totalBytes']), (0, 2**53 - 1))
                    self.assertEqual(datetime.fromisoformat(result['observedAt']).utcoffset().total_seconds(), 0)
            self.assertEqual(fs.call_count, 2)
        self.assertEqual(self.reader_calls.call_args_list, [call(101, 'day'), call(1101, 'day')])
        self.assertEqual([reader.identity.call_count for reader in self.readers], [2, 2])
        for reader in self.readers:reader.history.assert_not_called()
        after = (registry.read_bytes(), sidecar.read_bytes(), list(self.e.db.iterdump()), self.pve.vms, self.pve.calls)
        self.assertEqual(after, before)
        self.assertEqual(self.e.db.execute('SELECT client_id FROM allocation WHERE order_id=12').fetchone()[0], 16)
        self.assertEqual(self.e.db.execute('SELECT COUNT(*) FROM allocation').fetchone()[0], 2)

    def test_wrong_owner_node_vmid_and_malformed_requests_never_read_guest(self):
        cases = ({'account': '11111111-1111-4111-8111-111111111111'}, {'account': None},
                 {'node': 'other'}, {'node': None}, {'vmid': 1100}, {'vmid': True}, {'vmid': '101'})
        with patch.object(self.pve, 'guest_fs') as fs:
            for request in cases:
                with self.subTest(request=request), self.assertRaises(engine.Refused):self.disk(**request)
            fs.assert_not_called()
        self.reader_calls.assert_not_called()

    def test_guest_identity_and_fingerprint_are_checked_before_fs_read(self):
        original = copy.deepcopy(self.pve.vms[101])
        for change in ({'description': 'foreign'}, {'template': 1}, {'lock': 'backup'}, {'_type': 'lxc'}):
            with self.subTest(change=change):
                self.pve.vms[101] = {**original, **change}
                with patch.object(self.pve, 'guest_fs') as fs, self.assertRaises(engine.Refused):self.disk()
                fs.assert_not_called()
        self.pve.vms[101] = original

    def test_root_registration_and_guest_drift_after_fs_read_discard_even_missing_data(self):
        registry, config = copy.deepcopy(self.document), copy.deepcopy(self.pve.vms[101])
        cases = [DriftCase('registry', change) for change in (
            {'account': '11111111-1111-4111-8111-111111111111'}, {'node': 'other'}, {'configSha256': '0' * 64})]
        cases += [DriftCase('guest', {'description': 'foreign'}), DriftCase('missing', None),
                  DriftCase('guest', {'description': 'foreign'}, timeout=True)]
        for case in cases:
            with self.subTest(case=case):
                self.document, self.pve.vms[101] = copy.deepcopy(registry), copy.deepcopy(config)
                self.save_registry()
                def changed(vmid):
                    if case.target == 'registry':
                        self.document['servers'][0].update(case.change)
                        self.save_registry()
                    elif case.target == 'missing':
                        (self.e.state / 'infrastructure.json').unlink()
                    else:self.pve.vms[101].update(case.change)
                    if case.timeout:raise subprocess.TimeoutExpired('qm', 3)
                    return (1024, 4096)
                with patch.object(self.pve, 'guest_fs', side_effect=changed), self.assertRaises(engine.Refused):self.disk()
                self.assertEqual(self.readers[-1].identity.call_count, 2)

    def test_missing_and_invalid_fs_values_return_three_null_fields_without_fake_zero(self):
        invalid = (None, (), (1,), (1, 2, 3), {'used': 1, 'total': 2}, (True, 10), (1, True),
                   (-1, 10), (2, 1), (0, 0), (0, -1), (0, 2**53), (1.0, 10), ('1', 10))
        for value in invalid:
            with self.subTest(value=value), patch.object(self.pve, 'guest_fs', return_value=value):
                self.assert_unavailable(self.disk())
                self.assertEqual(self.readers[-1].identity.call_count, 2)

    def test_existing_qga_command_is_bounded_and_failures_are_unavailable(self):
        cases = [FilesystemCommandCase([{'mountpoint': '/', 'used-bytes': 1024, 'total-bytes': 4096}], (1024, 4096)),
                 FilesystemCommandCase([]), FilesystemCommandCase({'bad': 'shape'}),
                 FilesystemCommandCase([{'mountpoint': '/', 'used-bytes': True, 'total-bytes': 4096}]),
                 FilesystemCommandCase([], returncode=1), FilesystemCommandCase([], timeout=True)]
        for case in cases:
            with self.subTest(case=case):
                result = SimpleNamespace(returncode=case.returncode, stdout=json.dumps(case.output))
                effect = subprocess.TimeoutExpired('qm', 3) if case.timeout else None
                with patch.object(self.pve, 'guest_fs', side_effect=lambda vmid: engine.Proxmox.guest_fs(self.pve, vmid)), \
                     patch.object(engine.subprocess, 'run', return_value=result, side_effect=effect) as command:
                    observation = self.disk()
                command.assert_called_once_with(['/usr/sbin/qm', 'guest', 'cmd', '101', 'get-fsinfo'],
                                                capture_output=True, text=True, timeout=3)
                if case.expected is None:self.assert_unavailable(observation)
                else:self.assertEqual((observation['usedBytes'], observation['totalBytes']), case.expected)


class InfrastructureDiskTransportTests(unittest.TestCase):
    def test_disk_read_fails_fast_behind_mutation_lock(self):
        completed, outcome = engine_tests.CLILockingContracts.invoke_while_locked(self, fcntl.LOCK_EX, 'infrastructure_disk')
        self.assertTrue(completed)
        self.assertEqual(outcome, [engine.Refused])


if __name__ == '__main__':unittest.main()
