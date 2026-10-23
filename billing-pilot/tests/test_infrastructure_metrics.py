import copy
from contextlib import nullcontext
from datetime import datetime, timezone
from dataclasses import dataclass
import fcntl
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_engine import engine
import test_infrastructure as infrastructure
import test_engine as engine_tests
OWNER = infrastructure.OWNER


@dataclass(frozen=True)
class DriftCase:
    target: str
    change: dict[str, object] | None


class InfrastructureMetricsTests(unittest.TestCase):
    tearDown = infrastructure.InfrastructureTests.tearDown
    entry = infrastructure.InfrastructureTests.entry
    save_registry = infrastructure.InfrastructureTests.save_registry

    def setUp(self):
        infrastructure.InfrastructureTests.setUp(self)
        self.registered = int(datetime.now(timezone.utc).timestamp()) - 3600
        self.metrics_path = self.e.state / 'infrastructure-metrics.json'
        self.metrics_document = {'version': 1, 'servers': [
            {**{key: row[key] for key in ('vmid', 'node', 'account', 'configSha256')},
             'metricsSince': datetime.fromtimestamp(self.registered, timezone.utc).isoformat()}
            for row in self.document['servers']]}
        self.save_metrics()

    def save_metrics(self):
        self.metrics_path.unlink(missing_ok=True)
        self.metrics_path.write_text(json.dumps(self.metrics_document))
        self.metrics_path.chmod(0o600)

    def metrics(self, **extra):
        return self.e.handle({'action': 'infrastructure_metrics', 'account': OWNER, 'vmid': 101,
                              'node': 'pve1', 'timeframe': 'day', **extra})

    def test_registered_external_vm_has_readonly_bounded_metrics_without_allocation(self):
        samples = [{'time': self.registered - 60, 'cpu': .9},
                   {'time': self.registered + 59, 'cpu': .8},
                   {'time': self.registered + 60, 'cpu': .25, 'mem': 1024, 'maxmem': 4096,
                    'netin': 30, 'netout': 40, 'password': 'do-not-return'}]
        calls, allocation = list(self.pve.calls), list(self.e.db.iterdump())
        with patch.object(self.pve, 'api', return_value=samples) as api, \
             patch.object(self.e, 'monitor', side_effect=AssertionError('Full monitor is forbidden')), \
             patch.object(self.pve, 'current_configs', side_effect=AssertionError('Cluster config scan is forbidden')):
            result = self.metrics()
        api.assert_called_once_with('/nodes/pve1/qemu/101/rrddata', timeframe='day', cf='AVERAGE')
        self.assertEqual(set(result), {'timeframe', 'start', 'end', 'points'})
        self.assertEqual(result['end'] - result['start'], 86400)
        self.assertEqual(result['points'], [{'timestamp': self.registered + 60, 'cpuPercent': 25.0,
                         'memoryUsedBytes': 1024, 'memoryTotalBytes': 4096,
                         'networkInBytesPerSecond': 30, 'networkOutBytesPerSecond': 40}])
        self.assertEqual(self.pve.calls, calls)
        self.assertEqual(list(self.e.db.iterdump()), allocation)
        self.assertNotIn('do-not-return', json.dumps(result))

    def test_native_allocation_identity_remains_unchanged_for_site_vm(self):
        row = dict(self.e.db.execute('SELECT * FROM allocation WHERE order_id=12').fetchone())
        with patch.object(self.pve, 'api', return_value=[]) as api:
            result = self.metrics(vmid=1101)
        api.assert_called_once_with('/nodes/pve1/qemu/1101/rrddata', timeframe='day', cf='AVERAGE')
        self.assertEqual(result['points'], [])
        self.assertEqual(dict(self.e.db.execute('SELECT * FROM allocation WHERE order_id=12').fetchone()), row)
        self.assertEqual(row['client_id'], 16)

    def test_other_owner_node_vmid_and_bad_request_never_open_rrd_reader(self):
        cases = ({'account': '11111111-1111-4111-8111-111111111111'}, {'account': None},
                 {'node': 'other'}, {'node': None}, {'vmid': 1100}, {'vmid': True},
                 {'vmid': '101'}, {'timeframe': 'year'}, {'timeframe': []})
        with patch.object(self.pve, 'metrics_reader') as reader:
            for request in cases:
                with self.subTest(request=request), self.assertRaises(engine.Refused):
                    self.metrics(**request)
            reader.assert_not_called()

    def test_missing_or_invalid_registration_cutoff_never_reads_rrd(self):
        invalid = (None, '', '2026-10-23T00:00:00', '2026-10-23 00:00:00Z',
                   '1969-12-31T23:59:59Z', '9999-01-01T00:00:00Z', True)
        for value in invalid:
            with self.subTest(cutoff=value):
                if value is None:
                    self.metrics_document['servers'][0].pop('metricsSince', None)
                else:
                    self.metrics_document['servers'][0]['metricsSince'] = value
                self.save_metrics()
                with patch.object(self.pve, 'metrics_reader') as reader, self.assertRaises(engine.Refused):
                    self.metrics()
                reader.assert_not_called()

    def test_invalid_sidecar_affects_only_infrastructure_history_and_is_never_modified(self):
        original = copy.deepcopy(self.metrics_document)
        invalid_rows = ({'account': '11111111-1111-4111-8111-111111111111'}, {'node': 'other'},
                        {'vmid': 102}, {'configSha256': '0' * 64}, {'extra': True})
        def state(variant):
            self.metrics_document = copy.deepcopy(original)
            self.save_metrics()
            if isinstance(variant, dict):
                self.metrics_document['servers'][0].update(variant)
                self.save_metrics()
            elif variant == 'missing':
                self.metrics_path.unlink()
            elif variant == 'malformed':
                self.metrics_path.write_text('{')
            elif variant == 'duplicate_field':
                self.metrics_path.write_text('{"version":1,"version":1,"servers":[]}')
            elif variant == 'duplicate_vm':
                self.metrics_document['servers'].append(self.metrics_document['servers'][0])
                self.save_metrics()
            elif variant == 'mode':
                self.metrics_path.chmod(0o644)
            elif variant == 'directory_mode':
                self.e.state.chmod(0o755)
            elif variant == 'symlink':
                self.metrics_path.unlink()
                self.metrics_path.symlink_to(self.e.state / 'infrastructure.json')
        variants = (*invalid_rows, 'missing', 'malformed', 'duplicate_field', 'duplicate_vm',
                    'mode', 'directory_mode', 'symlink', 'owner')
        registry = (self.e.state / 'infrastructure.json').read_bytes()
        for variant in variants:
            with self.subTest(variant=variant):
                self.e.state.chmod(0o700)
                state(variant)
                before = self.metrics_path.read_bytes() if self.metrics_path.exists() else None
                # Simulate a process other than the root owner without requiring chown locally.
                uid = os.geteuid() + 1 if variant == 'owner' else os.geteuid()
                registry_rows = self.e.infrastructure_registry()
                with patch.object(engine.os, 'geteuid', return_value=uid), \
                     patch.object(self.pve, 'metrics_reader') as reader, self.assertRaises(engine.Refused):
                    if variant == 'owner':
                        self.e.infrastructure_metrics_registry(registry_rows, datetime.now(timezone.utc).timestamp())
                    else:
                        self.e.infrastructure_metrics(OWNER, 101, 'pve1', 'day')
                reader.assert_not_called()
                self.assertEqual(len(self.e.handle({'action': 'monitor'})['infrastructure']), 2)
                with self.assertRaisesRegex(engine.Refused, 'только для чтения'):
                    self.e.stop_vm({'slot': 101 - self.config['vm_first']})
                with patch.object(self.pve, 'api', return_value=[]):
                    self.assertEqual(self.e.handle({**self.ordinary, 'action': 'metrics', 'timeframe': 'day'})['points'], [])
                self.assertEqual(self.metrics_path.read_bytes() if self.metrics_path.exists() else None, before)
                self.assertEqual((self.e.state / 'infrastructure.json').read_bytes(), registry)
        self.e.state.chmod(0o700)

    def test_week_excludes_bucket_crossing_registration_and_invalid_numbers(self):
        samples = [{'time': self.registered + 1799, 'cpu': .9},
                   {'time': self.registered + 1800, 'cpu': float('nan'), 'mem': -1,
                    'maxmem': True, 'netin': float('inf'), 'netout': -1}]
        with patch.object(self.pve, 'api', return_value=samples):
            result = self.metrics(timeframe='week')
        self.assertEqual(len(result['points']), 1)
        self.assertTrue(all(value is None for key, value in result['points'][0].items() if key != 'timestamp'))

    def test_guest_identity_and_fingerprint_are_checked_before_history(self):
        original = copy.deepcopy(self.pve.vms[101])
        for drift in ({'description': 'foreign'}, {'template': 1}, {'lock': 'backup'}, {'_type': 'lxc'}):
            with self.subTest(drift=drift):
                self.pve.vms[101] = {**original, **drift}
                with patch.object(self.pve, 'api') as api, self.assertRaises(engine.Refused):
                    self.metrics()
                api.assert_not_called()
        self.pve.vms[101] = original

    def test_registration_sidecar_and_guest_drift_after_history_discard_the_result(self):
        registry, sidecar = copy.deepcopy(self.document), copy.deepcopy(self.metrics_document)
        fields = ({'account': '11111111-1111-4111-8111-111111111111'}, {'node': 'other'},
                  {'configSha256': '0' * 64})
        cases = [DriftCase('registry', change) for change in fields] + [DriftCase('sidecar', change) for change in fields]
        cases += [DriftCase('sidecar', {'metricsSince': datetime.fromtimestamp(self.registered + 60, timezone.utc).isoformat()}),
                  DriftCase('sidecar_missing', None), DriftCase('guest', None)]
        for case in cases:
            with self.subTest(case=case):
                self.document, self.metrics_document = copy.deepcopy(registry), copy.deepcopy(sidecar)
                self.save_registry()
                self.save_metrics()
                config = copy.deepcopy(self.pve.vms[101])
                def drift(*args, **kwargs):
                    if case.target == 'guest':
                        self.pve.vms[101]['description'] = 'foreign'
                    elif case.target == 'sidecar_missing':
                        self.metrics_path.unlink()
                    elif case.target == 'registry':
                        self.document['servers'][0].update(case.change)
                        self.save_registry()
                    else:
                        self.metrics_document['servers'][0].update(case.change)
                        self.save_metrics()
                    return [{'time': self.registered + 60, 'cpu': .5}]
                with patch.object(self.pve, 'api', side_effect=drift), self.assertRaises(engine.Refused):
                    self.metrics()
                self.pve.vms[101] = config


class InfrastructureMetricsTransportTests(unittest.TestCase):
    def test_infrastructure_metrics_fails_fast_behind_mutation_lock(self):
        completed, outcome = engine_tests.CLILockingContracts.invoke_while_locked(self, fcntl.LOCK_EX, 'infrastructure_metrics')
        self.assertTrue(completed)
        self.assertEqual(outcome, [engine.Refused])

    def test_infrastructure_metrics_uses_same_deadline_and_db_timeout_as_owned_metrics(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            config = state / 'config.json'
            config.write_text('{}')
            def path(value):
                return config if value == '/etc/safehost-billing/config.json' else state if value == '/var/lib/safehost-billing' else Path(value)
            for action in engine.METRICS_ACTIONS:
                with self.subTest(action=action):
                    fake = SimpleNamespace(db=SimpleNamespace(close=lambda: None), handle=lambda request: {'points': []})
                    with patch.object(engine, 'Path', side_effect=path), patch.object(engine, 'Engine', return_value=fake) as construct, \
                         patch.object(engine, 'metrics_deadline', return_value=nullcontext()) as deadline, \
                         patch.object(engine.sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(json.dumps({'action': action}).encode()))), \
                         patch.object(engine.sys, 'stdout', io.StringIO()):
                        engine.main()
                    deadline.assert_called_once_with()
                    construct.assert_called_once_with({}, state, '/var/lib/vz/snippets', db_timeout=1)


if __name__ == '__main__':
    unittest.main()
