from dataclasses import dataclass
import fcntl
import importlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_engine import engine
import test_infrastructure as infrastructure

observer_module = importlib.import_module('infrastructure_observer')
history = importlib.import_module('infrastructure_disk_history')


@dataclass(frozen=True)
class HistoryPeriodCase:
    timeframe: str
    points: int


@dataclass(frozen=True)
class PrivatePathCase:
    name: str
    kind: str


class DiskHistoryTests(unittest.TestCase):
    tearDown = infrastructure.InfrastructureTests.tearDown
    entry = infrastructure.InfrastructureTests.entry
    save_registry = infrastructure.InfrastructureTests.save_registry

    def setUp(self):
        infrastructure.InfrastructureTests.setUp(self)
        self.observer = observer_module.InfrastructureObserver(self.e.state, self.pve)
        self.store = history.DiskHistory(Path(self.temp.name) / 'monitoring/infrastructure-disk.sqlite3')
        self.tick = 1800000000
        (self.e.state / 'operation.lock').touch(mode=0o600)
        self.target = self.document['servers'][0]

    def query(self, timeframe='day', **extra):
        return self.observer.infrastructure_disk_history(infrastructure.OWNER, 101, 'pve1', timeframe,
                                                       store=self.store, clock=lambda: self.tick + 20, **extra)

    def test_observer_is_independent_and_preserves_refused_identity(self):
        self.assertIs(engine.Refused, observer_module.Refused)
        with patch.object(engine, 'Engine', side_effect=AssertionError('Allocator forbidden')), \
             patch.object(engine.sqlite3, 'connect', side_effect=AssertionError('No SQLite for observation')), \
             patch.object(self.pve, 'guest_fs', return_value=(0, 4096)):
            self.assertEqual(self.observer.infrastructure_disk(infrastructure.OWNER, 101, 'pve1')['usedBytes'], 0)

    def test_standalone_observer_import_has_no_engine_or_sqlite_dependency(self):
        import subprocess
        import sys
        source=Path(engine.__file__).resolve().parent
        code="import sys;sys.path.insert(0,"+repr(str(source))+");import infrastructure_observer;assert 'engine' not in sys.modules;assert 'sqlite3' not in sys.modules"
        subprocess.run([sys.executable,'-c',code],check=True,capture_output=True,text=True)

    def test_absent_store_is_readonly_and_returns_exact_grid_with_null_pairs(self):
        with patch.object(self.pve, 'guest_fs', side_effect=AssertionError('No QGA on history')):
            for case in (HistoryPeriodCase('day', 1440), HistoryPeriodCase('week', 10080)):
                result = self.query(case.timeframe)
                self.assertEqual(result['step'], 60)
                self.assertEqual(len(result['points']), case.points)
                self.assertEqual(result['points'][0]['timestamp'], result['start'] + 60)
                self.assertEqual(result['points'][-1]['timestamp'], result['end'])
                self.assertTrue(all(row['usedBytes'] is None and row['totalBytes'] is None for row in result['points']))
        self.assertFalse(self.store.path.parent.exists())

    def test_collection_is_allowlisted_readonly_and_deduplicated(self):
        self.document['servers'].append(self.entry(1100, '10.10.10.20'))
        self.save_registry()
        before = list(self.e.db.iterdump()), (self.e.state / 'infrastructure.json').read_bytes(), list(self.pve.calls)
        self.pve.vms[1100]['description'] = 'Unrelated VM remains uncollected'
        connect = sqlite3.connect
        def monitoring_only(database, *args, **kwargs):
            self.assertNotIn('allocations.sqlite', str(database))
            return connect(database, *args, **kwargs)
        with patch.object(engine, 'Engine', side_effect=AssertionError('Allocator forbidden')), \
             patch.object(history.sqlite3, 'connect', side_effect=monitoring_only), \
             patch.object(self.pve, 'guest_fs', return_value=(1024, 4096)) as fs:
            history.collect(self.observer, self.store, clock=lambda: self.tick + 3)
            self.assertEqual([call.args[0] for call in fs.call_args_list], [101, 1101])
            with patch.object(self.pve, 'guest_fs', return_value=(2048, 4096)):
                history.collect(self.observer, self.store, clock=lambda: self.tick + 15)
        self.assertEqual(self.query()['points'][-1]['usedBytes'], 1024)
        self.assertEqual((list(self.e.db.iterdump()), (self.e.state / 'infrastructure.json').read_bytes(), self.pve.calls), before)

    def test_gaps_are_not_filled_and_invalid_values_are_null(self):
        self.store.record(self.target, self.tick - 120, 1, 10, now=self.tick - 120)
        self.store.record(self.target, self.tick, None, None, now=self.tick)
        points = self.query()['points']
        self.assertEqual(points[-3:], [{'timestamp': self.tick - 120, 'usedBytes': 1, 'totalBytes': 10},
                                      {'timestamp': self.tick - 60, 'usedBytes': None, 'totalBytes': None},
                                      {'timestamp': self.tick, 'usedBytes': None, 'totalBytes': None}])

    def test_owner_pin_and_node_are_isolated_and_drift_discards_history(self):
        self.store.record({**self.target, 'account': '11111111-1111-4111-8111-111111111111'}, self.tick, 5, 10, now=self.tick)
        self.store.record({**self.target, 'configSha256': '0'*64}, self.tick, 5, 10, now=self.tick)
        self.assertIsNone(self.query()['points'][-1]['usedBytes'])
        original = self.store.read
        def changed(*args, **kwargs):
            result = original(*args, **kwargs)
            self.pve.vms[101]['description'] = 'changed after query'
            return result
        with patch.object(self.store, 'read', side_effect=changed), self.assertRaises(engine.Refused):self.query()

    def test_retention_is_eight_days_and_future_or_nonminute_samples_are_rejected(self):
        self.store.record(self.target, self.tick - 8*86400, 1, 10, now=self.tick - 8*86400)
        self.store.record(self.target, self.tick, 2, 10, now=self.tick)
        with sqlite3.connect(self.store.path) as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM sample').fetchone()[0], 1)
        for tick in (self.tick + 60, self.tick + 1, self.tick - 60):
            with self.subTest(tick=tick), self.assertRaises(engine.Refused):self.store.record(self.target, tick, 1, 10, now=self.tick)

    def test_retention_prunes_existing_store_when_both_observations_are_refused(self):
        self.assertFalse(self.store.path.exists())
        self.assertFalse(self.store.prune(self.tick))
        self.assertFalse(self.store.path.parent.exists())
        self.store.record(self.target, self.tick - 8*86400, 1, 10, now=self.tick - 8*86400)
        before=list(self.e.db.iterdump()),(self.e.state/'infrastructure.json').read_bytes()
        with patch.object(self.observer,'infrastructure_disk',side_effect=engine.Refused('Unavailable identity')):
            self.assertEqual(history.collect(self.observer,self.store,clock=lambda:self.tick+3),{'collected':0})
        with sqlite3.connect(self.store.path) as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM sample').fetchone()[0],0)
        self.assertEqual((list(self.e.db.iterdump()),(self.e.state/'infrastructure.json').read_bytes()),before)

    def test_private_modes_ownership_and_symlinks_are_rejected(self):
        cases = [PrivatePathCase(name, kind) for name in ('', 'infrastructure-disk.sqlite3', 'infrastructure-disk.sqlite3-wal', 'infrastructure-disk.sqlite3-shm')
                 for kind in ('mode', 'symlink')]
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)/'monitor';directory.mkdir(mode=0o700)
                path = directory/case.name if case.name else directory
                if case.name:path.touch(mode=0o600)
                if case.kind == 'mode':path.chmod(0o755 if not case.name else 0o644)
                else:
                    path.rmdir() if path.is_dir() else path.unlink()
                    path.symlink_to(Path(temporary))
                with self.assertRaises(engine.Refused):history.DiskHistory(directory/'infrastructure-disk.sqlite3').read(self.target, self.tick-60, self.tick)

    def test_late_collection_and_busy_locks_leave_gaps_without_backfill(self):
        with (self.e.state/'operation.lock').open() as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            with patch.object(self.pve, 'guest_fs') as fs:history.collect(self.observer, self.store, clock=lambda:self.tick+3)
            fs.assert_not_called()
        self.assertFalse(self.store.path.exists())
        values = iter([self.tick+59, self.tick+59, self.tick+61, self.tick+61])
        with patch.object(self.pve, 'guest_fs', return_value=(1, 10)) as fs:
            history.collect(self.observer, self.store, clock=lambda:next(values, self.tick+61))
        fs.assert_called_once_with(101)
        self.assertIsNone(self.query()['points'][-1]['usedBytes'])

    def test_maximum_week_reply_is_under_existing_transport_cap(self):
        self.store.record(self.target, self.tick, 2**53-1, 2**53-1, now=self.tick)
        with sqlite3.connect(self.store.path) as db:
            db.executemany('INSERT OR IGNORE INTO sample VALUES(?,?,?,?,?,?,?)',
                [(self.target['account'],101,'pve1',self.target['configSha256'],self.tick-i*60,2**53-1,2**53-1) for i in range(10080)])
        result = self.query('week')
        self.assertEqual(len(result['points']), 10080)
        self.assertLess(len(json.dumps({'ok':True,'result':result}).encode()), 1048576)

    def test_collector_lock_and_fatal_deadline_prevent_overlap_and_late_work(self):
        import time
        with self.store.collector_lock() as acquired:
            self.assertTrue(acquired)
            with patch.object(self.pve, 'guest_fs') as fs:history.collect(self.observer, self.store, clock=lambda:self.tick+3)
            fs.assert_not_called()
        def deadline(**kwargs):return observer_module.metrics_deadline(.01, **kwargs)
        with patch.object(history, 'metrics_deadline', side_effect=deadline), \
             patch.object(self.pve, 'guest_fs', side_effect=lambda vmid:time.sleep(.1)), self.assertRaises(history.CollectionDeadline):
            history.collect(self.observer, self.store, clock=lambda:self.tick+3)
        self.assertFalse(self.store.path.exists())

    def test_collector_main_reads_config_only_under_nonblocking_operation_lock(self):
        import io
        state=self.e.state;config=Path(self.temp.name)/'config.json';config.write_text(json.dumps(self.config))
        original_path=history.Path;loads=json.loads
        def path(value):
            return state if value=='/var/lib/safehost-billing' else config if value=='/etc/safehost-billing/config.json' else original_path(value)
        def locked_load(value):
            with (state/'operation.lock').open() as contender:
                with self.assertRaises(BlockingIOError):fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return loads(value)
        with patch.object(history, 'Path', side_effect=path),patch.object(history.os, 'geteuid', return_value=0), \
             patch.object(history.json, 'loads', side_effect=locked_load) as read, \
             patch.object(history, 'collect', return_value={'collected':0}) as collect, \
             patch.object(history, 'InfrastructureObserver'),patch.object(engine.sys, 'stdout', io.StringIO()):
            history.main();read.assert_called_once();collect.assert_called_once()
            read.reset_mock();collect.reset_mock()
            with (state/'operation.lock').open() as exclusive:
                fcntl.flock(exclusive, fcntl.LOCK_EX)
                history.main()
            read.assert_not_called();collect.assert_not_called()

    def test_history_refuses_bad_owner_target_period_before_store_access(self):
        base={'account':infrastructure.OWNER,'vmid':101,'node':'pve1','timeframe':'day'}
        for change in ({'account':None},{'account':'11111111-1111-4111-8111-111111111111'},
                       {'vmid':True},{'vmid':1100},{'node':'other'},{'timeframe':'year'},{'timeframe':[]}):
            with self.subTest(change=change),patch.object(self.store,'read') as read, \
                 patch.object(self.pve,'metrics_reader') as reader,self.assertRaises(engine.Refused):
                self.observer.infrastructure_disk_history(**(base|change),store=self.store)
            read.assert_not_called();reader.assert_not_called()

    def test_history_main_never_constructs_allocator(self):
        state=self.e.state;config=Path(self.temp.name)/'config.json';config.write_text(json.dumps(self.config))
        original_path=engine.Path
        def path(value):
            return config if value=='/etc/safehost-billing/config.json' else state if value=='/var/lib/safehost-billing' else original_path(value)
        import io
        payload={'action':'infrastructure_disk_history','account':infrastructure.OWNER,'vmid':101,'node':'pve1','timeframe':'day'}
        with patch.object(engine,'Path',side_effect=path),patch.object(engine,'Proxmox',return_value=self.pve), \
             patch.object(engine,'Engine',side_effect=AssertionError('Allocator forbidden')), \
             patch.object(engine.sys,'stdin',SimpleNamespace(buffer=io.BytesIO(json.dumps(payload).encode()))), \
             patch.object(engine.sys,'stdout',io.StringIO()), \
             patch.object(history,'STORE_PATH',self.store.path):engine.main()


if __name__=='__main__':unittest.main()
