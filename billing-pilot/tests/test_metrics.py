import json
import unittest
import os
import sys
import fcntl
import tempfile
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import patch

import test_admin_engine as admin
from test_engine import engine


class MetricsTests(unittest.TestCase):
    setUp = admin.AdminEngineTests.setUp
    tearDown = admin.AdminEngineTests.tearDown
    admin = admin.AdminEngineTests.admin

    def metrics(self, **extra):
        return self.e.handle({**self.request, 'action': 'metrics', 'timeframe': 'day', **extra})

    def test_history_is_owned_read_only_and_whitelisted(self):
        created = int(datetime.now(timezone.utc).timestamp()) - 3600
        self.e.db.execute('UPDATE allocation SET created_at=?',
                          (datetime.fromtimestamp(created, timezone.utc).isoformat(),))
        rows = [{'time': created - 60, 'cpu': .2},
                {'time': created, 'cpu': .4},
                {'time': created + 60, 'cpu': 0, 'mem': 1024, 'maxmem': 4096,
                 'netin': 500, 'netout': 750, 'password': 'never-return'},
                {'time': created + 120}]
        before = list(self.pve.calls)
        with patch.object(self.pve, 'api', return_value=rows) as api:
            result = self.metrics()
        api.assert_called_once_with('/nodes/pve1/qemu/1100/rrddata', timeframe='day', cf='AVERAGE')
        self.assertEqual(len(result['points']), 2)
        point = result['points'][0]
        self.assertEqual(point['cpuPercent'], 0)
        self.assertEqual(point['memoryUsedBytes'], 1024)
        self.assertEqual(point['networkInBytesPerSecond'], 500)
        self.assertIsNone(result['points'][1]['cpuPercent'])
        self.assertNotIn('password', json.dumps(result))
        self.assertEqual(self.pve.calls, before)

    def test_other_client_foreign_missing_and_reused_vmid_never_read_rrd(self):
        with patch.object(self.pve, 'api') as api:
            with self.assertRaises(engine.Refused):
                self.metrics(client_id=999)
            self.pve.vms[1100]['description'] = 'foreign'
            with self.assertRaises(engine.Refused):
                self.metrics()
            del self.pve.vms[1100]
            with self.assertRaises(engine.Refused):
                self.metrics()
            api.assert_not_called()

    def test_deleted_order_cannot_see_new_owners_history(self):
        self.admin('purge', confirm_vmid=1100)
        self.e.handle({**self.request, 'action': 'create', 'order_id': 3})
        with patch.object(self.pve, 'api') as api, self.assertRaises(engine.Refused):
            self.metrics()
        api.assert_not_called()

    def test_only_bounded_periods_and_finite_values(self):
        with patch.object(self.pve, 'api') as api:
            for timeframe in ('hour', 'year', '', None, [], '../status'):
                with self.subTest(timeframe=timeframe), self.assertRaises(engine.Refused):
                    self.metrics(timeframe=timeframe)
            api.assert_not_called()
        created = datetime.now(timezone.utc).timestamp() - 7200
        self.e.db.execute('UPDATE allocation SET created_at=?',
                          (datetime.fromtimestamp(created, timezone.utc).isoformat(),))
        rows = [{'time': int(created) + 1800, 'cpu': float('nan'), 'mem': -1,
                 'maxmem': True, 'netin': float('inf'), 'netout': -1}]
        with patch.object(self.pve, 'api', return_value=rows):
            result = self.metrics(timeframe='week')
        self.assertEqual(len(result['points']), 0)  # First bucket spans before this allocation.
        rows[0]['time'] += 1800
        with patch.object(self.pve, 'api', return_value=rows):
            point = self.metrics(timeframe='week')['points'][0]
        self.assertTrue(all(value is None for key, value in point.items() if key != 'timestamp'))

    def test_ownership_is_checked_again_after_history_read(self):
        def drift(*args, **kwargs):
            self.pve.vms[1100]['description'] = 'foreign'
            return []
        with patch.object(self.pve, 'api', side_effect=drift), self.assertRaises(engine.Refused):
            self.metrics()

    def test_legacy_unknown_creation_time_never_exposes_previous_rrd_history(self):
        self.e.db.execute('UPDATE allocation SET created_at=NULL')
        with patch.object(self.pve, 'api') as api, self.assertRaises(engine.Refused):
            self.metrics()
        api.assert_not_called()


class MetricsDeadlineTests(unittest.TestCase):
    def test_timeout_kills_the_pvesh_child_and_releases_locks(self):
        with tempfile.TemporaryDirectory() as temporary:
            lock_path = Path(temporary) / 'operation.lock'
            pid_path = Path(temporary) / 'child.pid'
            child = ("import os,fcntl,time; from pathlib import Path; "
                     f"lock=open({str(lock_path)!r},'a'); fcntl.flock(lock,fcntl.LOCK_SH); "
                     f"Path({str(pid_path)!r}).write_text(str(os.getpid())); time.sleep(60)")
            with self.assertRaises(TimeoutError):
                with lock_path.open('a') as lock:
                    fcntl.flock(lock, fcntl.LOCK_SH)
                    with engine.metrics_deadline(.5):
                        engine.run([sys.executable, '-c', child])
            self.assertTrue(pid_path.exists(), 'Child must start before the deadline')
            with self.assertRaises(ProcessLookupError):
                os.kill(int(pid_path.read_text()), 0)
            with lock_path.open('a') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
