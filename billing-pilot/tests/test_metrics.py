import json
import unittest
import os
import sys
import fcntl
import tempfile
import subprocess
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

    def helper_request(self, *, foreign=False, invalid=False, timeout=False):
        """Exercise the real process adapter through the owned metrics entry point."""
        vmid = self.e.vmid(self.e.db.execute('SELECT * FROM allocation').fetchone())
        snapshot = {'guest': self.pve.guests()[vmid], 'config': self.pve.config(vmid)}
        if foreign:
            snapshot['config']['description'] = 'foreign'
        log = Path(self.temp.name) / 'metrics-reads.jsonl'
        pid = Path(self.temp.name) / 'metrics-child.pid'
        script = r'''
import json,os,sys,time
from pathlib import Path
snapshot,log,pid,invalid,timeout=sys.argv[1:]
Path(pid).write_text(str(os.getpid()))
for line in sys.stdin:
    action=json.loads(line)
    with open(log,'a') as stream: stream.write(json.dumps(action)+'\n')
    if timeout == 'True': time.sleep(60)
    print('broken' if invalid == 'True' else snapshot if action == 'identity' else '[]',flush=True)
'''
        start = subprocess.Popen
        def launch(args, **kwargs):
            self.assertEqual(args[0], '/usr/bin/perl')
            self.assertEqual(args[-3:], ['pve1', str(vmid), 'day'])
            return start([sys.executable, '-u', '-c', script, json.dumps(snapshot), str(log), str(pid),
                          str(invalid), str(timeout)], **kwargs)
        self.e.pve = engine.Proxmox(self.config)
        with patch.object(engine.subprocess, 'Popen', side_effect=launch) as processes:
            if timeout:
                with self.assertRaises(TimeoutError), engine.metrics_deadline(.5):
                    self.metrics()
            elif foreign:
                with self.assertRaises(engine.Refused):
                    self.metrics()
            elif invalid:
                with self.assertRaises(OSError):
                    self.metrics()
            else:
                result = self.metrics()
                self.assertEqual(result['points'], [])
            self.assertEqual(processes.call_count, 1)
        with self.assertRaises(ProcessLookupError):
            os.kill(int(pid.read_text()), 0)
        return [json.loads(line) for line in log.read_text().splitlines()]

    def test_first_history_uses_one_process_with_fresh_checks_on_both_sides(self):
        self.assertEqual(self.helper_request(), ['identity', 'history', 'identity'])

    def test_foreign_identity_stops_before_history_and_reaps_reader(self):
        self.assertEqual(self.helper_request(foreign=True), ['identity'])

    def test_broken_reply_fails_closed_and_reaps_reader(self):
        self.assertEqual(self.helper_request(invalid=True), ['identity'])

    def test_deadline_interrupts_and_reaps_reader(self):
        self.assertEqual(self.helper_request(timeout=True), ['identity'])


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
