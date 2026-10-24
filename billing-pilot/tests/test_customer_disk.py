from dataclasses import dataclass
import copy
import fcntl
import importlib
import io
import json
from pathlib import Path
import sqlite3
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_engine import engine
import test_infrastructure as infrastructure

customer = importlib.import_module('allocation_observer')
history = importlib.import_module('infrastructure_disk_history')


@dataclass(frozen=True)
class DiskValueCase:
    value: object
    valid: bool


@dataclass(frozen=True)
class DiskPeriodCase:
    period: str
    count: int


@dataclass(frozen=True)
class NativeTargetCase:
    client: object
    order: object


class CustomerDiskTests(unittest.TestCase):
    entry = infrastructure.InfrastructureTests.entry
    save_registry = infrastructure.InfrastructureTests.save_registry
    tearDown = infrastructure.InfrastructureTests.tearDown

    def setUp(self):
        infrastructure.InfrastructureTests.setUp(self)
        (self.e.state/'allocations.sqlite').chmod(0o600)
        (self.e.state/'operation.lock').touch(mode=0o600)
        self.observer = customer.AllocationObserver(self.e.state, self.pve)
        self.store = customer.CustomerDiskHistory(Path(self.temp.name)/'monitoring/infrastructure-disk.sqlite3')
        self.tick = 1800000000

    def usage(self):return self.observer.disk_usage(2, 11)

    def query(self, period='day'):
        return self.observer.disk_history(2, 11, period, store=self.store, clock=lambda:self.tick+5)

    def test_exact_identity_no_allocator_writes_and_infrastructure_is_excluded(self):
        before=list(self.e.db.iterdump()),copy.deepcopy(self.pve.vms),list(self.pve.calls)
        connect=sqlite3.connect
        def readonly(database,*args,**kwargs):
            if 'allocations.sqlite' in str(database):self.assertIn('mode=ro', str(database))
            return connect(database,*args,**kwargs)
        with patch.object(engine,'Engine',side_effect=AssertionError('Engine constructor forbidden')), \
             patch.object(engine,'Ipam',side_effect=AssertionError('IPAM constructor forbidden')), \
             patch.object(sqlite3,'connect',side_effect=readonly),patch.object(self.pve,'guest_fs',return_value=(0,4096)):
            result=self.usage()
            self.assertEqual({key:result[key] for key in ('client_id','order_id','vmid','node','mountpoint')},
                             {'client_id':2,'order_id':11,'vmid':1100,'node':'pve1','mountpoint':'/'})
            self.assertEqual(result['usedBytes'],0)
            for case in (NativeTargetCase(16,12),NativeTargetCase(3,11),NativeTargetCase(True,11),NativeTargetCase(2,'11')):
                with self.subTest(case=case),self.assertRaises(engine.Refused):self.observer.disk_usage(case.client,case.order)
        self.assertEqual((list(self.e.db.iterdump()),self.pve.vms,self.pve.calls),before)

    def test_unavailable_offline_and_invalid_qga_are_all_null_without_other_vm_calls(self):
        cases=(DiskValueCase(None,False),DiskValueCase((True,10),False),DiskValueCase((-1,10),False),
               DiskValueCase((2,1),False),DiskValueCase((0,0),False),DiskValueCase((1,2**53),False),DiskValueCase((1,10),True))
        for case in cases:
            with self.subTest(case=case),patch.object(self.pve,'guest_fs',return_value=case.value):
                result=self.usage()
                self.assertEqual(result['usedBytes'] is not None,case.valid)
                self.assertEqual(result['observedAt'] is not None,case.valid)
        self.pve.states[1100]='stopped'
        with patch.object(self.pve,'guest_fs',side_effect=AssertionError('No QGA on stopped guest')):
            self.assertTrue(all(self.usage()[key] is None for key in ('usedBytes','totalBytes','observedAt')))

    def test_allocation_and_guest_drift_after_read_are_refused(self):
        def changed(vmid):
            self.pve.vms[vmid]['description']='foreign'
            return 1,10
        with patch.object(self.pve,'guest_fs',side_effect=changed),self.assertRaises(engine.Refused):self.usage()
        self.pve.vms[1100]['description']=self.e.marker(self.e.db.execute('SELECT * FROM allocation WHERE order_id=11').fetchone())
        def ownership(vmid):
            self.e.db.execute('UPDATE allocation SET client_id=3 WHERE order_id=11');self.e.db.commit()
            return 1,10
        with patch.object(self.pve,'guest_fs',side_effect=ownership),self.assertRaises(engine.Refused):self.usage()

    def test_exact_grid_absent_store_no_creation_and_no_qga(self):
        with patch.object(self.pve,'guest_fs',side_effect=AssertionError('History cannot call QGA')):
            for case in (DiskPeriodCase('day',1440),DiskPeriodCase('week',10080)):
                result=self.query(case.period)
                self.assertEqual((result['step'],len(result['points'])),(60,case.count))
                self.assertEqual(result['points'][0]['timestamp'],result['start']+60)
                self.assertTrue(all(p['usedBytes'] is None and p['totalBytes'] is None for p in result['points']))
        self.assertFalse(self.store.path.parent.exists())

    def test_customer_collection_isolates_generation_and_preserves_infrastructure_table(self):
        infra_store=history.DiskHistory(self.store.path)
        infra=self.document['servers'][0]
        infra_store.record(infra,self.tick,9,10,now=self.tick)
        before=list(self.e.db.iterdump()),(self.e.state/'infrastructure.json').read_bytes()
        with patch.object(self.pve,'guest_fs',return_value=(1,10)):
            history.collect(self.observer,self.store,include_customers=True,clock=lambda:self.tick+3)
        self.assertEqual(self.query()['points'][-1]['usedBytes'],1)
        self.assertEqual(infra_store.read(infra,self.tick-60,self.tick)[self.tick],(9,10))
        self.assertEqual((list(self.e.db.iterdump()),(self.e.state/'infrastructure.json').read_bytes()),before)
        self.e.db.execute("UPDATE allocation SET created_at='2026-10-24T00:00:00+00:00' WHERE order_id=11");self.e.db.commit()
        self.assertIsNone(self.query()['points'][-1]['usedBytes'])

    def test_customer_retention_runs_without_success_and_store_version_stays_one(self):
        with patch.object(self.pve,'guest_fs',return_value=(1,10)):
            history.collect(self.observer,self.store,include_customers=True,clock=lambda:self.tick-8*86400+3)
        with patch.object(self.observer,'observe_disk',side_effect=engine.Refused('Missing')):
            history.collect(self.observer,self.store,include_customers=True,clock=lambda:self.tick+3)
        with sqlite3.connect(self.store.path) as db:
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0],1)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM customer_sample WHERE timestamp<=?',(self.tick-8*86400,)).fetchone()[0],0)

    def test_retention_precedes_corrupt_registry_or_refused_allocator_discovery(self):
        for kind in ('registry','allocator'):
            with self.subTest(kind=kind):
                self.save_registry()
                with patch.object(self.pve,'guest_fs',return_value=(1,10)):
                    history.collect(self.observer,self.store,include_customers=True,clock=lambda:self.tick-8*86400+3)
                with sqlite3.connect(self.store.path) as db:
                    self.assertGreater(db.execute('SELECT COUNT(*) FROM sample').fetchone()[0],0)
                    self.assertGreater(db.execute('SELECT COUNT(*) FROM customer_sample').fetchone()[0],0)
                if kind=='registry':(self.e.state/'infrastructure.json').write_text('{corrupt')
                with patch.object(self.observer,'candidates',side_effect=engine.Refused('Allocator unavailable')), \
                     self.assertRaises(engine.Refused):
                    history.collect(self.observer,self.store,include_customers=True,clock=lambda:self.tick+3)
                with sqlite3.connect(self.store.path) as db:
                    self.assertEqual(db.execute('SELECT COUNT(*) FROM sample WHERE timestamp<=?',(self.tick-8*86400,)).fetchone()[0],0)
                    self.assertEqual(db.execute('SELECT COUNT(*) FROM customer_sample WHERE timestamp<=?',(self.tick-8*86400,)).fetchone()[0],0)

    def test_history_detects_drift_after_sql_and_missing_generation_never_reuses_history(self):
        with patch.object(self.pve,'guest_fs',return_value=(1,10)):
            history.collect(self.observer,self.store,include_customers=True,clock=lambda:self.tick+3)
        original=self.store.read_customer
        def changed(*args):
            result=original(*args);self.pve.vms[1100]['cores']=99;return result
        with patch.object(self.store,'read_customer',side_effect=changed),self.assertRaises(engine.Refused):self.query()
        self.e.db.execute('UPDATE allocation SET created_at=NULL WHERE order_id=11');self.e.db.commit()
        self.assertTrue(all(p['usedBytes'] is None for p in self.query()['points']))

    def test_root_disk_cli_never_constructs_engine_and_validates_period(self):
        config=Path(self.temp.name)/'config.json';config.write_text(json.dumps(self.config));original=engine.Path
        def path(value):return self.e.state if value=='/var/lib/safehost-billing' else config if value=='/etc/safehost-billing/config.json' else original(value)
        for action in ('disk_usage','disk_history'):
            payload={'action':action,'client_id':2,'order_id':11}
            if action=='disk_history':payload['timeframe']='day'
            output=io.StringIO()
            with patch.object(engine,'Path',side_effect=path),patch.object(engine,'Proxmox',return_value=self.pve), \
                 patch.object(engine,'Engine',side_effect=AssertionError('No Engine')), \
                 patch.object(engine.sys,'stdin',SimpleNamespace(buffer=io.BytesIO(json.dumps(payload).encode()))), \
                 patch.object(engine.sys,'stdout',output),patch.object(customer,'STORE_PATH',self.store.path):engine.main()
            self.assertEqual(json.loads(output.getvalue())['result']['order_id'],11)
        for period in (None,[], 'month'):
            with self.subTest(period=period),self.assertRaises(engine.Refused):self.query(period)

    def test_root_disk_deadline_cannot_be_swallowed_by_qga_unavailable_handling(self):
        import time
        original=engine.metrics_deadline
        def short(**kwargs):
            self.assertIs(kwargs['exception'],customer.DiskReadDeadline)
            return original(.01,**kwargs)
        config=Path(self.temp.name)/'config.json';config.write_text(json.dumps(self.config));original_path=engine.Path
        def path(value):return self.e.state if value=='/var/lib/safehost-billing' else config if value=='/etc/safehost-billing/config.json' else original_path(value)
        payload={'action':'disk_usage','client_id':2,'order_id':11}
        with patch.object(engine,'Path',side_effect=path),patch.object(engine,'Proxmox',return_value=self.pve), \
             patch.object(engine,'Engine',side_effect=AssertionError('No Engine')),patch.object(engine,'metrics_deadline',side_effect=short), \
             patch.object(engine.sys,'stdin',SimpleNamespace(buffer=io.BytesIO(json.dumps(payload).encode()))), \
             patch.object(self.pve,'guest_fs',side_effect=lambda vmid:time.sleep(.1)),self.assertRaises(customer.DiskReadDeadline):engine.main()

    def test_deadline_is_single_and_persistent_cursor_prevents_customer_starvation(self):
        import time
        self.e.handle({'action':'create','client_id':3,'order_id':13,'plan':'mini','ssh_key':''})
        calls=[]
        def fs(vmid):
            calls.append(vmid)
            if vmid==1100:time.sleep(.1)
            return 1,10
        def short_deadline(**kwargs):
            self.assertEqual(kwargs.pop('seconds'),45)
            return engine.metrics_deadline(.02,**kwargs)
        with patch.object(self.observer,'infrastructure_disk',return_value={'usedBytes':None,'totalBytes':None}), \
             patch.object(self.pve,'guest_fs',side_effect=fs), \
             patch.object(history,'metrics_deadline',side_effect=short_deadline) as alarm:
            with self.assertRaises(history.CollectionDeadline):history.collect(self.observer,self.store,include_customers=True,clock=lambda:self.tick+3)
            self.assertEqual(calls,[1100]);alarm.assert_called_once()
            calls.clear();alarm.reset_mock()
            with self.assertRaises(history.CollectionDeadline):history.collect(self.observer,self.store,include_customers=True,clock=lambda:self.tick+63)
            self.assertEqual(calls,[1102,1100]);alarm.assert_called_once()
        with sqlite3.connect(self.store.path) as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM customer_sample').fetchone()[0],1)

    def test_customer_late_minute_is_discarded_and_operation_lock_is_per_vm(self):
        clock=iter((self.tick+59,self.tick+59,self.tick+61))
        def fs(vmid):
            with (self.e.state/'operation.lock').open() as exclusive:
                with self.assertRaises(BlockingIOError):fcntl.flock(exclusive,fcntl.LOCK_EX | fcntl.LOCK_NB)
            return 1,10
        with patch.object(history,'COLLECT_VMID_ALLOWLIST',()),patch.object(self.pve,'guest_fs',side_effect=fs):
            history.collect(self.observer,self.store,include_customers=True,clock=lambda:next(clock,self.tick+61))
        self.assertTrue(all(p['usedBytes'] is None for p in self.query()['points']))
        with (self.e.state/'operation.lock').open() as exclusive:fcntl.flock(exclusive,fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_private_allocator_refuses_modes_and_symlinks_without_repair_or_creation(self):
        path=self.e.state/'allocations.sqlite';path.chmod(0o644)
        with self.assertRaises(engine.Refused):self.usage()
        self.assertEqual(path.stat().st_mode & 0o777,0o644);path.chmod(0o600)
        target=path.with_name('actual.sqlite');path.rename(target);path.symlink_to(target)
        with self.assertRaises(engine.Refused):self.usage()
        self.assertTrue(path.is_symlink())

    def test_public_lease_uses_the_same_identity_guard_as_native_engine(self):
        from test_public_engine import PublicEngineTests
        fixture=PublicEngineTests();fixture.setUp()
        try:
            lease=fixture.reserve_ip()
            fixture.handle('create',network_mode='public_ipv4',lease_id=lease['id'],**fixture.network)
            (fixture.e.state/'allocations.sqlite').chmod(0o600)
            observer=customer.AllocationObserver(fixture.e.state,fixture.pve)
            with patch.object(fixture.pve,'guest_fs',return_value=(1,10)):
                self.assertEqual(observer.disk_usage(2,1)['usedBytes'],1)
                fixture.pve.vms[1100]['net1']='virtio=foreign,bridge=vmbr0'
                with self.assertRaises(engine.Refused):observer.disk_usage(2,1)
        finally:fixture.tearDown()

    def test_standalone_allocation_observer_import_has_no_engine_or_ipam_constructor_dependency(self):
        import subprocess
        import sys
        source=Path(engine.__file__).resolve().parent
        code="import sys;sys.path.insert(0,"+repr(str(source))+");import allocation_observer;assert 'engine' not in sys.modules;assert 'ipam' not in sys.modules"
        subprocess.run([sys.executable,'-c',code],check=True,capture_output=True,text=True)


if __name__=='__main__':unittest.main()
