"""Public endpoint/lifecycle tests run the real allocator and engine with fake PVE."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))
import test_engine as fixtures
engine = fixtures.engine
from test_ipam import ACCOUNT, POOL
import json
import unittest
import uuid
import subprocess
from types import SimpleNamespace
from unittest.mock import patch
import guest_network

class PublicEngineTests(unittest.TestCase):
    handle = fixtures.EngineTests.handle
    tearDown = fixtures.EngineTests.tearDown
    def setUp(self):
        fixtures.EngineTests.setUp(self)
        self.e.db.close()
        (Path(self.temp.name)/'state/config.sha256').unlink()
        self.config['public_network'] = POOL
        self.e = engine.Engine(self.config, Path(self.temp.name)/'state', Path(self.temp.name)/'snippets', self.pve)
        self.ref = str(uuid.uuid4())
        self.network = {'account': ACCOUNT, 'reference': self.ref}
        self.pve.network_guard = lambda *args: None
        self.pve.public_ready = lambda ip: True
        self.pve.apply_public_network = lambda *args: None

    def reserve_ip(self):
        return self.e.handle({'action':'network_reserve', **self.network})

    def public_create(self):
        lease = self.reserve_ip()
        return self.handle('create', network_mode='public_ipv4', lease_id=lease['id'], **self.network)

    def test_public_create_exposes_port22_and_only_one_lease(self):
        result = self.public_create()
        self.assertEqual((result['public_ip'], result['ssh_port']), ('198.51.100.3', 22))
        self.assertEqual(result['network_mode'], 'public_ipv4')
        self.assertEqual(self.public_create(), result)
        cfg = self.pve.config(1100)
        self.assertEqual(cfg['ipconfig0'], 'ip=10.10.10.20/24')
        self.assertEqual(cfg['ipconfig1'], 'ip=198.51.100.3/29,gw=198.51.100.1')
        self.assertEqual(self.e.handle({'action':'network_capacity'})['assigned'], 1)

    def test_public_create_cannot_invent_lease(self):
        with self.assertRaises(ValueError):
            self.handle('create', network_mode='public_ipv4', lease_id=str(uuid.uuid4()), **self.network)
        self.assertNotIn(1100, self.pve.vms)

    def test_archive_drops_endpoint_then_restore_reacquires(self):
        self.public_create()
        def admin(command):
            return self.handle('admin', command=command, operation_id=str(uuid.uuid4()), reason='public network lifecycle', actor={'account': ACCOUNT, 'email':'operator@example.test'})
        old = self.handle('status')['lease_id']
        archived = admin('archive')
        self.assertIsNone(archived['public_ip'])
        self.assertIsNone(archived['ssh'])
        self.assertNotIn('net1', self.pve.config(1100))
        restored = admin('restore')
        self.assertEqual(restored['phase'], 'ready')
        self.assertNotEqual(restored['lease_id'], old)
        self.assertEqual(restored['ssh_port'], 22)

    def test_stop_keeps_lease_but_cancel_releases_only_after_stop(self):
        self.public_create()
        lease = self.handle('owner_stop')['lease_id']
        self.assertEqual(self.e.handle({'action':'network_capacity'})['free'], 0)
        self.handle('cancel')
        self.assertEqual(self.pve.status(1100), 'stopped')
        self.assertIsNone(self.handle('status')['public_ip'])
        self.assertEqual(self.e.handle({'action':'network_capacity'})['free'], 1)

    def test_restore_waits_for_guest_boot_before_changing_network(self):
        self.public_create()
        context={'reason':'restore after cold boot','actor':{'account':ACCOUNT,'email':'operator@example.test'}}
        self.handle('admin',command='archive',operation_id=str(uuid.uuid4()),**context)
        probes=[]
        def agent(args,**kwargs):
            if args[2]=='cmd':
                probes.append(args)
                return SimpleNamespace(returncode=0 if len(probes)>=3 else 1)
            if len(probes)<3:
                raise subprocess.CalledProcessError(1,args,stderr='QEMU guest agent is not running')
            return SimpleNamespace(stdout=json.dumps({'exitcode':0}))
        self.pve.apply_public_network=engine.Proxmox(self.config).apply_public_network
        with patch.object(guest_network.subprocess,'run',side_effect=agent),patch('time.sleep'):
            restored=self.handle('admin',command='restore',operation_id=str(uuid.uuid4()),**context)
        self.assertEqual(restored['phase'],'ready')
        self.assertEqual(self.pve.status(1100),'running')
        self.assertGreaterEqual(len(probes),3)
        self.assertEqual(self.e.handle({'action':'network_capacity'})['assigned'],1)

    def test_restore_boot_timeout_keeps_archive_and_releases_isolated_lease(self):
        self.public_create()
        context={'reason':'restore boot timeout','actor':{'account':ACCOUNT,'email':'operator@example.test'}}
        self.handle('admin',command='archive',operation_id=str(uuid.uuid4()),**context)
        self.pve.is_ready=False
        calls=[]
        def unavailable(args,**kwargs):
            calls.append(args)
            if args[2]=='cmd':return SimpleNamespace(returncode=1)
            raise subprocess.CalledProcessError(1,args,stderr='QEMU guest agent is not running')
        self.pve.apply_public_network=engine.Proxmox(self.config).apply_public_network
        with patch.object(guest_network.subprocess,'run',side_effect=unavailable),patch('time.monotonic',side_effect=[0,0,181]),patch('time.sleep'):
            with self.assertRaises(OSError):
                self.handle('admin',command='restore',operation_id=str(uuid.uuid4()),**context)
        self.assertTrue(calls)
        self.assertTrue(all(call[2]=='cmd' for call in calls))
        self.assertEqual(self.pve.status(1100),'stopped')
        self.assertEqual(self.handle('status')['phase'],'archived')
        self.assertIsNone(self.handle('status')['public_ip'])
        self.assertEqual(self.e.handle({'action':'network_capacity'})['free'],1)

    def test_lost_detach_response_resumes_archive_without_leaking_lease(self):
        self.public_create()
        command = self.pve.command
        failed = [False]
        def crash(verb, vmid, *args):
            command(verb, vmid, *args)
            if '--delete' in args and not failed[0]:
                failed[0] = True
                raise OSError('lost detach response')
        self.pve.command = crash
        request = {'command':'archive', 'operation_id':str(uuid.uuid4()), 'reason':'archive', 'actor':{'account':ACCOUNT,'email':'operator@example.test'}}
        with self.assertRaises(OSError):
            self.handle('admin', **request)
        self.assertEqual(self.e.handle({'action':'network_capacity'})['free'], 0)
        self.assertEqual(self.handle('admin', **request)['phase'], 'archived')
        self.assertEqual(self.e.handle({'action':'network_capacity'})['free'], 1)

    def test_expired_hold_cannot_reserve_vm_slot(self):
        self.e.ipam.clock = lambda: 1000
        lease = self.reserve_ip()
        self.e.ipam.clock = lambda: 2000
        with self.assertRaises(ValueError):
            self.handle('create', network_mode='public_ipv4', lease_id=lease['id'], **self.network)
        self.assertEqual(self.e.db.execute('SELECT COUNT(*) FROM allocation').fetchone()[0], 0)

    def test_foreign_public_address_is_not_sold(self):
        self.pve.vms[7777]={'_type':'lxc','net0':'name=eth0,ip=198.51.100.3/29'}
        self.assertEqual(self.e.handle({'action':'network_capacity'})['free'],0)
        with self.assertRaises(ValueError):self.reserve_ip()

    def test_restore_network_failure_stops_vm_and_preserves_archive(self):
        self.public_create()
        request={'operation_id':str(uuid.uuid4()),'reason':'network test','actor':{'account':ACCOUNT,'email':'operator@example.test'}}
        self.handle('admin',command='archive',**request)
        def fail(*args):raise OSError('agent unavailable')
        self.pve.apply_public_network=fail
        with self.assertRaises(OSError):self.handle('admin',command='restore',**{**request,'operation_id':str(uuid.uuid4())})
        self.assertEqual(self.pve.status(1100),'stopped')
        self.assertEqual(self.handle('status')['phase'],'archived')
        self.assertEqual(self.e.handle({'action':'network_capacity'})['free'],1)

    def test_public_readiness_waits_for_direct_ssh(self):
        self.public_create()
        self.pve.public_ready=lambda address:False
        self.assertFalse(self.handle('readiness')['ready'])

    def test_purge_removes_network_guard_before_nat_slot_reuse(self):
        self.public_create();removed=[]
        self.pve.remove_network_guard=lambda vmid:removed.append(vmid)
        self.handle('admin',command='purge',confirm_vmid=1100,operation_id=str(uuid.uuid4()),reason='test cleanup',actor={'account':ACCOUNT,'email':'operator@example.test'})
        self.assertEqual(removed,[1100])
        result=self.handle('create',order_id=3)
        self.assertEqual(result['vmid'],1100)
        self.assertEqual(result['ssh_port'],22220)
