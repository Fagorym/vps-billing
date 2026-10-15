import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
import test_engine as fixtures
from test_ipam import POOL

class NetworkMigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.old=json.loads((fixtures.ROOT/'config.json').read_text());self.old['template_marker']='test'
        self.pve=fixtures.FakePVE(self.old)
        self.engine=fixtures.engine.Engine(self.old,self.root/'state',self.root/'snippets',self.pve)
        self.engine.handle({'action':'create','order_id':1,'client_id':2,'plan':'mini','ssh_key':fixtures.KEY})
        self.engine.db.close();self.path=self.root/'config.json';self.path.write_text(json.dumps(self.old))
        self.new={**self.old,'public_ip':POOL['host_ip'],'public_network':{**POOL,'enabled':False}}
    def tearDown(self):self.temp.cleanup()
    def migrate(self,candidate=None,apply=False):
        path=fixtures.ROOT/'backend/network_migrate.py'
        self.assertTrue(path.exists(),'Sealed config migration is missing')
        import network_migrate
        return network_migrate.migrate(self.path,self.root/'state',candidate or self.new,self.pve,apply=apply)
    def test_check_does_not_change_live_config_or_seal(self):
        seal=(self.root/'state/config.sha256').read_bytes();config=self.path.read_bytes()
        result=self.migrate();self.assertEqual(result['allocations'],1)
        self.assertEqual(self.path.read_bytes(),config);self.assertEqual((self.root/'state/config.sha256').read_bytes(),seal)
    def test_migrate_preserves_nat_slot_and_rejects_storage_changes(self):
        with self.assertRaises(ValueError):self.migrate({**self.new,'storage':'foreign'},True)
        self.migrate(apply=True)
        reopened=fixtures.engine.Engine(self.new,self.root/'state',self.root/'snippets',self.pve)
        try:
            info=reopened.handle({'action':'status','order_id':1,'client_id':2})
            self.assertEqual((info['vmid'],info['private_ip'],info['ssh_port']),(1100,'10.10.10.20',22220))
            self.assertEqual(info['public_ip'],'198.51.100.2')
        finally:reopened.db.close()
    def test_foreign_guest_change_blocks_migration(self):
        self.pve.vms[1100]['net1']='virtio,bridge=foreign'
        with self.assertRaises(ValueError):self.migrate(apply=True)
        self.assertEqual(json.loads(self.path.read_text()),self.old)
    def test_interrupted_seal_write_rolls_forward_same_candidate(self):
        import network_migrate
        original=network_migrate.atomic_write
        failed=[False]
        def write(path,data,*args):
            if Path(path).name=='config.sha256' and not failed[0]:failed[0]=True;raise OSError('crash')
            return original(path,data,*args)
        with patch.object(network_migrate,'atomic_write',side_effect=write),self.assertRaises(OSError):self.migrate(apply=True)
        self.assertTrue(self.migrate(apply=True)['changed'])
        self.assertFalse((self.root/'state/network-migration.pending.json').exists())
