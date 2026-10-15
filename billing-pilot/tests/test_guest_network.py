import importlib.util
from pathlib import Path
import unittest
from test_ipam import POOL

class NetworkGuardTests(unittest.TestCase):
    def setUp(self):
        path = Path(__file__).resolve().parents[1]/'backend/guest_network.py'
        self.assertTrue(path.exists(), 'Public network enforcement is missing')
        spec = importlib.util.spec_from_file_location('guest_network', path)
        self.network = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.network)
        self.config = {'vm_first':1100, 'ip_first':'10.10.10.20', 'gateway':'10.10.10.1', 'public_network':POOL}
        self.row = {'order_id':1,'client_id':2,'slot':0}

    def test_guest_has_only_public_default_route_and_stable_mac_matches(self):
        config = self.network.guest_config(self.row, {'address':'198.51.100.3'}, self.config)
        interfaces = config['network']['ethernets']
        self.assertEqual(interfaces['private']['addresses'], ['10.10.10.20/24'])
        self.assertNotIn('routes', interfaces['private'])
        self.assertEqual(interfaces['public']['routes'], [{'to':'default','via':'198.51.100.1'}])
        self.assertEqual(interfaces['public']['addresses'], ['198.51.100.3/29'])

    def test_guard_rejects_shell_injection_and_unleased_address(self):
        for address in ('198.51.100.3; flush ruleset','127.0.0.1','198.51.100.1','198.51.100.2','198.51.100.99'):
            with self.subTest(address=address), self.assertRaises(ValueError):
                self.network.guard(self.row, {'address':address}, self.config)

    def test_apply_refuses_changed_foreign_netplan_without_mutating_it(self):
        import tempfile
        with tempfile.TemporaryDirectory() as root:
            folder = Path(root)/'etc/netplan'
            folder.mkdir(parents=True)
            (folder/'10-customer.yaml').write_text('network: {}')
            with self.assertRaises(ValueError):
                self.network.write_guest_config(self.network.guest_config(self.row, {'address':'198.51.100.3'}, self.config), Path(root))
            self.assertEqual((folder/'10-customer.yaml').read_text(), 'network: {}')
