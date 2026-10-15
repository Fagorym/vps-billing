"""Behavioral lease tests: no duplicates, stale owners, or timed-out payments."""
import concurrent.futures
import importlib.util
from pathlib import Path
import sqlite3
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
ACCOUNT = "11111111-1111-4111-8111-111111111111"
POOL = {"enabled": True, "pool_id": "selectel-spb4", "cidr": "198.51.100.0/29", "gateway": "198.51.100.1", "bridge": "vmbr0", "host_ip": "198.51.100.2", "reserved": ["198.51.100.4", "198.51.100.5", "198.51.100.6"]}

class IpamTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "state.sqlite"
        self.now = 1000
        self.db = sqlite3.connect(self.path, timeout=5)
        self.db.row_factory = sqlite3.Row
        path = ROOT / "backend/ipam.py"
        self.assertTrue(path.exists(), "Durable IPv4 allocator has not been implemented")
        spec = importlib.util.spec_from_file_location("public_ipam", path)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.ipam = self.module.Ipam(self.db, POOL, lambda: self.now)
        self.ref = str(uuid.uuid4())

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def test_reserve_is_idempotent_and_excludes_gateway_host_reserved(self):
        lease = self.ipam.reserve(ACCOUNT, self.ref)
        self.assertEqual(lease["address"], "198.51.100.3")
        self.assertEqual(self.ipam.reserve(ACCOUNT, self.ref), lease)
        self.assertEqual(self.ipam.capacity()["free"], 0)
        with self.assertRaises(ValueError):
            self.ipam.reserve(ACCOUNT, str(uuid.uuid4()))
        with self.assertRaises(ValueError):
            self.ipam.reserve(str(uuid.uuid4()), self.ref)

    def test_only_one_concurrent_buyer_gets_last_address(self):
        def reserve(_):
            db = sqlite3.connect(self.path, timeout=5); db.row_factory = sqlite3.Row
            try:
                allocator = self.module.Ipam(db, POOL, lambda: self.now)
                return allocator.reserve(str(uuid.uuid4()), str(uuid.uuid4()))["address"]
            except ValueError:
                return None
            finally:
                db.close()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as workers:
            results = list(workers.map(reserve, range(2)))
        self.assertEqual(results.count("198.51.100.3"), 1)
        self.assertEqual(results.count(None), 1)

    def test_expiry_never_releases_dispatched_payment(self):
        lease = self.ipam.reserve(ACCOUNT, self.ref)
        self.ipam.payment_pending(ACCOUNT, self.ref, lease["id"])
        self.now += 3600
        self.assertEqual(self.ipam.capacity()["held"], 1)
        with self.assertRaises(ValueError):
            self.ipam.reserve(ACCOUNT, str(uuid.uuid4()))
        self.assertFalse(self.ipam.release_hold(ACCOUNT, self.ref, lease["id"]))

    def test_unpaid_expiry_issues_new_generation_and_rejects_stale_bind(self):
        old = self.ipam.reserve(ACCOUNT, self.ref)
        self.now += 901
        new = self.ipam.reserve(ACCOUNT, self.ref)
        self.assertNotEqual(old["id"], new["id"])
        self.assertGreater(new["generation"], old["generation"])
        with self.assertRaises(ValueError):
            self.ipam.bind(ACCOUNT, self.ref, old["id"], 1, 2)
        self.assertEqual(self.ipam.bind(ACCOUNT, self.ref, new["id"], 1, 2)["state"], "assigned")

    def test_release_requires_isolation_and_old_lease_cannot_release_new_owner(self):
        lease = self.ipam.reserve(ACCOUNT, self.ref)
        self.ipam.bind(ACCOUNT, self.ref, lease["id"], 1, 2)
        with self.assertRaises(ValueError):
            self.ipam.release_assigned(1, 2, lease["id"], isolated=False)
        self.assertEqual(self.ipam.capacity()["free"], 0)
        self.ipam.release_assigned(1, 2, lease["id"], isolated=True)
        newer = self.ipam.reserve(str(uuid.uuid4()), str(uuid.uuid4()))
        self.ipam.release_assigned(1, 2, lease["id"], isolated=True)
        self.assertEqual(self.ipam.capacity()["held"], 1)
        self.assertNotEqual(newer["id"], lease["id"])

    def test_pool_mutation_with_existing_history_is_refused(self):
        self.ipam.reserve(ACCOUNT, self.ref)
        with self.assertRaises(ValueError):
            self.module.Ipam(self.db, {**POOL, "gateway": "198.51.100.6"})

    def test_private_and_multicast_pools_are_refused(self):
        for cidr,gw,host in [('10.0.0.0/29','10.0.0.1','10.0.0.2'),('127.0.0.0/29','127.0.0.1','127.0.0.2'),('224.0.0.0/29','224.0.0.1','224.0.0.2')]:
            with self.subTest(cidr=cidr),self.assertRaises(ValueError):
                with sqlite3.connect(':memory:') as fresh:
                    fresh.row_factory=sqlite3.Row
                    self.module.Ipam(fresh,{'enabled':True,'pool_id':'private','cidr':cidr,'gateway':gw,'host_ip':host,'bridge':'vmbr0'})
