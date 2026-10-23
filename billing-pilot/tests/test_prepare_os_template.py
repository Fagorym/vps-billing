import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('prepare_os_template', Path(__file__).resolve().parents[1] / 'tools/prepare-os-template.py')
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


class GuestAgentSetupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / 'etc/sysconfig/qemu-ga'
        self.path.parent.mkdir(parents=True)

    def test_allowlist_adds_only_execution_rpcs_and_preserves_other_settings(self):
        self.path.write_text('# vendor defaults\nFILTER_RPC_ARGS="--allow-rpcs=guest-ping,guest-info"\nFSFREEZE_HOOK_PATHNAME=/etc/qemu-ga/fsfreeze-hook\n')
        prepare.enable_guest_exec(self.root)
        self.assertEqual(self.path.read_text(), '# vendor defaults\nFILTER_RPC_ARGS="--allow-rpcs=guest-ping,guest-info,guest-exec,guest-exec-status"\nFSFREEZE_HOOK_PATHNAME=/etc/qemu-ga/fsfreeze-hook\n')
        previous = self.path.read_bytes()
        prepare.enable_guest_exec(self.root)
        self.assertEqual(self.path.read_bytes(), previous)

    def test_blocklist_retains_file_rpc_restrictions(self):
        self.path.write_text('FILTER_RPC_ARGS="--block-rpcs=guest-file-open,guest-exec,guest-exec-status,guest-file-write"\n')
        prepare.enable_guest_exec(self.root)
        self.assertEqual(self.path.read_text(), 'FILTER_RPC_ARGS="--block-rpcs=guest-file-open,guest-file-write"\n')

    def test_unexpected_or_ambiguous_settings_are_not_rewritten(self):
        for value in ('FILTER_RPC_ARGS="--other=guest-ping"\n', 'FILTER_RPC_ARGS="--allow-rpcs=guest-ping"\nFILTER_RPC_ARGS="--allow-rpcs=guest-info"\n'):
            with self.subTest(value=value):
                self.path.write_text(value)
                with self.assertRaises(ValueError):
                    prepare.enable_guest_exec(self.root)
                self.assertEqual(self.path.read_text(), value)

    def test_empty_resulting_blocklist_is_idempotent(self):
        self.path.write_text('FILTER_RPC_ARGS="--block-rpcs=guest-exec,guest-exec-status"\n')
        prepare.enable_guest_exec(self.root)
        prepare.enable_guest_exec(self.root)
        self.assertEqual(self.path.read_text(), 'FILTER_RPC_ARGS="--block-rpcs="\n')

    def test_symlink_is_not_followed(self):
        target = self.root / 'operator-config'
        target.write_text('FILTER_RPC_ARGS="--allow-rpcs=guest-ping"\n')
        self.path.symlink_to(target)
        with self.assertRaises(ValueError):
            prepare.enable_guest_exec(self.root)
        self.assertEqual(target.read_text(), 'FILTER_RPC_ARGS="--allow-rpcs=guest-ping"\n')


class MachineIdentityTests(unittest.TestCase):
    def test_cleaned_template_has_first_boot_marker_with_public_read_permissions(self):
        for previous in (None, '0123456789abcdef0123456789abcdef\n'):
            with self.subTest(previous=previous), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                path = root / 'etc/machine-id'
                path.parent.mkdir()
                if previous:
                    path.write_text(previous)
                prepare.reset_machine_identity(root)
                self.assertEqual(path.read_text(), 'uninitialized\n')
                self.assertEqual(path.stat().st_mode & 0o777, 0o644)

    def test_does_not_follow_machine_identity_symlink(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            path = root / 'etc/machine-id'
            path.parent.mkdir()
            target = root / 'operator-id'
            target.write_text('keep\n')
            path.symlink_to(target)
            with self.assertRaises(ValueError):
                prepare.reset_machine_identity(root)
            self.assertEqual(target.read_text(), 'keep\n')
