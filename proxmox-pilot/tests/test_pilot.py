import copy
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import yaml
from jinja2 import Environment, FileSystemLoader, StrictUndefined
from module_utils.pilot import (VMProvisioner, disk_size_gb, markers, repository_edits,
                               validate, validate_network_files)


ROOT = Path(__file__).resolve().parents[1]
CONFIG = yaml.safe_load((ROOT / "group_vars/proxmox.yml").read_text())["pilot"]
GUEST_ID = CONFIG["vps"]["id"]
KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICVxZgPnLAIpVBPrZph2PefMEQyw53INofmNiGHKTrYX fixture"
MAIN = f"""auto lo
iface lo inet loopback

iface nic0 inet manual

auto vmbr0
iface vmbr0 inet static
    address {CONFIG['public_cidr']}
    gateway {CONFIG['public_gateway']}
    bridge-ports nic0
    bridge-stp off
    bridge-fd 0

source /etc/network/interfaces.d/*
"""


class FakePVE:
    """In-memory CLI boundary. Represents persisted PVE resources, including failed imports."""
    def __init__(self):
        self.vms = {}
        self.commands = []
        self.fail_import = False
        self.fail_clone = False

    def run(self, argv):
        self.commands.append(argv)
        if argv[0] == "pvesh":
            if argv[2] == "/cluster/resources":
                return json.dumps([{"vmid": vid, "node": "pve1", "type": "qemu"} for vid in self.vms])
            match = re.fullmatch(r"/nodes/pve1/qemu/(\d+)/(config|status/current)", argv[2])
            vm = self.vms[int(match[1])]
            return json.dumps(vm["config"] if match[2] == "config" else {"status": vm["status"]})
        command = argv[1]
        vid = int(argv[3] if command in ("disk", "cloudinit") else argv[2])
        if command == "create":
            opts = dict(zip((s.removeprefix("--") for s in argv[3::2]), argv[4::2]))
            opts["net0"] = opts["net0"].replace("virtio,", "virtio=02:00:00:00:00:01,")
            opts["efidisk0"] = "local-lvm:vm-{}-disk-0,size=4M".format(vid)
            opts["ide2"] = "local-lvm:vm-{}-cloudinit,media=cdrom".format(vid)
            self.vms[vid] = {"config": opts, "status": "stopped"}
        elif command == "clone":
            target = int(argv[3])
            opts = dict(zip((s.removeprefix("--") for s in argv[4::2]), argv[5::2]))
            cfg = copy.deepcopy(self.vms[vid]["config"])
            cfg.pop("template", None)
            for key in ("scsi0", "efidisk0", "ide2"):
                cfg[key] = re.sub(r"(?:vm|base)-{}-".format(vid), "vm-{}-".format(target), cfg[key])
            cfg.update({"name": opts["name"], "description": opts["description"]})
            self.vms[target] = {"config": cfg, "status": "stopped"}
            if self.fail_clone:
                self.fail_clone = False
                raise ValueError("interrupted after clone persisted")
        elif command == "set":
            cfg = self.vms[vid]["config"]
            opts = dict(zip((s.removeprefix("--") for s in argv[3::2]), argv[4::2]))
            if "scsi0" in opts:
                opts["scsi0"] += ",size=3.5G"
                cfg.pop("unused0", None)
            cfg.update(opts)
        elif command == "disk" and argv[2] == "import":
            self.vms[vid]["config"]["unused0"] = "local-lvm:vm-{}-disk-1".format(vid)
            if self.fail_import:
                self.fail_import = False
                raise ValueError("interrupted after import persisted")
        elif command == "disk" and argv[2] == "resize":
            cfg = self.vms[vid]["config"]
            cfg["scsi0"] = re.sub(r"size=[0-9.]+[KMGT]", "size=" + argv[5], cfg["scsi0"])
        elif command == "template":
            cfg = self.vms[vid]["config"]
            cfg["template"] = 1
            for key in ("scsi0", "efidisk0"):
                cfg[key] = cfg[key].replace(":vm-", ":base-")
        elif command == "start":
            self.vms[vid]["status"] = "running"
        elif command != "cloudinit":
            raise AssertionError(argv)
        return ""


class ProvisioningTests(unittest.TestCase):
    def setUp(self):
        self.pve = FakePVE()

    def provisioner(self, config=None):
        return VMProvisioner(config or CONFIG, KEY, self.pve.run)

    def test_create_then_repeat_does_not_clone_import_or_change_again(self):
        self.assertTrue(self.provisioner().apply())
        vm = self.pve.vms[GUEST_ID]
        self.assertEqual(vm["status"], "running")
        self.assertEqual(disk_size_gb(vm["config"]["scsi0"]), 20)
        self.assertEqual(vm["config"]["ipconfig0"], "ip=10.10.10.10/24,gw=10.10.10.1")
        self.assertEqual(vm["config"]["onboot"], "1")
        self.assertEqual(set(self.pve.vms), {GUEST_ID, CONFIG["template_id"]})
        self.pve.commands.clear()
        self.assertFalse(self.provisioner().apply())
        self.assertTrue(all(cmd[0] == "pvesh" for cmd in self.pve.commands))

    def test_refuse_foreign_vmid_before_any_mutation(self):
        self.pve.vms[GUEST_ID] = {"config": {"description": "manual VPS"}, "status": "stopped"}
        with self.assertRaisesRegex(ValueError, "чужая VM"):
            self.provisioner().apply()
        self.assertTrue(all(cmd[0] == "pvesh" for cmd in self.pve.commands))

    def test_resume_import_without_second_volume(self):
        self.pve.fail_import = True
        with self.assertRaisesRegex(ValueError, "interrupted"):
            self.provisioner().apply()
        self.assertTrue(self.provisioner().apply())
        imports = [cmd for cmd in self.pve.commands if cmd[:3] == ["qm", "disk", "import"]]
        self.assertEqual(len(imports), 1)

    def test_resume_persisted_clone_without_duplicate(self):
        self.pve.fail_clone = True
        with self.assertRaisesRegex(ValueError, "interrupted"):
            self.provisioner().apply()
        self.assertTrue(self.provisioner().apply())
        self.assertEqual(sum(cmd[:2] == ["qm", "clone"] for cmd in self.pve.commands), 1)

    def test_refuse_changed_parameters_or_key(self):
        self.provisioner().apply()
        changed = copy.deepcopy(CONFIG)
        changed["vps"]["memory_mb"] = 4096
        with self.assertRaisesRegex(ValueError, "изменённые параметры"):
            self.provisioner(changed).apply()
        with self.assertRaisesRegex(ValueError, "изменённые параметры"):
            VMProvisioner(CONFIG, KEY.replace("TrYX", "TrYa"), self.pve.run).apply()

    def test_refuse_shrink_even_if_marker_unchanged(self):
        self.provisioner().apply()
        self.pve.vms[GUEST_ID]["config"]["scsi0"] = f"local-lvm:vm-{GUEST_ID}-disk-1,size=40G"
        with self.assertRaisesRegex(ValueError, "уменьшать"):
            self.provisioner().apply()

    def test_refuse_locked_vm(self):
        self.provisioner().apply()
        self.pve.vms[GUEST_ID]["config"]["lock"] = "clone"
        with self.assertRaisesRegex(ValueError, "заблокирована"):
            self.provisioner().apply()

    def test_refuse_unexpected_disk_or_public_bridge(self):
        self.provisioner().apply()
        self.pve.vms[GUEST_ID]["config"]["net0"] = "virtio=02:00:00:00:00:01,bridge=vmbr0"
        with self.assertRaisesRegex(ValueError, "сеть"):
            self.provisioner().apply()
        self.pve.vms[GUEST_ID]["config"]["net0"] = "virtio=02:00:00:00:00:01,bridge=vmbr1"
        self.pve.vms[GUEST_ID]["config"]["scsi1"] = f"local-lvm:vm-{GUEST_ID}-disk-5,size=10G"
        with self.assertRaisesRegex(ValueError, "дополнительные диски"):
            self.provisioner().apply()

    def test_started_vm_drift_is_not_applied_live(self):
        self.provisioner().apply()
        self.pve.vms[GUEST_ID]["config"]["memory"] = "1024"
        with self.assertRaisesRegex(ValueError, "Запущенная VPS"):
            self.provisioner().apply()

    def test_stopped_owned_vm_can_start_again(self):
        self.provisioner().apply()
        self.pve.vms[GUEST_ID]["status"] = "stopped"
        self.assertTrue(self.provisioner().apply())
        self.assertEqual(self.pve.vms[GUEST_ID]["status"], "running")


class ConfigurationTests(unittest.TestCase):
    def test_wrapper_and_ansible_resolve_different_host_and_guest_keys(self):
        from ansible.inventory.manager import InventoryManager
        from ansible.parsing.dataloader import DataLoader
        from ansible.playbook.play import Play
        from ansible.template import Templar
        from ansible.vars.manager import VariableManager
        source = importlib.machinery.SourceFileLoader("pilot_cli", str(ROOT / "pilot"))
        module = importlib.util.module_from_spec(importlib.util.spec_from_loader(source.name, source))
        source.exec_module(module)
        with tempfile.TemporaryDirectory() as folder:
            fixture = Path(folder)
            (fixture / 'group_vars').mkdir()
            (fixture / '.secrets').mkdir()
            (fixture / 'group_vars/proxmox.yml').write_text((ROOT / 'group_vars/proxmox.yml').read_text())
            (fixture / 'inventory.yml').write_text((ROOT / 'inventory.yml').read_text())
            (fixture / '.secrets/vps_ed25519.pub').write_text(KEY)
            with patch.object(module, 'ROOT', fixture), patch.object(module, 'bootstrap'), \
                 patch.object(module, 'keys'), patch.object(module, 'authorize'), \
                 patch.object(module, 'execute') as execute, patch.object(sys, 'argv', ['pilot', 'up']), \
                 patch('builtins.print'):
                module.main()
            argv = execute.call_args.args[0]
            extra = json.loads(argv[argv.index('-e') + 1])
            self.assertNotIn('ansible_ssh_private_key_file', extra)
            self.assertNotIn('ansible_ssh_common_args', extra)
            loader = DataLoader()
            loader.set_basedir(str(ROOT))
            inventory = InventoryManager(loader=loader, sources=str(ROOT / 'inventory.yml'))
            inventory.add_group('pilot_guests')
            inventory.add_host('pilot_vps', group='pilot_guests')
            host = inventory.get_host('pve1')
            guest = inventory.get_host('pilot_vps')
            guest.vars['ansible_ssh_private_key_file'] = extra['pilot_guest_key']
            variables = VariableManager(loader=loader, inventory=inventory)
            variables._extra_vars = extra
            data = loader.load_from_file(str(ROOT / 'pilot.yml'), trusted_as_template=True)
            # Only play-level variables are relevant; no action plugins or server tasks run here.
            transport = lambda play: {key: value for key, value in play.items()
                                      if key not in ('pre_tasks', 'post_tasks', 'tasks', 'roles')}
            host_vars = variables.get_vars(play=Play.load(transport(data[0]), loader=loader), host=host)
            guest_vars = variables.get_vars(play=Play.load(transport(data[1]), loader=loader), host=guest)
            self.assertEqual(Templar(loader=loader, variables=host_vars).template(host_vars['ansible_ssh_private_key_file']), extra['pilot_host_key'])
            self.assertEqual(guest_vars['ansible_ssh_private_key_file'], extra['pilot_guest_key'])
            self.assertNotEqual(extra['pilot_host_key'], extra['pilot_guest_key'])

    def test_valid_config_and_unsafe_ports_addresses(self):
        validate(CONFIG, KEY)
        for field, value in (("ip", "10.10.10.1"), ("ip", "10.10.10.0"), ("ssh_port", 22),
                             ("ssh_port", 8006), ("name", "vps;reboot")):
            config = copy.deepcopy(CONFIG)
            config["vps"][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                validate(config, KEY)

    def test_key_comments_do_not_change_ownership(self):
        self.assertEqual(markers(CONFIG, KEY), markers(CONFIG, KEY.replace("fixture", "another comment")))

    def test_manual_drop_in_can_be_migrated_and_different_one_cannot(self):
        legacy = (ROOT / "files/legacy-vps-pilot").read_text()
        self.assertTrue(validate_network_files(CONFIG, MAIN, {"/etc/network/interfaces.d/vps-pilot": legacy}, legacy))
        with self.assertRaisesRegex(ValueError, "отличается"):
            validate_network_files(CONFIG, MAIN, {"/etc/network/interfaces.d/vps-pilot": legacy.replace("10.10.10.1", "10.20.20.1")}, legacy)

    def test_public_network_mismatch_and_foreign_bridge_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "Публичная сеть"):
            validate_network_files(CONFIG, MAIN.replace(f"gateway {CONFIG['public_gateway']}", "gateway 192.0.2.1"), {}, "")
        with self.assertRaisesRegex(ValueError, "чужой"):
            validate_network_files(CONFIG, MAIN + "\niface vmbr1 inet static\n    bridge-ports none\n", {}, "")

    def test_only_enterprise_stanza_is_disabled_and_debian_is_preserved(self):
        debian = "Types: deb\nURIs: https://deb.debian.org/debian\nSuites: trixie\nComponents: main\n"
        enterprise = "Types: deb\nURIs: https://enterprise.proxmox.com/debian/pve\nSuites: trixie\nComponents: pve-enterprise\n"
        files = {"/etc/apt/sources.list.d/mixed.sources": debian + "\n" + enterprise}
        edits = repository_edits(files)
        self.assertTrue(edits[next(iter(files))].startswith(debian))
        self.assertIn("Enabled: no", edits[next(iter(files))])
        self.assertIn("pve-no-subscription", edits["/etc/apt/sources.list.d/proxmox-pilot.sources"])
        files.update(edits)
        self.assertEqual(repository_edits(files), {})

    def test_existing_free_sources_are_not_duplicated(self):
        text = "deb http://download.proxmox.com/debian/pve trixie pve-no-subscription\n"
        self.assertEqual(repository_edits({"/etc/apt/sources.list.d/free.list": text}), {})

    def test_legacy_enterprise_and_ceph_disabled(self):
        text = "deb https://enterprise.proxmox.com/debian/ceph-squid trixie enterprise\n"
        edits = repository_edits({"/etc/apt/sources.list.d/ceph.list": text})
        self.assertIn("# disabled by", edits["/etc/apt/sources.list.d/ceph.list"])

    def test_mixed_uri_stanza_and_wrong_release_are_rejected(self):
        text = "Types: deb\nURIs: https://enterprise.proxmox.com/debian/pve https://deb.debian.org/debian\nSuites: trixie\nComponents: main\n"
        with self.assertRaisesRegex(ValueError, "Смешанный"):
            repository_edits({"mixed.sources": text})
        with self.assertRaisesRegex(ValueError, "Неожиданный"):
            repository_edits({"wrong.list": "deb http://download.proxmox.com/debian/pve bookworm pve-no-subscription\n"})

    def render(self, relative):
        environment = Environment(loader=FileSystemLoader(str(ROOT)), undefined=StrictUndefined)
        environment.filters["to_json"] = json.dumps
        return environment.get_template(relative).render(pilot=CONFIG, pilot_guest_public_key=KEY)

    def test_cloud_init_has_key_only_user_and_guest_agent(self):
        data = yaml.safe_load(self.render("roles/vps/templates/user-data.yml.j2"))
        self.assertFalse(data["ssh_pwauth"])
        self.assertTrue(data["disable_root"])
        user = data["users"][0]
        self.assertEqual(user["name"], "vpsadmin")
        self.assertEqual(user["ssh_authorized_keys"], [KEY])
        self.assertTrue(user["lock_passwd"])
        self.assertIn("qemu-guest-agent", data["packages"])

    def test_nat_is_scoped_and_never_flushes_global_tables(self):
        script = self.render("roles/host/templates/nat.sh.j2")
        subprocess.run(["/bin/sh", "-n"], input=script, text=True, check=True)
        self.assertIn(f"-d {CONFIG['public_ip']}/32 -p tcp --dport 2222", script)
        self.assertIn("--to-destination 10.10.10.10:22", script)
        self.assertIn(f"--ctorigdst {CONFIG['public_ip']} --ctorigdstport 2222", script)
        self.assertNotIn("--dport 8006", script)
        self.assertNotIn("-F FORWARD", script)
        self.assertNotIn("iptables-restore", script)
        self.assertIn('ipt -t "$table" -F "$chain"', script)


if __name__ == "__main__":
    unittest.main()
