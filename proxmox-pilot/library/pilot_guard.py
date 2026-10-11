#!/usr/bin/python
import glob
import ipaddress
import os
import re
import shutil
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.pilot import (VMProvisioner, repository_edits, require,
                                       validate_network_files)


def main():
    module = AnsibleModule(argument_spec={"config": {"type": "dict", "required": True},
                                          "public_key": {"type": "str", "required": True},
                                          "legacy_expected": {"type": "str", "required": True}})
    def run(argv):
        rc, out, err = module.run_command(argv)
        require(rc == 0, "{}: {} {}".format(" ".join(argv[:4]), out, err))
        return out
    def read(path):
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    try:
        c = module.params["config"]
        provisioner = VMProvisioner(c, module.params["public_key"], run)
        require(os.geteuid() == 0, "Нужен SSH-доступ root на Proxmox")
        require(os.path.exists("/dev/kvm"), "Отсутствует /dev/kvm; проверьте VT-x/AMD-V")
        require("VERSION_CODENAME=trixie" in read("/etc/os-release"), "Ожидается Debian 13 trixie")
        require(re.search(r"pve-manager/9\.", run(["pveversion"])), "Ожидается Proxmox VE 9")
        require(run(["hostname", "-s"]).strip() == c["node"], "Имя node отличается")
        require(os.path.exists("/usr/share/keyrings/proxmox-archive-keyring.gpg"), "Нет ключа репозиториев PVE")
        require(not os.path.exists("/etc/network/interfaces.new"),
                "Есть отложенные изменения сети interfaces.new. Сначала разберите их в GUI.")
        main_network = read("/etc/network/interfaces")
        includes = {p: read(p) for p in glob.glob("/etc/network/interfaces.d/*") if os.path.isfile(p)}
        legacy = validate_network_files(c, main_network, includes, module.params["legacy_expected"])
        import json
        addresses = json.loads(run(["ip", "-j", "address", "show"]))
        nics = {row["ifname"]: row for row in addresses}
        require(c["physical_nic"] in nics and
                nics[c["physical_nic"]]["address"].lower() == c["physical_mac"],
                "Не совпадает MAC физической карты")
        require(any(a.get("local") == c["public_ip"] for a in nics.get(c["uplink"], {}).get("addr_info", [])),
                "На публичном bridge нет ожидаемого IP")
        routes = json.loads(run(["ip", "-j", "route", "show"]))
        require(any(r.get("dst") == "default" and r.get("gateway") == c["public_gateway"]
                    and r.get("dev") == c["uplink"] for r in routes), "Не совпадает default route")
        subnet = ipaddress.ip_network(c["subnet"])
        for route in routes:
            dst = route.get("dst", "default")
            if dst != "default" and route.get("dev") != c["bridge"]:
                require(not subnet.overlaps(ipaddress.ip_network(dst)), "Частная сеть пересекает существующий маршрут")
        for addr in nics.get(c["bridge"], {}).get("addr_info", []):
            if addr.get("family") == "inet":
                require(addr["local"] == c["gateway"] and addr["prefixlen"] == subnet.prefixlen,
                        "Существующий private bridge имеет другой IP")
        bridge_ready = any(a.get("local") == c["gateway"] for a in nics.get(c["bridge"], {}).get("addr_info", []))
        for path in ("/etc/pve/firewall/cluster.fw", "/etc/pve/nodes/{}/host.fw".format(c["node"])):
            if os.path.exists(path):
                text = read(path)
                options = re.search(r"(?ms)^\[OPTIONS\]\s*\n(.*?)(?=^\[|\Z)", text)
                require(not options or not re.search(r"(?m)^\s*enable:\s*1\s*$", options[1]),
                        "Включён PVE firewall. Для этого пилота нужны отдельные правила; проект его не отключает.")
        listening = run(["ss", "-H", "-lnt", "sport", "=", ":" + str(c["vps"]["ssh_port"])])
        require(not listening.strip(), "Публичный SSH-порт VPS занят процессом на хосте")
        if shutil.which("iptables-save"):
            nat_rules = run(["iptables-save", "-t", "nat"])
            filter_rules = run(["iptables-save", "-t", "filter"])
            if any(chain in nat_rules + filter_rules for chain in (":PILOT_DNAT ", ":PILOT_SNAT ", ":PILOT_FWD ")):
                require(os.path.exists("/usr/local/sbin/proxmox-pilot-nat") and
                        "# managed-by: proxmox-pilot:v1" in read("/usr/local/sbin/proxmox-pilot-nat"),
                        "Цепочки PILOT_* уже существуют без маркера владельца")
            for rule in nat_rules.splitlines():
                if re.search(r"--dport\s+{}(?:\s|$)".format(c["vps"]["ssh_port"]), rule):
                    require(rule.startswith("-A PILOT_DNAT "), "SSH-порт VPS уже используется другим NAT-правилом")
        repo_paths = ["/etc/apt/sources.list"] + glob.glob("/etc/apt/sources.list.d/*.list") + glob.glob("/etc/apt/sources.list.d/*.sources")
        repository_edits({p: read(p) for p in repo_paths if os.path.isfile(p)})
        local = provisioner.api("/storage/local")
        require(local.get("type") == "dir" and local.get("path") == "/var/lib/vz", "Нестандартный local storage")
        disk = provisioner.api("/storage/" + c["storage"])
        require(disk.get("type") == "lvmthin" and "images" in disk.get("content", "").split(","),
                "local-lvm должен быть LVM-Thin для images")
        status = provisioner.api("/nodes/{}/storage/{}/status".format(c["node"], c["storage"]))
        require(status.get("active"), "local-lvm не активен")
        owned = provisioner.inspect()
        if owned["vps"] is None:
            available_kib = int(re.search(r"(?m)^MemAvailable:\s+(\d+)", read("/proc/meminfo"))[1])
            require(available_kib >= (c["vps"]["memory_mb"] + 2048) * 1024,
                    "Мало свободной RAM для VPS и резерва Proxmox")
            require(c["vps"]["cores"] <= (os.cpu_count() or 1), "VPS требует больше CPU, чем доступно на хосте")
            require(status.get("avail", 0) >= (c["vps"]["disk_gb"] + 5) * 1024 ** 3,
                    "Мало свободного места на local-lvm")
        require(os.statvfs("/var/lib/vz").f_bavail * os.statvfs("/var/lib/vz").f_frsize >= 1024 ** 3,
                "Нужно минимум 1 ГиБ свободного места для cloud image")
        # Avoid creating an IP duplicate even when another VM has a different ID.
        for row in provisioner.api("/cluster/resources", type="vm"):
            if row["type"] == "qemu" and row["node"] == c["node"] and int(row["vmid"]) != c["vps"]["id"]:
                cfg = provisioner.config(row["vmid"])
                require(not any(re.search(r"(?:^|,)ip=" + re.escape(c["vps"]["ip"]) + r"/", str(value))
                                for key, value in cfg.items() if key.startswith("ipconfig")),
                        "IP VPS уже прописан в другой VM")
        module.exit_json(changed=False, legacy_present=legacy, bridge_ready=bridge_ready,
                         summary={"node": c["node"], "vmid": c["vps"]["id"],
                                  "template_exists": owned["template"] is not None,
                                  "vps_exists": owned["vps"] is not None,
                                  "storage_free_gib": round(status.get("avail", 0) / 1024 ** 3, 1)})
    except (OSError, ValueError, KeyError, TypeError) as exc:
        module.fail_json(msg=str(exc))


if __name__ == "__main__":
    main()
