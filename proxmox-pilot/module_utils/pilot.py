"""Validation and resumable VM provisioning. No third-party target dependencies."""
import hashlib
import ipaddress
import json
import re
from urllib.parse import urlparse


OWNER = "proxmox-pilot:v1"
NETWORK_BEGIN = "# BEGIN PROXMOX-PILOT PRIVATE BRIDGE"
NETWORK_END = "# END PROXMOX-PILOT PRIVATE BRIDGE"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate(config, public_key):
    vps = config["vps"]
    subnet = ipaddress.ip_network(config["subnet"], strict=True)
    require(subnet.version == 4 and subnet.is_private, "Нужна частная IPv4-подсеть")
    gateway, guest = (ipaddress.ip_address(config["gateway"]),
                      ipaddress.ip_address(vps["ip"]))
    require(gateway in subnet and guest in subnet and gateway != guest,
            "IP VPS и gateway должны отличаться и входить в подсеть")
    require(gateway not in (subnet.network_address, subnet.broadcast_address)
            and guest not in (subnet.network_address, subnet.broadcast_address),
            "Нельзя использовать адрес сети или broadcast")
    public = ipaddress.ip_interface(config["public_cidr"])
    require(str(public.ip) == config["public_ip"] and public.version == 4,
            "public_ip не совпадает с public_cidr")
    require(not subnet.overlaps(public.network), "Частная сеть пересекает публичную")
    require(ipaddress.ip_address(config["public_gateway"]) in public.network,
            "Публичный gateway вне сети")
    ipaddress.IPv4Address(config["dns"])
    for key in ("bridge", "uplink", "physical_nic"):
        require(re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_-]{0,14}", config[key]),
                "Некорректное имя интерфейса: " + key)
    require(config["bridge"] != config["uplink"], "Частный и публичный bridge совпадают")
    require(re.fullmatch(r"[a-zA-Z][a-zA-Z0-9-]*", config["node"]), "Некорректное имя node")
    require(config["storage"] == "local-lvm", "Этот пилот рассчитан на local-lvm")
    require(re.fullmatch(r"[a-z][a-z0-9-]{0,62}", vps["name"]), "Некорректное имя VPS")
    require(re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", vps["user"])
            and vps["user"] != "root", "Нужен отдельный пользователь VPS")
    for value in (config["template_id"], vps["id"]):
        require(type(value) is int and 100 <= value <= 999999999, "Некорректный VMID")
    require(config["template_id"] != vps["id"], "VMID шаблона и VPS совпадают")
    for name, low, high in (("cores", 1, 8), ("memory_mb", 512, 32768),
                            ("disk_gb", 4, 1000), ("ssh_port", 1024, 65535)):
        require(type(vps[name]) is int and low <= vps[name] <= high,
                "Некорректное значение " + name)
    require(vps["ssh_port"] not in (8006,), "Порт занят панелью Proxmox")
    require(re.fullmatch(r"[0-9a-f]{64}", config["image_sha256"]), "Нужен SHA256 образа")
    image = urlparse(config["image_url"])
    require(image.scheme == "https" and image.netloc == "cloud-images.ubuntu.com",
            "Ожидается официальный Ubuntu cloud image по HTTPS")
    require(config["image_path"].startswith("/var/lib/proxmox-pilot/")
            and ".." not in config["image_path"], "Некорректный путь образа")
    require(re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/=]+(?: [^\r\n]+)?", public_key),
            "Нужен один открытый SSH Ed25519 ключ")
    require(re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", config["physical_mac"]),
            "Некорректный MAC физической карты")


def fingerprint(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def markers(config, public_key):
    source = {key: config[key] for key in ("image_sha256", "storage", "bridge")}
    source["format"] = "ovmf-q35-scsi-v1"
    guest = {"template": source, "vps": config["vps"], "gateway": config["gateway"],
             "subnet": config["subnet"], "dns": config["dns"],
             "public_ip": config["public_ip"], "key": " ".join(public_key.split()[:2])}
    return {"template": OWNER + ":template:" + fingerprint(source),
            "vps": OWNER + ":vps:" + fingerprint(guest)}


def fields(stanza):
    result = {}
    last = None
    for line in stanza.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line[0].isspace() and last:
            result[last] += " " + line.strip()
        elif ":" in line:
            last, value = line.split(":", 1)
            last = last.lower()
            result[last] = value.strip()
    return result


def repository_edits(files):
    """Disable subscription-only sources, preserving all other stanzas."""
    edits = {}
    have_public = False
    for path, text in files.items():
        if path.endswith(".sources"):
            output = []
            for stanza in re.split(r"\n\s*\n", text.strip()):
                data = fields(stanza)
                active = data.get("enabled", "yes").lower() != "no"
                uris = data.get("uris", "").split()
                enterprise = [u for u in uris if urlparse(u).hostname == "enterprise.proxmox.com"]
                if active and enterprise:
                    require(len(enterprise) == len(uris), "Смешанный enterprise stanza: " + path)
                    stanza = re.sub(r"(?im)^Enabled:.*$", "Enabled: no", stanza)
                    if "enabled" not in data:
                        stanza += "\nEnabled: no"
                if active and any(urlparse(u).hostname == "download.proxmox.com"
                                  and urlparse(u).path.rstrip("/") == "/debian/pve" for u in uris):
                    require(data.get("suites") == "trixie"
                            and data.get("components") == "pve-no-subscription",
                            "Неожиданный активный PVE repository: " + path)
                    have_public = True
                output.append(stanza)
            new = "\n\n".join(output) + "\n"
        else:
            output = []
            for line in text.splitlines():
                if re.match(r"^\s*deb(?:-src)?\s", line):
                    if re.search(r"https?://enterprise\.proxmox\.com/", line):
                        line = "# disabled by proxmox-pilot: " + line
                    elif re.search(r"https?://download\.proxmox\.com/debian/pve\s", line):
                        require(re.search(r"\strixie\s+pve-no-subscription(?:\s|$)", line),
                                "Неожиданный активный PVE repository: " + path)
                        have_public = True
                output.append(line)
            new = "\n".join(output) + "\n"
        if new != text:
            edits[path] = new
    if not have_public:
        path = "/etc/apt/sources.list.d/proxmox-pilot.sources"
        require(path not in files, "Существующий proxmox-pilot.sources не содержит нужный repository")
        edits[path] = ("Types: deb\nURIs: http://download.proxmox.com/debian/pve\n"
                       "Suites: trixie\nComponents: pve-no-subscription\n"
                       "Signed-By: /usr/share/keyrings/proxmox-archive-keyring.gpg\n")
    return edits


def interface_stanzas(text):
    result = {}
    current = None
    for line in text.splitlines():
        clean = line.split("#", 1)[0].strip()
        if not clean:
            continue
        match = re.match(r"iface\s+(\S+)\s+inet\s+(\S+)", clean)
        if match:
            current = match[1]
            require(current not in result, "Повторяющийся iface: " + current)
            result[current] = {"method": match[2]}
        elif clean.startswith(("auto ", "source ", "source-directory ", "allow-", "iface ")):
            current = None
        elif current:
            key, _, value = clean.partition(" ")
            result[current][key] = value.strip()
    return result


def validate_network_files(config, main, includes, legacy_expected):
    require("source /etc/network/interfaces.d/*" in main,
            "Ожидается стандартный source /etc/network/interfaces.d/*")
    public = interface_stanzas(main).get(config["uplink"], {})
    require(public.get("address") == config["public_cidr"]
            and public.get("gateway") == config["public_gateway"]
            and public.get("bridge-ports") == config["physical_nic"],
            "Публичная сеть отличается от конфигурации пилота; ничего не меняем")
    private = interface_stanzas(main).get(config["bridge"])
    if private:
        require(NETWORK_BEGIN in main and NETWORK_END in main,
                "В основном interfaces уже есть чужой " + config["bridge"])
        require(private.get("bridge-ports") == "none", "Частный bridge связан с физической картой")
    legacy = "/etc/network/interfaces.d/vps-pilot"
    for path, text in includes.items():
        if path == legacy:
            normalize = lambda t: [s.strip() for s in t.splitlines() if s.strip()]
            require(normalize(text) == normalize(legacy_expected),
                    "vps-pilot отличается от прежней ручной конфигурации; удалять его нельзя")
        else:
            require(config["bridge"] not in interface_stanzas(text),
                    "Частный bridge уже задан в другом файле: " + path)
    return legacy in includes


def disk_size_gb(disk):
    match = re.search(r"(?:^|,)size=([0-9.]+)([KMGT])(?:,|$)", disk)
    require(match, "Не удалось определить размер диска VM")
    return float(match[1]) * {"K": 1 / 1048576, "M": 1 / 1024, "G": 1, "T": 1024}[match[2]]


class VMProvisioner:
    """Only operates on IDs carrying the exact desired ownership marker."""
    def __init__(self, config, public_key, run):
        validate(config, public_key)
        self.c, self.key, self.run = config, public_key, run
        self.owned = markers(config, public_key)
        self.changed = False

    def api(self, path, **params):
        argv = ["pvesh", "get", path, "--output-format", "json"]
        for key, value in params.items():
            argv += ["--" + key, str(value)]
        return json.loads(self.run(argv))

    def config(self, vmid):
        return self.api("/nodes/{}/qemu/{}/config".format(self.c["node"], vmid))

    def status(self, vmid):
        return self.api("/nodes/{}/qemu/{}/status/current".format(self.c["node"], vmid))["status"]

    def mutate(self, *argv):
        self.changed = True  # A failed CLI operation can already have allocated a volume.
        result = self.run(list(argv))
        return result

    def inspect(self):
        guests = self.api("/cluster/resources", type="vm")
        ids = {int(g["vmid"]): g for g in guests}
        result = {}
        for kind, vmid in (("template", self.c["template_id"]), ("vps", self.c["vps"]["id"])):
            if vmid not in ids:
                result[kind] = None
                continue
            row = ids[vmid]
            require(row["type"] == "qemu" and row["node"] == self.c["node"],
                    "VMID {} занят другим ресурсом".format(vmid))
            cfg = self.config(vmid)
            require(cfg.get("description") == self.owned[kind],
                    "VMID {} уже существует: чужая VM или изменённые параметры. Ничего не удаляем.".format(vmid))
            require(not cfg.get("lock"), "VM {} заблокирована: {}".format(vmid, cfg.get("lock")))
            require(kind != "vps" or not cfg.get("template"), "VM VPS стала шаблоном")
            require(cfg.get("bios") == "ovmf" and cfg.get("machine") == "q35"
                    and cfg.get("scsihw") == "virtio-scsi-single", "Изменена виртуальная платформа VM")
            net = cfg.get("net0", "").split(",")
            require(net[0].startswith("virtio=") and "bridge=" + self.c["bridge"] in net
                    and "firewall=1" not in net, "Изменена сеть VM")
            require(not any(re.fullmatch(r"net[1-9][0-9]*", k) for k in cfg),
                    "У VM появилась дополнительная сеть")
            for disk in ("scsi0", "efidisk0", "ide2"):
                if disk in cfg:
                    volume = cfg[disk].split(",")[0]
                    require(re.fullmatch(re.escape(self.c["storage"]) +
                                         r":(?:vm|base)-" + str(vmid) + r"-[a-z0-9-]+", volume),
                            "VM {} использует неожиданный том {}".format(vmid, volume))
            require(not any(re.fullmatch(r"(?:scsi|sata|virtio|ide)[0-9]+", k)
                            and k not in ("scsi0", "ide2") for k in cfg),
                    "У управляемой VM появились дополнительные диски")
            result[kind] = cfg
        return result

    def ensure_template(self, cfg):
        c, vmid = self.c, self.c["template_id"]
        if cfg is None:
            self.mutate("qm", "create", str(vmid), "--name", "ubuntu-noble-pilot", "--memory", "1024",
                        "--cores", "1", "--bios", "ovmf", "--machine", "q35",
                        "--scsihw", "virtio-scsi-single", "--serial0", "socket", "--vga", "serial0",
                        "--agent", "enabled=1", "--net0", "virtio,bridge=" + c["bridge"] + ",firewall=0",
                        "--efidisk0", c["storage"] + ":1,efitype=4m,pre-enrolled-keys=0",
                        "--ide2", c["storage"] + ":cloudinit", "--tags", "ansible-pilot",
                        "--description", self.owned["template"])
            cfg = self.config(vmid)
        if cfg.get("template"):
            require("scsi0" in cfg, "У шаблона отсутствует системный диск")
            return
        require(self.status(vmid) == "stopped", "Шаблон запущен; остановите его вручную")
        if "scsi0" not in cfg:
            unused = [key for key in cfg if re.fullmatch(r"unused[0-9]+", key)]
            require(len(unused) <= 1, "У шаблона несколько неиспользуемых дисков")
            if not unused:
                self.mutate("qm", "disk", "import", str(vmid), c["image_path"], c["storage"])
                cfg = self.config(vmid)
                unused = [key for key in cfg if re.fullmatch(r"unused[0-9]+", key)]
            require(len(unused) == 1, "Импорт не создал один unused-диск")
            volume = cfg[unused[0]].split(",")[0]
            require(volume.startswith(c["storage"] + ":vm-" + str(vmid) + "-disk-"),
                    "Неожиданный импортированный диск")
            self.mutate("qm", "set", str(vmid), "--scsi0", volume + ",discard=on,iothread=1")
        self.mutate("qm", "set", str(vmid), "--boot", "order=scsi0", "--protection", "1")
        self.mutate("qm", "template", str(vmid))

    def desired_guest(self):
        c, v = self.c, self.c["vps"]
        return {"name": v["name"], "cores": str(v["cores"]), "memory": str(v["memory_mb"]),
                "sockets": "1", "cpu": "host", "onboot": "1", "protection": "1",
                "ciuser": v["user"], "ciupgrade": "0", "nameserver": c["dns"],
                "ipconfig0": "ip={}/{},gw={}".format(v["ip"], ipaddress.ip_network(c["subnet"]).prefixlen, c["gateway"]),
                "cicustom": "user=local:snippets/proxmox-pilot-{}-user.yaml".format(v["id"])}

    def ensure_guest(self, cfg):
        c, vmid = self.c, self.c["vps"]["id"]
        if cfg is None:
            self.mutate("qm", "clone", str(c["template_id"]), str(vmid), "--full", "1",
                        "--storage", c["storage"], "--name", c["vps"]["name"],
                        "--description", self.owned["vps"])
            cfg = self.config(vmid)
        require("scsi0" in cfg, "У VPS отсутствует системный диск")
        require(cfg.get("bios") == "ovmf" and cfg.get("machine") == "q35", "Изменён BIOS/machine VPS")
        require("bridge=" + c["bridge"] in cfg.get("net0", "").split(",")
                and "firewall=1" not in cfg.get("net0", "").split(","), "Изменена сеть VPS")
        desired = self.desired_guest()
        changes = {key: value for key, value in desired.items() if str(cfg.get(key, "")) != value}
        size = disk_size_gb(cfg["scsi0"])
        require(size <= c["vps"]["disk_gb"], "Диск VPS больше заданного; уменьшать его нельзя")
        running = self.status(vmid) != "stopped"
        require(not running or (not changes and size == c["vps"]["disk_gb"]),
                "Запущенная VPS отличается от заданных параметров; остановите её вручную")
        if changes:
            argv = ["qm", "set", str(vmid)]
            for key, value in changes.items():
                argv += ["--" + key, value]
            self.mutate(*argv)
        if size < c["vps"]["disk_gb"]:
            self.mutate("qm", "disk", "resize", str(vmid), "scsi0", str(c["vps"]["disk_gb"]) + "G")
        if changes:
            self.mutate("qm", "cloudinit", "update", str(vmid))
        if not running:
            self.mutate("qm", "start", str(vmid))

    def apply(self):
        existing = self.inspect()
        self.ensure_template(existing["template"])
        self.ensure_guest(existing["vps"])
        return self.changed
