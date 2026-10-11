#!/usr/bin/env python3
"""Persistent CLI stub for executing the real Ansible module offline."""
import json
import os
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_pilot import FakePVE


path = Path(os.environ["PILOT_FAKE_STATE"])
pve = FakePVE()
if path.exists():
    state = json.loads(path.read_text())
    pve.vms = {int(key): value for key, value in state["vms"].items()}
    pve.commands = state["commands"]
try:
    output = pve.run([os.path.basename(sys.argv[0]), *sys.argv[1:]])
    path.write_text(json.dumps({"vms": pve.vms, "commands": pve.commands}))
    print(output)
except (ValueError, KeyError, AssertionError) as exc:
    path.write_text(json.dumps({"vms": pve.vms, "commands": pve.commands}))
    print(str(exc), file=sys.stderr)
    sys.exit(1)
