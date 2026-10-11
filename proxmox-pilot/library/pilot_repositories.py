#!/usr/bin/python
import glob
import os
import tempfile
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.pilot import repository_edits


def main():
    module = AnsibleModule(argument_spec={}, supports_check_mode=True)
    paths = ["/etc/apt/sources.list"] + glob.glob("/etc/apt/sources.list.d/*.list") + glob.glob("/etc/apt/sources.list.d/*.sources")
    try:
        files = {path: open(path, encoding="utf-8").read() for path in paths if os.path.isfile(path)}
        edits = repository_edits(files)
        backups = []
        if not module.check_mode:
            for path, content in edits.items():
                if os.path.exists(path):
                    backups.append(module.backup_local(path))
                fd, temporary = tempfile.mkstemp(dir="/etc/apt/sources.list.d")
                with os.fdopen(fd, "w", encoding="utf-8") as output:
                    output.write(content)
                os.chmod(temporary, 0o644)
                module.atomic_move(temporary, path)
        module.exit_json(changed=bool(edits), files=list(edits), backups=backups)
    except (OSError, ValueError) as exc:
        module.fail_json(msg=str(exc))


if __name__ == "__main__":
    main()
