#!/usr/bin/python
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.pilot import VMProvisioner


def main():
    module = AnsibleModule(argument_spec={"config": {"type": "dict", "required": True},
                                          "public_key": {"type": "str", "required": True}})
    def run(argv):
        rc, out, err = module.run_command(argv)
        if rc:
            raise ValueError("{}: {} {}".format(" ".join(argv[:4]), out, err))
        return out
    provisioner = None
    try:
        provisioner = VMProvisioner(module.params["config"], module.params["public_key"], run)
        module.exit_json(changed=provisioner.apply(), vmid=module.params["config"]["vps"]["id"])
    except (ValueError, KeyError, TypeError) as exc:
        module.fail_json(msg=str(exc), changed=bool(provisioner and provisioner.changed))


if __name__ == "__main__":
    main()
