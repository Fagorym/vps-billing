#!/usr/bin/python3
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.pilot import VMProvisioner, validate, require

def main():
    module = AnsibleModule(argument_spec={'config': {'type': 'dict', 'required': True},
                                          'public_key': {'type': 'str', 'required': True}})
    def run(argv):
        rc, out, err = module.run_command(argv)
        require(rc == 0, 'Не удалось проверить Proxmox')
        return out
    try:
        c, key = module.params['config'], module.params['public_key']
        validate(c, key)
        p = VMProvisioner(c, key, run)
        existing = p.inspect()
        require(existing['template'] is not None, 'Сначала запустите proxmox-pilot')
        if existing['vps'] is None:
            node = p.api('/nodes/' + c['node'] + '/status')
            used = sum(int(v.get('maxmem', 0)) for v in p.api('/cluster/resources', type='vm')
                       if v['node'] == c['node'] and not v.get('template'))
            require(used + c['vps']['memory_mb'] * 1048576 <= node['memory']['total'] - 2 * 1073741824,
                    'Недостаточно RAM для VM биллинга и резерва хоста')
            storage = p.api('/nodes/' + c['node'] + '/storage/' + c['storage'] + '/status')
            require(storage['avail'] >= (c['vps']['disk_gb'] + 5) * 1073741824, 'Недостаточно места для биллинга')
        module.exit_json(changed=False)
    except (ValueError, KeyError, TypeError) as exc:
        module.fail_json(msg=str(exc))

if __name__ == '__main__':
    main()
