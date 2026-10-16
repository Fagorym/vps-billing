#!/usr/bin/python3
"""Rebuild only Safehost bridge tables from canonical leases before VM autostart."""
import json
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
from expand_pool import fingerprint, require
from guest_network import guard


def reload_guards(config_path='/etc/safehost-billing/config.json',state='/var/lib/safehost-billing',pve_configs='/etc/pve/qemu-server'):
    config=json.loads(Path(config_path).read_text());state=Path(state)
    require((state/'config.sha256').read_text().strip()==fingerprint(config),'Конфигурация пула не прошла проверку')
    rules=[]
    tables=subprocess.run(['/usr/sbin/nft','list','tables'],capture_output=True,text=True,check=True,timeout=10).stdout
    for line in tables.splitlines():
        if re.fullmatch(r'table bridge safehost_[0-9]+',line):rules.append('delete '+line)
    with sqlite3.connect('file:'+str(state/'allocations.sqlite')+'?mode=ro',uri=True) as db:
        db.row_factory=sqlite3.Row
        for row in db.execute('SELECT * FROM allocation'):
            spec=json.loads(row['spec'])
            if spec.get('network_mode')!='public_ipv4':continue
            vmid=config['vm_first']+row['slot']
            source=Path(pve_configs)/f'{vmid}.conf'
            if not source.exists():continue
            marker=f'safehost-billing:v1:order:{row["order_id"]}:client:{row["client_id"]}:'+fingerprint(spec)
            # Proxmox stores descriptions as encoded comments. Its local API
            # provides the same canonical ownership value used by the engine.
            vm=json.loads(subprocess.check_output(['/usr/bin/pvesh','get',f'/nodes/{config["node"]}/qemu/{vmid}/config','--output-format','json'],text=True,timeout=15))
            require(vm.get('description')==marker and not vm.get('template'),'VMID занят чужой VM; запуск остановлен')
            lease=db.execute('SELECT * FROM ipv4_lease WHERE order_id=? AND client_id=? ORDER BY generation DESC LIMIT 1',(row['order_id'],row['client_id'])).fetchone()
            require(lease is not None,'Потеряна история IPv4; запуск остановлен')
            rules.append(guard(row,dict(lease),config))
    if rules:
        payload='\n'.join(rules)+'\n'
        subprocess.run(['/usr/sbin/nft','--check','-f','-'],input=payload,text=True,capture_output=True,check=True,timeout=30)
        subprocess.run(['/usr/sbin/nft','-f','-'],input=payload,text=True,capture_output=True,check=True,timeout=30)


if __name__=='__main__':reload_guards()
