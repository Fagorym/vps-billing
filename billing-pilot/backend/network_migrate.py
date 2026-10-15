#!/usr/bin/python3
"""Operator-only sealed config migration. Never changes VLAN, uplink, NAT or VMs."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import uuid
from engine import Engine, Proxmox, require
from expand_pool import atomic_write, fingerprint
from ipam import Ipam


def migrate(config_path, state, candidate, pve=None, apply=False):
    config_path,state=Path(config_path),Path(state)
    pending_path=state/'network-migration.pending.json'
    seal_path=state/'config.sha256'
    with (state/'operation.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        current=json.loads(config_path.read_text())
        pending=json.loads(pending_path.read_text()) if pending_path.exists() else None
        old=pending['old'] if pending else current
        require({k:v for k,v in old.items() if k not in ('public_ip','public_network')}=={k:v for k,v in candidate.items() if k not in ('public_ip','public_network')},'Изменять можно только public_ip и public_network')
        seal=seal_path.read_text().strip()
        if pending:
            require(pending['new']==candidate and current in (old,candidate) and seal in (fingerprint(old),fingerprint(candidate)),'Конфликт незавершённой миграции')
        else:
            require(seal==fingerprint(old),'Конфигурация не соответствует config.sha256')
        require(candidate.get('public_network') and candidate['public_network']['host_ip']==candidate['public_ip'],'Нужен полный пул с адресом хоста')
        database=state/'allocations.sqlite'
        with sqlite3.connect('file:'+str(database)+'?mode=ro',uri=True) as source, tempfile.TemporaryDirectory() as scratch:
            require(source.execute('PRAGMA quick_check').fetchone()[0]=='ok','Повреждена БД allocator')
            copy=Path(scratch)
            with sqlite3.connect(copy/'allocations.sqlite') as snapshot:source.backup(snapshot)
            checked_config=old if seal==fingerprint(old) else candidate
            (copy/'config.sha256').write_text(fingerprint(checked_config)+'\n')
            # Schema/pool validation runs against a disposable copy, never the live DB.
            probe=Engine(checked_config,copy,copy/'snippets',pve or Proxmox(old))
            try:
                rows=probe.db.execute('SELECT * FROM allocation').fetchall()
                for row in rows:probe.owned_config(row)
                Ipam(probe.db,candidate['public_network'])
            finally:probe.db.close()
            result={'changed':False,'allocations':len(rows),'publicIp':candidate['public_ip']}
            if not apply:return result
            if not pending:
                backup=state/'backups'/('network-'+uuid.uuid4().hex);backup.mkdir(mode=0o700,parents=True)
                for path in (config_path,seal_path,state/'credential.key'):
                    if path.exists():shutil.copyfile(path,backup/path.name);(backup/path.name).chmod(0o600)
                with sqlite3.connect(backup/'allocations.sqlite') as saved:source.backup(saved)
                (backup/'allocations.sqlite').chmod(0o600)
                pending={'old':old,'new':candidate,'backup':str(backup)}
                atomic_write(pending_path,json.dumps(pending,sort_keys=True)+'\n')
            atomic_write(config_path,json.dumps(candidate,sort_keys=True,indent=2)+'\n')
            atomic_write(seal_path,fingerprint(candidate)+'\n')
            pending_path.unlink()
            return {**result,'changed':True,'backup':pending['backup']}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--candidate',required=True);parser.add_argument('--apply',action='store_true')
    args=parser.parse_args();require(os.geteuid()==0,'Запускается только администратором хоста')
    os.umask(0o077)
    print(json.dumps(migrate('/etc/safehost-billing/config.json','/var/lib/safehost-billing',json.loads(Path(args.candidate).read_text()),apply=args.apply),ensure_ascii=False))


if __name__=='__main__':main()
