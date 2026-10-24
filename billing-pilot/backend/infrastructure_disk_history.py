#!/usr/bin/python3
"""Root-private minute snapshots. Never imports or opens the allocator database."""
import fcntl
import json
import math
import os
from pathlib import Path
import sqlite3
import stat
import time
from contextlib import contextmanager, closing

from infrastructure_observer import InfrastructureObserver, Refused, require, fingerprint, metrics_deadline

STORE_PATH = Path('/var/lib/safehost-monitoring/infrastructure-disk.sqlite3')
COLLECT_VMID_ALLOWLIST = (101, 1101)
RETENTION_SECONDS = 8 * 86400
IDENTITY_FIELDS = ('account', 'vmid', 'node', 'configSha256')


class CollectionDeadline(BaseException):
    """Must bypass guest_fs's expected OSError/unavailable handling."""
    pass


def valid_pair(used, total):
    return type(used) is int and type(total) is int and 0 <= used <= total and 0 < total <= 2**53 - 1


class DiskHistory:
    def __init__(self, path=None):
        self.path = Path(STORE_PATH if path is None else path)

    @staticmethod
    def private(path, *, directory=False):
        try:metadata = path.lstat()
        except FileNotFoundError:return False
        correct_type = stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
        require(correct_type and metadata.st_uid == os.geteuid()
                and stat.S_IMODE(metadata.st_mode) == (0o700 if directory else 0o600),
                'Небезопасное хранилище истории диска')
        return True

    def checked(self):
        if not self.private(self.path.parent, directory=True):return False
        # Validate even orphaned sidecars before considering an absent DB empty.
        for suffix in ('-wal', '-shm', '-journal'):
            self.private(Path(str(self.path) + suffix))
        return self.private(self.path)

    @contextmanager
    def writer(self):
        self.path.parent.mkdir(mode=0o700, parents=False, exist_ok=True)
        exists = self.checked()
        if not exists:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.close(fd)
        with closing(sqlite3.connect(self.path.as_uri() + '?mode=rw', uri=True, timeout=.5)) as db, db:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('PRAGMA synchronous=FULL')
            version = db.execute('PRAGMA user_version').fetchone()[0]
            require(version in (0, 1), 'Неизвестная версия истории диска')
            db.execute('''CREATE TABLE IF NOT EXISTS sample (
                account TEXT NOT NULL, vmid INTEGER NOT NULL, node TEXT NOT NULL, configSha256 TEXT NOT NULL,
                timestamp INTEGER NOT NULL, usedBytes INTEGER, totalBytes INTEGER,
                PRIMARY KEY(account,vmid,node,configSha256,timestamp))''')
            db.execute('CREATE INDEX IF NOT EXISTS sample_retention ON sample(timestamp)')
            db.execute('PRAGMA user_version=1')
            yield db
        self.checked()

    def record(self, entry, tick, used, total, *, now):
        require(type(tick) is int and tick >= 0 and tick % 60 == 0 and tick == int(now) // 60 * 60,
                'Некорректная минута наблюдения')
        require((used is None and total is None) or valid_pair(used, total), 'Некорректные размеры диска')
        with self.writer() as db:
            db.execute('INSERT OR IGNORE INTO sample VALUES(?,?,?,?,?,?,?)',
                       (*[entry[key] for key in IDENTITY_FIELDS], tick, used, total))
            db.execute('DELETE FROM sample WHERE timestamp<=?', (int(now) - RETENTION_SECONDS,))

    def prune(self, now):
        if not self.checked():return False
        with self.writer() as db:
            db.execute('DELETE FROM sample WHERE timestamp<=?', (int(now) - RETENTION_SECONDS,))
        return True

    def read(self, entry, start, end):
        if not self.checked():return {}
        # mode=ro cannot create the database or migrate its schema.
        with closing(sqlite3.connect(self.path.as_uri() + '?mode=ro', uri=True, timeout=.5)) as db:
            db.execute('PRAGMA query_only=ON')
            require(db.execute('PRAGMA user_version').fetchone()[0] == 1, 'Неизвестная версия истории диска')
            rows = db.execute('''SELECT timestamp,usedBytes,totalBytes FROM sample
                WHERE account=? AND vmid=? AND node=? AND configSha256=? AND timestamp>? AND timestamp<=?
                ORDER BY timestamp LIMIT 10081''', (*[entry[key] for key in IDENTITY_FIELDS], start, end)).fetchall()
        self.checked()
        require(len(rows) <= 10080, 'Слишком много точек истории диска')
        result = {}
        for tick, used, total in rows:
            require(type(tick) is int and tick % 60 == 0 and tick not in result
                    and ((used is None and total is None) or valid_pair(used, total)), 'Повреждена история диска')
            result[tick] = (used, total)
        return result

    @contextmanager
    def collector_lock(self):
        self.path.parent.mkdir(mode=0o700, parents=False, exist_ok=True)
        self.checked()
        path = self.path.parent / 'collector.lock'
        self.private(path)
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'r+') as lock:
            self.private(path)
            try:fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                yield False
                return
            yield True


def collect(observer, store=None, *, clock=time.time):
    store = store or DiskHistory()
    started = clock()
    require(type(started) in (int, float) and math.isfinite(started) and started >= 0, 'Некорректное время collector')
    tick = int(started) // 60 * 60
    with (observer.state / 'operation.lock').open('r') as operation:
        try:fcntl.flock(operation, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:return {'collected': 0}
        require((observer.state / 'config.sha256').read_text().strip() == fingerprint(observer.c), 'Конфигурация пула изменилась')
        with store.collector_lock() as acquired:
            if not acquired:return {'collected': 0}
            with metrics_deadline(exception=CollectionDeadline):
                store.prune(started)
                registry = observer.infrastructure_registry()
                count = 0
                for vmid in COLLECT_VMID_ALLOWLIST:
                    current = clock()
                    minute_expired = current >= tick + 60
                    deadline_expired = current - started >= 15
                    if minute_expired or deadline_expired:break
                    entry = registry.get(vmid)
                    if entry is None:continue
                    try:
                        observation = observer.infrastructure_disk(entry['account'], vmid, entry['node'])
                        require(observer.infrastructure_registry().get(vmid) == entry, 'Изменилась регистрация перед сохранением')
                    except TimeoutError:raise
                    except (Refused, OSError):continue
                    observed = clock()
                    if int(observed) // 60 * 60 != tick:continue
                    store.record(entry, tick, observation['usedBytes'], observation['totalBytes'], now=observed)
                    count += 1
                return {'collected': count}


def main():
    # Importing Proxmox is side-effect free; Engine is never instantiated.
    from engine import Proxmox
    os.umask(0o077)
    require(os.geteuid() == 0, 'Collector должен работать от root')
    state = Path('/var/lib/safehost-billing')
    with (state / 'operation.lock').open('r') as operation:
        try:fcntl.flock(operation, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            print(json.dumps({'collected': 0}))
            return
        config = json.loads(Path('/etc/safehost-billing/config.json').read_text())
        require((state / 'config.sha256').read_text().strip() == fingerprint(config), 'Конфигурация пула изменилась')
        try:result = collect(InfrastructureObserver(state, Proxmox(config)))
        except CollectionDeadline:raise SystemExit('Disk collection deadline exceeded')
    print(json.dumps(result))


if __name__ == '__main__':main()
