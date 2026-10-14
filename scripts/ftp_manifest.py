#!/usr/bin/env python3
"""List stable regular FTP archive files and their SHA-256 for the master pull."""
import hashlib
import fcntl
import json
import os
from pathlib import Path
import stat
import time

ROOT = Path('/srv/ispsupport/ftp')


def manifest(root=ROOT, min_age=120, now=None):
    now = time.time() if now is None else now
    if root.is_symlink() or not root.is_dir():
        raise RuntimeError('FTP root is absent or is a symlink')
    files, skipped = [], 0
    for directory, folders, names in os.walk(root, followlinks=False):
        folders[:] = sorted(n for n in folders if not (Path(directory) / n).is_symlink())
        for name in sorted(names):
            path = Path(directory) / name
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode):
                continue
            if now - info.st_mtime < min_age:
                skipped += 1
                continue
            digest = hashlib.sha256()
            with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as handle:
                try:
                    # vsftpd holds a POSIX write lock for the duration of STOR.
                    fcntl.lockf(handle, fcntl.LOCK_SH | fcntl.LOCK_NB)
                except BlockingIOError:
                    skipped += 1
                    continue
                before = os.fstat(handle.fileno())
                for chunk in iter(lambda: handle.read(1024 * 1024), b''):
                    digest.update(chunk)
                after = os.fstat(handle.fileno())
            current = path.lstat()
            identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            if identity(info) != identity(before) or identity(before) != identity(after) or identity(after) != identity(current):
                skipped += 1
                continue
            files.append({'path': path.relative_to(root).as_posix(), 'size': after.st_size, 'sha256': digest.hexdigest()})
            if len(files) > 200000:
                raise RuntimeError('Archive manifest exceeds 200000 files')
    return {'schema': 1, 'root': str(ROOT), 'generated_at': int(now), 'skipped_recent_or_changed': skipped, 'files': files}


if __name__ == '__main__':
    print(json.dumps(manifest(), ensure_ascii=True))
