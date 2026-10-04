#!/usr/bin/env python3
"""Create a consistent SQLite and report archive inside the persistent volume."""

from __future__ import annotations

import sqlite3
import tarfile
import os
import hashlib
import io
import json
from datetime import UTC, datetime
from pathlib import Path
import tempfile
import stat


def archive_file(archive, path: Path, name: str) -> dict:
    """Hash the exact bounded descriptor bytes consumed by the tar writer."""
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("Backup sources must be regular files.")
        digest = hashlib.sha256()
        remaining = metadata.st_size

        class Reader:
            def read(self, size):
                nonlocal remaining
                requested = min(size, remaining)
                blocks = []
                collected = 0
                while collected < requested:
                    block = os.read(descriptor, requested - collected)
                    if not block:
                        break
                    blocks.append(block)
                    collected += len(block)
                data = b"".join(blocks)
                digest.update(data)
                remaining -= len(data)
                return data

        entry = tarfile.TarInfo(name)
        entry.size = metadata.st_size
        entry.mode = 0o600
        entry.mtime = metadata.st_mtime
        archive.addfile(entry, Reader())
        if remaining:
            raise ValueError("A backup source was truncated during archiving.")
        return {"path": name, "size_bytes": metadata.st_size, "sha256": digest.hexdigest()}
    finally:
        os.close(descriptor)


def archive_tree(archive, root: Path, prefix: str, *, pattern: str = "*") -> list[dict]:
    if not root.exists() and not root.is_symlink():
        return []
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Backup directories must be real directories.")
    manifest = []
    for path in sorted(root.rglob(pattern)):
        if path.is_symlink():
            raise ValueError("Backup sources must not contain symbolic links.")
        if path.is_dir():
            continue
        manifest.append(archive_file(archive, path, prefix + "/" + path.relative_to(root).as_posix()))
    return manifest


DATA_DIR = Path(os.environ.get("DAEDALUS_DATA_DIR", "/data"))
BACKUP_DIR = DATA_DIR / "backups"
DATABASE = DATA_DIR / "daedalus.db"
REPORTS = DATA_DIR / "reports"


def main() -> int:
    if not DATABASE.is_file():
        raise SystemExit("Daedalus database was not found in /data.")
    previous_umask = os.umask(0o077)
    BACKUP_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        BACKUP_DIR.chmod(0o700)
    except OSError:
        pass
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    database_copy = BACKUP_DIR / f"daedalus-{stamp}.db"
    archive_path = BACKUP_DIR / f"daedalus-data-{stamp}.tar.gz"
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".daedalus-data-", suffix=".tar.gz.tmp", dir=BACKUP_DIR
    )
    os.close(descriptor)
    temporary_archive = Path(temporary_name)
    try:
        with sqlite3.connect(DATABASE, timeout=30) as source:
            with sqlite3.connect(database_copy) as destination:
                source.backup(destination)
        with tarfile.open(temporary_archive, "w:gz") as archive:
            manifest = [archive_file(archive, database_copy, "daedalus.db")]
            manifest.extend(archive_tree(archive, REPORTS, "reports"))
            artifacts = DATA_DIR / "scanner-artifacts"
            manifest.extend(archive_tree(archive, artifacts, "scanner-artifacts", pattern="*.json"))
            encoded = json.dumps({"version": 1, "created_at": stamp, "files": manifest}, sort_keys=True, indent=2).encode()
            entry = tarfile.TarInfo("manifest.json")
            entry.size = len(encoded)
            entry.mode = 0o600
            archive.addfile(entry, io.BytesIO(encoded))
        temporary_archive.chmod(0o600)
        os.replace(temporary_archive, archive_path)
    finally:
        database_copy.unlink(missing_ok=True)
        temporary_archive.unlink(missing_ok=True)
        os.umask(previous_umask)
    print(archive_path.name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
