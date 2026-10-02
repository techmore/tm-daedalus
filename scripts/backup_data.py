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
    try:
        with sqlite3.connect(DATABASE, timeout=30) as source:
            with sqlite3.connect(database_copy) as destination:
                source.backup(destination)
        with tarfile.open(archive_path, "w:gz") as archive:
            manifest = []

            def record(path, name):
                digest = hashlib.sha256()
                with path.open("rb") as source:
                    for block in iter(lambda: source.read(1024 * 1024), b""):
                        digest.update(block)
                manifest.append({"path": name, "size_bytes": path.stat().st_size, "sha256": digest.hexdigest()})

            archive.add(database_copy, arcname="daedalus.db")
            record(database_copy, "daedalus.db")
            if REPORTS.is_dir():
                archive.add(REPORTS, arcname="reports")
                for path in sorted(REPORTS.rglob("*")):
                    if path.is_file() and not path.is_symlink():
                        record(path, "reports/" + str(path.relative_to(REPORTS)))
            artifacts = DATA_DIR / "scanner-artifacts"
            if artifacts.is_dir() and not artifacts.is_symlink():
                archive.add(artifacts, arcname="scanner-artifacts", recursive=False)
                for path in sorted(artifacts.rglob("*.json")):
                    if path.is_file() and not path.is_symlink():
                        name = "scanner-artifacts/" + str(path.relative_to(artifacts))
                        archive.add(path, arcname=name, recursive=False)
                        record(path, name)
            encoded = json.dumps({"version": 1, "created_at": stamp, "files": manifest}, sort_keys=True, indent=2).encode()
            entry = tarfile.TarInfo("manifest.json")
            entry.size = len(encoded)
            entry.mode = 0o600
            archive.addfile(entry, io.BytesIO(encoded))
    finally:
        database_copy.unlink(missing_ok=True)
        os.umask(previous_umask)
    try:
        archive_path.chmod(0o600)
    except OSError:
        pass
    print(archive_path.name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
