#!/usr/bin/env python3
"""Verify a Daedalus backup and atomically restore into a fresh directory."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sqlite3
import tarfile
import tempfile
from pathlib import Path, PurePosixPath


DEFAULT_MAX_BYTES = 32 * 1024**3
MAX_MEMBERS = 100_000
MAX_MANIFEST_BYTES = 32 * 1024**2


class RestoreError(ValueError):
    pass


def _safe_name(name: str) -> str:
    path = PurePosixPath(name)
    normalized = str(path)
    if (
        not name or len(name) > 512 or "\\" in name or "\x00" in name
        or path.is_absolute() or any(part in {".", ".."} for part in name.split("/"))
        or name.rstrip("/") != normalized
        or path.parts[0] not in {"daedalus.db", "manifest.json", "reports", "scanner-artifacts"}
        or (path.parts[0] in {"daedalus.db", "manifest.json"} and len(path.parts) != 1)
    ):
        raise RestoreError("The archive contains an unsupported or unsafe path.")
    return normalized


def _manifest_files(contents: bytes) -> dict[str, tuple[int, str]]:
    try:
        manifest = json.loads(contents)
    except (ValueError, UnicodeDecodeError) as exc:
        raise RestoreError("The backup manifest is not valid JSON.") from exc
    if not isinstance(manifest, dict) or manifest.get("version") != 1 or not isinstance(manifest.get("files"), list):
        raise RestoreError("A version 1 backup file manifest is required.")
    expected = {}
    for row in manifest["files"]:
        if not isinstance(row, dict) or not isinstance(row.get("path"), str):
            raise RestoreError("The manifest contains an invalid file entry.")
        name = _safe_name(row["path"])
        size, digest = row.get("size_bytes"), row.get("sha256")
        if (
            name in expected or name == "manifest.json" or name in {"reports", "scanner-artifacts"}
            or type(size) is not int or size < 0
            or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
        ):
            raise RestoreError("The manifest contains an invalid size, digest or duplicate path.")
        expected[name] = (size, digest)
    if "daedalus.db" not in expected:
        raise RestoreError("The manifest does not include the SQLite database.")
    return expected


def _check_database_integrity(database_path: Path) -> None:
    try:
        uri = database_path.as_uri() + "?mode=ro&immutable=1"
        with sqlite3.connect(uri, uri=True) as db:
            if db.execute("PRAGMA integrity_check").fetchmany(2) != [("ok",)]:
                raise RestoreError("The backup database failed its integrity check.")
            if db.execute("PRAGMA foreign_key_check").fetchone() is not None:
                raise RestoreError("The backup database contains broken foreign-key relationships.")
    except sqlite3.DatabaseError as exc:
        raise RestoreError("The backup database is invalid.") from exc


def verify_archive(archive_path: Path, *, max_bytes: int = DEFAULT_MAX_BYTES) -> None:
    """Stream-check archive paths, manifest digests, and SQLite integrity."""
    if max_bytes <= 0:
        raise RestoreError("The verification byte limit must be positive.")
    archive_path = archive_path.expanduser()
    try:
        with tempfile.TemporaryDirectory(prefix=".daedalus-backup-verify-") as temporary:
            database_copy = Path(temporary) / "daedalus.db"
            with tarfile.open(archive_path, "r:*") as archive:
                members = {}
                regular_files = {}
                total_bytes = 0
                for member in archive:
                    if len(members) >= MAX_MEMBERS:
                        raise RestoreError("The backup exceeds the archive member limit.")
                    name = _safe_name(member.name)
                    if name in members or not (member.isdir() or member.isfile()):
                        raise RestoreError("The archive has duplicate paths, links or unsupported file types.")
                    if member.size < 0 or (member.isdir() and member.size != 0):
                        raise RestoreError("The archive contains an invalid file size.")
                    if member.isdir() and name in {"daedalus.db", "manifest.json"}:
                        raise RestoreError("The database and manifest must be regular files.")
                    members[name] = member
                    if member.isfile():
                        total_bytes += member.size
                        if total_bytes > max_bytes:
                            raise RestoreError("The backup exceeds the configured verification byte limit.")
                        regular_files[name] = member

                manifest_member = regular_files.get("manifest.json")
                if manifest_member is None or manifest_member.size > MAX_MANIFEST_BYTES:
                    raise RestoreError("A bounded backup manifest is required.")
                manifest_stream = archive.extractfile(manifest_member)
                if manifest_stream is None:
                    raise RestoreError("The backup manifest could not be read.")
                with manifest_stream:
                    manifest_content = manifest_stream.read(MAX_MANIFEST_BYTES + 1)
                if len(manifest_content) != manifest_member.size:
                    raise RestoreError("The backup manifest size is inconsistent.")
                expected = _manifest_files(manifest_content)
                if set(expected) != set(regular_files) - {"manifest.json"}:
                    raise RestoreError("The archive files do not exactly match the backup manifest.")
                for name, (size, _digest) in expected.items():
                    if regular_files[name].size != size:
                        raise RestoreError("An archive file size does not match the manifest.")

                for name, member in regular_files.items():
                    if name == "manifest.json":
                        continue
                    source = archive.extractfile(member)
                    if source is None:
                        raise RestoreError("A backup file could not be read.")
                    digest = hashlib.sha256()
                    count = 0
                    output = database_copy.open("xb") if name == "daedalus.db" else None
                    try:
                        with source:
                            while block := source.read(1024 * 1024):
                                count += len(block)
                                if count > expected[name][0]:
                                    raise RestoreError("An archive file is larger than its manifest entry.")
                                digest.update(block)
                                if output is not None:
                                    output.write(block)
                    finally:
                        if output is not None:
                            output.close()
                    if count != expected[name][0] or digest.hexdigest() != expected[name][1]:
                        raise RestoreError("An archive file does not match its manifest digest.")
            _check_database_integrity(database_copy)
    except (tarfile.TarError, OSError) as exc:
        raise RestoreError("The backup could not be safely verified.") from exc


def restore_archive(archive_path: Path, destination: Path, *, max_bytes: int = DEFAULT_MAX_BYTES) -> Path:
    """No existing data is replaced; every extracted byte is checked before installation."""
    if max_bytes <= 0:
        raise RestoreError("The extraction byte limit must be positive.")
    destination = destination.expanduser().absolute()
    if destination.is_symlink():
        raise RestoreError("The restore destination must not be a symbolic link.")
    if destination.exists() and (not destination.is_dir() or any(destination.iterdir())):
        raise RestoreError("The restore destination already contains data.")
    parent = destination.parent.resolve(strict=True)
    destination = parent / destination.name
    staging = Path(tempfile.mkdtemp(prefix=".daedalus-restore-", dir=parent))
    staging.chmod(0o700)
    installed = False
    try:
        members = {}
        regular_files = {}
        total_bytes = 0
        with tarfile.open(archive_path, "r:*") as archive:
            for member in archive:
                if len(members) >= MAX_MEMBERS:
                    raise RestoreError("The backup exceeds the archive member limit.")
                name = _safe_name(member.name)
                if name in members or not (member.isdir() or member.isfile()):
                    raise RestoreError("The archive has duplicate paths, links or unsupported file types.")
                if member.size < 0 or (member.isdir() and member.size != 0):
                    raise RestoreError("The archive contains an invalid file size.")
                if member.isdir() and name in {"daedalus.db", "manifest.json"}:
                    raise RestoreError("The database and manifest must be regular files.")
                members[name] = member
                if member.isfile():
                    total_bytes += member.size
                    if total_bytes > max_bytes:
                        raise RestoreError("The backup exceeds the configured extracted byte limit.")
                    regular_files[name] = member
            manifest_member = regular_files.get("manifest.json")
            if manifest_member is None or manifest_member.size > MAX_MANIFEST_BYTES:
                raise RestoreError("A bounded backup manifest is required.")
            manifest_content = archive.extractfile(manifest_member).read()
            expected = _manifest_files(manifest_content)
            if set(expected) != set(regular_files) - {"manifest.json"}:
                raise RestoreError("The archive files do not exactly match the backup manifest.")
            for name, (size, _digest) in expected.items():
                if regular_files[name].size != size:
                    raise RestoreError("An archive file size does not match the manifest.")
            for name, member in members.items():
                target = staging / name
                if member.isdir():
                    target.mkdir(parents=True, mode=0o700, exist_ok=True)
                    target.chmod(0o700)
                    continue
                target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
                for ancestor in target.parents:
                    if ancestor == staging.parent:
                        break
                    ancestor.chmod(0o700)
                digest = hashlib.sha256()
                with archive.extractfile(member) as source, target.open("xb") as output:
                    target.chmod(0o600)
                    for block in iter(lambda: source.read(1024 * 1024), b""):
                        digest.update(block)
                        output.write(block)
                    output.flush()
                    os.fsync(output.fileno())
                if name != "manifest.json" and digest.hexdigest() != expected[name][1]:
                    raise RestoreError("An archive file digest does not match the manifest.")
        try:
            _check_database_integrity(staging / "daedalus.db")
        except RestoreError as exc:
            raise RestoreError("The restored SQLite database is invalid or failed its integrity check.") from exc
        # Recheck after verification so occupied destinations remain protected.
        if destination.is_symlink() or (destination.exists() and (not destination.is_dir() or any(destination.iterdir()))):
            raise RestoreError("The restore destination became occupied during verification.")
        os.replace(staging, destination)
        installed = True
        directory_fd = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return destination
    except (tarfile.TarError, OSError) as exc:
        raise RestoreError("The backup could not be safely read or installed.") from exc
    finally:
        if not installed:
            shutil.rmtree(staging, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--destination", type=Path, help="An absent or empty data directory; its parent must exist")
    parser.add_argument("--verify-only", action="store_true", help="Verify paths, manifest digests and SQLite integrity without installing files")
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES, help="Maximum extracted size (default: 32 GiB)")
    args = parser.parse_args()
    try:
        if args.verify_only:
            if args.destination is not None:
                parser.error("--destination cannot be used with --verify-only")
            verify_archive(args.archive, max_bytes=args.max_bytes)
            print(f"Verified backup archive: {args.archive}")
            return 0
        if args.destination is None:
            parser.error("--destination is required unless --verify-only is used")
        restored = restore_archive(args.archive, args.destination, max_bytes=args.max_bytes)
    except (RestoreError, OSError) as exc:
        parser.exit(1, f"Restore refused: {exc}\n")
    print(f"Verified backup restored to {restored}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
