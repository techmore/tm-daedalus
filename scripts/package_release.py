#!/usr/bin/env python3
"""Build, verify, and safely extract a secret-free Daedalus release bundle."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import BinaryIO


ARCHIVE_ROOT = "daedalus"
MANIFEST_PATH = f"{ARCHIVE_ROOT}/MANIFEST.json"
MAX_FILES = 20_000
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
ROOT_FILES = (
    "PUBLIC-PROJECT-REPORT.md",
    "README.md",
    "pyproject.toml",
    "uv.lock",
    "requirements-production.txt",
    ".env.production.example",
)
SCRIPT_FILES = (
    "__init__.py",
    "backup_data.py",
    "backup_incus.sh",
    "check_production_env.py",
    "check_public_deployment.py",
    "deploy_incus.py",
    "deploy_incus_remote.sh",
    "package_release.py",
    "restore_data.py",
)
REQUIRED_ARCHIVE_PATHS = {
    *ROOT_FILES,
    *(f"scripts/{name}" for name in SCRIPT_FILES),
    "src/daedalus/server.py",
}
FORBIDDEN_PARTS = {
    ".git",
    ".venv",
    "__pycache__",
    "node_modules",
    "data",
    "backups",
    "client_bundle",
    "dist",
    "tmp",
    "output",
    "validation",
}
FORBIDDEN_NAMES = {
    ".env",
    ".env.production",
    "config.yaml",
    "cis-client.yaml",
    "cis-client.yml",
    "daedalus.db",
    "daedalus-encryption.key",
}


class BundleError(ValueError):
    pass


def _is_forbidden(relative: PurePosixPath) -> bool:
    return (
        any(part in FORBIDDEN_PARTS for part in relative.parts)
        or any(part.lower() in FORBIDDEN_NAMES for part in relative.parts)
        or any(part.startswith(".env.") and part != ".env.production.example" for part in relative.parts)
        or any(part.lower().endswith((".pem", ".p12", ".pfx", ".key")) for part in relative.parts)
    )


def collect_files(project_root: Path) -> list[tuple[PurePosixPath, Path]]:
    """Return the allowlisted runtime/deployment source tree, never local state."""
    project_root = project_root.resolve(strict=True)
    selected: dict[str, Path] = {}
    for name in ROOT_FILES:
        path = project_root / name
        if not path.is_file() or path.is_symlink():
            raise BundleError(f"Required deployment file is missing or unsafe: {name}")
        selected[name] = path
    for name in SCRIPT_FILES:
        path = project_root / "scripts" / name
        if not path.is_file() or path.is_symlink():
            raise BundleError(f"Required deployment script is missing or unsafe: scripts/{name}")
        selected[f"scripts/{name}"] = path

    source_root = project_root / "src" / "daedalus"
    if not source_root.is_dir() or source_root.is_symlink():
        raise BundleError("The Daedalus application source directory is missing or unsafe.")
    for path in source_root.rglob("*"):
        if path.is_symlink():
            continue
        if not path.is_file():
            continue
        relative = PurePosixPath(path.relative_to(project_root).as_posix())
        if _is_forbidden(relative) or path.suffix in {".pyc", ".pyo"}:
            continue
        selected[relative.as_posix()] = path

    result = [(PurePosixPath(name), path) for name, path in sorted(selected.items())]
    if len(result) > MAX_FILES:
        raise BundleError("The deployment bundle contains too many files.")
    total = 0
    for relative, path in result:
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            raise BundleError(f"A deployment file is larger than the per-file limit: {relative}")
        total += size
    if total > MAX_TOTAL_BYTES:
        raise BundleError("The deployment bundle exceeds the total uncompressed size limit.")
    return result


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _tar_info(name: str, size: int, executable: bool = False) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = size
    info.mode = 0o755 if executable else 0o644
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    return info


def build_bundle(project_root: Path, output: Path) -> dict:
    project_root = project_root.resolve(strict=True)
    output = output.expanduser().resolve()
    if output.exists():
        raise BundleError(f"Output already exists; choose a new path: {output}")
    files = collect_files(project_root)
    manifest = {
        "format": 1,
        "project": "Daedalus",
        "files": [
            {"path": relative.as_posix(), "size_bytes": path.stat().st_size, "sha256": _digest(path)}
            for relative, path in files
        ],
    }
    encoded_manifest = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output.open("xb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                    for relative, path in files:
                        relative_name = relative.as_posix()
                        if _is_forbidden(relative):
                            raise BundleError(f"Refusing private path: {relative_name}")
                        executable = bool(path.stat().st_mode & 0o111)
                        with path.open("rb") as stream:
                            archive.addfile(
                                _tar_info(f"{ARCHIVE_ROOT}/{relative_name}", path.stat().st_size, executable),
                                stream,
                            )
                    archive.addfile(
                        _tar_info(MANIFEST_PATH, len(encoded_manifest)), io.BytesIO(encoded_manifest)
                    )
    except Exception:
        output.unlink(missing_ok=True)
        raise
    try:
        verify_bundle(output)
    except Exception:
        output.unlink(missing_ok=True)
        raise
    return {
        "archive": str(output),
        "archive_sha256": _digest(output),
        "archive_bytes": output.stat().st_size,
        "file_count": len(files),
        "total_bytes": sum(path.stat().st_size for _relative, path in files),
        "manifest_verified": True,
    }


def _safe_member_name(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if path.is_absolute() or not path.parts or path.parts[0] != ARCHIVE_ROOT or any(part in {"", ".", ".."} for part in path.parts):
        raise BundleError("The archive contains an unsafe path.")
    relative = PurePosixPath(*path.parts[1:])
    if not relative.parts or _is_forbidden(relative):
        raise BundleError("The archive contains a forbidden deployment path.")
    return relative


def inspect_archive(archive_path: Path) -> tuple[dict, list[tuple[str, tarfile.TarInfo]]]:
    try:
        archive = tarfile.open(archive_path, mode="r:gz")
    except (OSError, tarfile.TarError) as exc:
        raise BundleError("The deployment archive could not be opened.") from exc
    with archive:
        members = archive.getmembers()
        if not members or len(members) > MAX_FILES + 1:
            raise BundleError("The deployment archive has an invalid number of entries.")
        by_name: dict[str, tarfile.TarInfo] = {}
        total = 0
        for member in members:
            _safe_member_name(member.name)
            if not member.isfile() or member.issparse():
                raise BundleError("The archive may contain regular files only.")
            if member.name in by_name:
                raise BundleError("The archive contains duplicate paths.")
            if member.size < 0 or member.size > MAX_FILE_BYTES:
                raise BundleError("The archive contains an invalid file size.")
            total += member.size
            if total > MAX_TOTAL_BYTES:
                raise BundleError("The archive exceeds the total uncompressed size limit.")
            by_name[member.name] = member
        manifest_member = by_name.get(MANIFEST_PATH)
        if manifest_member is None or manifest_member.size > MAX_MANIFEST_BYTES:
            raise BundleError("A bounded deployment manifest is required.")
        stream = archive.extractfile(manifest_member)
        if stream is None:
            raise BundleError("The deployment manifest could not be read.")
        with stream:
            raw_manifest = stream.read(MAX_MANIFEST_BYTES + 1)
        if len(raw_manifest) != manifest_member.size:
            raise BundleError("The deployment manifest size is inconsistent.")
        try:
            manifest = json.loads(raw_manifest)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BundleError("The deployment manifest is not valid JSON.") from exc
        if not isinstance(manifest, dict) or manifest.get("format") != 1 or manifest.get("project") != "Daedalus" or not isinstance(manifest.get("files"), list):
            raise BundleError("The deployment manifest has an unsupported format.")
        expected: dict[str, tuple[int, str]] = {}
        for row in manifest["files"]:
            if not isinstance(row, dict) or not isinstance(row.get("path"), str):
                raise BundleError("The deployment manifest contains an invalid entry.")
            relative = PurePosixPath(row["path"])
            if relative.is_absolute() or not relative.parts or any(part in {"", ".", ".."} for part in relative.parts) or _is_forbidden(relative):
                raise BundleError("The deployment manifest contains an unsafe path.")
            size = row.get("size_bytes")
            digest = row.get("sha256")
            if not isinstance(size, int) or size < 0 or size > MAX_FILE_BYTES or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest) or row["path"] in expected:
                raise BundleError("The deployment manifest contains an invalid size, digest, or duplicate path.")
            expected[row["path"]] = (size, digest)
        if not REQUIRED_ARCHIVE_PATHS.issubset(expected):
            raise BundleError("The bundle is missing required deployment files.")
        actual_names = set(by_name) - {MANIFEST_PATH}
        if actual_names != {f"{ARCHIVE_ROOT}/{name}" for name in expected}:
            raise BundleError("The archive files do not exactly match the deployment manifest.")
        for relative, (size, digest) in expected.items():
            member = by_name[f"{ARCHIVE_ROOT}/{relative}"]
            if member.size != size:
                raise BundleError("An archive file size does not match the manifest.")
            stream = archive.extractfile(member)
            if stream is None:
                raise BundleError("An archive file could not be read.")
            hasher = hashlib.sha256()
            read_bytes = 0
            with stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    read_bytes += len(chunk)
                    hasher.update(chunk)
            if read_bytes != size or hasher.hexdigest() != digest:
                raise BundleError("An archive file does not match its manifest digest.")
        return manifest, [(name, by_name[name]) for name in sorted(actual_names)]


def verify_bundle(archive_path: Path) -> dict:
    manifest, entries = inspect_archive(archive_path)
    return {
        "project": manifest["project"],
        "file_count": len(entries),
        "total_bytes": sum(row["size_bytes"] for row in manifest["files"]),
        "archive_sha256": _digest(archive_path),
        "manifest_verified": True,
    }


def extract_bundle(archive_path: Path, destination: Path) -> Path:
    destination = destination.expanduser().resolve()
    if destination.exists():
        raise BundleError("Extraction destination already exists; use a new, empty release directory.")
    manifest, entries = inspect_archive(archive_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".daedalus-release-", dir=destination.parent) as temporary:
        staging = Path(temporary) / ARCHIVE_ROOT
        staging.mkdir(mode=0o755)
        with tarfile.open(archive_path, mode="r:gz") as archive:
            for name, member in entries:
                relative = _safe_member_name(name)
                target = staging.joinpath(*relative.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                stream = archive.extractfile(member)
                if stream is None:
                    raise BundleError("An archive file could not be read during extraction.")
                with stream, target.open("xb") as output:
                    shutil.copyfileobj(stream, output, 1024 * 1024)
                target.chmod(0o755 if member.mode & 0o111 else 0o644)
        manifest_path = staging / "MANIFEST.json"
        manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        manifest_path.chmod(0o644)
        os.replace(staging, destination)
    return destination


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build", help="build a deterministic secret-free deployment archive")
    build.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    build.add_argument("--output", type=Path, required=True)
    verify = subparsers.add_parser("verify", help="verify manifest, paths, and checksums")
    verify.add_argument("--archive", type=Path, required=True)
    extract = subparsers.add_parser("extract", help="verify then safely extract to a new release directory")
    extract.add_argument("--archive", type=Path, required=True)
    extract.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            result = build_bundle(args.root, args.output)
        elif args.command == "verify":
            result = verify_bundle(args.archive)
        else:
            path = extract_bundle(args.archive, args.destination)
            result = {"extracted_to": str(path), "manifest_verified": True}
    except (BundleError, OSError, tarfile.TarError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
