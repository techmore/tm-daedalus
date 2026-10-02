#!/usr/bin/env python3
"""Package the runtime NmapUI source needed by Daedalus scanner installs."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import zipfile
from pathlib import Path


ROOT_FILES = (
    "app.py",
    "customer_fingerprint.py",
    "customer_fingerprint_matcher.py",
    "customer_fingerprint_store.py",
    "persistence.py",
    "requirements.txt",
    "VERSION",
    "nmap-modern.xsl",
    "nmap-pdf-olive-legacy.xsl",
    "config/auto_scan_config.example.json",
    "config/customers_example.yaml",
    "nmap-vulners/LICENSE",
    "nmap-vulners/vulners.nse",
    "nmap-vulners/http-vulners-regex.nse",
    "nmap-vulners/http-vulners-regex.json",
    "nmap-vulners/http-vulners-paths.txt",
)
RUNTIME_DIRECTORIES = ("nmapui", "templates", "static")
EXCLUDED_PARTS = {"__pycache__", "tests", "testdata", "node_modules"}
EXCLUDED_NAMES = {".DS_Store", "customers.yaml"}


def _source_commit(source: Path) -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(source), "rev-parse", "--short=12", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unavailable"


def _source_worktree_paths(source: Path, packaged_paths: set[str]) -> list[str]:
    """Identify packaged files whose bytes are not represented by the source HEAD."""
    try:
        status = subprocess.check_output(
            ["git", "-C", str(source), "status", "--porcelain", "--untracked-files=all"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError):
        return []
    changed = set()
    for line in status.splitlines():
        if len(line) < 4:
            continue
        path = line[3:].split(" -> ")[-1].strip().strip('"')
        if path in packaged_paths:
            changed.add(path)
    return sorted(changed)


def collect_files(source: Path) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    for name in ROOT_FILES:
        path = source / name
        if not path.is_file() or path.is_symlink():
            raise SystemExit(f"Required NmapUI runtime file is missing: {name}")
        contents = path.read_bytes()
        if name == "requirements.txt":
            runtime_lines = []
            for line in contents.decode("utf-8").splitlines():
                if line.strip().lower().startswith("# test dependencies"):
                    break
                runtime_lines.append(line)
            contents = ("\n".join(runtime_lines).rstrip() + "\n").encode("utf-8")
        files[name] = contents

    for directory in RUNTIME_DIRECTORIES:
        root = source / directory
        if not root.is_dir() or root.is_symlink():
            raise SystemExit(f"Required NmapUI runtime directory is missing: {directory}")
        for path in sorted(root.rglob("*")):
            relative = path.relative_to(source)
            if path.is_symlink() or not path.is_file():
                continue
            if any(part in EXCLUDED_PARTS for part in relative.parts):
                continue
            if path.name in EXCLUDED_NAMES or path.name.startswith(".env"):
                continue
            files[relative.as_posix()] = path.read_bytes()

    digest = hashlib.sha256()
    for name, contents in sorted(files.items()):
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(contents)
        digest.update(b"\0")
    source_paths = set(files)
    manifest = {
        "version": (source / "VERSION").read_text(encoding="utf-8").strip(),
        "source_commit": _source_commit(source),
        "source_worktree_paths": _source_worktree_paths(source, source_paths),
        "source_tree_sha256": digest.hexdigest(),
        "file_count": len(files),
        "scope": "runtime source only; no settings, customer data, credentials, or Node dependencies",
    }
    files["manifest.json"] = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    return files


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source",
        type=Path,
        default=Path(__file__).resolve().parents[1].parent / "NmapUI",
        help="NmapUI source checkout (defaults to the sibling NmapUI project)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parents[1]
        / "src"
        / "daedalus"
        / "agent_bundle"
        / "nmapui-source.zip",
    )
    args = parser.parse_args()
    source = args.source.expanduser().resolve(strict=True)
    output = args.output.expanduser()
    output.parent.mkdir(parents=True, exist_ok=True)
    files = collect_files(source)
    with zipfile.ZipFile(
        output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for name, contents in sorted(files.items()):
            info = zipfile.ZipInfo(f"daedalus-nmapui-source/{name}")
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, contents, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    manifest = json.loads(files["manifest.json"])
    print(
        f"Built NmapUI {manifest['version']} source bundle: {len(files) - 1} files, "
        f"{output.stat().st_size} bytes; source sha256 {manifest['source_tree_sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
