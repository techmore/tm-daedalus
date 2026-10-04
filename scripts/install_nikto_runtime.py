#!/usr/bin/env python3
"""Install the pinned external Nikto runtime into a fresh directory.

Linux prerequisites: perl, libnet-ssleay-perl and libxml-writer-perl.
Nikto retains its license files in the installed runtime.
This installer never updates an existing runtime or starts a network audit.
"""
from __future__ import annotations
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import tarfile
import tempfile
from urllib.request import urlopen

COMMIT = "312645d873478a77986627ab1fc8cffe595e85d4"
SHA256 = "fbd123fab2d74bfb0a4c66c158aabdfa394dd642bab618ada844956562b62fac"
URL = "https://codeload.github.com/sullo/nikto/tar.gz/" + COMMIT


def install(content: bytes, destination: Path) -> dict:
    if hashlib.sha256(content).hexdigest() != SHA256:
        raise ValueError("Nikto archive does not match the pinned source digest.")
    destination = destination.expanduser().absolute()
    if destination.exists() or destination.is_symlink():
        raise ValueError("Nikto destination already exists; preserve it for reviewed upgrades.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    prefix = "nikto-" + COMMIT
    with tempfile.TemporaryDirectory(prefix=".nikto-install-", dir=destination.parent) as temporary:
        staging = Path(temporary)
        with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as archive:
            total = 0
            names = set()
            for member in archive:
                parts = PurePosixPath(member.name).parts
                if not parts or parts[0] != prefix or ".." in parts or PurePosixPath(member.name).is_absolute() or not (member.isfile() or member.isdir()) or member.name in names:
                    raise ValueError("Nikto source archive contains an unexpected member.")
                names.add(member.name)
                total += member.size
                if len(names) > 10000 or total > 64 * 1024 * 1024:
                    raise ValueError("Nikto source archive exceeds the extraction limit.")
            archive.extractall(staging, filter="data")
        source = staging / prefix
        if not (source / "program/nikto.pl").is_file():
            raise ValueError("Nikto program is missing from the pinned source.")
        for path in source.rglob("*"):
            path.chmod(0o755 if path.is_dir() else 0o644)
        source.chmod(0o755)
        metadata = {"source_commit": COMMIT, "archive_sha256": SHA256, "source_url": URL}
        (source / "daedalus-runtime.json").write_text(json.dumps(metadata, indent=2) + "\n")
        source.rename(destination)
        return metadata


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, default=Path("/opt/daedalus/nikto"))
    parser.add_argument("--archive", type=Path, help="Use a previously downloaded pinned archive")
    args = parser.parse_args()
    if args.archive:
        content = args.archive.read_bytes()
    else:
        with urlopen(URL, timeout=30) as response:
            content = response.read(8 * 1024 * 1024 + 1)
    print(json.dumps(install(content, args.destination), indent=2))


if __name__ == "__main__":
    main()
