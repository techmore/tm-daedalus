"""Read operator-installed CIS releases, never user-supplied packages.

Apple verification runs on the release Mac. The protected release manifest
records that result; these Linux-side checks verify identity and integrity,
not Apple's signatures independently.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile

FILENAME = "CSP-CIS_Audit-macOS-notarized.zip"
MAX_PACKAGE_BYTES = 32 * 1024 * 1024
MAX_EXPANDED_BYTES = 128 * 1024 * 1024


class ReleaseInvalid(ValueError):
    pass


def _read(path: Path, limit: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ReleaseInvalid("Release file is not a bounded regular file")
        value = source.read(limit + 1)
        if len(value) > limit:
            raise ReleaseInvalid("Release file exceeds its size limit")
        return value


def load_release(directory: Path) -> tuple[dict, bytes]:
    if directory.is_symlink():
        raise ReleaseInvalid("Release directory must not be a symlink")
    try:
        metadata = _read(directory / "manifest.json", 16384)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise ReleaseInvalid("The installed CIS manifest could not be read") from exc
    try:
        manifest = json.loads(metadata)
        if not isinstance(manifest, dict):
            raise ReleaseInvalid("Invalid release metadata")
        required = {"schema", "filename", "sha256", "signing", "team_id", "architectures",
                    "source_commit", "verification"}
        if set(manifest) != required or type(manifest["schema"]) is not int or manifest["schema"] != 1:
            raise ReleaseInvalid("Unsupported release manifest")
        if manifest["filename"] != FILENAME or manifest["signing"] != "developer-id-notarized":
            raise ReleaseInvalid("A notarized release is required")
        if not isinstance(manifest["team_id"], str) or not re.fullmatch(r"[A-Z0-9]{10}", manifest["team_id"]):
            raise ReleaseInvalid("Invalid signing team")
        for name, size in (("sha256", 64), ("source_commit", 40)):
            if not isinstance(manifest[name], str) or not re.fullmatch(r"[0-9a-f]{%d}" % size, manifest[name]):
                raise ReleaseInvalid("Invalid release identity")
        architectures = manifest["architectures"]
        if not isinstance(architectures, list) or not architectures or any(
            not isinstance(value, str) or value not in {"arm64", "x86_64"} for value in architectures
        ) or len(set(architectures)) != len(architectures):
            raise ReleaseInvalid("Unsupported release architectures")
        if manifest["verification"] != {"codesign": True, "stapler": True, "gatekeeper": True} or any(
            type(value) is not bool for value in manifest["verification"].values()
        ):
            raise ReleaseInvalid("Complete release-Mac verification is required")
        contents = _read(directory / FILENAME, MAX_PACKAGE_BYTES)
        if hashlib.sha256(contents).hexdigest() != manifest["sha256"]:
            raise ReleaseInvalid("Release checksum mismatch")
        with zipfile.ZipFile(io.BytesIO(contents)) as package:
            entries = package.infolist()
            names = [entry.filename for entry in entries]
            if not entries or len(entries) > 10000 or len(set(names)) != len(names):
                raise ReleaseInvalid("Invalid release archive entries")
            if sum(entry.file_size for entry in entries) > MAX_EXPANDED_BYTES:
                raise ReleaseInvalid("Release archive expands beyond its limit")
            for entry in entries:
                path = PurePosixPath(entry.filename)
                if path.is_absolute() or ".." in path.parts or "\\" in entry.filename or "\0" in entry.filename:
                    raise ReleaseInvalid("Unsafe release archive path")
                if not path.parts or path.parts[0] not in {"CSP-CIS_Audit.app", "__MACOSX"}:
                    raise ReleaseInvalid("Unexpected release archive root")
                if path.name.lower() in {"config.yaml", "cis-client.yaml", "cis-client.yml"}:
                    raise ReleaseInvalid("Workspace configuration must not be distributed")
                if stat.S_ISLNK(entry.external_attr >> 16) or entry.flag_bits & 1:
                    raise ReleaseInvalid("Unsupported release archive entry")
            if "CSP-CIS_Audit.app/Contents/Info.plist" not in names or package.testzip() is not None:
                raise ReleaseInvalid("Incomplete or corrupt release archive")
        return manifest, contents
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile, RuntimeError) as exc:
        raise ReleaseInvalid("The installed CIS release failed integrity checks") from exc


def release_status(directory: Path) -> dict:
    try:
        manifest, _ = load_release(directory)
        return {"available": True, "architectures": manifest["architectures"],
                "source_commit": manifest["source_commit"], "sha256": manifest["sha256"]}
    except FileNotFoundError:
        return {"available": False, "reason": "not_published"}
    except ReleaseInvalid:
        return {"available": False, "reason": "integrity_failed"}
