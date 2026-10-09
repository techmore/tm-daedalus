"""Bounded upload observations and a private journal of incomplete local saves.

A clear queue describes retained files. It never proves scan completeness.
No event payload, event identity, path or credential leaves this module.
"""
from __future__ import annotations

from datetime import UTC, datetime
import json
import os
from pathlib import Path
import stat
import tempfile
import threading
import time
from typing import Any
from uuid import UUID

MAX_ENTRIES = 10_000
MAX_JOURNAL_BYTES = 16 * 1024
MAX_UNRESOLVED = 256
FIELDS = {"schema_version", "state", "pending_events", "review_events", "preservation_failed", "last_acknowledged_at"}


def unknown_delivery(preservation_failed: bool | None = None) -> dict[str, Any]:
    return {"schema_version": 1, "state": "unknown", "pending_events": None,
            "review_events": None, "preservation_failed": preservation_failed, "last_acknowledged_at": None}


def utc_timestamp(value: Any) -> str | None:
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset().total_seconds() != 0:
            return None
        return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")
    except (ValueError, OverflowError, AttributeError):
        return None


def validated_delivery(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict) or set(value) != FIELDS or type(value.get("schema_version")) is not int or value["schema_version"] != 1:
        return None
    if value["state"] == "unknown":
        flag = value["preservation_failed"]
        if flag is not None and flag is not True:
            return None
        return unknown_delivery(flag) if value == unknown_delivery(flag) else None
    if value["state"] != "observed" or any(type(value[field]) is not int or not 0 <= value[field] <= MAX_ENTRIES for field in ("pending_events", "review_events")):
        return None
    if type(value["preservation_failed"]) is not bool:
        return None
    ack = value["last_acknowledged_at"]
    if ack is not None and utc_timestamp(ack) is None:
        return None
    return {**value, "last_acknowledged_at": utc_timestamp(ack) if ack is not None else None}


def needs_review(value: dict[str, Any]) -> bool:
    return value.get("preservation_failed") is True or (value.get("state") == "observed" and value.get("review_events", 0) > 0)


def _atomic_private_json(path: Path, value: dict[str, Any]) -> None:
    if path.is_symlink():
        raise OSError("Upload state is a symbolic link")
    descriptor, temporary_name = tempfile.mkstemp(prefix=".delivery-", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(json.dumps(value, separators=(",", ":")).encode())
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


class DeliveryJournal:
    """Persist intent before saving an event; matching save/ack resolves it.

    Corrupt journals stay unknown instead of being replaced with a clean state.
    Overflow stays latched for operator review: missing identities cannot be
    resolved by an unrelated successful upload. Managed bridges own one spool.
    """
    def __init__(self, spool: Path):
        self.path = spool / "delivery.journal"
        self.lock = threading.RLock()
        self.unresolved: set[str] = set()
        self.overflow = False
        self.last_acknowledged_at = None
        self.corrupt = False
        self.io_unknown = False
        try:
            descriptor = os.open(self.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        except FileNotFoundError:
            self._persist()
            return
        except OSError:
            self.corrupt = True
            return
        try:
            with os.fdopen(descriptor, "rb") as source:
                metadata = os.fstat(source.fileno())
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_JOURNAL_BYTES:
                    raise ValueError("Invalid upload journal")
                contents = source.read(MAX_JOURNAL_BYTES + 1)
                if len(contents) > MAX_JOURNAL_BYTES:
                    raise ValueError("Upload journal exceeds its limit")
            body = json.loads(contents)
            if not isinstance(body, dict) or set(body) != {"version", "unresolved", "overflow", "last_acknowledged_at"} or type(body["version"]) is not int or body["version"] != 1:
                raise ValueError("Invalid upload journal schema")
            identifiers = body["unresolved"]
            if not isinstance(identifiers, list) or len(identifiers) > MAX_UNRESOLVED or any(not isinstance(item, str) or str(UUID(item)) != item for item in identifiers):
                raise ValueError("Invalid upload save identities")
            if len(set(identifiers)) != len(identifiers) or type(body["overflow"]) is not bool:
                raise ValueError("Invalid upload save state")
            ack = body["last_acknowledged_at"]
            if ack is not None and utc_timestamp(ack) is None:
                raise ValueError("Invalid upload acknowledgement date")
            self.unresolved = set(identifiers)
            self.overflow = body["overflow"]
            self.last_acknowledged_at = utc_timestamp(ack) if ack is not None else None
        except (OSError, ValueError, TypeError, RecursionError):
            self.corrupt = True

    def _persist(self) -> bool:
        if self.corrupt:
            return False
        try:
            _atomic_private_json(self.path, {"version": 1, "unresolved": sorted(self.unresolved),
                "overflow": self.overflow, "last_acknowledged_at": self.last_acknowledged_at})
            self.io_unknown = False
            return True
        except OSError:
            self.io_unknown = True
            return False

    def begin(self, identifier: str) -> bool:
        with self.lock:
            identifier = str(UUID(identifier))
            if len(self.unresolved) < MAX_UNRESOLVED or identifier in self.unresolved:
                self.unresolved.add(identifier)
            else:
                self.overflow = True
            return self._persist()

    def saved(self, identifier: str) -> None:
        with self.lock:
            self.unresolved.discard(str(UUID(identifier)))
            self._persist()

    def acknowledged(self, identifier: str) -> None:
        with self.lock:
            self.unresolved.discard(str(UUID(identifier)))
            self.last_acknowledged_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
            self._persist()

    def observation(self, spool: Path) -> dict[str, Any]:
        with self.lock:
            failed = True if self.unresolved or self.overflow else None
            if self.corrupt or self.io_unknown:
                return unknown_delivery(failed)
            pending = review = entries = 0
            deadline = time.monotonic() + .25
            try:
                with os.scandir(spool) as stream:
                    for entry in stream:
                        entries += 1
                        if entries > MAX_ENTRIES or time.monotonic() > deadline:
                            return unknown_delivery(failed)
                        if not entry.name.endswith((".json", ".rejected", ".json.tmp")):
                            continue
                        if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                            return unknown_delivery(failed)
                        if entry.name.endswith(".json"):
                            pending += 1
                        else:
                            review += 1
            except OSError:
                return unknown_delivery(failed)
            return {"schema_version": 1, "state": "observed", "pending_events": pending,
                    "review_events": review, "preservation_failed": bool(self.unresolved or self.overflow),
                    "last_acknowledged_at": self.last_acknowledged_at}

    def publish_local_observation(self, spool: Path, value: dict[str, Any]) -> None:
        # Local visibility continues during a portal outage. Receipt freshness on
        # the portal is independent of this device's local observation time.
        try:
            _atomic_private_json(spool / "upload.status", {**value,
                "observed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z")})
        except OSError:
            pass  # Local consumers expire their prior observation after 45 seconds.
