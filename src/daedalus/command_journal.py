"""Private, bounded command claims and ordered result acknowledgements."""
from __future__ import annotations

import hashlib
import json
import math
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Any


class CommandJournal:
    MAX_BYTES = 16 * 1024 * 1024
    MAX_FILES = 10_000
    CLAIM_FINGERPRINT_VERSION = 2

    def __init__(self, root: Path):
        self.root = root
        if root.is_symlink():
            raise OSError("Refusing a command journal through a symbolic link")
        root.mkdir(parents=True, mode=0o700, exist_ok=True)
        root.chmod(0o700)
        self.lock = threading.RLock()

    def _write(self, path: Path, value: dict[str, Any], *, exclusive: bool = False) -> None:
        encoded = json.dumps(value, sort_keys=True).encode()
        if path.is_symlink():
            raise OSError("Refusing a journal entry through a symbolic link")
        files = list(self.root.iterdir())
        if len(files) + (not path.exists()) > self.MAX_FILES or sum(p.stat().st_size for p in files if p.is_file()) + len(encoded) - (path.stat().st_size if path.exists() else 0) > self.MAX_BYTES:
            raise OSError("Command journal reached its storage limit")
        temporary = self.root / (uuid.uuid4().hex + ".tmp")
        try:
            with temporary.open("xb") as output:
                temporary.chmod(0o600)
                output.write(encoded)
                output.flush()
                os.fsync(output.fileno())
            if exclusive:
                os.link(temporary, path)
            else:
                temporary.replace(path)
            descriptor = os.open(self.root, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        finally:
            temporary.unlink(missing_ok=True)

    def claim(self, command: dict[str, Any]) -> bool:
        """Record intent before a side effect; never execute the same ID again."""
        identifier = command.get("id")
        if type(identifier) is not int or identifier <= 0:
            raise ValueError("Invalid command ID")
        action = command.get("action")
        target = command.get("target")
        skip_host_discovery = command.get("skip_host_discovery", False)
        if not isinstance(action, str) or (target is not None and not isinstance(target, str)) or type(skip_host_discovery) is not bool:
            raise ValueError("Invalid command payload")
        legacy_payload = {"action": action, "target": target}
        payload = {**legacy_payload, "skip_host_discovery": skip_host_discovery}
        fingerprint = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        legacy_fingerprint = hashlib.sha256(json.dumps(legacy_payload, sort_keys=True).encode()).hexdigest()
        path = self.root / f"claim-{identifier}.json"

        def already_claimed() -> bool:
            if path.is_symlink():
                raise ValueError("Command ID conflicts with a prior local claim")
            prior = json.loads(path.read_text())
            if prior.get("fingerprint_version") == self.CLAIM_FINGERPRINT_VERSION:
                matches = prior.get("fingerprint") == fingerprint
            else:
                # Pre-v2 claims did not encode per-scan options. They can only
                # match the legacy behavior (host discovery enabled).
                matches = skip_host_discovery is False and prior.get("fingerprint") == legacy_fingerprint
            if not matches:
                raise ValueError("Command ID conflicts with a prior local claim")
            return False

        with self.lock:
            if path.exists():
                return already_claimed()
            try:
                self._write(path, {"command_id": identifier, "fingerprint_version": self.CLAIM_FINGERPRINT_VERSION,
                                   "fingerprint": fingerprint, "claimed_at": time.time()}, exclusive=True)
                return True
            except FileExistsError:
                return already_claimed()

    def enqueue(self, identifier: int, status: str, result: str) -> None:
        if type(identifier) is not int or identifier <= 0 or status not in {"accepted", "succeeded", "failed", "timed_out"} or not isinstance(result, str):
            raise ValueError("Invalid command outcome")
        value = {"command_id": identifier, "status": status, "result": result[:1000]}
        with self.lock:
            claim = self.root / f"claim-{identifier}.json"
            if claim.exists() and not claim.is_symlink():
                acknowledged = json.loads(claim.read_text()).get("terminal_result")
                if acknowledged and (status == "accepted" or acknowledged == value):
                    return
            pending = sorted(self.root.glob("result-*.json"))
            last = 0
            for path in pending:
                if path.is_symlink():
                    raise OSError("Refusing a pending result through a symbolic link")
                try:
                    sequence = int(path.name.split("-")[1])
                    existing = json.loads(path.read_text())
                except (ValueError, UnicodeDecodeError, IndexError):
                    self.reject(path)
                    continue
                last = max(last, sequence)
                if existing == value:
                    return
            sequence = max(time.time_ns(), last + 1)
            self._write(self.root / f"result-{sequence:020d}-{identifier}.json", value)

    def pending(self) -> list[tuple[Path, dict[str, Any]]]:
        with self.lock:
            result = []
            for path in sorted(self.root.glob("result-*.json"))[:20]:
                if path.is_symlink():
                    raise OSError("Refusing a pending result through a symbolic link")
                try:
                    value = json.loads(path.read_text())
                    if not isinstance(value, dict) or type(value.get("command_id")) is not int or value["command_id"] <= 0 or value.get("status") not in {"accepted", "succeeded", "failed", "timed_out"} or not isinstance(value.get("result"), str):
                        raise ValueError("Invalid command result entry")
                    result.append((path, value))
                except (ValueError, UnicodeDecodeError):
                    self.reject(path)
            return result

    def acknowledge(self, path: Path) -> None:
        with self.lock:
            value = json.loads(path.read_text())
            claim = self.root / f"claim-{value['command_id']}.json"
            if value["status"] in {"succeeded", "failed", "timed_out"} and claim.exists():
                if claim.is_symlink():
                    raise OSError("Refusing a claimed command through a symbolic link")
                record = json.loads(claim.read_text())
                record["terminal_result"] = value
                self._write(claim, record)
            path.unlink()

    def was_claimed(self, identifier: int) -> bool:
        path = self.root / f"claim-{identifier}.json"
        return path.is_file() and not path.is_symlink() and json.loads(path.read_text()).get("command_id") == identifier

    def wait_for_restart(self, command: dict[str, Any]) -> None:
        with self.lock:
            self._write(self.root / f"waiting-{int(command['id'])}.json", {"command_id": int(command["id"]), "deadline_at": command.get("deadline_at"), "started_at": time.time()})

    def waiting_restarts(self) -> list[tuple[Path, dict[str, Any]]]:
        with self.lock:
            records = []
            for path in self.root.glob("waiting-*.json"):
                if path.is_symlink():
                    raise OSError("Refusing a restart receipt through a symbolic link")
                try:
                    record = json.loads(path.read_text())
                    if (
                        not isinstance(record, dict)
                        or type(record.get("command_id")) is not int
                        or record["command_id"] <= 0
                        or path.name != f"waiting-{record['command_id']}.json"
                        or type(record.get("started_at")) not in {int, float}
                        or not math.isfinite(record["started_at"])
                        or not isinstance(record.get("deadline_at"), (str, type(None)))
                    ):
                        raise ValueError("Invalid restart receipt")
                    records.append((path, record))
                except (ValueError, UnicodeDecodeError):
                    self.reject(path)
            return records

    def reject(self, path: Path) -> None:
        with self.lock:
            path.replace(path.with_suffix(".rejected"))

    def counts(self) -> dict[str, int]:
        with self.lock:
            return {"pending_command_results": len(list(self.root.glob("result-*.json"))),
                    "rejected_command_results": len(list(self.root.glob("result-*.rejected")))}
