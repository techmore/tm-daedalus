from __future__ import annotations

import argparse
import base64
import ctypes
from contextlib import contextmanager
import getpass
import hashlib
import ipaddress
import json
import logging
import os
import platform
import re
import secrets
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
import socketio

from daedalus import __version__
from daedalus.command_journal import CommandJournal


LOG = logging.getLogger("daedalus.agent")
COMMAND_PROTOCOL_VERSION = 4


class UpdateOutputIncomplete(ValueError):
    """A bounded tool read cannot establish a complete update result."""


def _bounded_update_command(args: list[str], *, timeout: float, env=None) -> subprocess.CompletedProcess:
    """Capture at most 128 KiB across both streams of an owned tool process.

    Never invoke a shell, inherit stdin or retain raw output in a receipt.
    The timeout includes draining pipes and waiting for process completion.
    """
    limit = 128 * 1024
    deadline = time.monotonic() + timeout
    process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, bufsize=0, env=env, start_new_session=True)
    output = [bytearray(), bytearray()]
    completed = False
    try:
        with selectors.DefaultSelector() as selector:
            for index, stream in enumerate((process.stdout, process.stderr)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, index)
            total = 0
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(args, timeout)
                for key, _ in selector.select(min(remaining, 0.25)):
                    try:
                        chunk = os.read(key.fileobj.fileno(), 4096)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if total + len(chunk) > limit:
                        raise UpdateOutputIncomplete("Update catalog exceeded the capture limit")
                    output[key.data].extend(chunk)
                    total += len(chunk)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(args, timeout)
            process.wait(timeout=remaining)
            completed = True
        try:
            stdout, stderr = (bytes(value).decode("utf-8") for value in output)
        except UnicodeDecodeError as exc:
            raise UpdateOutputIncomplete("Update catalog contained unsupported encoding") from exc
        return subprocess.CompletedProcess(args, process.returncode, stdout, stderr)
    finally:
        # Stop only this invocation's isolated process group. This also handles
        # a child retaining a pipe after its parent exits; never signal a daemon.
        try:
            if not completed:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            process.wait(timeout=2)
        finally:
            process.stdout.close()
            process.stderr.close()


def discover_connected_networks() -> list[str]:
    """Derive the active default connection's IPv4 subnet; never guess a prefix."""
    def read(args: list[str]) -> str:
        result = subprocess.run(args, capture_output=True, text=True, timeout=3, check=True)
        if len(result.stdout) > 65536:
            raise ValueError("Network inventory exceeded its limit")
        return result.stdout

    try:
        system = platform.system()
        if system == "Darwin":
            route = read(["/sbin/route", "-n", "get", "default"])
            match = re.search(r"^\s*interface:\s*([A-Za-z0-9_.-]{1,32})\s*$", route, re.M)
            if not match:
                return []
            interface = match.group(1)
            # Tunnel connections do not identify a directly attached LAN.
            if interface.startswith(("utun", "tun", "tap", "lo")):
                return []
            inventory = read(["/sbin/ifconfig", interface])
            addresses = re.findall(r"\binet ([0-9.]+) netmask (0x[0-9a-fA-F]+|[0-9.]+)", inventory)
            candidates = []
            for address, mask in addresses:
                if mask.startswith("0x"):
                    mask = str(ipaddress.IPv4Address(int(mask, 16)))
                candidates.append(ipaddress.IPv4Interface(f"{address}/{mask}"))
        elif system == "Linux":
            executable = shutil.which("ip")
            if not executable:
                return []
            routes = json.loads(read([executable, "-j", "route", "show", "default"]))
            routes = sorted(routes, key=lambda route: route.get("metric", 0))
            interface = next((route.get("dev") for route in routes if route.get("dev")), None)
            if not isinstance(interface, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", interface):
                return []
            if interface.startswith(("tun", "tap", "tailscale", "wg", "lo")):
                return []
            inventory = json.loads(read([executable, "-j", "address", "show", "dev", interface]))
            candidates = [ipaddress.IPv4Interface(f"{entry['local']}/{entry['prefixlen']}")
                          for device in inventory for entry in device.get("addr_info", [])
                          if entry.get("family") == "inet" and entry.get("scope") == "global"]
        else:
            return []
        return sorted({str(address.network) for address in candidates
                       if address.ip.is_private and not address.ip.is_loopback
                       and not address.ip.is_link_local and not address.ip.is_unspecified
                       and address.network.prefixlen > 0})[:32]
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError):
        return []


def _total_memory_bytes(system: str) -> int | None:
    """Read a public physical-memory scalar; never spawn a process."""
    try:
        if system == "Darwin":
            library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
            query = library.sysctlbyname
            query.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p, ctypes.c_size_t]
            query.restype = ctypes.c_int
            value = ctypes.c_uint64()
            size = ctypes.c_size_t(ctypes.sizeof(value))
            if query(b"hw.memsize", ctypes.byref(value), ctypes.byref(size), None, 0) != 0 or size.value != ctypes.sizeof(value):
                return None
            memory = value.value
        elif system == "Linux":
            pages, page_size = os.sysconf("SC_PHYS_PAGES"), os.sysconf("SC_PAGE_SIZE")
            if pages <= 0 or page_size <= 0:
                return None
            memory = pages * page_size
        else:
            return None
        return memory if type(memory) is int and 0 < memory <= 2**60 else None
    except (OSError, ValueError, AttributeError, TypeError):
        return None


def _host_inventory() -> dict[str, Any]:
    """Allowlisted anonymous host capabilities; memory is host physical capacity."""
    def read(reader, unknown=None):
        try:
            return reader()
        except (OSError, ValueError, AttributeError, TypeError):
            return unknown
    system = read(platform.system, "unknown")
    if system not in {"Darwin", "Linux", "Windows"}:
        system = "unknown"
    raw_version = read(lambda: platform.mac_ver()[0], "") if system == "Darwin" else read(platform.release, "") if system != "unknown" else ""
    if not isinstance(raw_version, str):
        raw_version = ""
    version = re.match(r"\A[0-9]+(?:\.[0-9]+){0,3}", raw_version or "")
    architecture = read(platform.machine, "unknown")
    if architecture not in {"arm64", "aarch64", "x86_64", "AMD64", "i386", "i686", "armv7l", "armv6l", "ppc64", "ppc64le", "s390x", "riscv64"}:
        architecture = "unknown"
    cpus = read(os.cpu_count)
    return {"platform": system, "os_version": version.group(0)[:40] if version else None, "architecture": architecture, "cpu_count": cpus if type(cpus) is int and 0 < cpus <= 65536 else None, "total_memory_bytes": _total_memory_bytes(system)}


def _os_update_result(evidence: dict[str, Any]) -> str:
    """Keep the bounded catalog result valid within the command result limit."""
    bounded = dict(evidence)
    if "updates" in bounded:
        bounded["updates"] = list(bounded["updates"])
    encoded = json.dumps(bounded, ensure_ascii=False, separators=(",", ":"))
    while len(encoded) > 1000 and bounded.get("updates"):
        bounded["updates"].pop()
        bounded["truncated"] = True
        encoded = json.dumps(bounded, ensure_ascii=False, separators=(",", ":"))
    # Non-list fields are fixed-size values produced by _check_os_updates.
    if len(encoded) > 1000:
        raise ValueError("OS update result exceeds the command result limit.")
    return encoded


def _diagnostics_result(evidence: dict[str, Any]) -> str:
    try:
        encoded = json.dumps(evidence, ensure_ascii=False, separators=(",", ":"))
    except (ValueError, TypeError):
        encoded = " " * 1001
    if len(encoded) <= 1000:
        return encoded
    # Preserve a complete versioned inventory rather than journal truncation.
    def version(key):
        value = evidence.get(key)
        matched = re.match(r"\Av?[0-9]+(?:\.[0-9]+){0,3}", value) if isinstance(value, str) else None
        return matched.group(0)[:40] if matched else None
    def integer(key, maximum):
        value = evidence.get(key)
        return value if type(value) is int and 0 < value <= maximum else None
    bounded = {"schema_version": 1, "bridge_version": version("bridge_version"), "os_version": version("os_version"), "platform": evidence.get("platform") if evidence.get("platform") in ("Darwin", "Linux", "Windows") else "unknown", "architecture": evidence.get("architecture") if evidence.get("architecture") in ("arm64", "aarch64", "x86_64", "AMD64", "i386", "i686", "armv7l", "armv6l", "ppc64", "ppc64le", "s390x", "riscv64") else "unknown", "cpu_count": integer("cpu_count", 65536), "total_memory_bytes": integer("total_memory_bytes", 2**60)}
    bounded["operational_fields_omitted"] = True
    return json.dumps(bounded, ensure_ascii=False, separators=(",", ":"))


NMAPUI_LAUNCHD_LABEL = re.compile(r"org\.daedalus\.nmapui(?:\.[a-z0-9-]{1,40})?\Z")
NMAPUI_SYSTEMD_UNIT = "daedalus-nmapui.service"
NMAPUI_SYSTEMD_BRIDGE_UNIT = "daedalus-scanner-bridge.service"
NMAPUI_SYSTEMD_ENV_FILE = "daedalus-nmapui.env"
NMAPUI_SYSTEMD_OWNERSHIP_FILE = ".daedalus-scanner-services.json"
NMAPUI_SYSTEMD_LOCK_FILE = ".daedalus-scanner-services.lock"
NMAPUI_SYSTEMD_UPGRADE_FILE = ".daedalus-scanner-upgrade.json"
FORWARDED_EVENTS = {
    "app_update_available",
    "job_status",
    "scan_feedback",
    "scan_results",
    "quickscan_results",
    "scan_complete_summary",
    "scan_error",
    "quick_scan_start",
    "quick_scan_complete",
    "arp_scan_start",
    "arp_results",
    "arp_scan_complete",
    "deep_scan_results",
    "scan_xml_chunk",
    "cve_array",
    "service_info",
    "deep_scan_host_complete",
    "deep_scan_complete",
    "deep_scan_error",
    "report_progress",
    "report_error",
    "report_complete",
    "file_updated",
}


def default_config_dir() -> Path:
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Daedalus"
    base = os.environ.get("XDG_CONFIG_HOME")
    return Path(base) / "daedalus" if base else Path.home() / ".config" / "daedalus"


def save_config(
    config: dict[str, Any],
    agent_id: int,
    path: Path | None = None,
) -> Path:
    destination = path or (default_config_dir() / f"agent-{agent_id}.json")
    if destination.is_symlink():
        raise RuntimeError(f"Refusing to write agent config through a symbolic link: {destination}")
    directory = destination.parent
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    destination.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    try:
        destination.chmod(0o600)
        directory.chmod(0o700)
    except OSError:
        pass
    return destination


def validate_endpoint(value: str, *, local_scanner: bool = False) -> str:
    """Validate credential destinations before constructing an HTTP client."""
    if not isinstance(value, str) or not value or any(character.isspace() or ord(character) < 32 for character in value) or "\\" in value:
        raise ValueError("Endpoint must be a valid HTTP(S) origin.")
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Endpoint must be a valid HTTP(S) origin.") from exc
    if parsed.scheme not in {"http", "https"} or not host or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment or parsed.path not in {"", "/"} or "%" in parsed.netloc or (port is not None and not 1 <= port <= 65535):
        raise ValueError("Endpoint must be an HTTP(S) origin without credentials, paths, queries or fragments.")
    loopback = host.lower() in {"localhost", "127.0.0.1", "::1"}
    if local_scanner and not loopback:
        raise ValueError("NmapUI must use an exact loopback host.")
    if parsed.scheme == "http" and not loopback:
        raise ValueError("Remote Daedalus portals require HTTPS.")
    return value.rstrip("/")


def enroll(server: str, name: str, code: str) -> dict[str, Any]:
    server = validate_endpoint(server)
    response = httpx.post(
        server.rstrip("/") + "/api/agents/enroll",
        json={"code": code, "name": name},
        timeout=15, follow_redirects=False,
    )
    if response.is_error:
        raise RuntimeError(f"Daedalus enrollment failed ({response.status_code}). Check the portal enrollment code and workspace access.")
    body = response.json()
    return {
        "server": server.rstrip("/"),
        "agent_id": body["agent_id"],
        "agent_name": body["agent_name"],
        "organization": body["organization"],
        "agent_token": body["agent_token"],
        "created_at": time.time(),
    }


class NmapUIBridge:
    def __init__(self, config: dict[str, Any], nmapui_url: str, *, spool_dir: Path | None = None):
        self.config = config
        self.nmapui_url = validate_endpoint(nmapui_url, local_scanner=True)
        self.agent_id = int(config["agent_id"])
        self.server = validate_endpoint(str(config["server"]))
        self.token = str(config["agent_token"])
        self.http = httpx.Client(
            timeout=httpx.Timeout(10.0, connect=4.0),
            headers={"Authorization": "Bearer " + self.token},
            follow_redirects=False,
        )
        self.sio = socketio.Client(
            reconnection=True,
            reconnection_attempts=0,
            reconnection_delay=1,
            reconnection_delay_max=15,
            logger=False,
            engineio_logger=False,
        )
        self.nmapui_connected = threading.Event()
        self.stop_requested = threading.Event()
        self.last_socket_failure_log = 0.0
        self.command_completion_supported = False
        self.source_protocol = False
        self.source_job_metadata = False
        identity = hashlib.sha256(f"{self.server}:{self.agent_id}".encode()).hexdigest()[:24]
        self.spool_dir = spool_dir or default_config_dir() / "event-spool" / identity
        if self.spool_dir.is_symlink():
            raise RuntimeError("Refusing a scanner event spool through a symbolic link.")
        self.spool_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
        self.spool_dir.chmod(0o700)
        # A process interruption after fsync but before rename can leave a complete temp entry.
        for temporary in self.spool_dir.glob("*.json.tmp"):
            try:
                if temporary.is_symlink():
                    raise ValueError("Temporary spool entry is a symbolic link")
                json.loads(temporary.read_text(encoding="utf-8"))
                temporary.replace(temporary.with_suffix(""))
            except (OSError, ValueError):
                LOG.error("Interrupted spool entry requires review: %s", temporary.name)
        self.command_namespace = hashlib.sha256(f"{self.server}:{self.agent_id}:{self.token}".encode()).hexdigest()[:24]
        self.command_journal = CommandJournal(self.spool_dir / ("commands-" + self.command_namespace))
        self.command_upload_lock = threading.Lock()
        self.last_successful_check_in = None
        self.spool_lock = threading.Lock()
        self.upload_lock = threading.Lock()
        self.next_upload_at = 0.0
        self.upload_backoff = 2.0
        self._register_socket_handlers()

    def _register_socket_handlers(self) -> None:
        @self.sio.event
        def connect():
            self.nmapui_connected.set()
            LOG.info("Connected to the local NmapUI service.")

        @self.sio.event
        def disconnect(reason=None):
            self.nmapui_connected.clear()
            self.source_protocol = False
            self.source_job_metadata = False
            self.command_completion_supported = False
            LOG.warning("NmapUI disconnected%s", f": {reason}" if reason else ".")

        @self.sio.on("*")
        def any_event(event_name, *args):
            if event_name == "daedalus_protocol":
                self.source_protocol = bool(args and isinstance(args[0], dict) and args[0].get("version") == 1)
                self.command_completion_supported = bool(self.source_protocol and args[0].get("command_results") is True)
                self.source_job_metadata = bool(self.source_protocol and args[0].get("source_job_metadata") is True)
                return
            if event_name == "daedalus_event":
                if not args or not isinstance(args[0], dict):
                    return
                source = args[0]
                if source.get("event_name") == "daedalus_command_result":
                    self._handle_command_completion(source.get("payload"))
                    return
                if source.get("event_name") not in FORWARDED_EVENTS:
                    return
                try:
                    source_id = str(uuid.UUID(source["client_event_id"]))
                    source_job_metadata = self._validated_source_job_metadata(source.get("source_job_id"), source.get("source_job_type"))
                    occurred = datetime.fromisoformat(source["occurred_at"].replace("Z", "+00:00"))
                    occurred = occurred.replace(tzinfo=occurred.tzinfo or UTC).astimezone(UTC).isoformat()
                except (KeyError, ValueError, TypeError, AttributeError):
                    LOG.error("Ignored a scanner source event with invalid identity or timestamp")
                    return
                self._forward_event(source["event_name"], source.get("payload"), client_event_id=source_id, occurred_at=occurred, **source_job_metadata)
                return
            if event_name == "job_status" and self.source_job_metadata:
                return  # Modern source emits its own stable grouped job-status envelopes.
            if self.source_protocol and event_name not in {"job_status", "app_update_available"}:
                return  # Versioned source envelopes own event identity; raw browser events are not evidence.
            if event_name not in FORWARDED_EVENTS:
                return
            if not args:
                payload = None
            elif len(args) == 1:
                payload = args[0]
            else:
                payload = list(args)
            self._forward_event(event_name, payload)

    def _request(self, method: str, path: str, **kwargs):
        return self.http.request(method, self.server + path, **kwargs)

    @staticmethod
    def _validated_source_job_metadata(source_job_id: str | None, source_job_type: str | None) -> dict[str, str]:
        if source_job_id is None and source_job_type is None:
            return {}
        if source_job_type not in {"scan", "report"} or not isinstance(source_job_id, str):
            raise ValueError("Source job metadata requires an explicit UUID and scan/report type")
        return {"source_job_id": str(uuid.UUID(source_job_id)), "source_job_type": source_job_type}

    def _forward_event(self, event_name: str, payload: Any, *, client_event_id: str | None = None, occurred_at: str | None = None,
                       source_job_id: str | None = None, source_job_type: str | None = None) -> None:
        event = {
            "client_event_id": client_event_id or str(uuid.uuid4()),
            "occurred_at": occurred_at or datetime.now(UTC).isoformat(),
            "event_name": event_name, "payload": payload,
            **self._validated_source_job_metadata(source_job_id, source_job_type),
        }
        # Commit locally before attempting the network. Never overwrite pending evidence.
        try:
            encoded = json.dumps(event, ensure_ascii=False).encode("utf-8")
            with self.spool_lock:
                if client_event_id:
                    for pending in self.spool_dir.glob(f"*-{client_event_id}.json"):
                        if json.loads(pending.read_text(encoding="utf-8")) == event:
                            return
                size = 0
                for entry in self.spool_dir.iterdir():
                    try:
                        if entry.is_file():
                            size += entry.stat().st_size
                    except FileNotFoundError:
                        pass  # An upload may finish while the queue size is being measured.
                if size + len(encoded) > 256 * 1024 * 1024:
                    raise OSError("Scanner event spool reached its 256 MiB storage limit")
                name = f"{time.time_ns():020d}-{event['client_event_id']}.json"
                temporary = self.spool_dir / (name + ".tmp")
                with temporary.open("xb") as output:
                    os.chmod(temporary, 0o600)
                    output.write(encoded)
                    output.flush()
                    os.fsync(output.fileno())
                temporary.replace(self.spool_dir / name)
        except (OSError, TypeError, ValueError) as exc:
            LOG.error("Could not preserve scanner event %s locally: %s", event_name, exc)

    def _flush_events(self) -> None:
        if time.monotonic() < self.next_upload_at or not self.upload_lock.acquire(blocking=False):
            return
        try:
            for path in sorted(self.spool_dir.glob("*.json"))[:20]:
                if self.stop_requested.is_set():
                    return
                try:
                    if path.is_symlink():
                        raise ValueError("Spool entry is a symbolic link")
                    event = json.loads(path.read_text(encoding="utf-8"))
                    payload_size = len(json.dumps(event.get("payload"), ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
                    route = "event-artifacts" if payload_size > 512_000 else "events"
                    response = self._request("POST", f"/api/agents/{self.agent_id}/{route}", json=event)
                    if response.is_success:
                        try:
                            acknowledgement = response.json()
                        except ValueError:
                            acknowledgement = None
                        if (
                            isinstance(acknowledgement, dict)
                            and acknowledgement.get("ok") is True
                            and type(acknowledgement.get("event_id")) is int
                            and acknowledgement["event_id"] > 0
                        ):
                            path.unlink()
                            self.upload_backoff = 2.0
                            continue
                        LOG.warning("Scanner event upload lacked a durable acknowledgement; keeping %s", path.name)
                        self.next_upload_at = time.monotonic() + self.upload_backoff
                        self.upload_backoff = min(300.0, self.upload_backoff * 2)
                        return
                    if response.status_code not in {401, 403, 408, 429} and response.status_code < 500:
                        path.replace(path.with_suffix(".rejected"))
                        LOG.error("Scanner event retained for review after permanent rejection (%s): %s", response.status_code, path.name)
                        continue
                except (ValueError, UnicodeDecodeError) as exc:
                    path.replace(path.with_suffix(".rejected"))
                    LOG.error("Malformed scanner event retained for review: %s", exc)
                    continue
                except (httpx.HTTPError, OSError) as exc:
                    LOG.warning("Scanner upload delayed; pending evidence remains on disk: %s", exc)
                self.next_upload_at = time.monotonic() + self.upload_backoff
                self.upload_backoff = min(300.0, self.upload_backoff * 2)
                return
        finally:
            self.upload_lock.release()

    def _event_upload_loop(self) -> None:
        while not self.stop_requested.is_set():
            try:
                self._flush_events()
                self._flush_command_results()
            except (OSError, ValueError) as exc:
                LOG.error("Scanner queues could not be read (%s)", type(exc).__name__)
            self.stop_requested.wait(2)

    def _heartbeat(self) -> None:
        scanner_health = self._read_nmapui_health()
        now = time.monotonic()
        if now >= getattr(self, "_network_inventory_due", 0):
            self._detected_networks = discover_connected_networks()
            self._network_inventory_due = now + 60
        payload = {
            "command_protocol_version": COMMAND_PROTOCOL_VERSION,
            "nmapui_connected": self.nmapui_connected.is_set(),
            "nmapui_restart_supported": self._nmapui_restart_supported(),
            "version": f"Daedalus bridge {__version__}",
            "platform": platform.system(),
            "detected_networks": self._detected_networks,
            **scanner_health,
        }
        response = self._request(
            "POST",
            f"/api/agents/{self.agent_id}/heartbeat",
            json=payload,
        )
        response.raise_for_status()
        self.last_successful_check_in = datetime.now(UTC).isoformat()

    def _read_nmapui_health(self) -> dict[str, Any]:
        """Read only the NmapUI readiness and version fields for the fleet card."""
        username = os.environ.get("NMAPUI_USERNAME", "")
        password = os.environ.get("NMAPUI_PASSWORD", "")
        basic_auth = (username, password) if username and password else None
        try:
            response = httpx.get(
                self.nmapui_url + "/api/health/ready",
                auth=basic_auth,
                timeout=4,
            )
            response.raise_for_status()
            body = response.json()
            if not isinstance(body, dict):
                raise ValueError("NmapUI readiness response was not an object")
            ready = body.get("ready")
            if not isinstance(ready, bool):
                ready = body.get("status") == "ready"
            version = body.get("app_version")
            return {
                "nmapui_version": str(version)[:80] if version else None,
                "nmapui_ready": ready,
            }
        except (httpx.HTTPError, ValueError):
            return {"nmapui_version": None, "nmapui_ready": False}

    def _send_command_result(self, command_id: int, status: str, result: str) -> None:
        # Preserve before sending; a network failure must not erase the outcome.
        self.command_journal.enqueue(command_id, status, result)
        self._flush_command_results()

    def _flush_command_results(self) -> None:
        if not self.command_upload_lock.acquire(blocking=False):
            return
        try:
            for path, entry in self.command_journal.pending():
                identifier = entry["command_id"]
                try:
                    response = self._request("POST", f"/api/agents/{self.agent_id}/commands/{identifier}/result",
                                             json={"status": entry["status"], "result": entry["result"]})
                    if response.is_success:
                        try:
                            body = response.json()
                        except ValueError:
                            body = None
                        if (isinstance(body, dict) and body.get("ok") is True
                                and type(body.get("command_id")) is int and body["command_id"] == identifier
                                and body.get("status") == entry["status"]):
                            self.command_journal.acknowledge(path)
                            continue
                        LOG.warning("Command result lacks an explicit acknowledgement; retained locally")
                        return
                    if response.status_code < 500 and response.status_code not in {401, 403, 408, 429}:
                        self.command_journal.reject(path)
                        LOG.error("Command result retained for review after rejection (%s)", response.status_code)
                        continue
                    return
                except httpx.HTTPError:
                    LOG.warning("Command result upload delayed; retained locally")
                    return
        finally:
            self.command_upload_lock.release()

    def _handle_command_completion(self, payload: Any) -> None:
        if not isinstance(payload, dict):
            return
        if payload.get("command_namespace") != self.command_namespace:
            LOG.warning("Correlated result belongs to another enrollment; ignored")
            return
        identifier, status, result = payload.get("command_id"), payload.get("status"), payload.get("result")
        if type(identifier) is not int or identifier <= 0 or status not in {"accepted", "succeeded", "failed"} or not isinstance(result, str):
            LOG.error("Invalid correlated command result ignored")
            return
        if not self.command_journal.was_claimed(identifier):
            LOG.error("Correlated result for an unclaimed command ignored")
            return
        try:
            self.command_journal.enqueue(identifier, status, result)
        except (OSError, ValueError) as exc:
            LOG.error("Could not preserve correlated command outcome (%s)", type(exc).__name__)

    def _complete_waiting_restarts(self) -> None:
        for path, record in self.command_journal.waiting_restarts():
            try:
                deadline = datetime.fromisoformat(record["deadline_at"].replace("Z", "+00:00")).timestamp() if record.get("deadline_at") else record["started_at"] + 300
            except (ValueError, AttributeError, TypeError):
                deadline = record["started_at"] + 300
            if time.time() >= deadline:
                self._send_command_result(record["command_id"], "timed_out", "NmapUI readiness after restart remained unconfirmed.")
                path.unlink()
            elif self.nmapui_connected.is_set() and self._read_nmapui_health().get("nmapui_ready") is True:
                self._send_command_result(record["command_id"], "succeeded", "Managed NmapUI reconnected and reports ready after restart.")
                path.unlink()

    def _collect_diagnostics(self) -> dict[str, Any]:
        # Only explicit operational fields. Never include logs, config, environment,
        # host/user names, credentials, interface addresses, or scan targets.
        return {
            "schema_version": 1, "bridge_version": __version__,
            **_host_inventory(),
            "nmapui_connected": self.nmapui_connected.is_set(),
            **self._read_nmapui_health(),
            "pending_scan_events": len(list(self.spool_dir.glob("*.json"))),
            "rejected_scan_events": len(list(self.spool_dir.glob("*.rejected"))),
            "data_volume_free_bytes": shutil.disk_usage(self.spool_dir).free,
            "last_successful_check_in": self.last_successful_check_in,
            **self.command_journal.counts(),
        }

    def _nmapui_restart_supported(self) -> bool:
        service_label = str(self.config.get("nmapui_service_label") or "")
        if sys.platform == "darwin":
            return bool(NMAPUI_LAUNCHD_LABEL.fullmatch(service_label))
        if sys.platform != "linux" or self.config.get("nmapui_service_manager") != "systemd-user":
            return False
        if service_label != NMAPUI_SYSTEMD_UNIT:
            return False
        unit_dir = Path(str(self.config.get("nmapui_systemd_unit_dir") or ""))
        config_dir = Path(str(self.config.get("nmapui_systemd_config_dir") or ""))
        return bool(
            unit_dir.is_absolute()
            and config_dir.is_absolute()
            and (unit_dir / NMAPUI_SYSTEMD_UNIT).is_file()
            and (config_dir / NMAPUI_SYSTEMD_OWNERSHIP_FILE).is_file()
        )

    def _verify_managed_linux_nmapui_install(self) -> None:
        unit_dir = Path(str(self.config["nmapui_systemd_unit_dir"]))
        config_dir = Path(str(self.config["nmapui_systemd_config_dir"]))
        try:
            if unit_dir.is_symlink() or config_dir.is_symlink() or not unit_dir.is_dir() or not config_dir.is_dir():
                raise ValueError("Managed service directories are missing or unsafe.")
            if stat.S_IMODE(unit_dir.stat().st_mode) != 0o700 or stat.S_IMODE(config_dir.stat().st_mode) != 0o700:
                raise ValueError("Managed service directories have unexpected permissions.")
            state_path = config_dir / NMAPUI_SYSTEMD_OWNERSHIP_FILE
            if state_path.is_symlink() or not state_path.is_file() or stat.S_IMODE(state_path.stat().st_mode) != 0o600:
                raise ValueError("Managed service ownership record is missing or unsafe.")
            state = json.loads(state_path.read_text(encoding="utf-8"))
            if not isinstance(state, dict):
                raise ValueError("Managed service ownership record is invalid.")
            expected_files = {NMAPUI_SYSTEMD_ENV_FILE, NMAPUI_SYSTEMD_UNIT, NMAPUI_SYSTEMD_BRIDGE_UNIT}
            if state.get("format") != 1 or state.get("unit_dir") != str(unit_dir):
                raise ValueError("Managed service ownership record does not match the installed paths.")
            if set(state.get("files", {})) != expected_files:
                raise ValueError("Managed service ownership record has an unexpected file set.")
            for name in expected_files:
                path = config_dir / name if name == NMAPUI_SYSTEMD_ENV_FILE else unit_dir / name
                if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) != 0o600:
                    raise ValueError("A managed service file is missing or unsafe.")
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                if digest != state["files"][name]:
                    raise ValueError("A managed service file changed after installation.")
        except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError("Managed Linux service verification failed; refusing to restart NmapUI.") from exc

    def _check_os_updates(self) -> dict[str, Any]:
        """Read the macOS catalog or Linux's existing APT package index."""
        observed_at = datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
        if platform.system() == "Linux":
            return self._check_linux_updates(observed_at)
        if platform.system() != "Darwin":
            return {"schema_version": 1, "observed_at": observed_at, "status": "unsupported", "platform": platform.system()[:32]}
        executable = Path("/usr/sbin/softwareupdate")
        if not executable.is_file():
            return {"schema_version": 1, "observed_at": observed_at, "status": "unavailable", "platform": "Darwin"}
        try:
            result = _bounded_update_command(
                [str(executable), "--list"],
                timeout=120,
                env={**os.environ, "LC_ALL": "C", "LANG": "C"},
            )
        except UpdateOutputIncomplete:
            return {"schema_version": 1, "observed_at": observed_at, "status": "unknown", "platform": "Darwin"}
        except subprocess.TimeoutExpired:
            return {"schema_version": 1, "observed_at": observed_at, "status": "timed_out", "platform": "Darwin"}
        except OSError:
            return {"schema_version": 1, "observed_at": observed_at, "status": "unavailable", "platform": "Darwin"}
        if result.returncode != 0:
            return {"schema_version": 1, "observed_at": observed_at, "status": "error", "platform": "Darwin"}
        # Apple's tool can write a successful catalog result to stderr.
        output = "\n".join(
            stream for stream in (result.stdout, result.stderr)
            if isinstance(stream, str)
        )
        labels = re.findall(r"^\s*\*\s+Label:\s*(.{1,200})\s*$", output, re.MULTILINE)
        titles = re.findall(r"^\s*Title:\s*(.{1,240})\s*$", output, re.MULTILINE)
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        no_updates_lines = {"No new software available.", "No new software available"}
        no_updates = any(line in no_updates_lines for line in lines)
        if labels and no_updates:
            return {"schema_version": 1, "observed_at": observed_at, "status": "unknown", "platform": "Darwin"}
        if labels:
            count = len(labels)
            entries = []
            for index, label in enumerate(labels[:5]):
                item = {"label": label.strip()[:200]}
                if index < len(titles):
                    item["title"] = titles[index].strip()[:160]
                entries.append(item)
            return {"schema_version": 1, "observed_at": observed_at, "status": "updates_available",
                    "platform": "Darwin", "update_count": count, "updates": entries, "truncated": count > len(entries)}
        if no_updates and all(line in no_updates_lines | {"Software Update Tool", "Finding available software"}
                              for line in lines):
            return {"schema_version": 1, "observed_at": observed_at, "status": "no_updates", "platform": "Darwin", "update_count": 0, "updates": []}
        return {"schema_version": 1, "observed_at": observed_at, "status": "unknown", "platform": "Darwin"}

    def _check_linux_updates(self, observed_at: str) -> dict[str, Any]:
        evidence = {"schema_version": 1, "observed_at": observed_at, "platform": "Linux",
                    "source": "existing_apt_index", "catalog_refreshed": False}
        executable = Path("/usr/bin/apt")
        if not executable.is_file():
            return {**evidence, "status": "unavailable"}
        try:
            result = _bounded_update_command([str(executable), "list", "--upgradable"], timeout=30,
                                    env={**os.environ, "LC_ALL": "C", "LANG": "C"})
        except UpdateOutputIncomplete:
            return {**evidence, "status": "unknown"}
        except subprocess.TimeoutExpired:
            return {**evidence, "status": "timed_out"}
        except OSError:
            return {**evidence, "status": "unavailable"}
        if result.returncode != 0:
            return {**evidence, "status": "error"}
        if isinstance(result.stderr, str) and any(
            line.strip() != "WARNING: apt does not have a stable CLI interface. Use with caution in scripts."
            for line in result.stderr.splitlines() if line.strip()
        ):
            return {**evidence, "status": "unknown"}
        output = result.stdout
        if not isinstance(output, str) or len(output) > 128 * 1024:
            return {**evidence, "status": "unknown"}
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        if not lines or lines[0] != "Listing...":
            return {**evidence, "status": "unknown"}
        updates = []
        for line in lines[1:]:
            match = re.fullmatch(r"([a-z0-9][a-z0-9+.-]*(?::[a-z0-9_-]+)?)/\S+\s+(\S+)\s+\S+\s+\[upgradable from: ([^\]]+)\]", line)
            if not match:
                return {**evidence, "status": "unknown"}
            updates.append({"label": match[1][:160], "title": f"{match[1]} {match[3]} → {match[2]}"[:200]})
        return {**evidence, "status": "updates_available" if updates else "no_updates",
                "update_count": len(updates), "updates": updates[:5], "truncated": len(updates) > 5}

    @contextmanager
    def _managed_restart_lock(self):
        if sys.platform == "darwin":
            try:
                with self._managed_macos_restart_lock():
                    yield
            except OSError as exc:
                raise RuntimeError("Managed macOS lifecycle verification failed; refusing to restart NmapUI.") from exc
            return
        if sys.platform != "linux":
            yield
            return
        import fcntl
        self._verify_managed_linux_nmapui_install()
        config_dir = Path(str(self.config["nmapui_systemd_config_dir"]))
        if config_dir.stat().st_uid != os.getuid():
            raise RuntimeError("Managed Linux service verification failed; refusing to restart NmapUI.")
        lock = os.open(config_dir / NMAPUI_SYSTEMD_LOCK_FILE, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            info = os.fstat(lock)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
                raise RuntimeError("Managed Linux service verification failed; refusing to restart NmapUI.")
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RuntimeError("A scanner lifecycle action is running; retry restart after it finishes.") from exc
            pending = config_dir / NMAPUI_SYSTEMD_UPGRADE_FILE
            if pending.exists() or pending.is_symlink():
                raise RuntimeError("Resolve the pending local upgrade before restarting NmapUI.")
            self._verify_managed_linux_nmapui_install()
            yield
        finally:
            os.close(lock)

    @contextmanager
    def _managed_macos_restart_lock(self):
        # Same path and ownership contract as the standalone macOS helper.
        # The bridge kit intentionally runs without importing helper scripts.
        import fcntl
        root = Path.home().absolute()
        support = root / "Library/Application Support/Daedalus"
        current = support
        while current.is_relative_to(root):
            if current.is_symlink():
                raise RuntimeError("Managed scanner directory cannot contain symbolic links.")
            if current == root:
                break
            current = current.parent
        info = support.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022:
            raise RuntimeError("Managed scanner directory must be owned and not writable by others.")
        descriptor = os.open(support / NMAPUI_SYSTEMD_LOCK_FILE,
                             os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
                raise RuntimeError("Scanner lifecycle lock must be a private owned regular file.")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RuntimeError("A scanner lifecycle action is running; retry restart after it finishes.") from exc
            yield
        finally:
            os.close(descriptor)

    def _restart_managed_nmapui(self) -> None:
        label = str(self.config.get("nmapui_service_label") or "")
        if not self._nmapui_restart_supported():
            raise RuntimeError("This scanner is not configured for managed NmapUI restarts.")
        with self._managed_restart_lock():
            self._restart_managed_nmapui_locked(label)

    def _restart_managed_nmapui_locked(self, label: str) -> None:
        if self.sio.connected:
            self.sio.disconnect()
        self.nmapui_connected.clear()
        try:
            command = (
                ["systemctl", "--user", "restart", NMAPUI_SYSTEMD_UNIT]
                if sys.platform == "linux"
                else ["/bin/launchctl", "kickstart", "-k", f"gui/{os.getuid()}/{label}"]
            )
            subprocess.run(command, check=True, timeout=20, capture_output=True, text=True)
        except (OSError, subprocess.SubprocessError) as exc:
            manager = "Linux systemd user service" if sys.platform == "linux" else "macOS service manager"
            raise RuntimeError(f"The {manager} could not restart NmapUI.") from exc

    def _run_one_command(self) -> None:
        response = self._request(
            "GET",
            f"/api/agents/{self.agent_id}/commands/next",
        )
        response.raise_for_status()
        command = response.json().get("command")
        if not command:
            return
        command_id = int(command["id"])
        action = command.get("action")
        if not self.command_journal.claim(command):
            LOG.warning("Command %s was already claimed; its side effect will not be repeated", command_id)
            return
        if action in {"refresh_health", "collect_diagnostics"}:
            evidence = self._collect_diagnostics()
            if action == "refresh_health":
                self._heartbeat()
            self._send_command_result(command_id, "succeeded", _diagnostics_result(evidence))
            return
        if action == "check_os_updates":
            if COMMAND_PROTOCOL_VERSION < 3:
                self._send_command_result(command_id, "failed", "Update this scanner kit before checking macOS updates.")
                return
            evidence = self._check_os_updates()
            self._send_command_result(command_id, "succeeded", _os_update_result(evidence))
            return
        if action == "restart_nmapui":
            try:
                self._restart_managed_nmapui()
            except RuntimeError as exc:
                self._send_command_result(command_id, "failed", str(exc))
            else:
                self._send_command_result(
                    command_id,
                    "accepted",
                    "Restart requested for the managed NmapUI service.",
                )
                self.command_journal.wait_for_restart(command)
            return
        if not self.nmapui_connected.is_set():
            self._send_command_result(
                command_id,
                "failed",
                "NmapUI is offline and this command requires its live service.",
            )
            return
        if action == "start_scan":
            target = str(command.get("target") or "").strip()
            if not target:
                self._send_command_result(command_id, "failed", "Missing scan target.")
                return
            data = {"target": target}
            if type(command.get("skip_host_discovery")) is bool:
                data["skip_host_discovery"] = command["skip_host_discovery"]
            if self.command_completion_supported:
                data["daedalus_command_id"] = command_id
                data["daedalus_command_namespace"] = self.command_namespace
            self.sio.emit("start_scan", data)
            if self.command_completion_supported:
                return
            self._send_command_result(
                command_id,
                "accepted",
                "Scan request delivered to the local NmapUI service.",
            )
            LOG.info("Delivered a scan request to NmapUI.")
            return
        if action == "cancel_scan":
            data = {"job_type": "scan"}
            if self.command_completion_supported:
                data["daedalus_command_id"] = command_id
                data["daedalus_command_namespace"] = self.command_namespace
            self.sio.emit("cancel_job", data)
            if self.command_completion_supported:
                return
            self._send_command_result(
                command_id,
                "accepted",
                "Cancellation request delivered to the local NmapUI service.",
            )
            LOG.info("Delivered a scan cancellation request to NmapUI.")
            return
        if action == "check_nmapui_updates":
            if self.command_completion_supported:
                self.sio.emit("check_app_updates", {"daedalus_command_id": command_id, "daedalus_command_namespace": self.command_namespace})
                return
            self.sio.emit("check_app_updates")
            self._send_command_result(
                command_id,
                "accepted",
                "NmapUI was asked to check its release channel.",
            )
            LOG.info("Requested an NmapUI update check.")
            return
        self._send_command_result(command_id, "failed", "Unsupported command.")

    def _connect_nmapui(self) -> None:
        if self.sio.connected:
            return
        try:
            username = os.environ.get("NMAPUI_USERNAME", "")
            password = os.environ.get("NMAPUI_PASSWORD", "")
            basic_auth = (username, password) if username and password else None
            token_response = httpx.get(
                self.nmapui_url + "/api/socket-token",
                auth=basic_auth,
                timeout=4,
            )
            token_response.raise_for_status()
            socket_token = token_response.json().get("token")
            if not socket_token:
                raise RuntimeError("NmapUI did not return a Socket.IO connection token")
            self.sio.connect(
                self.nmapui_url,
                transports=["websocket", "polling"],
                wait_timeout=5,
                auth={"token": socket_token, "daedalus_bridge": True, "command_namespace": self.command_namespace},
                headers={"Authorization": "Basic " + base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")} if basic_auth else {},
            )
        except Exception as exc:
            now = time.monotonic()
            if now - self.last_socket_failure_log > 15:
                LOG.warning("NmapUI is not reachable at %s: %s", self.nmapui_url, exc)
                self.last_socket_failure_log = now

    def run(self) -> None:
        LOG.info(
            "Daedalus bridge starting for %s (agent %s).",
            self.config.get("organization", "workspace"),
            self.agent_id,
        )
        LOG.info("NmapUI endpoint: %s", self.nmapui_url)
        uploader = threading.Thread(target=self._event_upload_loop, name="scanner-event-uploader", daemon=True)
        uploader.start()
        self._connect_nmapui()
        last_heartbeat = 0.0
        try:
            while not self.stop_requested.is_set():
                now = time.monotonic()
                if not self.sio.connected and now - last_heartbeat >= 5:
                    self._connect_nmapui()
                if now - last_heartbeat >= 8:
                    try:
                        self._heartbeat()
                        last_heartbeat = now
                    except httpx.HTTPError as exc:
                        LOG.warning("Daedalus heartbeat failed: %s", exc)
                try:
                    self._complete_waiting_restarts()
                    self._run_one_command()
                except (httpx.HTTPError, OSError, ValueError) as exc:
                    LOG.warning("Could not execute or preserve Daedalus command (%s)", type(exc).__name__)
                self.stop_requested.wait(2)
        except KeyboardInterrupt:
            LOG.info("Stopping Daedalus bridge.")
        finally:
            self.stop_requested.set()
            uploader.join(timeout=15)
            if self.sio.connected:
                self.sio.disconnect()
            self.http.close()


def load_config(path: Path) -> dict[str, Any]:
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Could not read agent config at {path}: {exc}") from exc
    for key in ("server", "agent_id", "agent_token"):
        if not config.get(key):
            raise RuntimeError(f"Agent config is missing {key}.")
    service_label = config.get("nmapui_service_label")
    service_manager = config.get("nmapui_service_manager")
    if service_manager is None:
        if service_label is not None and not NMAPUI_LAUNCHD_LABEL.fullmatch(str(service_label)):
            raise RuntimeError("Agent config has an invalid NmapUI service label.")
    elif service_manager == "systemd-user":
        paths = [config.get("nmapui_systemd_unit_dir"), config.get("nmapui_systemd_config_dir")]
        if service_label != NMAPUI_SYSTEMD_UNIT or any(
            not isinstance(value, str) or not Path(value).is_absolute() for value in paths
        ):
            raise RuntimeError("Agent config has invalid managed Linux service settings.")
    else:
        raise RuntimeError("Agent config has an unsupported NmapUI service manager.")
    return config


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Connect a local NmapUI scanner to Daedalus."
    )
    parser.add_argument("--server", help="Daedalus base URL, such as http://127.0.0.1:8000")
    parser.add_argument("--nmapui-url", default="http://127.0.0.1:9000")
    parser.add_argument("--enroll-code", help="One-time code from the Daedalus scanner page")
    parser.add_argument("--name", default=platform.node() or "NmapUI scanner")
    parser.add_argument("--config", type=Path, help="Existing agent config to run")
    parser.add_argument("--config-path", type=Path, help="Where to save a newly enrolled agent config")
    parser.add_argument("--nmapui-service-label", help="Managed macOS NmapUI LaunchAgent label")
    parser.add_argument("--nmapui-systemd-unit-dir", type=Path, help="Managed Linux systemd user unit directory")
    parser.add_argument("--nmapui-systemd-config-dir", type=Path, help="Managed Linux service configuration directory")
    parser.add_argument("--enroll-only", action="store_true", help="Enroll and save credentials without starting the bridge")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    if args.config:
        if args.config_path or args.nmapui_service_label or args.nmapui_systemd_unit_dir or args.nmapui_systemd_config_dir or args.enroll_only:
            parser.error("Enrollment options cannot be combined with --config")
        config = load_config(args.config)
    else:
        if not args.server:
            parser.error("--server is required when enrolling a scanner")
        code = args.enroll_code or getpass.getpass("One-time Daedalus enrollment code: ")
        if not code:
            parser.error("An enrollment code is required")
        if args.nmapui_service_label and not NMAPUI_LAUNCHD_LABEL.fullmatch(args.nmapui_service_label):
            parser.error("--nmapui-service-label must use the org.daedalus.nmapui label namespace")
        systemd_paths = (args.nmapui_systemd_unit_dir, args.nmapui_systemd_config_dir)
        if any(systemd_paths) and (not all(systemd_paths) or sys.platform != "linux"):
            parser.error("Managed systemd service options require both unit/config paths on Linux")
        if any(systemd_paths) and any(not path.is_absolute() for path in systemd_paths if path):
            parser.error("Managed systemd service paths must be absolute")
        if args.nmapui_service_label and any(systemd_paths):
            parser.error("macOS and Linux service manager options cannot be combined")
        config = enroll(args.server, args.name, code)
        config["nmapui_url"] = args.nmapui_url
        if args.nmapui_service_label:
            config["nmapui_service_label"] = args.nmapui_service_label
        if all(systemd_paths):
            config.update({
                "nmapui_service_manager": "systemd-user",
                "nmapui_service_label": NMAPUI_SYSTEMD_UNIT,
                "nmapui_systemd_unit_dir": str(args.nmapui_systemd_unit_dir),
                "nmapui_systemd_config_dir": str(args.nmapui_systemd_config_dir),
            })
        path = save_config(config, int(config["agent_id"]), args.config_path)
        LOG.info(
            "Enrolled %s in %s. Credentials saved to %s.",
            config["agent_name"],
            config["organization"],
            path,
        )
        if args.enroll_only:
            return
    nmapui_url = args.nmapui_url if not args.config else (
        args.nmapui_url if args.nmapui_url != "http://127.0.0.1:9000"
        else str(config.get("nmapui_url") or args.nmapui_url)
    )
    NmapUIBridge(config, nmapui_url).run()


if __name__ == "__main__":
    main()
