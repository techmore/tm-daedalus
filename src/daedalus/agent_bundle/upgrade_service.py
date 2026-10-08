#!/usr/bin/env python3
"""Safely stage and switch an already managed macOS Daedalus scanner."""

from __future__ import annotations

import hashlib
import io
import json
import os
import plistlib
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path, PurePosixPath
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

try:  # Package import for tests; script import for the bundled macOS CLI.
    from . import macos_service
except ImportError:  # pragma: no cover - exercised by the bundled direct-script entrypoint
    import macos_service  # type: ignore[no-redef]

class _NoLocalRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# Local service credentials must stay on loopback, without proxies or redirects.
urlopen = build_opener(ProxyHandler({}), _NoLocalRedirect()).open


MAX_KIT_BYTES = 512 * 1024 * 1024
MAX_MEMBER_BYTES = 256 * 1024 * 1024
MAX_MEMBERS = 20000
KIT_PREFIX = "daedalus-scanner-kit/"
REQUIRED_KIT_FILES = {
    "nmapui-source.zip", "pyproject.toml", "src/daedalus/__init__.py",
    "src/daedalus/agent.py", "src/daedalus/command_journal.py", "src/daedalus/scanner_activity.py",
}


def _private_file(path: Path, root: Path) -> bytes:
    macos_service._check_managed_path(path, root.absolute())
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError("Managed enrollment file must be private and owned by the current user")
    return path.read_bytes()


def _read_kit(bundle_path: Path) -> tuple[dict[str, bytes], str]:
    try:
        descriptor = os.open(bundle_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_KIT_BYTES:
                raise ValueError("Scanner kit is missing, unsafe, or too large")
            raw = stream.read(MAX_KIT_BYTES + 1)
        if len(raw) > MAX_KIT_BYTES:
            raise ValueError("Scanner kit expands beyond the allowed size")
    except OSError as exc:
        raise ValueError("Scanner kit is missing, unsafe, or unreadable") from exc
    digest = hashlib.sha256(raw).hexdigest()
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw))
    except (OSError, zipfile.BadZipFile) as exc:
        raise ValueError("Scanner kit is not a valid ZIP archive") from exc
    files: dict[str, bytes] = {}
    with archive:
        infos = archive.infolist()
        if not infos or len(infos) > MAX_MEMBERS:
            raise ValueError("Scanner kit has an invalid member count")
        total = 0
        normalized_names: set[str] = set()
        for item in infos:
            name = item.filename
            pure = PurePosixPath(name)
            if (not name.startswith(KIT_PREFIX) or "\\" in name or pure.is_absolute()
                    or ".." in pure.parts or "" in pure.parts or item.is_dir()
                    or any(part in {"", "."} for part in name.rstrip("/").split("/"))):
                raise ValueError("Scanner kit contains an unsafe or unexpected path")
            rel = name[len(KIT_PREFIX):]
            normalized = str(PurePosixPath(rel))
            if not rel or rel in files or normalized in normalized_names or item.file_size > MAX_MEMBER_BYTES:
                raise ValueError("Scanner kit contains duplicate or oversized files")
            normalized_names.add(normalized)
            total += item.file_size
            if total > MAX_KIT_BYTES:
                raise ValueError("Scanner kit expands beyond the allowed size")
            mode = item.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise ValueError("Scanner kit contains a symbolic link")
            files[rel] = archive.read(item)
    if not REQUIRED_KIT_FILES.issubset(files):
        raise ValueError("Scanner kit is missing required scanner files")
    try:
        with zipfile.ZipFile(__import__("io").BytesIO(files["nmapui-source.zip"])) as nested:
            names = nested.namelist()
            nested_infos = nested.infolist()
            nested_total = sum(info.file_size for info in nested_infos)
            normalized_names = set()
            for name in names:
                normalized = str(PurePosixPath(name))
                if normalized in normalized_names:
                    raise ValueError("NmapUI source archive contains duplicate paths")
                normalized_names.add(normalized)
            if not names or len(names) > MAX_MEMBERS or nested_total > MAX_KIT_BYTES or any(
                PurePosixPath(n).is_absolute() or ".." in PurePosixPath(n).parts or "\\" in n
                or any(part in {"", "."} for part in n.rstrip("/").split("/"))
                or stat.S_ISLNK(info.external_attr >> 16) or info.file_size > MAX_MEMBER_BYTES
                for n, info in zip(names, nested_infos)
            ):
                raise ValueError("NmapUI source archive contains unsafe paths")
            if "daedalus-nmapui-source/app.py" not in names or "daedalus-nmapui-source/requirements.txt" not in names:
                raise ValueError("NmapUI source archive is missing required files")
    except (OSError, zipfile.BadZipFile) as exc:
        raise ValueError("NmapUI source archive is invalid") from exc
    return files, digest


def _rebase_bridge_launcher(launcher: Path, staged_python: Path, final_python: Path) -> None:
    contents = launcher.read_bytes()
    staged = str(staged_python).encode()
    if contents.count(staged) != 1:
        raise ValueError("Bridge launcher does not contain the expected staged interpreter")
    mode = launcher.stat().st_mode & 0o777
    launcher.write_bytes(contents.replace(staged, str(final_python).encode(), 1))
    os.chmod(launcher, mode)


def _default_prepare(files: dict[str, bytes], user_root: Path, kit_digest: str) -> tuple[Path, Path]:
    """Materialize immutable release source trees and their Python runtimes."""
    support = user_root / "Library/Application Support/Daedalus"
    return prepare_releases(files, support)


def prepare_releases(files: dict[str, bytes], support: Path) -> tuple[Path, Path]:
    """Prepare content-versioned runtimes under a validated platform support directory."""
    nmap_hash = hashlib.sha256(files["nmapui-source.zip"]).hexdigest()
    bridge_hash = hashlib.sha256(b"".join(files[k] for k in sorted(REQUIRED_KIT_FILES - {"nmapui-source.zip"}))).hexdigest()
    nmap_release = support / "nmapui/releases" / nmap_hash
    bridge_release = support / "scanner-bridge/releases" / bridge_hash
    for rel in (nmap_release, bridge_release):
        rel.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if rel.parent.is_symlink() or rel.is_symlink():
            raise ValueError("Refusing to stage through a symbolic link")
        parent_info = rel.parent.stat()
        if parent_info.st_uid != os.getuid() or stat.S_IMODE(parent_info.st_mode) & 0o077:
            raise ValueError("Runtime release parent must be private and owned by the current user")
        if rel.exists():
            info = rel.stat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
                raise ValueError("Cached runtime release must be private and owned by the current user")
            continue
        stage = Path(tempfile.mkdtemp(prefix=".stage-", dir=rel.parent))
        try:
            os.chmod(stage, 0o700)
            if rel == nmap_release:
                with zipfile.ZipFile(__import__("io").BytesIO(files["nmapui-source.zip"])) as source:
                    source.extractall(stage)
                source_dir = stage / "daedalus-nmapui-source"
                if not (source_dir / "app.py").is_file():
                    raise ValueError("Staged NmapUI release is incomplete")
                venv = stage / ".venv"
                subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True, capture_output=True, timeout=120)
                subprocess.run([str(venv / "bin/python"), "-m", "pip", "install", "--disable-pip-version-check", "-r", str(source_dir / "requirements.txt")], check=True, capture_output=True, timeout=900)
                browser_dir = stage / "playwright-browsers"
                subprocess.run([str(venv / "bin/python"), "-m", "playwright", "install", "chromium"], check=True, capture_output=True, timeout=900, env={**os.environ, "PLAYWRIGHT_BROWSERS_PATH": str(browser_dir)})
            else:
                package = stage / "package"
                (package / "src/daedalus").mkdir(mode=0o700, parents=True)
                for key, contents in files.items():
                    if key == "nmapui-source.zip":
                        continue
                    destination = package / key
                    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    destination.write_bytes(contents)
                venv = stage / ".venv"
                subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True, capture_output=True, timeout=120)
                subprocess.run([str(venv / "bin/python"), "-m", "pip", "install", "--disable-pip-version-check", str(package)], check=True, capture_output=True, timeout=900)
                # Setuptools writes an absolute interpreter path into its
                # console launcher. The release directory is renamed after
                # staging, so rebase that one generated path before cutover.
                launcher = venv / "bin/daedalus-agent"
                _rebase_bridge_launcher(
                    launcher,
                    venv / "bin/python",
                    rel / ".venv/bin/python",
                )
                shutil.rmtree(package)
            os.rename(stage, rel)
        except Exception:
            shutil.rmtree(stage, ignore_errors=True)
            raise
    return nmap_release, bridge_release


def _atomic_plist(path: Path, contents: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".daedalus-upgrade-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp, 0o600)
        os.replace(temp, path)
        os.chmod(path, 0o600)
    finally:
        Path(temp).unlink(missing_ok=True)


def _run(executor, args: list[str], timeout: int = 20):
    result = executor(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError("Managed scanner service operation failed")
    return result


def _default_ready(nmapui_payload: dict, timeout: int = 60) -> bool:
    env = nmapui_payload["EnvironmentVariables"]
    port = env["NMAPUI_PORT"]
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            request = Request(f"http://127.0.0.1:{port}/api/health/ready")
            username = env.get("NMAPUI_USERNAME", "")
            password = env.get("NMAPUI_PASSWORD", "")
            if username and password:
                import base64
                request.add_header("Authorization", "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode())
            with urlopen(request, timeout=2) as response:
                import json
                payload = json.load(response)
            if payload.get("status") == "ready" and payload.get("ready") is True:
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


def _require_scanner_idle(nmapui_payload: dict) -> None:
    """Defer cutover unless the local engine explicitly reports no active jobs."""
    env = nmapui_payload["EnvironmentVariables"]
    request = Request(f"http://127.0.0.1:{env['NMAPUI_PORT']}/api/runtime/status")
    username, password = env.get("NMAPUI_USERNAME", ""), env.get("NMAPUI_PASSWORD", "")
    if username and password:
        import base64
        request.add_header("Authorization", "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode())
    try:
        with urlopen(request, timeout=3) as response:
            raw = response.read(65537)
        if len(raw) > 65536:
            raise ValueError("Oversized local status")
        payload = json.loads(raw)
    except Exception as exc:
        raise RuntimeError("Scanner activity could not be confirmed; retry the upgrade when the local scanner is available") from exc
    if (not isinstance(payload, dict) or payload.get("has_active_jobs") is not False
            or payload.get("active_jobs") != [] or payload.get("active_job_types") != []):
        raise RuntimeError("Scanner is busy or its activity is unknown; retry the upgrade after scans and reports finish")


def _require_scanner_offline(nmapui_payload: dict) -> None:
    """Only a refused loopback connection proves the local listener is stopped."""
    port = int(nmapui_payload["EnvironmentVariables"]["NMAPUI_PORT"])
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=3):
            pass
    except ConnectionRefusedError:
        return
    except OSError as exc:
        raise RuntimeError("Scanner offline state is unknown; refusing offline upgrade") from exc
    raise RuntimeError("A scanner listener is still running; refusing offline upgrade")


def _scanner_maintenance(nmapui_payload: dict, token: str | None = None, *, claim: bool = False) -> dict:
    """Claim/release local admission under the engine's job registry lock."""
    env = nmapui_payload["EnvironmentVariables"]
    request = Request(
        f"http://127.0.0.1:{env['NMAPUI_PORT']}/api/runtime/maintenance",
        data=json.dumps({"token": token} if token is not None else {}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST" if claim or token is None else "DELETE",
    )
    username, password = env.get("NMAPUI_USERNAME", ""), env.get("NMAPUI_PASSWORD", "")
    if username and password:
        import base64
        request.add_header("Authorization", "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode())
    with urlopen(request, timeout=3) as response:
        raw = response.read(65537)
    if len(raw) > 65536:
        raise ValueError("Oversized maintenance response")
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("Invalid maintenance response")
    return payload


def _acquire_scanner_maintenance(nmapui_payload: dict, previous_token: str | None = None) -> str:
    try:
        payload = _scanner_maintenance(nmapui_payload, previous_token, claim=True)
        token = payload.get("token")
        if (payload.get("maintenance_active") is not True or not isinstance(token, str)
                or len(token) != 32 or any(c not in "0123456789abcdef" for c in token)):
            raise ValueError("Invalid maintenance ownership")
        return token
    except Exception as exc:
        raise RuntimeError(
            "Scanner maintenance could not be acquired; upgrade deferred. "
            "The engine must support maintenance and have no active scans or reports. "
            "If admission remains paused, restart the idle scanner to recover."
        ) from exc


def _release_scanner_maintenance(nmapui_payload: dict, token: str) -> None:
    payload = _scanner_maintenance(nmapui_payload, token)
    if payload.get("maintenance_active") is not False:
        raise RuntimeError("Scanner maintenance release was not confirmed")


def upgrade_managed_scanner(bundle_path, user_root, executor=None, prepare_release=None, wait_ready=None, *, offline=False) -> dict:
    with macos_service.lifecycle_lock(user_root):
        return _upgrade_managed_scanner_locked(bundle_path, user_root, executor, prepare_release, wait_ready, offline=offline)


def _upgrade_managed_scanner_locked(bundle_path, user_root, executor=None, prepare_release=None, wait_ready=None, *, offline=False) -> dict:
    """Upgrade exactly the two recognized, loaded managed LaunchAgents.

    Hook contract: ``prepare_release(files, user_root, kit_sha256)`` returns
    ``(nmapui_release_dir, bridge_release_dir)``; ``wait_ready(nmapui_plist)``
    returns a truthy value when the candidate service is ready.
    """
    root = Path(user_root).expanduser().absolute()
    if type(offline) is not bool:
        raise ValueError("Offline upgrade mode must be explicitly boolean")
    executor = executor or subprocess.run
    # Validate ownership/configuration before kit reads, backups, or other writes.
    descriptors = macos_service.managed_artifacts(root)
    expected = {macos_service.BRIDGE_LABEL, macos_service.NMAPUI_LABEL}
    if len(descriptors) != 2 or {d["label"] for d in descriptors} != expected:
        raise ValueError("Upgrade requires both recognized managed scanner services")
    config_path = root / "Library/Application Support/Daedalus/managed-agent.json"
    _private_file(config_path, root)
    by_label = {d["label"]: d for d in descriptors}
    old_bytes = {label: Path(by_label[label]["path"]).read_bytes() for label in expected}
    domain = f"gui/{os.getuid()}"
    for label in (macos_service.NMAPUI_LABEL, macos_service.BRIDGE_LABEL):
        probe = executor([macos_service.LAUNCHCTL, "print", f"{domain}/{label}"], capture_output=True, text=True, timeout=10)
        if offline:
            if not probe.returncode or not any(message in (getattr(probe, "stderr", "") or "") for message in ("Could not find service", "Could not find specified service")):
                raise ValueError("Offline upgrade requires both managed services to be confirmed unloaded")
        elif probe.returncode or "state = running" not in (getattr(probe, "stdout", "") or ""):
            raise ValueError("Both managed scanner services must be loaded before upgrade")
    files, kit_digest = _read_kit(Path(bundle_path).expanduser().absolute())
    support = root / "Library/Application Support/Daedalus"
    for managed_path in (
        support, support / "nmapui", support / "nmapui/releases",
        support / "scanner-bridge", support / "scanner-bridge/releases",
        support / "service-upgrades",
    ):
        macos_service._check_managed_path(managed_path, root)
    expected_nmap_hash = hashlib.sha256(files["nmapui-source.zip"]).hexdigest()
    expected_bridge_hash = hashlib.sha256(b"".join(files[k] for k in sorted(REQUIRED_KIT_FILES - {"nmapui-source.zip"}))).hexdigest()
    old_nmap = plistlib.loads(old_bytes[macos_service.NMAPUI_LABEL])
    old_bridge = plistlib.loads(old_bytes[macos_service.BRIDGE_LABEL])
    current_nmap = old_nmap.get("WorkingDirectory") == str(support / "nmapui/releases" / expected_nmap_hash / "daedalus-nmapui-source")
    current_bridge = old_bridge.get("WorkingDirectory") == str(support / "scanner-bridge/releases" / expected_bridge_hash)
    if current_nmap and current_bridge and not offline:
        return {"upgraded": False, "already_current": True, "kit_sha256": kit_digest, "data_preserved": True}
    activity_guard = _require_scanner_offline if offline else _require_scanner_idle
    activity_guard(old_nmap)
    if prepare_release:
        nmap_release, bridge_release = prepare_release(files, root, kit_digest)
    else:
        nmap_release, bridge_release = _default_prepare(files, root, kit_digest)
    nmap_release, bridge_release = Path(nmap_release).absolute(), Path(bridge_release).absolute()
    for path in (nmap_release, bridge_release):
        macos_service._check_managed_path(path, root)
        if not path.is_dir() or path.is_symlink():
            raise ValueError("Prepared scanner release is unavailable")
    if nmap_release.name != expected_nmap_hash or bridge_release.name != expected_bridge_hash:
        raise ValueError("Prepared scanner release is not content-versioned")
    for executable in (nmap_release / ".venv/bin/python", bridge_release / ".venv/bin/daedalus-agent"):
        macos_service._check_managed_path(executable.parent, root)
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise ValueError("Prepared scanner release has an unavailable executable")
    if not (nmap_release / "daedalus-nmapui-source/app.py").is_file():
        raise ValueError("Prepared NmapUI application is unavailable")
    nenv = dict(old_nmap["EnvironmentVariables"])
    enrollment = json.loads(config_path.read_bytes())
    portal = macos_service.management_portal_url(enrollment.get("server") if isinstance(enrollment, dict) else None)
    if portal:
        nenv["NMAPUI_MANAGEMENT_PORTAL_URL"] = portal
    else:
        nenv.pop("NMAPUI_MANAGEMENT_PORTAL_URL", None)
    benv = dict(old_bridge["EnvironmentVariables"])
    nenv["PLAYWRIGHT_BROWSERS_PATH"] = str(nmap_release / "playwright-browsers")
    nmap_payload = dict(old_nmap)
    nmap_payload["ProgramArguments"] = [str(nmap_release / ".venv/bin/python"), "app.py"]
    nmap_payload["WorkingDirectory"] = str(nmap_release / "daedalus-nmapui-source")
    nmap_payload["EnvironmentVariables"] = nenv
    bridge_payload = dict(old_bridge)
    bridge_payload["ProgramArguments"] = [str(bridge_release / ".venv/bin/daedalus-agent"), "--config", str(config_path)]
    bridge_payload["WorkingDirectory"] = str(bridge_release)
    bridge_payload["EnvironmentVariables"] = benv
    candidate_payloads = {macos_service.NMAPUI_LABEL: nmap_payload, macos_service.BRIDGE_LABEL: bridge_payload}
    destinations = {label: Path(by_label[label]["path"]) for label in expected}
    # Validate candidate descriptors in a private temporary directory before cutover.
    scratch = Path(tempfile.mkdtemp(prefix=".daedalus-upgrade-check-", dir=destinations[macos_service.NMAPUI_LABEL].parent))
    candidate_bytes = {}
    try:
        for label, payload in candidate_payloads.items():
            macos_service.write_plist(scratch / (label + ".plist"), payload)
            candidate_bytes[label] = (scratch / (label + ".plist")).read_bytes()
        candidate = macos_service.managed_artifacts(root, descriptor_dir=scratch)
        if len(candidate) != 2:
            raise ValueError("Candidate LaunchAgents failed managed validation")
    except Exception:
        shutil.rmtree(scratch, ignore_errors=True)
        raise
    old_set_digest = hashlib.sha256(b"".join(old_bytes[label] for label in sorted(old_bytes))).hexdigest()
    backup_root = support / "service-upgrades" / kit_digest / old_set_digest
    macos_service._check_managed_path(backup_root, root)
    backup_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if backup_root.is_symlink():
        raise ValueError("Refusing a backup directory symlink")
    backup_info = backup_root.stat()
    if not stat.S_ISDIR(backup_info.st_mode) or backup_info.st_uid != os.getuid() or stat.S_IMODE(backup_info.st_mode) & 0o077:
        raise ValueError("Upgrade backup directory must be private and owned by the current user")
    backups = {}
    for label, contents in old_bytes.items():
        path = backup_root / (label + ".plist")
        if path.is_symlink():
            raise ValueError("Refusing a symbolic link in upgrade backups")
        if path.exists() and path.read_bytes() != contents:
            raise ValueError("Existing upgrade backup does not match current service")
        if not path.exists():
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(contents)
                stream.flush()
                os.fsync(stream.fileno())
        backups[label] = str(path)
    cutover_started = False
    maintenance_token = None
    try:
        activity_guard(old_nmap)
        if offline:
            for label in expected:
                probe = executor([macos_service.LAUNCHCTL, "print", f"{domain}/{label}"], capture_output=True, text=True, timeout=10)
                if not probe.returncode or not any(message in (getattr(probe, "stderr", "") or "") for message in ("Could not find service", "Could not find specified service")):
                    raise RuntimeError("A managed service restarted during preparation; refusing offline cutover")
        else:
            maintenance_token = _acquire_scanner_maintenance(old_nmap)
        cutover_started = True
        for label in (() if offline else (macos_service.BRIDGE_LABEL, macos_service.NMAPUI_LABEL)):
            _run(executor, [macos_service.LAUNCHCTL, "bootout", domain, str(destinations[label])])
        for label, payload in candidate_payloads.items():
            destinations[label].parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            _atomic_plist(destinations[label], candidate_bytes[label])
        for label in (macos_service.NMAPUI_LABEL, macos_service.BRIDGE_LABEL):
            _run(executor, [macos_service.LAUNCHCTL, "bootstrap", domain, str(destinations[label])])
        ready = wait_ready(nmap_payload) if wait_ready else _default_ready(nmap_payload)
        if not ready:
            raise RuntimeError("Candidate NmapUI did not become ready")
        # Confirm both services remain loaded and descriptors meet the managed contract.
        for label in expected:
            response = _run(executor, [macos_service.LAUNCHCTL, "print", f"{domain}/{label}"])
            if "state = running" not in (getattr(response, "stdout", "") or ""):
                raise RuntimeError("A managed scanner service did not remain running after cutover")
        macos_service.managed_artifacts(root)
    except Exception:
        if cutover_started:
            rollback_errors = []
            for label in (macos_service.BRIDGE_LABEL, macos_service.NMAPUI_LABEL):
                try:
                    response = executor([macos_service.LAUNCHCTL, "bootout", domain, str(destinations[label])], capture_output=True, text=True, timeout=15)
                    if response.returncode:
                        rollback_errors.append(label)
                except Exception:
                    rollback_errors.append(label)
            for label in expected:
                try:
                    _atomic_plist(destinations[label], old_bytes[label])
                except Exception:
                    rollback_errors.append(label)
            for label in (macos_service.NMAPUI_LABEL, macos_service.BRIDGE_LABEL):
                try:
                    response = executor([macos_service.LAUNCHCTL, "bootstrap", domain, str(destinations[label])], capture_output=True, text=True, timeout=15)
                    if response.returncode:
                        rollback_errors.append(label)
                except Exception:
                    rollback_errors.append(label)
            for label, contents in old_bytes.items():
                try:
                    if destinations[label].read_bytes() != contents:
                        rollback_errors.append(label)
                except OSError:
                    rollback_errors.append(label)
            for label in (macos_service.NMAPUI_LABEL, macos_service.BRIDGE_LABEL):
                try:
                    probe = executor([macos_service.LAUNCHCTL, "print", f"{domain}/{label}"], capture_output=True, text=True, timeout=10)
                    if probe.returncode or "state = running" not in (getattr(probe, "stdout", "") or ""):
                        rollback_errors.append(label)
                except Exception:
                    rollback_errors.append(label)
            try:
                original_ready = wait_ready(old_nmap) if wait_ready else _default_ready(old_nmap)
                if not original_ready:
                    rollback_errors.append("nmapui-readiness")
            except Exception:
                rollback_errors.append("nmapui-readiness")
            if rollback_errors:
                raise RuntimeError("Managed scanner upgrade failed and automatic rollback was incomplete")
        raise
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
        # The old engine loses its in-memory gate on restart. A release against
        # a replacement engine cannot clear another owner's maintenance token.
        if maintenance_token is not None:
            try:
                _release_scanner_maintenance(old_nmap, maintenance_token)
            except Exception:
                if not cutover_started:
                    raise RuntimeError("Scanner admission remains paused; restart the idle scanner to recover")
    result = {"upgraded": True, "kit_sha256": kit_digest, "backups": backups, "data_preserved": True}
    if offline:
        result["offline_upgrade"] = True
    return result
