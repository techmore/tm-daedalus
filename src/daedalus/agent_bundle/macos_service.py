#!/usr/bin/env python3
"""Write owner-only LaunchAgent property lists for a managed Daedalus scanner."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import plistlib
import re
import stat
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlparse


NMAPUI_LABEL = "org.daedalus.nmapui"
BRIDGE_LABEL = "org.daedalus.scanner-bridge"
LAUNCHCTL = "/bin/launchctl"
SAFE_LABEL = re.compile(r"org\.daedalus\.(?:nmapui|scanner-bridge)\Z")
LIFECYCLE_LOCK_FILE = ".daedalus-scanner-services.lock"


@contextmanager
def lifecycle_lock(user_root: Path):
    """Serialize lifecycle mutations without deleting the shared lock inode."""
    import fcntl
    root = Path(user_root).expanduser().absolute()
    support = root / "Library/Application Support/Daedalus"
    _check_managed_path(support, root)
    info = support.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022:
        raise ValueError("Managed scanner directory must be owned and not writable by others")
    descriptor = os.open(support / LIFECYCLE_LOCK_FILE,
                         os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
            raise ValueError("Scanner lifecycle lock must be a private owned regular file")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("A scanner lifecycle action is running; retry after it finishes") from exc
        yield
    finally:
        os.close(descriptor)


def _absolute(path: str) -> str:
    value = Path(path).expanduser()
    if not value.is_absolute():
        raise ValueError("LaunchAgent paths must be absolute")
    return str(value)



def management_portal_url(value: object) -> str:
    if not isinstance(value, str):
        return ""
    value = value.strip()
    try:
        parsed = urlparse(value)
        if parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment or chr(92) in value or any(ord(c) < 32 or ord(c) == 127 for c in value):
            return ""
        if parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
            return ""
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            return ""
        return value.rstrip("/")
    except ValueError:
        return ""


def _auth_environment() -> dict[str, str]:
    username = os.environ.get("NMAPUI_USERNAME", "")
    password = os.environ.get("NMAPUI_PASSWORD", "")
    if bool(username) != bool(password):
        raise ValueError("NMAPUI_USERNAME and NMAPUI_PASSWORD must be set together")
    values = {}
    if username:
        values["NMAPUI_USERNAME"] = username
        values["NMAPUI_PASSWORD"] = password
    for name in ("NMAPUI_TRUST_LOCAL_UI", "NMAPUI_COOKIE_SECURE"):
        value = os.environ.get(name)
        if value is not None:
            value = value.strip().lower()
            if value not in {"true", "false"}:
                raise ValueError(f"{name} must be true or false")
            values[name] = value
    return values


def build_nmapui_plist(
    *,
    python: str,
    app_dir: str,
    data_dir: str,
    log_dir: str,
    browser_dir: str,
    port: int,
) -> dict:
    if not 1 <= port <= 65535:
        raise ValueError("NmapUI port must be between 1 and 65535")
    python = _absolute(python)
    app_dir = _absolute(app_dir)
    data_dir = _absolute(data_dir)
    log_dir = _absolute(log_dir)
    browser_dir = _absolute(browser_dir)
    environment = {
        "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        "NMAPUI_DATA_DIR": str(Path(data_dir) / "data"),
        "NMAPUI_LOG_DIR": str(Path(data_dir) / "logs"),
        "NMAPUI_HOST": "127.0.0.1",
        "NMAPUI_PORT": str(port),
        "NMAPUI_SKIP_LEGACY_MIGRATION": "1",
        "NMAPUI_ENABLE_NETWORK_FINGERPRINT": "false",
        "NMAPUI_ENABLE_VULNERS": "false",
        "NMAPUI_ENABLE_UPDATE_CHECK": "false",
        "NMAPUI_ALLOW_UNSAFE_WERKZEUG": "true",
        "PLAYWRIGHT_BROWSERS_PATH": browser_dir,
    }
    portal = management_portal_url(os.environ.get("NMAPUI_MANAGEMENT_PORTAL_URL", ""))
    if portal:
        environment["NMAPUI_MANAGEMENT_PORTAL_URL"] = portal
    environment.update(_auth_environment())
    return {
        "Label": NMAPUI_LABEL,
        "ProgramArguments": [python, "app.py"],
        "WorkingDirectory": app_dir,
        "RunAtLoad": True,
        "KeepAlive": True,
        "ThrottleInterval": 10,
        "ProcessType": "Background",
        "StandardOutPath": str(Path(log_dir) / "managed-nmapui.out.log"),
        "StandardErrorPath": str(Path(log_dir) / "managed-nmapui.err.log"),
        "EnvironmentVariables": environment,
    }


def build_bridge_plist(
    *,
    agent_executable: str,
    config_path: str,
    install_dir: str,
    log_dir: str,
) -> dict:
    agent_executable = _absolute(agent_executable)
    config_path = _absolute(config_path)
    install_dir = _absolute(install_dir)
    log_dir = _absolute(log_dir)
    environment = {
        "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
    }
    environment.update(_auth_environment())
    return {
        "Label": BRIDGE_LABEL,
        "ProgramArguments": [agent_executable, "--config", config_path],
        "WorkingDirectory": install_dir,
        "RunAtLoad": True,
        "KeepAlive": True,
        "ThrottleInterval": 10,
        "ProcessType": "Background",
        "StandardOutPath": str(Path(log_dir) / "scanner-bridge.out.log"),
        "StandardErrorPath": str(Path(log_dir) / "scanner-bridge.err.log"),
        "EnvironmentVariables": environment,
    }


def write_plist(path: Path, payload: dict, *, exclusive: bool = False) -> None:
    if not SAFE_LABEL.fullmatch(str(payload.get("Label", ""))):
        raise ValueError("Refusing to write an unexpected Daedalus service label")
    path = path.expanduser()
    if not path.is_absolute():
        raise ValueError("LaunchAgent output path must be absolute")
    if path.is_symlink():
        raise ValueError("Refusing to write a LaunchAgent through a symbolic link")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_path = tempfile.mkstemp(prefix=".daedalus-service-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            plistlib.dump(payload, stream, fmt=plistlib.FMT_XML, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary_path, 0o600)
        if exclusive:
            # Creating a hard link is an atomic no-overwrite operation.
            os.link(temporary_path, path)
        else:
            os.replace(temporary_path, path)
            os.chmod(path, 0o600)
    finally:
        try:
            os.unlink(temporary_path)
        except FileNotFoundError:
            pass


def _check_managed_path(path: Path, user_root: Path) -> None:
    if not path.is_absolute() or not path.is_relative_to(user_root):
        raise ValueError("Managed service path is outside the user directory")
    current = path
    while current.is_relative_to(user_root):
        if current.is_symlink():
            raise ValueError("Refusing a managed service through a symbolic link")
        if current == user_root:
            break
        current = current.parent


def managed_artifacts(user_root: Path, *, descriptor_dir: Path | None = None) -> list[dict]:
    """Validate service ownership without opening enrollment configuration."""
    user_root = user_root.absolute()
    support = user_root / "Library/Application Support/Daedalus"
    legacy_scanner_data = user_root / "Library/Application Support/NmapUI"
    isolated_scanner_data = support / "nmapui-data"
    bridge_install = support / "scanner-bridge"
    descriptors = []
    for label in (BRIDGE_LABEL, NMAPUI_LABEL):
        path = (descriptor_dir or user_root / "Library/LaunchAgents") / (label + ".plist")
        _check_managed_path(path, user_root)
        if not path.exists():
            continue
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError("Managed LaunchAgent must be private and owned by the current user")
        contents = path.read_bytes()
        payload = plistlib.loads(contents)
        if payload.get("Label") != label:
            raise ValueError("Refusing a LaunchAgent with an unexpected label")
        arguments = payload.get("ProgramArguments")
        working = payload.get("WorkingDirectory")
        if label == BRIDGE_LABEL:
            legacy_executable = bridge_install / ".venv/bin/daedalus-agent"
            release_root = bridge_install / "releases"
            executable = Path(str(arguments[0])) if isinstance(arguments, list) and arguments else Path("/")
            release_dir = executable.parent.parent.parent
            versioned = (
                release_dir.parent == release_root
                and re.fullmatch(r"[0-9a-f]{64}", release_dir.name)
                and executable == release_dir / ".venv/bin/daedalus-agent"
                and working == str(release_dir)
            )
            legacy = arguments == [str(legacy_executable), "--config", str(support / "managed-agent.json")] and working == str(bridge_install)
            if not (legacy or (versioned and arguments[1:] == ["--config", str(support / "managed-agent.json")])):
                raise ValueError("Refusing an unrecognized bridge installation")
            _check_managed_path(executable, user_root)
            if not executable.is_file() or not os.access(executable, os.X_OK):
                raise ValueError("Refusing a managed bridge with an unavailable executable")
        else:
            source = Path(str(working or ""))
            releases = support / "nmapui/releases"
            if source.parent.parent != releases or source.name != "daedalus-nmapui-source" or not re.fullmatch(r"[0-9a-f]{64}", source.parent.name):
                raise ValueError("Refusing an unrecognized NmapUI release")
            if arguments != [str(source.parent / ".venv/bin/python"), "app.py"]:
                raise ValueError("Refusing an unrecognized NmapUI executable")
            executable = Path(arguments[0])
            # Python virtual environments commonly link ``bin/python`` to a
            # sibling interpreter. Permit that link only when its resolved
            # target remains inside this immutable release.
            _check_managed_path(executable.parent, user_root)
            try:
                resolved_executable = executable.resolve(strict=True)
                release_root = source.parent.resolve(strict=True)
                contained = resolved_executable.is_relative_to(release_root)
                # macOS venvs created by supported Python installers link to
                # their framework interpreter outside the release directory.
                framework_python = (
                    executable.is_symlink()
                    and "Python.framework/Versions/" in str(resolved_executable)
                    and resolved_executable.name.startswith("python")
                )
                if not contained and not framework_python:
                    raise ValueError
            except (OSError, ValueError):
                raise ValueError("Refusing a managed NmapUI interpreter outside its release") from None
            if not resolved_executable.is_file() or not os.access(resolved_executable, os.X_OK) or not (source / "app.py").is_file():
                raise ValueError("Refusing a managed NmapUI service with unavailable runtime files")
            environment = payload.get("EnvironmentVariables", {})
            accepted_data_roots = {legacy_scanner_data, isolated_scanner_data}
            data_dir = environment.get("NMAPUI_DATA_DIR")
            log_dir = environment.get("NMAPUI_LOG_DIR")
            if (
                environment.get("NMAPUI_HOST") != "127.0.0.1"
                or data_dir not in {str(root / "data") for root in accepted_data_roots}
                or log_dir not in {str(root / "logs") for root in accepted_data_roots}
                or Path(data_dir).parent != Path(log_dir).parent
            ):
                raise ValueError("Refusing an unrecognized NmapUI configuration")
            _check_managed_path(source, user_root)
        descriptors.append({"label": label, "path": path, "sha256": hashlib.sha256(contents).hexdigest()})
    return descriptors


def _private_bytes(path: Path, user_root: Path) -> bytes:
    _check_managed_path(path, user_root.absolute())
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError("Resume files must be private and owned by the current user")
    return path.read_bytes()


def _write_private_bytes_exclusive(path: Path, contents: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".daedalus-resume-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.link(temporary, path)
    finally:
        os.unlink(temporary)


def _enrollment_digest(user_root: Path) -> str:
    contents = _private_bytes(user_root / "Library/Application Support/Daedalus/managed-agent.json", user_root)
    config = json.loads(contents)
    server = urlparse(str(config.get("server", "")))
    if server.username or server.password or not server.hostname or not (server.scheme == "https" or (server.scheme == "http" and server.hostname in {"127.0.0.1", "localhost"})):
        raise ValueError("Unrecognized preserved enrollment server")
    if type(config.get("agent_id")) is not int or config["agent_id"] <= 0 or not isinstance(config.get("agent_token"), str) or not config["agent_token"] or not isinstance(config.get("organization"), str) or not config["organization"]:
        raise ValueError("Unrecognized preserved enrollment identity")
    return hashlib.sha256(contents).hexdigest()


def _resume_directory(user_root: Path) -> Path:
    path = user_root / "Library/Application Support/Daedalus/service-resume"
    _check_managed_path(path, user_root.absolute())
    if path.exists():
        info = path.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError("Restore directory must be private and owned by the current user")
    return path


def _save_resume(user_root: Path, descriptors: list[dict]) -> None:
    """Retain private exact descriptors before removing either service."""
    if {item["label"] for item in descriptors} != {BRIDGE_LABEL, NMAPUI_LABEL}:
        raise ValueError("Both recognized services are required to preserve a restore record")
    directory = _resume_directory(user_root)
    receipt = {"version": 1, "uid": os.getuid(), "enrollment_sha256": _enrollment_digest(user_root), "services": {item["label"]: item["sha256"] for item in descriptors}}
    if directory.exists():
        previous = json.loads(_private_bytes(directory / "receipt.json", user_root))
        if previous != receipt:
            raise ValueError("Existing restore record does not match this installation")
        for item in descriptors:
            saved = _private_bytes(directory / (item["label"] + ".plist"), user_root)
            if hashlib.sha256(saved).hexdigest() != item["sha256"]:
                raise ValueError("Saved service descriptor changed")
        return
    directory.mkdir(mode=0o700)
    try:
        for item in descriptors:
            _write_private_bytes_exclusive(directory / (item["label"] + ".plist"), _private_bytes(item["path"], user_root))
        _write_private_bytes_exclusive(directory / "receipt.json", json.dumps(receipt, sort_keys=True).encode())
    except Exception:
        # Remove only this operation's new, known resume files.
        for name in (BRIDGE_LABEL + ".plist", NMAPUI_LABEL + ".plist", "receipt.json"):
            (directory / name).unlink(missing_ok=True)
        directory.rmdir()
        raise


def _restore_descriptors(user_root: Path) -> list[dict]:
    directory = _resume_directory(user_root)
    receipt = json.loads(_private_bytes(directory / "receipt.json", user_root))
    if receipt.get("version") != 1 or receipt.get("uid") != os.getuid() or receipt.get("enrollment_sha256") != _enrollment_digest(user_root):
        raise ValueError("Restore enrollment or device identity changed")
    saved = managed_artifacts(user_root, descriptor_dir=directory)
    if {item["label"]: item["sha256"] for item in saved} != receipt.get("services") or len(saved) != 2:
        raise ValueError("Saved service descriptors changed or are incomplete")
    destinations = user_root / "Library/LaunchAgents"
    for item in saved:
        path = destinations / (item["label"] + ".plist")
        _check_managed_path(path, user_root.absolute())
        if path.exists():
            if hashlib.sha256(_private_bytes(path, user_root)).hexdigest() != item["sha256"]:
                raise ValueError("Refusing to replace an existing service")
        payload = plistlib.loads(_private_bytes(item["path"], user_root))
        executable = Path(payload["ProgramArguments"][0])
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise ValueError("Preserved service executable is unavailable; restore requires the original installation")
        if item["label"] == NMAPUI_LABEL and not (Path(payload["WorkingDirectory"]) / "app.py").is_file():
            raise ValueError("Preserved scanner application is unavailable")
    for item in saved:
        path = destinations / (item["label"] + ".plist")
        if not path.exists():
            _write_private_bytes_exclusive(path, _private_bytes(item["path"], user_root))
    return managed_artifacts(user_root)


def manage_services(action: str, *, user_root: Path, executor=None) -> dict:
    """Operate only validated user LaunchAgents; retain all data and tokens."""
    if action not in {"status", "restart", "uninstall", "restore"}:
        raise ValueError("Unsupported managed service action")
    if action == "status":
        return _manage_services_locked(action, user_root=user_root, executor=executor)
    with lifecycle_lock(user_root):
        return _manage_services_locked(action, user_root=user_root, executor=executor)


def _manage_services_locked(action: str, *, user_root: Path, executor=None) -> dict:
    executor = executor or subprocess.run
    descriptors = _restore_descriptors(user_root) if action == "restore" else managed_artifacts(user_root)
    if action == "uninstall" and descriptors:
        _save_resume(user_root, descriptors)
    domain = f"gui/{os.getuid()}"
    result = {"action": action, "services": [], "data_preserved": True}
    if action in {"restart", "restore"}:
        descriptors.reverse()
    for descriptor in descriptors:
        label, path = descriptor["label"], descriptor["path"]

        def verify_unchanged():
            _check_managed_path(path, user_root.absolute())
            info = path.stat()
            if info.st_uid != os.getuid() or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077 or hashlib.sha256(path.read_bytes()).hexdigest() != descriptor["sha256"]:
                raise ValueError("Managed LaunchAgent changed during this action")

        verify_unchanged()
        probe = executor([LAUNCHCTL, "print", f"{domain}/{label}"], capture_output=True, text=True, timeout=10)
        loaded = probe.returncode == 0
        printed_state = re.search(r"^\s*state\s*=\s*(.+?)\s*$", getattr(probe, "stdout", "") or "", re.MULTILINE)
        running = loaded and (printed_state is None or printed_state.group(1) == "running")
        if not loaded and not any(text in str(probe.stderr) for text in ("Could not find service", "Could not find specified service")):
            raise RuntimeError("Could not determine service state; descriptor retained")
        if action == "status":
            state = "running" if running else "loaded_not_running" if loaded else "not_loaded"
            result["services"].append({"label": label, "state": state})
            continue
        verify_unchanged()
        if action in {"restart", "restore"}:
            command = [LAUNCHCTL, "kickstart", "-k", f"{domain}/{label}"] if loaded else [LAUNCHCTL, "bootstrap", domain, str(path)]
        else:
            command = [LAUNCHCTL, "bootout", domain, str(path)] if loaded else None
        if command:
            response = executor(command, capture_output=True, text=True, timeout=15)
            if response.returncode != 0:
                raise RuntimeError("Service action failed; descriptor retained")
        if action == "uninstall":
            verify_unchanged()
            path.unlink()
        result["services"].append({"label": label, "state": "restart_requested" if action in {"restart", "restore"} else "uninstalled"})
    return result


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "manage":
        parser = argparse.ArgumentParser(description="Manage validated Daedalus LaunchAgents; retain configuration and evidence")
        parser.add_argument("kind", choices=("manage",))
        parser.add_argument("action", choices=("status", "restart", "uninstall", "restore", "upgrade", "upgrade-offline"))
        parser.add_argument("--bundle", type=Path, help="Scanner kit ZIP used by the explicit upgrade action")
        args = parser.parse_args()
        if sys.platform != "darwin":
            parser.error("Managed LaunchAgent lifecycle commands require macOS")
        if args.action in {"upgrade", "upgrade-offline"} and args.bundle is None:
            parser.error("upgrade actions require --bundle <scanner-kit.zip>")
        if args.action not in {"upgrade", "upgrade-offline"} and args.bundle is not None:
            parser.error("--bundle is supported only with upgrade actions")
        try:
            if args.action in {"upgrade", "upgrade-offline"}:
                from upgrade_service import upgrade_managed_scanner

                result = upgrade_managed_scanner(args.bundle, user_root=Path.home(), offline=args.action == "upgrade-offline")
            else:
                result = manage_services(args.action, user_root=Path.home())
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            parser.exit(1, f"Managed scanner action failed: {type(exc).__name__}; configuration and evidence retained.\n")
        print(json.dumps(result, indent=2))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=("nmapui", "bridge"))
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--exclusive", action="store_true", help="Refuse to replace an existing LaunchAgent")
    parser.add_argument("--python")
    parser.add_argument("--app-dir")
    parser.add_argument("--data-dir")
    parser.add_argument("--log-dir", required=True)
    parser.add_argument("--browser-dir")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--agent-executable")
    parser.add_argument("--config-path")
    parser.add_argument("--install-dir")
    args = parser.parse_args()

    if args.kind == "nmapui":
        required = (args.python, args.app_dir, args.data_dir, args.browser_dir)
        if not all(required):
            parser.error("nmapui requires --python, --app-dir, --data-dir, and --browser-dir")
        payload = build_nmapui_plist(
            python=args.python,
            app_dir=args.app_dir,
            data_dir=args.data_dir,
            log_dir=args.log_dir,
            browser_dir=args.browser_dir,
            port=args.port,
        )
    else:
        required = (args.agent_executable, args.config_path, args.install_dir)
        if not all(required):
            parser.error("bridge requires --agent-executable, --config-path, and --install-dir")
        payload = build_bridge_plist(
            agent_executable=args.agent_executable,
            config_path=args.config_path,
            install_dir=args.install_dir,
            log_dir=args.log_dir,
        )
    write_plist(args.output, payload, exclusive=args.exclusive)


if __name__ == "__main__":
    main()
