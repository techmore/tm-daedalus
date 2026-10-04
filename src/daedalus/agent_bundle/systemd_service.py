#!/usr/bin/env python3
"""Create and verify Daedalus-owned systemd user units for a local scanner."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys


NMAPUI_UNIT = "daedalus-nmapui.service"
BRIDGE_UNIT = "daedalus-scanner-bridge.service"
ENV_FILE = "daedalus-nmapui.env"
STATE_FILE = ".daedalus-scanner-services.json"
RESUME_FILE = ".daedalus-scanner-services-resume.json"
LOCK_FILE = ".daedalus-scanner-services.lock"
UPGRADE_FILE = ".daedalus-scanner-upgrade.json"
SYSTEMCTL = "/usr/bin/systemctl"


class ServiceError(ValueError):
    pass


def _reject_control(value: str, label: str) -> str:
    if not isinstance(value, str) or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ServiceError(f"{label} cannot contain control characters or newlines.")
    return value


def _quote(value: str, label: str) -> str:
    value = _reject_control(value, label)
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _environment_quote(value: str, label: str) -> str:
    value = _reject_control(value, label).replace("%", "%%")
    return _quote(value, label)


def _env_file_quote(value: str, label: str) -> str:
    value = _reject_control(value, label)
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("`", "\\`")
    return '"' + escaped + '"'


def _unit_path(value: str, label: str) -> str:
    """Encode paths for systemd path directives (which do not use shell quotes)."""
    value = _reject_control(value, label)
    encoded = []
    for byte in value.encode("utf-8"):
        character = chr(byte)
        if character == "%":
            encoded.append("%%")
        elif character.isascii() and (character.isalnum() or character in "_./:-"):
            encoded.append(character)
        else:
            encoded.append(f"\\x{byte:02x}")
    return "".join(encoded)


def _exec_quote(value: str, label: str) -> str:
    value = _reject_control(value, label)
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "$$").replace("%", "%%")
    return '"' + escaped + '"'


def _absolute(value: str, label: str) -> Path:
    path = Path(_reject_control(value, label))
    if not path.is_absolute() or "\x00" in str(path):
        raise ServiceError(f"{label} must be an absolute filesystem path.")
    return path


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_exclusive(path: Path, contents: bytes, mode: int = 0o600) -> None:
    if path.is_symlink():
        raise ServiceError(f"Refusing a symbolic link at {path}.")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, mode)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(path, mode)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _nmapui_unit(args: argparse.Namespace, env_path: Path) -> str:
    environment = {
        "NMAPUI_DATA_DIR": str(args.nmapui_data_dir),
        "NMAPUI_LOG_DIR": str(args.nmapui_data_dir / "logs"),
        "NMAPUI_SKIP_LEGACY_MIGRATION": "1",
        "NMAPUI_HOST": "127.0.0.1",
        "NMAPUI_PORT": str(args.port),
        "NMAPUI_ENABLE_NETWORK_FINGERPRINT": "false",
        "NMAPUI_ENABLE_VULNERS": "false",
        "NMAPUI_ENABLE_UPDATE_CHECK": "false",
        "NMAPUI_ALLOW_UNSAFE_WERKZEUG": "true",
        "NMAPUI_TRUST_LOCAL_UI": "false",
        "NMAPUI_COOKIE_SECURE": "false",
        "PLAYWRIGHT_BROWSERS_PATH": str(args.browser_dir),
    }
    lines = [
        "[Unit]",
        "Description=Daedalus managed NmapUI scanner",
        "[Service]",
        "Type=simple",
        f"WorkingDirectory={_unit_path(str(args.nmapui_app_dir), 'NmapUI application path')}",
        f"EnvironmentFile={_unit_path(str(env_path), 'NmapUI environment path')}",
    ]
    lines.extend(f"Environment={key}={_environment_quote(value, key)}" for key, value in environment.items())
    lines.extend([
        f"ExecStart={_exec_quote(str(args.nmapui_python), 'NmapUI Python path')} {_exec_quote(str(args.nmapui_app_dir / 'app.py'), 'NmapUI application path')}",
        "Restart=on-failure",
        "RestartSec=5",
        "UMask=0077",
        "NoNewPrivileges=true",
        "PrivateTmp=true",
        "[Install]",
        "WantedBy=default.target",
        "",
    ])
    return "\n".join(lines)


def _bridge_unit(args: argparse.Namespace, env_path: Path) -> str:
    lines = [
        "[Unit]",
        "Description=Daedalus outbound scanner bridge",
        f"After={NMAPUI_UNIT}",
        "[Service]",
        "Type=simple",
        f"WorkingDirectory={_unit_path(str(args.bridge_working_dir), 'bridge working directory')}",
        f"EnvironmentFile={_unit_path(str(env_path), 'NmapUI environment path')}",
        f"Environment=XDG_CONFIG_HOME={_environment_quote(str(env_path.parent.parent), 'bridge configuration home')}",
        f"Environment=XDG_RUNTIME_DIR={_environment_quote(f'/run/user/{os.getuid()}', 'bridge runtime directory')}",
        f"Environment=DBUS_SESSION_BUS_ADDRESS={_environment_quote(f'unix:path=/run/user/{os.getuid()}/bus', 'bridge user bus')}",
        f"ExecStart={_exec_quote(str(args.agent_executable), 'Daedalus bridge path')} --config {_exec_quote(str(args.agent_config), 'agent config path')}",
        "Restart=always",
        "RestartSec=5",
        "UMask=0077",
        "NoNewPrivileges=true",
        "PrivateTmp=true",
        "[Install]",
        "WantedBy=default.target",
        "",
    ]
    return "\n".join(lines)


def install(args: argparse.Namespace) -> dict[str, object]:
    unit_dir = _absolute(args.unit_dir, "systemd user unit directory")
    config_dir = _absolute(args.config_dir, "Daedalus config directory")
    paths = {
        "nmapui_python": _absolute(args.nmapui_python, "NmapUI Python path"),
        "nmapui_app_dir": _absolute(args.nmapui_app_dir, "NmapUI application path"),
        "nmapui_data_dir": _absolute(args.nmapui_data_dir, "NmapUI data directory"),
        "browser_dir": _absolute(args.browser_dir, "Playwright browser directory"),
        "agent_executable": _absolute(args.agent_executable, "Daedalus bridge path"),
        "bridge_working_dir": _absolute(args.bridge_working_dir, "bridge working directory"),
        "agent_config": _absolute(args.agent_config, "agent config path"),
    }
    for name, path in paths.items():
        setattr(args, name, path)
    if not 1 <= args.port <= 65535:
        raise ServiceError("NmapUI port must be between 1 and 65535.")
    username = _reject_control(os.environ.get("NMAPUI_USERNAME", ""), "NMAPUI_USERNAME")
    password = _reject_control(os.environ.get("NMAPUI_PASSWORD", ""), "NMAPUI_PASSWORD")
    if bool(username) != bool(password):
        raise ServiceError("Set both NMAPUI_USERNAME and NMAPUI_PASSWORD, or leave both unset.")

    for directory in (unit_dir, config_dir):
        if directory.is_symlink():
            raise ServiceError(f"Refusing to use a symbolic-link directory: {directory}.")
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory.chmod(0o700)
    env_path = config_dir / ENV_FILE
    files = {
        env_path: (f'NMAPUI_USERNAME={_env_file_quote(username, "NMAPUI_USERNAME")}\nNMAPUI_PASSWORD={_env_file_quote(password, "NMAPUI_PASSWORD")}\n').encode(),
        unit_dir / NMAPUI_UNIT: _nmapui_unit(args, env_path).encode(),
        unit_dir / BRIDGE_UNIT: _bridge_unit(args, env_path).encode(),
    }
    state_path = config_dir / STATE_FILE
    created: list[Path] = []
    try:
        for path, contents in files.items():
            _write_exclusive(path, contents)
            created.append(path)
        state = {
            "format": 1,
            "unit_dir": str(unit_dir),
            "files": {path.name: _digest(path) for path in files},
        }
        _write_exclusive(state_path, (json.dumps(state, sort_keys=True, indent=2) + "\n").encode())
    except BaseException:
        for path in reversed(created):
            path.unlink(missing_ok=True)
        raise
    return {"installed": True, "unit_names": [NMAPUI_UNIT, BRIDGE_UNIT], "state_file": str(state_path)}


def _private_bytes(path: Path) -> bytes:
    """Read only a bounded, private, regular file belonging to this account."""
    if path.is_symlink():
        raise ServiceError(f"Managed service file is missing or unsafe: {path}.")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise ServiceError(f"Managed service file must be regular and owned by this user: {path}.")
        if stat.S_IMODE(info.st_mode) != 0o600:
            raise ServiceError(f"Managed service file must have mode 0600: {path}.")
        contents = stream.read(131073)
        if len(contents) > 131072:
            raise ServiceError("Managed service file exceeds the size limit.")
        return contents


def _ownership(unit_dir: Path, config_dir: Path) -> dict:
    _absolute(str(unit_dir), "systemd user unit directory")
    _absolute(str(config_dir), "Daedalus config directory")
    if unit_dir.is_symlink() or config_dir.is_symlink():
        raise ServiceError("Managed service directories cannot be symbolic links.")
    if not unit_dir.is_dir() or not config_dir.is_dir():
        raise ServiceError("Managed service directories are missing.")
    if stat.S_IMODE(unit_dir.stat().st_mode) != 0o700 or stat.S_IMODE(config_dir.stat().st_mode) != 0o700:
        raise ServiceError("Managed service directories must have mode 0700.")
    if unit_dir.stat().st_uid != os.getuid() or config_dir.stat().st_uid != os.getuid():
        raise ServiceError("Managed service directories must belong to this user.")
    state_path = config_dir / STATE_FILE
    if state_path.is_symlink() or not state_path.is_file():
        raise ServiceError("Daedalus Linux service ownership record is missing or unsafe.")
    try:
        state = json.loads(_private_bytes(state_path))
    except (OSError, json.JSONDecodeError, UnicodeError) as exc:
        raise ServiceError("Daedalus Linux service ownership record is invalid.") from exc
    if not isinstance(state, dict) or state.get("format") != 1 or state.get("unit_dir") != str(unit_dir):
        raise ServiceError("Daedalus Linux service ownership record does not match these paths.")
    expected = {ENV_FILE, NMAPUI_UNIT, BRIDGE_UNIT}
    if not isinstance(state.get("files"), dict) or set(state["files"]) != expected:
        raise ServiceError("Daedalus Linux service ownership record has an unexpected file set.")
    for digest in state["files"].values():
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ServiceError("Daedalus Linux service ownership record has an invalid fingerprint.")
    return state


def verify(unit_dir: Path, config_dir: Path) -> dict[str, object]:
    state = _ownership(unit_dir, config_dir)
    expected = {ENV_FILE, NMAPUI_UNIT, BRIDGE_UNIT}
    for name in expected:
        path = (config_dir / name) if name == ENV_FILE else (unit_dir / name)
        if path.is_symlink() or not path.is_file():
            raise ServiceError(f"Managed service file is missing or unsafe: {path}.")
        if hashlib.sha256(_private_bytes(path)).hexdigest() != state["files"][name]:
            raise ServiceError(f"Managed service file changed after installation: {path}.")
    return {"verified": True, "unit_names": [NMAPUI_UNIT, BRIDGE_UNIT]}


def _resume(unit_dir: Path, config_dir: Path) -> dict:
    """Validate exact retained descriptors against the original ownership record."""
    state = _ownership(unit_dir, config_dir)
    try:
        resume = json.loads(_private_bytes(config_dir / RESUME_FILE))
    except (OSError, ValueError) as exc:
        raise ServiceError("Managed service recovery record is missing or invalid.") from exc
    if (
        not isinstance(resume, dict) or resume.get("format") != 1
        or resume.get("unit_dir") != str(unit_dir)
        or resume.get("ownership_sha256") != hashlib.sha256(_private_bytes(config_dir / STATE_FILE)).hexdigest()
        or not isinstance(resume.get("units"), dict)
        or set(resume["units"]) != {NMAPUI_UNIT, BRIDGE_UNIT}
    ):
        raise ServiceError("Managed service recovery record does not match this installation.")
    if hashlib.sha256(_private_bytes(config_dir / ENV_FILE)).hexdigest() != state["files"][ENV_FILE]:
        raise ServiceError("Managed service environment changed after installation.")
    for name, contents in resume["units"].items():
        if not isinstance(contents, str) or hashlib.sha256(contents.encode()).hexdigest() != state["files"][name]:
            raise ServiceError("Managed service recovery descriptor does not match its fingerprint.")
        path = unit_dir / name
        if path.exists() or path.is_symlink():
            if hashlib.sha256(_private_bytes(path)).hexdigest() != state["files"][name]:
                raise ServiceError("Managed service file changed during this action.")
    return resume


def manage(action: str, unit_dir: Path, config_dir: Path, *, executor=None) -> dict:
    """Remove/resume only fixed owned services, preserving enrollment and evidence."""
    if action not in {"uninstall", "restore", "restart"}:
        raise ServiceError("Unsupported Linux service lifecycle action.")
    if (config_dir / UPGRADE_FILE).exists() or (config_dir / UPGRADE_FILE).is_symlink():
        raise ServiceError("Resolve the pending upgrade with upgrade-rollback before removal or recovery.")
    _ownership(unit_dir, config_dir)
    lock = os.open(config_dir / LOCK_FILE, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        info = os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise ServiceError("Lifecycle lock must be a private regular file belonging to this user.")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ServiceError("Another scanner lifecycle action is running; retry when it finishes.") from exc
        if (config_dir / UPGRADE_FILE).exists() or (config_dir / UPGRADE_FILE).is_symlink():
            raise ServiceError("Resolve the pending upgrade with upgrade-rollback before removal or recovery.")
        if action == "restart":
            return _restart_locked(unit_dir, config_dir, executor=executor)
        return _manage_locked(action, unit_dir, config_dir, executor=executor)
    finally:
        # Keep the lock file: unlinking it could let another process lock a different inode.
        os.close(lock)


def _restart_locked(unit_dir: Path, config_dir: Path, *, executor=None) -> dict:
    """Restart only loaded owned units while excluding every local lifecycle action."""
    executor = executor or subprocess.run

    def run(*arguments):
        verify(unit_dir, config_dir)
        try:
            result = executor([SYSTEMCTL, "--user", *arguments], capture_output=True, text=True, timeout=30)
        except subprocess.TimeoutExpired as exc:
            raise ServiceError("Service restart timed out; inspect service status before retrying.") from exc
        if result.returncode:
            raise ServiceError("Service restart failed; inspect service status before retrying.")
        return result

    def observe(name):
        response = run("show", "--property=LoadState", "--property=ActiveState", "--property=UnitFileState", "--property=MainPID", "--property=FragmentPath", "--property=DropInPaths", "--", name)
        values = {}
        for line in response.stdout.splitlines():
            key, separator, value = line.partition("=")
            if not separator or key in values:
                raise ServiceError("Systemd service state is ambiguous; restart refused.")
            values[key] = value
        if (
            set(values) != {"LoadState", "ActiveState", "UnitFileState", "MainPID", "FragmentPath", "DropInPaths"}
            or values["LoadState"] != "loaded"
            or values["FragmentPath"] != str(unit_dir / name)
            or values["DropInPaths"]
            or not values["MainPID"].isascii() or not values["MainPID"].isdigit()
        ):
            raise ServiceError("Systemd loaded an unexpected unit or override; restart refused.")
        return values

    for name in (NMAPUI_UNIT, BRIDGE_UNIT):
        observe(name)
    observations = []
    for name in (NMAPUI_UNIT, BRIDGE_UNIT):
        observe(name)
        run("restart", name)
        state = observe(name)
        if state["ActiveState"] != "active" or state["MainPID"] == "0":
            raise ServiceError("Restarted service startup is unconfirmed; inspect service status.")
        observations.append({"unit": name, "active_state": state["ActiveState"]})
    return {"action": "restart", "services": observations, "data_preserved": True}


def _manage_locked(action: str, unit_dir: Path, config_dir: Path, *, executor=None) -> dict:
    executor = executor or subprocess.run
    resume_path = config_dir / RESUME_FILE
    if action == "uninstall" and not (resume_path.exists() or resume_path.is_symlink()):
        verify(unit_dir, config_dir)
        resume = {
            "format": 1, "unit_dir": str(unit_dir),
            "ownership_sha256": hashlib.sha256(_private_bytes(config_dir / STATE_FILE)).hexdigest(),
            "units": {name: _private_bytes(unit_dir / name).decode("utf-8") for name in (NMAPUI_UNIT, BRIDGE_UNIT)},
        }
        _write_exclusive(resume_path, (json.dumps(resume, sort_keys=True, indent=2) + "\n").encode())
    resume = _resume(unit_dir, config_dir)

    def run(*arguments: str):
        _resume(unit_dir, config_dir)  # Recheck before every manager operation.
        try:
            response = executor([SYSTEMCTL, "--user", *arguments], capture_output=True, text=True, timeout=30)
        except subprocess.TimeoutExpired as exc:
            raise ServiceError("Service action timed out; recovery descriptors and data were retained.") from exc
        if response.returncode != 0:
            # Never include manager output, which can contain local paths or credentials.
            raise ServiceError("Service action failed; recovery descriptors and data were retained.")
        return response

    def observe(name: str) -> dict[str, str]:
        response = run("show", "--property=LoadState", "--property=ActiveState", "--property=UnitFileState", "--property=MainPID", "--property=FragmentPath", "--property=DropInPaths", "--", name)
        values = {}
        for line in response.stdout.splitlines():
            key, separator, value = line.partition("=")
            if not separator or key in values:
                raise ServiceError("Systemd service state is ambiguous; recovery descriptors were retained.")
            values[key] = value
        if (
            set(values) != {"LoadState", "ActiveState", "UnitFileState", "MainPID", "FragmentPath", "DropInPaths"}
            or values["LoadState"] not in {"loaded", "not-found"}
            or not values["MainPID"].isascii() or not values["MainPID"].isdigit()
        ):
            raise ServiceError("Systemd service state is unavailable; recovery descriptors were retained.")
        if values["DropInPaths"] or (values["LoadState"] == "loaded" and values["FragmentPath"] != str(unit_dir / name)):
            raise ServiceError("Systemd loaded an unexpected unit or override; recovery descriptors were retained.")
        return values

    run("show-environment")
    if action == "restore":
        for name, contents in resume["units"].items():
            _resume(unit_dir, config_dir)
            if not (unit_dir / name).exists():
                _write_exclusive(unit_dir / name, contents.encode())
    run("daemon-reload")
    observations = []
    names = (BRIDGE_UNIT, NMAPUI_UNIT) if action == "uninstall" else (NMAPUI_UNIT, BRIDGE_UNIT)
    for name in names:
        if action == "uninstall":
            state = observe(name)
            if state["LoadState"] == "loaded":
                run("disable", "--now", name)
            elif (unit_dir / name).exists():
                raise ServiceError("Systemd did not load the verified unit; its descriptor was retained.")
            state = observe(name)
            if state["ActiveState"] not in {"inactive", "failed"} or state["MainPID"] != "0" or state["UnitFileState"] not in {"disabled", ""}:
                raise ServiceError("Service stop/disable is unconfirmed; its descriptor was retained.")
        else:
            run("enable", "--now", name)
            state = observe(name)
            if state["ActiveState"] != "active" or state["MainPID"] == "0" or state["UnitFileState"] != "enabled":
                raise ServiceError("Restored service startup is unconfirmed; descriptors and data were retained.")
        observations.append({"unit": name, "active_state": state["ActiveState"], "enabled_state": state["UnitFileState"]})
    if action == "uninstall":
        for name in names:
            _resume(unit_dir, config_dir)
            (unit_dir / name).unlink(missing_ok=True)
        run("daemon-reload")
    return {"action": action, "services": observations, "data_preserved": True, "recovery_file": str(resume_path)}


def _absolute_arg(parser: argparse.ArgumentParser, value: str) -> Path:
    try:
        return _absolute(value, "path")
    except ServiceError as exc:
        parser.error(str(exc))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("install")
    for name in ("unit-dir", "config-dir", "nmapui-python", "nmapui-app-dir", "nmapui-data-dir", "browser-dir", "agent-executable", "bridge-working-dir", "agent-config"):
        create.add_argument("--" + name, required=True)
    create.add_argument("--port", required=True, type=int)
    check = commands.add_parser("verify")
    check.add_argument("--unit-dir", required=True, type=Path)
    check.add_argument("--config-dir", required=True, type=Path)
    for action in ("uninstall", "restore", "restart"):
        lifecycle = commands.add_parser(action)
        lifecycle.add_argument("--unit-dir", required=True, type=Path)
        lifecycle.add_argument("--config-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "install":
            result = install(args)
        elif args.command == "verify":
            result = verify(args.unit_dir, args.config_dir)
        else:
            result = manage(args.command, args.unit_dir, args.config_dir)
    except (ServiceError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
