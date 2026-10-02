#!/usr/bin/env python3
"""Create and verify Daedalus-owned systemd user units for a local scanner."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys


NMAPUI_UNIT = "daedalus-nmapui.service"
BRIDGE_UNIT = "daedalus-scanner-bridge.service"
ENV_FILE = "daedalus-nmapui.env"
STATE_FILE = ".daedalus-scanner-services.json"


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


def verify(unit_dir: Path, config_dir: Path) -> dict[str, object]:
    if unit_dir.is_symlink() or config_dir.is_symlink():
        raise ServiceError("Managed service directories cannot be symbolic links.")
    if not unit_dir.is_dir() or not config_dir.is_dir():
        raise ServiceError("Managed service directories are missing.")
    if stat.S_IMODE(unit_dir.stat().st_mode) != 0o700 or stat.S_IMODE(config_dir.stat().st_mode) != 0o700:
        raise ServiceError("Managed service directories must have mode 0700.")
    state_path = config_dir / STATE_FILE
    if state_path.is_symlink() or not state_path.is_file():
        raise ServiceError("Daedalus Linux service ownership record is missing or unsafe.")
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ServiceError("Daedalus Linux service ownership record is invalid.") from exc
    if state.get("format") != 1 or state.get("unit_dir") != str(unit_dir):
        raise ServiceError("Daedalus Linux service ownership record does not match these paths.")
    expected = {ENV_FILE, NMAPUI_UNIT, BRIDGE_UNIT}
    if set(state.get("files", {})) != expected:
        raise ServiceError("Daedalus Linux service ownership record has an unexpected file set.")
    for name in expected:
        path = (config_dir / name) if name == ENV_FILE else (unit_dir / name)
        if path.is_symlink() or not path.is_file():
            raise ServiceError(f"Managed service file is missing or unsafe: {path}.")
        if stat.S_IMODE(path.stat().st_mode) != 0o600:
            raise ServiceError(f"Managed service file must have mode 0600: {path}.")
        if _digest(path) != state["files"][name]:
            raise ServiceError(f"Managed service file changed after installation: {path}.")
    if stat.S_IMODE(state_path.stat().st_mode) != 0o600:
        raise ServiceError("Daedalus Linux service ownership record must have mode 0600.")
    return {"verified": True, "unit_names": [NMAPUI_UNIT, BRIDGE_UNIT]}


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
    args = parser.parse_args(argv)
    try:
        if args.command == "install":
            result = install(args)
        else:
            result = verify(args.unit_dir, args.config_dir)
    except (ServiceError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
