#!/usr/bin/env python3
"""Validate a Daedalus production env file without printing secret values."""

from __future__ import annotations

import base64
import os
import re
import stat
import sys
from pathlib import Path
from urllib.parse import urlparse


PLACEHOLDERS = ("replace-with", "change-me", "changeme", "your-")
DNS_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


class UnsafeEnvironmentFile(ValueError):
    """The production environment file is not stored with the required permissions."""


def read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    # Inspect the opened target so a symlink cannot bypass the permissions
    # check and a path replacement between stat() and read() cannot race it.
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    try:
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode):
            raise UnsafeEnvironmentFile("Production env file must resolve to a regular file")
        mode = stat.S_IMODE(file_stat.st_mode)
        if mode != 0o600:
            raise UnsafeEnvironmentFile(
                f"Production env file must have permission mode 0600 (found {mode:04o})"
            )
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            descriptor = -1
            content = stream.read()
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        name, separator, value = line.partition("=")
        if not separator:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[name.strip()] = value
    return values


def hostname_list(value: str) -> list[str]:
    return [host.strip().lower().rstrip(".") for host in re.split(r"[,\s]+", value) if host.strip()]


def valid_hostname(hostname: str) -> bool:
    return (
        len(hostname) <= 253
        and all(DNS_LABEL.fullmatch(label) for label in hostname.split("."))
        and "." in hostname
    )


def validate(values: dict[str, str]) -> list[str]:
    errors: list[str] = []
    required = (
        "DAEDALUS_BASE_URL",
        "DAEDALUS_HOSTNAMES",
        "DAEDALUS_SESSION_SECRET",
        "GOOGLE_CLIENT_ID",
        "GOOGLE_CLIENT_SECRET",
        "DAEDALUS_ENCRYPTION_KEY",
    )
    for name in required:
        value = values.get(name, "").strip()
        if not value or any(marker in value.casefold() for marker in PLACEHOLDERS):
            errors.append(f"{name} must be set to a real value")

    if values.get("DAEDALUS_ENV", "").strip().lower() != "production":
        errors.append("DAEDALUS_ENV must be production")
    if values.get("DAEDALUS_DEMO_MODE", "").strip().lower() not in {"false", "0", "no", "off"}:
        errors.append("DAEDALUS_DEMO_MODE must be false")

    secret = values.get("DAEDALUS_SESSION_SECRET", "")
    if secret and len(secret) < 32:
        errors.append("DAEDALUS_SESSION_SECRET must contain at least 32 characters")

    encryption_key = values.get("DAEDALUS_ENCRYPTION_KEY", "")
    if encryption_key and not any(marker in encryption_key.casefold() for marker in PLACEHOLDERS):
        try:
            decoded = base64.urlsafe_b64decode(encryption_key.encode("ascii"))
            if len(decoded) != 32 or not encryption_key.endswith("="):
                raise ValueError("invalid Fernet key")
        except (UnicodeEncodeError, ValueError):
            errors.append("DAEDALUS_ENCRYPTION_KEY must be a valid Fernet key")

    base_url = values.get("DAEDALUS_BASE_URL", "")
    parsed_base = urlparse(base_url)
    if base_url and (parsed_base.scheme != "https" or not parsed_base.hostname):
        errors.append("DAEDALUS_BASE_URL must be an HTTPS URL with a hostname")
    if base_url and (
        parsed_base.username is not None
        or parsed_base.password is not None
        or parsed_base.path not in {"", "/"}
        or parsed_base.query
        or parsed_base.fragment
    ):
        errors.append("DAEDALUS_BASE_URL must be an origin without credentials, path, query or fragment")
    try:
        if parsed_base.port not in {None, 443}:
            errors.append("DAEDALUS_BASE_URL must use the public HTTPS port 443")
    except ValueError:
        errors.append("DAEDALUS_BASE_URL has an invalid port")

    public_hosts = hostname_list(values.get("DAEDALUS_HOSTNAMES", ""))
    if not public_hosts:
        errors.append("DAEDALUS_HOSTNAMES must contain at least one public hostname")
    elif any(not valid_hostname(host) for host in public_hosts):
        errors.append("DAEDALUS_HOSTNAMES must contain DNS hostnames only")
    if parsed_base.hostname and parsed_base.hostname.lower().rstrip(".") not in public_hosts:
        errors.append("DAEDALUS_HOSTNAMES must include the DAEDALUS_BASE_URL hostname")

    allowed_hosts = hostname_list(values.get("DAEDALUS_ALLOWED_HOSTS", ""))
    if any(not valid_hostname(host) for host in allowed_hosts):
        errors.append("DAEDALUS_ALLOWED_HOSTS must contain DNS hostnames only")
    public_host_set = set(public_hosts)
    if any(host not in public_host_set for host in allowed_hosts):
        errors.append("DAEDALUS_ALLOWED_HOSTS must not contain hostnames outside DAEDALUS_HOSTNAMES")
    base_hostname = parsed_base.hostname.lower().rstrip(".") if parsed_base.hostname else ""
    if base_hostname and base_hostname not in allowed_hosts:
        errors.append("DAEDALUS_ALLOWED_HOSTS must include the DAEDALUS_BASE_URL hostname")
    missing_allowed = sorted(set(public_hosts) - set(allowed_hosts))
    if missing_allowed:
        errors.append("DAEDALUS_ALLOWED_HOSTS must include every DAEDALUS_HOSTNAMES entry")

    return errors


def main() -> int:
    env_path = Path(sys.argv[1] if len(sys.argv) > 1 else ".env.production")
    try:
        values = read_env(env_path)
    except UnsafeEnvironmentFile as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    except OSError:
        print(f"Production env file not found or unreadable: {env_path}", file=sys.stderr)
        return 2
    errors = validate(values)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("Production environment is valid. Secret values were not displayed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
