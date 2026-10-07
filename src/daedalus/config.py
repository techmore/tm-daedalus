from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlparse

from cryptography.fernet import Fernet
from dotenv import load_dotenv

from .dns_settings import parse_audit_nameservers


load_dotenv()


def env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


# Scheduled audits run overnight, in this timezone, starting at this local hour.
SCHEDULE_TIMEZONE = os.environ.get("DAEDALUS_SCHEDULE_TIMEZONE", "America/New_York").strip() or "America/New_York"
SCHEDULE_HOUR = min(23, max(0, int(os.environ.get("DAEDALUS_SCHEDULE_HOUR", "1") or 1)))
# Platform owners are made admins of every workspace created through Daedalus.
PLATFORM_ADMIN_EMAILS = tuple(sorted({
    email.strip().lower() for email in os.environ.get("DAEDALUS_PLATFORM_ADMIN_EMAILS", "").split(",") if "@" in email
}))
AUDIT_DNS_NAMESERVERS = parse_audit_nameservers(os.environ.get("DAEDALUS_AUDIT_DNS_NAMESERVERS", ""))

APP_ENV = os.environ.get("DAEDALUS_ENV", "development").strip().lower()
BACKGROUND_WORKERS_ENABLED = env_bool("DAEDALUS_BACKGROUND_WORKERS_ENABLED", True)
DEMO_MODE = env_bool("DAEDALUS_DEMO_MODE", APP_ENV != "production")
SESSION_SECRET = os.environ.get(
    "DAEDALUS_SESSION_SECRET",
    "local-only-change-this-daedalus-session-secret",
)
DATABASE_URL = os.environ.get(
    "DAEDALUS_DATABASE_URL",
    "sqlite:///./data/daedalus.db",
)
BASE_URL = os.environ.get("DAEDALUS_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
HOST = os.environ.get("DAEDALUS_HOST", "127.0.0.1")
PORT = int(os.environ.get("DAEDALUS_PORT", "8000"))
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "").strip()
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "").strip()
ENCRYPTION_KEY = os.environ.get("DAEDALUS_ENCRYPTION_KEY", "").strip()
configured_hosts = [
    host.strip().lower().rstrip(".")
    for host in os.environ.get("DAEDALUS_ALLOWED_HOSTS", "").replace(" ", ",").split(",")
    if host.strip()
]
base_host = urlparse(BASE_URL).hostname
allowed_host_candidates = (base_host, *configured_hosts)
if APP_ENV != "production":
    allowed_host_candidates += ("127.0.0.1", "localhost", "testserver")
ALLOWED_HOSTS = tuple(
    dict.fromkeys(
        host
        for host in allowed_host_candidates
        if host
    )
)
REPORTS_DIR = Path(
    os.environ.get(
        "DAEDALUS_REPORTS_DIR",
        "/data/reports" if APP_ENV == "production" else "data/reports",
    )
).expanduser()
DATA_DIR = Path(os.environ.get("DAEDALUS_DATA_DIR", "/data" if APP_ENV == "production" else "data")).expanduser()

if APP_ENV == "production" and DEMO_MODE:
    raise RuntimeError("DAEDALUS_DEMO_MODE must be false in production.")
if APP_ENV == "production" and (
    SESSION_SECRET == "local-only-change-this-daedalus-session-secret"
    or len(SESSION_SECRET) < 32
):
    raise RuntimeError("Set a long, random DAEDALUS_SESSION_SECRET in production.")
if APP_ENV == "production" and (
    urlparse(BASE_URL).scheme != "https" or not base_host
):
    raise RuntimeError("Set DAEDALUS_BASE_URL to the public HTTPS portal URL in production.")
if APP_ENV == "production" and not (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET):
    raise RuntimeError("Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in production.")
if APP_ENV == "production":
    if not ENCRYPTION_KEY:
        raise RuntimeError("Set DAEDALUS_ENCRYPTION_KEY to a Fernet key in production.")
    try:
        Fernet(ENCRYPTION_KEY.encode("ascii"))
    except (UnicodeEncodeError, ValueError) as exc:
        raise RuntimeError("DAEDALUS_ENCRYPTION_KEY must be a valid Fernet key in production.") from exc
