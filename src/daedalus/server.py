from __future__ import annotations

from .report_storage import report_artifact

import asyncio
import hashlib
import hmac
import io
import ipaddress
import json
import logging
import os
import re
import secrets
import threading
import time
import zipfile
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit
from uuid import UUID

from authlib.integrations.starlette_client import OAuth
from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field, StrictBool, model_validator
from pydantic import ValidationError
from sqlalchemy import func, inspect as sqlalchemy_inspect, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, defer
from starlette.concurrency import run_in_threadpool
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from anyio import from_thread

from daedalus import __version__
from daedalus.config import (
    APP_ENV,
    AUDIT_DNS_NAMESERVERS,
    ALLOWED_HOSTS,
    BASE_URL,
    BACKGROUND_WORKERS_ENABLED,
    DEMO_MODE,
    DATA_DIR,
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    HOST,
    PORT,
    REPORTS_DIR,
    SESSION_SECRET,
)
from daedalus.cis import (
    CISDataError,
    apply_profile_coverage_limits,
    bind_report_to_profile,
    load_macos26_starter_profiles,
    load_starter_profile,
    normalize_cis_report,
    profile_checksum,
    validate_profile,
    validate_report_target_os,
)
from daedalus.db import Base, SessionLocal, engine, get_db
from daedalus.live import live_hub
from daedalus.models import (
    Agent,
    AgentCommand,
    AuditLog,
    CISAPIKey,
    CISDevice,
    CISProfile,
    CISReport,
    CISReportChange,
    DomainChallenge,
    EnrollmentToken,
    ExternalCheckChange,
    ExternalCheckRun,
    ExternalCheckSchedule,
    MerakiCredential,
    MerakiOrganizationGrant,
    Membership,
    Organization,
    ProbationOverride,
    ReportJob,
    ScanEvent,
    ScannerRunComparison,
    User,
    UserAPIKey,
    WorkspaceNotification,
    WorkspaceNotificationRead,
    VendorReview,
)
from daedalus.domain_verification import (
    challenge_record_name,
    challenge_record_value,
    has_matching_txt,
    issue_challenge,
    normalize_domain,
)
from daedalus.active_website_checks import run_active_website_check
from daedalus.nikto_checks import run_nikto_check
from daedalus.external_checks import (
    ExternalCheckFailure,
    compare_snapshots,
    run_dns_check,
    run_website_check,
)
from daedalus.email_policy import analyze_email_auth
from daedalus.credential_store import CredentialEncryptionError, decrypt_secret, encrypt_secret
from daedalus.meraki_api import MerakiAPIError, MerakiClient, compare_meraki_snapshots
from daedalus.meraki_history import compare_meraki_inventory
from daedalus.reports import (
    build_cis_endpoint_pdf,
    build_external_posture_pdf,
    build_meraki_security_pdf,
    build_scanner_results_pdf,
    scanner_result_hosts,
)


PACKAGE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=PACKAGE_DIR / "templates")
logger = logging.getLogger(__name__)
oauth = OAuth()
if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
    oauth.register(
        name="google",
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid profile email"},
    )


def utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def token_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def build_agent_bundle() -> bytes:
    """Build a workspace-secret-free NmapUI and Daedalus scanner kit."""
    bundle_dir = PACKAGE_DIR / "agent_bundle"
    files = {
        "README.md": bundle_dir / "README.md",
        "install.sh": bundle_dir / "install.sh",
        "install-nmapui.sh": bundle_dir / "install-nmapui.sh",
        "install-service-macos.sh": bundle_dir / "install-service-macos.sh",
        "manage-service-macos.sh": bundle_dir / "manage-service-macos.sh",
        "install-service-linux.sh": bundle_dir / "install-service-linux.sh",
        "manage-service-linux.sh": bundle_dir / "manage-service-linux.sh",
        "macos_service.py": bundle_dir / "macos_service.py",
        "ScannerStatus.swift": bundle_dir / "ScannerStatus.swift",
        "install-status-macos.sh": bundle_dir / "install-status-macos.sh",
        "systemd_service.py": bundle_dir / "systemd_service.py",
        "upgrade_service.py": bundle_dir / "upgrade_service.py",
        "linux_upgrade.py": bundle_dir / "linux_upgrade.py",
        "nmapui-source.zip": bundle_dir / "nmapui-source.zip",
        "pyproject.toml": bundle_dir / "pyproject.toml",
        "src/daedalus/__init__.py": PACKAGE_DIR / "__init__.py",
        "src/daedalus/agent.py": PACKAGE_DIR / "agent.py",
        "src/daedalus/command_journal.py": PACKAGE_DIR / "command_journal.py",
    }
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, mode="w", compression=zipfile.ZIP_DEFLATED) as output:
        for archive_path, source_path in files.items():
            if not source_path.is_file():
                raise RuntimeError(f"Missing scanner bridge bundle file: {source_path.name}")
            contents = source_path.read_bytes()
            if archive_path == "pyproject.toml":
                contents = contents.replace(
                    b"__DAEDALUS_VERSION__", __version__.encode("ascii")
                )
            output.writestr(f"daedalus-scanner-kit/{archive_path}", contents)
    return archive.getvalue()


def seed_demo_workspace() -> None:
    if not DEMO_MODE:
        return
    with SessionLocal() as db:
        organization = db.scalar(
            select(Organization).where(Organization.slug == "csp")
        )
        if organization is None:
            organization = Organization(
                name="Cyber Security Pilot",
                slug="csp",
                domain="cybersecuritypilot.org",
                verification_status="verified",
                created_at=utcnow(),
            )
            db.add(organization)
            db.flush()

        user = db.scalar(
            select(User).where(User.google_subject == "daedalus-local-demo-admin")
        )
        if user is None:
            user = User(
                google_subject="daedalus-local-demo-admin",
                email="demo.admin@cybersecuritypilot.org",
                display_name="CSP Demo Admin",
                created_at=utcnow(),
            )
            db.add(user)
            db.flush()

        demo_member = db.scalar(
            select(User).where(User.google_subject == "daedalus-local-demo-member")
        )
        if demo_member is None:
            demo_member = User(
                google_subject="daedalus-local-demo-member",
                email="demo.member@outside-example.net",
                display_name="Demo Member",
                created_at=utcnow(),
            )
            db.add(demo_member)
            db.flush()

        membership = db.scalar(
            select(Membership).where(
                Membership.user_id == user.id,
                Membership.organization_id == organization.id,
            )
        )
        if membership is None:
            db.add(
                Membership(
                    user_id=user.id,
                    organization_id=organization.id,
                    role="admin",
                    status="approved",
                    created_at=utcnow(),
                )
            )
        db.commit()


def ensure_agent_telemetry_columns(connection) -> None:
    """Add optional scanner telemetry to databases created by earlier builds."""
    existing = {
        column["name"] for column in sqlalchemy_inspect(connection).get_columns("agents")
    }
    additions = {
        "bridge_version": "VARCHAR(80)",
        "host_platform": "VARCHAR(80)",
        "nmapui_version": "VARCHAR(80)",
        "nmapui_ready": "BOOLEAN",
        "nmapui_restart_supported": "BOOLEAN NOT NULL DEFAULT 0",
        "command_protocol_version": "INTEGER NOT NULL DEFAULT 0",
        "authorized_networks": "JSON NOT NULL DEFAULT '[]'",
        "detected_networks": "JSON NOT NULL DEFAULT '[]'",
    }
    for name, sql_type in additions.items():
        if name not in existing:
            connection.execute(text(f"ALTER TABLE agents ADD COLUMN {name} {sql_type}"))
            existing.add(name)


def ensure_enrollment_scope_columns(connection) -> None:
    """Add scanner identity/scope to outstanding one-time enrollment codes."""
    existing = {
        column["name"] for column in sqlalchemy_inspect(connection).get_columns("enrollment_tokens")
    }
    for name, sql_type in {
        "scanner_name": "VARCHAR(120)",
        "authorized_networks": "JSON",
    }.items():
        if name not in existing:
            connection.execute(text(f"ALTER TABLE enrollment_tokens ADD COLUMN {name} {sql_type}"))
            existing.add(name)


def ensure_agent_command_columns(connection) -> None:
    existing = {column["name"] for column in sqlalchemy_inspect(connection).get_columns("agent_commands")}
    for name in ("delivered_at", "deadline_at", "completed_at"):
        if name not in existing:
            connection.execute(text(f"ALTER TABLE agent_commands ADD COLUMN {name} TIMESTAMP"))
            existing.add(name)
    if "skip_host_discovery" not in existing:
        connection.execute(text(
            "ALTER TABLE agent_commands ADD COLUMN skip_host_discovery BOOLEAN NOT NULL DEFAULT 0"
        ))


def ensure_scanner_event_columns(connection) -> None:
    existing = {column["name"] for column in sqlalchemy_inspect(connection).get_columns("scan_events")}
    for name, sql_type in {
        "client_event_id": "VARCHAR(36)", "occurred_at": "TIMESTAMP",
        "source_job_id": "VARCHAR(36)", "source_job_type": "VARCHAR(16)",
        "artifact_sha256": "VARCHAR(64)", "artifact_size_bytes": "INTEGER",
    }.items():
        if name not in existing:
            connection.execute(text(f"ALTER TABLE scan_events ADD COLUMN {name} {sql_type}"))
    connection.execute(text(
        "CREATE UNIQUE INDEX IF NOT EXISTS ux_scan_event_client_id ON scan_events (agent_id, client_event_id)"
    ))
    if {"organization_id", "agent_id"}.issubset(existing):
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_scan_event_source_run ON scan_events (organization_id, agent_id, source_job_id)"))


def ensure_external_check_columns(connection) -> None:
    """Add trigger metadata to external-check runs from earlier builds."""
    existing = {
        column["name"]
        for column in sqlalchemy_inspect(connection).get_columns("external_check_runs")
    }
    if "trigger_source" not in existing:
        connection.execute(
            text(
                "ALTER TABLE external_check_runs ADD COLUMN trigger_source "
                "VARCHAR(24) NOT NULL DEFAULT 'manual'"
            )
        )
    for column in ("queued_at", "collection_started_at"):
        if column not in existing:
            connection.execute(text(f"ALTER TABLE external_check_runs ADD COLUMN {column} TIMESTAMP"))


def ensure_cis_presence_columns(connection) -> None:
    existing = {column["name"] for column in sqlalchemy_inspect(connection).get_columns("cis_devices")}
    if "last_client_heartbeat_at" not in existing:
        connection.execute(text("ALTER TABLE cis_devices ADD COLUMN last_client_heartbeat_at TIMESTAMP"))


def recover_interrupted_external_checks() -> int:
    """Preserve incomplete attempts and notify their workspace after process loss."""
    with SessionLocal() as db:
        runs = db.scalars(select(ExternalCheckRun).where(ExternalCheckRun.status == "running")).all()
        for run in runs:
            run.status = "failed"
            run.error_summary = "The check did not finish before the server restarted."
            run.completed_at = utcnow()
            audit(db, run.organization_id, None, "external_check.interrupted", {
                "run_id": run.id, "check_type": run.check_type, "source": run.trigger_source,
            })
            existing = db.scalar(select(WorkspaceNotification.id).where(
                WorkspaceNotification.organization_id == run.organization_id,
                WorkspaceNotification.source_type == "external_check_run",
                WorkspaceNotification.source_id == run.id,
            ))
            if existing is None:
                db.add(WorkspaceNotification(
                    organization_id=run.organization_id,
                    source_type="external_check_run", source_id=run.id,
                    title=f"{check_type_label(run.check_type)} check interrupted · {run.domain}",
                    summary="The server restarted before this audit finished. This attempt has no completed assessment; review its history and start a new run when appropriate.",
                    reason="check_failed", detected_at=run.completed_at,
                ))
        if runs:
            db.commit()
        return len(runs)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    Base.metadata.create_all(bind=engine)
    with engine.begin() as connection:
        ensure_agent_telemetry_columns(connection)
        ensure_enrollment_scope_columns(connection)
        ensure_scanner_event_columns(connection)
        ensure_agent_command_columns(connection)
        ensure_external_check_columns(connection)
        ensure_cis_presence_columns(connection)
        connection.execute(
            text(
                "CREATE UNIQUE INDEX IF NOT EXISTS ux_organizations_domain "
                "ON organizations (domain)"
            )
        )
    seed_demo_workspace()
    recover_interrupted_report_jobs()
    recover_interrupted_external_checks()
    recover_interrupted_external_check_schedules()
    tasks = []
    if BACKGROUND_WORKERS_ENABLED:
        tasks = [asyncio.create_task(external_check_scheduler()), asyncio.create_task(website_audit_worker())]
    else:
        logger.warning("Scheduled checks and website audit worker disabled by configuration")
    try:
        yield
    finally:
        for task in tasks:
            task.cancel()
        for task in tasks:
            try:
                await task
            except asyncio.CancelledError:
                pass


app = FastAPI(title="Daedalus", version=__version__, lifespan=lifespan)
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    session_cookie="daedalus_session",
    max_age=12 * 60 * 60,
    same_site="lax",
    https_only=APP_ENV == "production",
)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=list(ALLOWED_HOSTS),
)
app.mount("/static", StaticFiles(directory=PACKAGE_DIR / "static"), name="static")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; "
        "style-src 'self' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; connect-src 'self' ws: wss:; "
        "base-uri 'self'; object-src 'none'; form-action 'self'; frame-ancestors 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["X-Frame-Options"] = "DENY"
    if APP_ENV == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


class EnrollmentRequest(BaseModel):
    code: str = Field(min_length=16, max_length=200)
    name: str = Field(min_length=1, max_length=120)


class ScannerEnrollmentOptions(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    authorized_networks: list[str] = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def normalize_networks(self):
        self.name = self.name.strip()
        if not self.name:
            raise ValueError("A scanner name is required.")
        self.authorized_networks = validate_scanner_network_scopes(self.authorized_networks)
        return self


class ScannerNetworkScopeInput(BaseModel):
    authorized_networks: list[str] = Field(max_length=32)

    @model_validator(mode="after")
    def normalize_networks(self):
        self.authorized_networks = validate_scanner_network_scopes(self.authorized_networks)
        return self


class AgentEventRequest(BaseModel):
    event_name: str = Field(min_length=1, max_length=100)
    payload: Any = None
    client_event_id: UUID | None = None
    occurred_at: datetime | None = None
    source_job_id: UUID | None = None
    source_job_type: Literal["scan", "report"] | None = None

    @model_validator(mode="after")
    def validate_source_run(self):
        if (self.source_job_id is None) != (self.source_job_type is None):
            raise ValueError("Source job UUID and type must be supplied together.")
        return self


class AgentHeartbeatRequest(BaseModel):
    detected_networks: list[str] | None = Field(default=None, max_length=32)

    @model_validator(mode="after")
    def normalize_detected_networks(self):
        if self.detected_networks is not None:
            self.detected_networks = validate_scanner_network_scopes(self.detected_networks)
        return self

    nmapui_connected: bool = False
    version: str | None = Field(default=None, max_length=80)
    platform: str | None = Field(default=None, max_length=80)
    nmapui_version: str | None = Field(default=None, max_length=80)
    nmapui_ready: bool | None = None
    nmapui_restart_supported: bool = False
    command_protocol_version: int = Field(default=0, ge=0, le=100)


class NewCommandRequest(BaseModel):
    action: Literal[
        "start_scan",
        "cancel_scan",
        "check_nmapui_updates",
        "restart_nmapui",
        "refresh_health",
        "collect_diagnostics",
        "check_os_updates",
    ]
    target: str | None = Field(default=None, max_length=255)
    skip_host_discovery: StrictBool = False

    @model_validator(mode="after")
    def validate_scan_options(self):
        if self.skip_host_discovery and self.action != "start_scan":
            raise ValueError("Host discovery options apply only to scan commands.")
        return self

class MerakiCredentialInput(BaseModel):
    api_key: str = Field(min_length=16, max_length=256)


class MerakiReportInput(BaseModel):
    organization_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")


class MerakiOrganizationScopeInput(BaseModel):
    meraki_organization_id: str = Field(
        min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_-]+$"
    )


class CISProfileInput(BaseModel):
    slug: str | None = None
    name: str = Field(min_length=1, max_length=200)
    version: str = Field(min_length=1, max_length=32)
    platform: Literal["macos", "windows", "linux", "browser", "multi"] = "multi"
    description: str = Field(default="", max_length=1000)
    benchmark: dict[str, Any] | None = None
    checks: list[dict[str, Any]] = Field(min_length=1, max_length=2000)


class CommandResultRequest(BaseModel):
    status: Literal["accepted", "succeeded", "failed", "timed_out"]
    result: str | None = Field(default=None, max_length=1000)


class WorkspaceCreateRequest(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    domain: str = Field(min_length=3, max_length=253)


class AccessRequestInput(BaseModel):
    domain: str = Field(min_length=3, max_length=253)


class MembershipDecisionRequest(BaseModel):
    approve: bool


class MembershipRoleRequest(BaseModel):
    role: Literal["admin", "user"]


class ProbationOverrideRequest(BaseModel):
    reason: str = Field(min_length=8, max_length=500)


class WorkspaceSelectRequest(BaseModel):
    organization_id: int


class ExternalCheckScheduleInput(BaseModel):
    enabled: bool
    interval_hours: Literal[24, 168] = 24


def validate_user_key(db: Session, key: UserAPIKey | None) -> UserAPIKey:
    if key is None or key.revoked_at is not None or key.expires_at <= utcnow():
        raise HTTPException(status_code=401, detail="Invalid or expired access key")
    membership = db.scalar(select(Membership).where(
        Membership.user_id == key.user_id,
        Membership.organization_id == key.organization_id,
        Membership.status == "approved",
    ))
    if membership is None:
        raise HTTPException(status_code=401, detail="Invalid or expired access key")
    return key


def get_session_user(request: Request, db: Session) -> User:
    authorization = request.headers.get("authorization")
    key = None
    if authorization is not None:
        if not authorization.startswith("Bearer dd_user_") or len(authorization) > 200:
            raise HTTPException(status_code=401, detail="Invalid access key")
        key = validate_user_key(db, db.scalar(select(UserAPIKey).where(
            UserAPIKey.token_hash == token_digest(authorization[7:])
        )))
        user_id = key.user_id
    elif request.session.get("api_key_id"):
        key = validate_user_key(db, db.get(UserAPIKey, request.session["api_key_id"]))
        user_id = key.user_id
    else:
        user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Sign in required")
    if key is not None:
        request.session["organization_id"] = key.organization_id
        request.state.user_api_key = key
        if request.url.path in {"/api/workspaces", "/api/workspaces/select", "/api/membership-requests", "/api/my-workspaces"}:
            raise HTTPException(status_code=403, detail="Access key is limited to its workspace")
    user = db.get(User, int(user_id))
    if user is None:
        request.session.clear()
        raise HTTPException(status_code=401, detail="Sign in required")
    return user


def get_org_context(
    request: Request,
    db: Session,
    *,
    admin: bool = False,
) -> tuple[User, Organization, Membership]:
    user = get_session_user(request, db)
    organization_id = request.session.get("organization_id")
    query = (
        select(Membership, Organization)
        .join(Organization, Organization.id == Membership.organization_id)
        .where(Membership.user_id == user.id, Membership.status == "approved")
    )
    if organization_id:
        query = query.where(Organization.id == int(organization_id))
    row = db.execute(query.order_by(Organization.id)).first()
    if row is None:
        raise HTTPException(status_code=403, detail="No approved workspace membership")
    membership, organization = row
    request.session["organization_id"] = organization.id
    if (
        organization.verification_status == "pending"
        and organization.verification_expires_at is not None
        and organization.verification_expires_at <= utcnow()
    ):
        organization.verification_status = "expired"
        db.commit()
    if admin and membership.role != "admin":
        raise HTTPException(status_code=403, detail="Workspace admin role required")
    return user, organization, membership


def active_probation_override(
    db: Session,
    organization_id: int,
    *,
    now: datetime | None = None,
) -> ProbationOverride | None:
    current_time = now or utcnow()
    return db.scalar(
        select(ProbationOverride)
        .where(
            ProbationOverride.organization_id == organization_id,
            ProbationOverride.starts_at <= current_time,
            ProbationOverride.expires_at > current_time,
            ProbationOverride.revoked_at.is_(None),
        )
        .order_by(ProbationOverride.id.desc())
    )


def workspace_controls_available(db: Session, organization: Organization) -> bool:
    return organization.verification_status == "verified" or active_probation_override(
        db, organization.id
    ) is not None


def audit(
    db: Session,
    organization_id: int,
    actor_user_id: int | None,
    action: str,
    details: dict[str, Any] | None = None,
) -> None:
    db.add(
        AuditLog(
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action=action,
            details=details,
            created_at=utcnow(),
        )
    )


def iso_utc(value: datetime | None) -> str | None:
    return value.isoformat() + "Z" if value else None


def serialize_external_run(run: ExternalCheckRun, actor: User | None = None) -> dict[str, Any]:
    snapshot = run.snapshot
    if run.check_type == "dns" and isinstance(snapshot, dict):
        snapshot = dict(snapshot)
        if "email_authentication_assessment" not in snapshot:
            records = snapshot.get("records") if isinstance(snapshot.get("records"), dict) else {}
            errors = snapshot.get("resolver_errors") if isinstance(snapshot.get("resolver_errors"), dict) else {}
            if any(key in records for key in ("SPF", "DMARC", "TXT")) or any(
                key in errors for key in ("TXT", "DMARC")
            ):
                snapshot["email_authentication_assessment"] = analyze_email_auth(records, errors)
    return {
        "id": run.id,
        "check_type": run.check_type,
        "domain": run.domain,
        "status": run.status,
        "source": run.trigger_source,
        "actor": actor.email if actor else (
            "Scheduled check" if run.trigger_source == "schedule" else None
        ),
        "started_at": iso_utc(run.started_at),
        "queued_at": iso_utc(run.queued_at),
        "collection_started_at": iso_utc(run.collection_started_at),
        "completed_at": iso_utc(run.completed_at),
        "duration_ms": run.duration_ms,
        "change_count": run.change_count,
        "snapshot": snapshot,
        "error_summary": run.error_summary,
    }


def serialize_external_schedule(
    schedule: ExternalCheckSchedule | None,
    check_type: str,
) -> dict[str, Any]:
    return {
        "check_type": check_type,
        "enabled": schedule.enabled if schedule else False,
        "interval_hours": schedule.interval_hours if schedule else 24,
        "next_run_at": iso_utc(schedule.next_run_at) if schedule else None,
        "last_started_at": iso_utc(schedule.last_started_at) if schedule else None,
        "last_completed_at": iso_utc(schedule.last_completed_at) if schedule else None,
        "last_run_status": schedule.last_run_status if schedule else None,
        "updated_at": iso_utc(schedule.updated_at) if schedule else None,
    }


def meraki_review_summary(snapshot: dict[str, Any] | None) -> dict[str, int]:
    snapshot = snapshot if isinstance(snapshot, dict) else {}
    totals = snapshot.get("summary") if isinstance(snapshot.get("summary"), dict) else {}
    summary = {key: value for key, value in totals.items()
               if key in {"network_count", "device_count", "security_controls_collected", "security_controls_unavailable"}
               and type(value) is int and value >= 0}
    findings = snapshot.get("findings")
    if isinstance(findings, list):
        summary["review_observation_count"] = sum(
            isinstance(item, dict) and item.get("status") == "Review" for item in findings
        )
    return summary


def serialize_report_job(job: ReportJob, actor: User | None = None) -> dict[str, Any]:
    comparison = (job.report_snapshot or {}).get("meraki_comparison")
    return {
        "id": job.id,
        "report_type": job.report_type,
        "domain": job.domain,
        "status": job.status,
        "progress": job.progress,
        "stage": job.stage,
        "file_name": job.file_name,
        "size_bytes": job.size_bytes,
        "error_summary": job.error_summary,
        "actor": actor.email if actor else "former user",
        "created_at": iso_utc(job.created_at),
        "updated_at": iso_utc(job.updated_at),
        "completed_at": iso_utc(job.completed_at),
        "download_url": f"/api/reports/{job.id}/download" if job.status == "completed" else None,
        "meraki_summary": meraki_review_summary((job.report_snapshot or {}).get("meraki")) if job.report_type == "meraki_security" and job.status == "completed" else None,
        "meraki_comparison": {key: comparison.get(key) for key in (
            "baseline", "previous_report_id", "changed_control_count", "coverage_change_count",
            "inventory_change_count", "inventory_coverage_change_count",
        )} if comparison and job.status == "completed" else None,
        "meraki_changes_url": f"/api/meraki/reports/{job.id}/changes" if comparison and job.status == "completed" else None,
        "meraki_snapshot_url": f"/api/meraki/reports/{job.id}/snapshot" if job.report_type == "meraki_security" and job.status == "completed" else None,
    }


def capture_external_report_snapshot(
    db: Session,
    organization: Organization,
    user: User,
) -> dict[str, Any]:
    checks: dict[str, Any] = {}
    for check_type in ("dns", "web", "web-active", "web-nikto"):
        latest = db.scalar(
            select(ExternalCheckRun)
            .where(
                ExternalCheckRun.organization_id == organization.id,
                ExternalCheckRun.check_type == check_type,
            )
            .order_by(ExternalCheckRun.id.desc())
            .limit(1)
        )
        latest_attempt = {
            "id": latest.id,
            "status": latest.status,
            "started_at": iso_utc(latest.started_at),
            "queued_at": iso_utc(latest.queued_at),
            "collection_started_at": iso_utc(latest.collection_started_at),
            "completed_at": iso_utc(latest.completed_at),
            "error_summary": latest.error_summary,
        } if latest is not None else None
        row = db.execute(
            select(ExternalCheckRun, User)
            .outerjoin(User, User.id == ExternalCheckRun.triggered_by_user_id)
            .where(
                ExternalCheckRun.organization_id == organization.id,
                ExternalCheckRun.check_type == check_type,
                ExternalCheckRun.status.in_(("completed", "completed_with_warnings")),
            )
            .order_by(ExternalCheckRun.id.desc())
            .limit(1)
        ).first()
        if row is None:
            checks[check_type] = {"run": None, "changes": [], "latest_attempt": latest_attempt}
            continue
        run, actor = row
        change_rows = db.scalars(
            select(ExternalCheckChange)
            .where(ExternalCheckChange.run_id == run.id)
            .order_by(ExternalCheckChange.id.asc())
            .limit(101)
        ).all()
        checks[check_type] = {
            "run": serialize_external_run(run, actor),
            "latest_attempt": latest_attempt,
            "changes": [
                {
                    "field_path": change.field_path,
                    "previous_value": change.previous_value,
                    "current_value": change.current_value,
                    "detected_at": iso_utc(change.detected_at),
                }
                for change in change_rows
            ],
        }
    web_run = (checks.get("web") or {}).get("run")
    if web_run:
        scope = (VendorReview.organization_id == organization.id, VendorReview.run_id == web_run["id"])
        ranked = select(VendorReview.id, func.row_number().over(partition_by=VendorReview.resource_index, order_by=VendorReview.id.desc()).label("rank")).where(*scope).subquery()
        latest_ids = select(ranked.c.id).where(ranked.c.rank == 1)
        latest_reviews = db.execute(select(VendorReview, User).outerjoin(User, User.id == VendorReview.actor_user_id).where(VendorReview.id.in_(latest_ids)).order_by(VendorReview.resource_index)).all()
        history = db.execute(select(VendorReview, User).outerjoin(User, User.id == VendorReview.actor_user_id).where(*scope).order_by(VendorReview.id.desc()).limit(101)).all()
        def frozen_review(row, reviewer):
            return {**_serialize_vendor_review(row), "reviewer": (reviewer.display_name or reviewer.email) if reviewer else "Former member"}
        checks["web"]["vendor_reviews"] = {
            "run_id": web_run["id"], "security_assessment": False,
            "latest": [frozen_review(*row) for row in latest_reviews],
            "history": [frozen_review(*row) for row in history[:100]],
            "history_truncated": len(history) > 100,
        }
    return {
        "domain": organization.domain,
        "organization_name": organization.name,
        "generated_at": iso_utc(utcnow()),
        "requested_by": user.email,
        "checks": checks,
    }


def update_report_progress(report_job_id: int, progress: int, stage: str) -> None:
    with SessionLocal() as db:
        job = db.get(ReportJob, report_job_id)
        if job is None or job.status not in {"queued", "running"}:
            return
        job.status = "running"
        job.progress = max(job.progress, min(95, max(0, progress)))
        job.stage = stage[:120]
        job.updated_at = utcnow()
        db.commit()


def record_meraki_report_notification(
    db: Session,
    *,
    organization_id: int,
    report_id: int,
    domain: str,
    comparison: dict[str, Any],
    detected_at: datetime,
) -> bool:
    """Persist a truthful, deduplicated Meraki change or coverage notice."""
    counts = {
        key: value if type(value) is int and value > 0 else 0
        for key, value in comparison.items()
        if key in {
            "changed_control_count",
            "coverage_change_count",
            "inventory_change_count",
            "inventory_coverage_change_count",
        }
    }
    changed_controls = counts.get("changed_control_count", 0)
    changed_inventory = counts.get("inventory_change_count", 0)
    coverage_controls = counts.get("coverage_change_count", 0)
    coverage_inventory = counts.get("inventory_coverage_change_count", 0)
    has_changes = changed_controls > 0 or changed_inventory > 0
    has_coverage_changes = coverage_controls > 0 or coverage_inventory > 0
    if not has_changes and not has_coverage_changes:
        return False

    existing = db.scalar(select(WorkspaceNotification.id).where(
        WorkspaceNotification.organization_id == organization_id,
        WorkspaceNotification.source_type == "meraki_report",
        WorkspaceNotification.source_id == report_id,
    ))
    if existing is not None:
        return False

    def count_label(count: int, singular: str) -> str:
        return f"{count} {singular if count == 1 else singular + 's'}"

    parts: list[str] = []
    if has_changes:
        changes = []
        if changed_controls:
            changes.append(count_label(changed_controls, "security-control change"))
        if changed_inventory:
            changes.append(count_label(changed_inventory, "inventory change"))
        parts.append("Observed " + " and ".join(changes) + ".")
    else:
        parts.append("No confirmed control or inventory changes were detected.")
    if has_coverage_changes:
        coverage = []
        if coverage_controls:
            coverage.append(count_label(coverage_controls, "control-coverage change"))
        if coverage_inventory:
            coverage.append(count_label(coverage_inventory, "inventory-coverage change"))
        parts.append("Collection coverage changed in " + " and ".join(coverage) + ".")
    parts.append(f"Review Meraki report #{report_id} for the saved comparison.")
    reason = "changes_and_coverage" if has_changes and has_coverage_changes else "changes" if has_changes else "coverage"
    try:
        with db.begin_nested():
            db.add(WorkspaceNotification(
                organization_id=organization_id,
                source_type="meraki_report",
                source_id=report_id,
                title=f"Meraki report comparison · {domain}",
                summary=" ".join(parts)[:1000],
                reason=reason,
                detected_at=detected_at,
            ))
            db.flush()
        return True
    except IntegrityError:
        return False


def record_probation_override_notification(
    db: Session,
    *,
    organization_id: int,
    override_id: int,
    action: str,
    actor_name: str,
    detected_at: datetime,
    expires_at: datetime,
) -> bool:
    """Persist a workspace-wide notice when temporary access controls change."""
    if action not in {"granted", "revoked"}:
        return False
    source_type = f"probation_override_{action}"
    if db.scalar(select(WorkspaceNotification.id).where(
        WorkspaceNotification.organization_id == organization_id,
        WorkspaceNotification.source_type == source_type,
        WorkspaceNotification.source_id == override_id,
    )) is not None:
        return False

    actor = actor_name.strip()[:120] or "A workspace administrator"
    if action == "granted":
        title = "Temporary probation override granted"
        summary = (
            f"{actor} granted a temporary 14-day probation override through {expires_at.isoformat()}Z."
        )
    else:
        title = "Temporary probation override revoked"
        summary = (
            f"{actor} revoked the probation override before its scheduled expiry."
        )
    try:
        with db.begin_nested():
            db.add(WorkspaceNotification(
                organization_id=organization_id,
                source_type=source_type,
                source_id=override_id,
                title=title,
                summary=summary[:1000],
                reason="access_override",
                detected_at=detected_at,
            ))
            db.flush()
        return True
    except IntegrityError:
        return False


def record_cis_report_notification(
    db: Session,
    *,
    organization_id: int,
    report_id: int,
    device_name: str,
    profile_slug: str,
    profile_version: str,
    changed_check_count: int,
    detected_at: datetime,
) -> bool:
    """Save one workspace inbox notice for changed CIS check statuses."""
    if type(changed_check_count) is not int or changed_check_count <= 0:
        return False
    if db.scalar(select(WorkspaceNotification.id).where(
        WorkspaceNotification.organization_id == organization_id,
        WorkspaceNotification.source_type == "cis_report",
        WorkspaceNotification.source_id == report_id,
    )) is not None:
        return False

    endpoint = device_name.strip()[:120] or "endpoint"
    profile_slug = profile_slug.strip() if isinstance(profile_slug, str) else ""
    profile_version = profile_version.strip() if isinstance(profile_version, str) else ""
    profile = " ".join(part for part in (profile_slug, profile_version) if part)
    profile_label = profile or "the selected profile"
    result_label = "result" if changed_check_count == 1 else "results"
    notification = WorkspaceNotification(
        organization_id=organization_id,
        source_type="cis_report",
        source_id=report_id,
        title=f"CIS endpoint results changed · {endpoint}"[:200],
        summary=(
            f"{changed_check_count} CIS check {result_label} changed status for {profile_label} "
            f"on {endpoint}. Review the endpoint history. Status changes are not a compliance conclusion."
        )[:1000],
        reason="changes",
        detected_at=detected_at,
    )
    try:
        with db.begin_nested():
            db.add(notification)
            db.flush()
        return True
    except IntegrityError:
        return False


def record_scanner_comparison_notification(
    db: Session,
    *,
    agent: Agent,
    comparison_id: int,
    comparison: dict[str, Any],
    detected_at: datetime,
    meaningful_change_count: int,
) -> bool:
    """Save a notice for explicitly observed changes between completed scanner runs."""
    if type(meaningful_change_count) is not int or meaningful_change_count <= 0:
        return False
    if db.scalar(select(WorkspaceNotification.id).where(
        WorkspaceNotification.organization_id == agent.organization_id,
        WorkspaceNotification.source_type == "scanner_comparison",
        WorkspaceNotification.source_id == comparison_id,
    )) is not None:
        return False

    counts = comparison.get("counts") if isinstance(comparison.get("counts"), dict) else {}
    observed = {
        key: value if type(value) is int and value > 0 else 0
        for key, value in counts.items()
        if key in {"hosts_added", "hosts_removed", "newly_observed_ports", "reported_port_changes", "confirmed_removed_ports"}
    }
    details = []
    if observed.get("hosts_added"):
        count = observed["hosts_added"]
        details.append(f"{count} {'host' if count == 1 else 'hosts'} newly observed")
    if observed.get("hosts_removed"):
        count = observed["hosts_removed"]
        details.append(f"{count} {'host' if count == 1 else 'hosts'} no longer observed within comparable target scope")
    if observed.get("newly_observed_ports"):
        count = observed["newly_observed_ports"]
        details.append(f"{count} {'port' if count == 1 else 'ports'} newly observed")
    if observed.get("reported_port_changes"):
        count = observed["reported_port_changes"]
        label = "change" if count == 1 else "changes"
        details.append(f"{count} reported port state/service {label}")
    if observed.get("confirmed_removed_ports"):
        count = observed["confirmed_removed_ports"]
        details.append(f"{count} {'port' if count == 1 else 'ports'} no longer reported after complete port coverage")
    if not details:
        label = "change" if meaningful_change_count == 1 else "changes"
        details.append(f"{meaningful_change_count} observed scanner {label}")

    scanner_name = agent.name.strip()[:120] or f"scanner {agent.id}"
    summary = (
        f"{scanner_name}: " + "; ".join(details)
        + ". Review the saved comparison in NmapUI scanners."
    )
    coverage = comparison.get("coverage") if isinstance(comparison.get("coverage"), dict) else {}
    if coverage.get("comparable") is not True:
        summary += " Target scope or coverage is not fully comparable; new observations may reflect broader coverage, and absence does not confirm removal."

    notification = WorkspaceNotification(
        organization_id=agent.organization_id,
        source_type="scanner_comparison",
        source_id=comparison_id,
        title=f"Internal scan changes · {scanner_name}"[:200],
        summary=summary[:1000],
        reason="changes",
        detected_at=detected_at,
    )
    try:
        with db.begin_nested():
            db.add(notification)
            db.flush()
        return True
    except IntegrityError:
        return False


def record_report_failure_notification(db: Session, job: ReportJob) -> bool:
    if db.scalar(select(WorkspaceNotification.id).where(
        WorkspaceNotification.organization_id == job.organization_id,
        WorkspaceNotification.source_type == "report_job_failure",
        WorkspaceNotification.source_id == job.id,
    )) is not None:
        return False
    try:
        with db.begin_nested():
            db.add(WorkspaceNotification(
                organization_id=job.organization_id, source_type="report_job_failure", source_id=job.id,
                title=f"Report generation failed · {job.domain}"[:200],
                summary=f"Report #{job.id} did not finish. Open Reports to review its saved error and request a new PDF. Previously completed reports remain available.",
                reason="report_failed", detected_at=job.completed_at or utcnow(),
            ))
            db.flush()
        return True
    except IntegrityError:
        return False


def recover_interrupted_report_jobs() -> int:
    with SessionLocal() as db:
        jobs = db.scalars(select(ReportJob).where(ReportJob.status.in_(("queued", "running")))).all()
        for job in jobs:
            job.status = "failed"
            job.stage = "Interrupted by server restart"
            job.error_summary = "The report job did not finish before the server restarted."
            job.completed_at = utcnow()
            job.updated_at = job.completed_at
            audit(db, job.organization_id, job.created_by_user_id, "report.failed",
                {"report_id": job.id, "report_type": job.report_type, "reason": "server_restart"})
            record_report_failure_notification(db, job)
        db.commit()
        return len(jobs)


def generate_report_job(report_job_id: int) -> None:
    """Render one queued report into persistent storage and record its progress."""
    with SessionLocal() as db:
        job = db.get(ReportJob, report_job_id)
        if job is None:
            return
        claimed = db.execute(update(ReportJob).where(ReportJob.id == report_job_id, ReportJob.status == "queued")
            .values(status="running").execution_options(synchronize_session=False))
        if claimed.rowcount != 1:
            db.rollback()
            return
        job.status = "running"
        job.progress = 5 if job.report_type == "meraki_security" else 12
        if job.report_type == "meraki_security":
            job.stage = "Preparing Meraki report"
        elif job.report_type == "cis_endpoint":
            job.stage = "Preparing CIS endpoint report"
        elif job.report_type == "scanner_results":
            job.stage = "Preparing saved NmapUI scanner evidence"
        else:
            job.stage = "Preparing saved DNS and website evidence"
        job.updated_at = utcnow()
        organization_id = job.organization_id
        actor_id = job.created_by_user_id
        file_name = job.file_name
        snapshot = job.report_snapshot
        report_type = job.report_type
        db.commit()

    try:
        if report_type == "external_posture":
            pdf_bytes = build_external_posture_pdf(snapshot)
        elif report_type == "cis_endpoint":
            update_report_progress(report_job_id, 40, "Rendering CIS endpoint results")
            pdf_bytes = build_cis_endpoint_pdf(snapshot)
        elif report_type == "scanner_results":
            update_report_progress(report_job_id, 40, "Rendering saved NmapUI scanner results")
            pdf_bytes = build_scanner_results_pdf(snapshot)
        elif report_type == "meraki_security":
            update_report_progress(report_job_id, 8, "Loading encrypted Meraki credential")
            with SessionLocal() as db:
                credential = db.scalar(
                    select(MerakiCredential).where(
                        MerakiCredential.organization_id == organization_id
                    )
                )
                encrypted_key = credential.encrypted_api_key if credential else None
            if not encrypted_key:
                raise CredentialEncryptionError("No Meraki credential is configured.")
            api_key = decrypt_secret(encrypted_key)
            requested_org_id = str(snapshot.get("meraki_organization_id") or "")

            def report_progress(progress: int, stage: str) -> None:
                update_report_progress(report_job_id, progress, stage)

            with MerakiClient(api_key) as client:
                meraki_snapshot = client.collect_security_report(
                    requested_org_id,
                    progress=report_progress,
                )
            with SessionLocal() as db:
                previous = db.scalar(select(ReportJob).where(
                    ReportJob.organization_id == organization_id,
                    ReportJob.report_type == "meraki_security", ReportJob.status == "completed",
                    ReportJob.id < report_job_id,
                    ReportJob.report_snapshot["meraki_organization_id"].as_string() == requested_org_id,
                ).order_by(ReportJob.id.desc()))
                previous_meraki = (previous.report_snapshot or {}).get("meraki") if previous else None
                comparison = compare_meraki_snapshots(previous_meraki, meraki_snapshot) if previous_meraki else {
                    "organization_id": requested_org_id, "changes": [], "coverage_changes": [], "changed_control_count": 0,
                }
                comparison.update(compare_meraki_inventory(previous_meraki, meraki_snapshot) if previous_meraki else {
                    "inventory_changes": [], "inventory_change_count": 0,
                    "inventory_coverage_changes": [], "inventory_coverage_change_count": 0,
                })
                comparison.update({"baseline": not bool(previous_meraki), "previous_report_id": previous.id if previous_meraki else None,
                                   "coverage_change_count": len(comparison["coverage_changes"])})
            snapshot = {**snapshot, "meraki": meraki_snapshot, "meraki_comparison": comparison}
            with SessionLocal() as db:
                job = db.get(ReportJob, report_job_id)
                if job is not None:
                    job.report_snapshot = snapshot
                    job.progress = max(job.progress, 90)
                    job.stage = "Rendering Meraki security PDF"
                    job.updated_at = utcnow()
                    db.commit()
            pdf_bytes = build_meraki_security_pdf(snapshot)
        else:
            raise ValueError("Unknown report type")
        with SessionLocal() as db:
            job = db.get(ReportJob, report_job_id)
            if job is None:
                return
            job.progress = max(job.progress, 92 if report_type == "meraki_security" else 82)
            job.stage = "Saving the PDF"
            job.updated_at = utcnow()
            db.commit()

        report_directory = REPORTS_DIR / str(organization_id)
        report_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            report_directory.chmod(0o700)
        except OSError:
            pass
        final_path = report_directory / file_name
        temporary_path = final_path.with_suffix(".pdf.tmp")
        temporary_path.write_bytes(pdf_bytes)
        try:
            temporary_path.chmod(0o600)
        except OSError:
            pass
        temporary_path.replace(final_path)

        with SessionLocal() as db:
            job = db.get(ReportJob, report_job_id)
            if job is None:
                return
            job.status = "completed"
            job.progress = 100
            job.stage = "PDF ready"
            job.artifact_path = str(final_path.resolve())
            job.size_bytes = len(pdf_bytes)
            job.error_summary = None
            job.completed_at = utcnow()
            job.updated_at = job.completed_at
            audit(
                db,
                organization_id,
                actor_id,
                "report.generated",
                {
                    "report_id": job.id,
                    "report_type": job.report_type,
                    "file_name": file_name,
                    "size_bytes": len(pdf_bytes),
                },
            )
            if report_type == "meraki_security":
                comparison = snapshot["meraki_comparison"]
                if any(comparison[key] for key in ("changed_control_count", "coverage_change_count", "inventory_change_count", "inventory_coverage_change_count")):
                    audit(db, organization_id, actor_id, "meraki.report.changes_detected", {
                        "report_id": job.id, "meraki_organization_id": comparison["organization_id"],
                        "previous_report_id": comparison["previous_report_id"],
                        "changed_control_count": comparison["changed_control_count"],
                        "coverage_change_count": comparison["coverage_change_count"],
                        "inventory_change_count": comparison["inventory_change_count"],
                        "inventory_coverage_change_count": comparison["inventory_coverage_change_count"],
                    })
                record_meraki_report_notification(
                    db,
                    organization_id=organization_id,
                    report_id=job.id,
                    domain=job.domain,
                    comparison=comparison,
                    detected_at=job.completed_at,
                )
            db.commit()
        if report_type == "meraki_security":
            try:
                from_thread.run(live_hub.publish, organization_id, {
                    "type": "meraki_report_finished", "report_id": report_job_id,
                    "meraki_organization_id": comparison["organization_id"],
                    "changed_control_count": comparison["changed_control_count"],
                    "coverage_change_count": comparison["coverage_change_count"],
                    "inventory_change_count": comparison["inventory_change_count"],
                    "inventory_coverage_change_count": comparison["inventory_coverage_change_count"],
                    "baseline": comparison["baseline"],
                })
            except RuntimeError:
                logger.debug("Report generated outside a live server worker; live notification skipped")
    except Exception as exc:
        with SessionLocal() as db:
            job = db.get(ReportJob, report_job_id)
            if job is not None:
                job.status = "failed"
                job.stage = "PDF generation failed"
                job.error_summary = f"PDF generation failed ({type(exc).__name__})."
                job.completed_at = utcnow()
                job.updated_at = job.completed_at
                audit(
                    db,
                    organization_id,
                    actor_id,
                    "report.failed",
                    {"report_id": job.id, "report_type": job.report_type, "error": job.error_summary},
                )
                record_report_failure_notification(db, job)
                db.commit()
        try:
            from_thread.run(live_hub.publish, organization_id, {
                "type": "workspace_notification_created", "report_id": report_job_id,
            })
        except RuntimeError:
            logger.debug("Report failure saved outside a live server worker; broadcast skipped")


def check_type_label(check_type: str) -> str:
    return {"dns": "DNS and email", "web": "Website", "web-active": "Website exposure", "web-nikto": "Nikto website audit"}.get(check_type, "Security")


def external_check_field_label(field_path: str) -> str:
    """Turn stored comparison paths into labels people can scan in the dashboard."""
    labels = {
        "page_content.sampled_bytes": "Page content size",
        "page_content.sha256": "Page content fingerprint",
        "http_status": "Website HTTP status",
        "title": "Website page title",
        "external_resources": "Linked third-party resources",
        "external_host_count": "Linked third-party hosts",
        "tls.valid": "TLS certificate validity",
        "tls.days_remaining": "TLS certificate lifetime",
    }
    if field_path in labels:
        return labels[field_path]
    if field_path.startswith("records."):
        field = field_path.removeprefix("records.")
        is_www = field.startswith("WWW_")
        field = field.removeprefix("WWW_").replace("_", " ")
        return f"DNS record {'www ' if is_www else ''}{field}"
    if field_path.startswith("resolver_errors."):
        query = field_path.removeprefix("resolver_errors.")
        return f"DNS lookup status {query}"
    if field_path.startswith("security_headers."):
        header = field_path.removeprefix("security_headers.").replace("-", " ")
        return f"Security header {header}"
    if field_path.startswith("tls."):
        attribute = field_path.removeprefix("tls.").replace("_", " ").replace(".", " ")
        return f"TLS {attribute}"
    return field_path.replace("_", " ").replace(".", " · ").strip().capitalize()


def external_check_change_group(check_type: str, field_path: str) -> str:
    """Use compact category names in inbox notices; the history retains each detail."""
    if check_type in {"web-active", "web-nikto"}:
        return "website findings"
    if check_type == "web":
        if field_path.startswith("page_content."):
            return "page content"
        if field_path.startswith("security_headers."):
            return "security headers"
        if field_path.startswith("tls."):
            return "TLS certificate"
        if field_path.startswith(("external_resources", "external_host_count")):
            return "linked third-party resources"
        return "website configuration"
    if field_path.startswith("records."):
        return "DNS records"
    if field_path.startswith("resolver_errors."):
        return "DNS lookup status"
    if field_path.startswith("email_authentication_assessment."):
        return "email authentication policy"
    return "DNS and email configuration"


def external_check_warning_reasons(check_type: str, snapshot: dict[str, Any]) -> list[str]:
    """Return concise, stable reasons when a completed snapshot has limited coverage."""
    reasons: list[str] = []
    if check_type == "dns":
        errors = snapshot.get("resolver_errors")
        if isinstance(errors, dict) and errors:
            reasons.append(f"{len(errors)} DNS lookup(s) could not be confirmed")
    elif check_type == "web":
        status = snapshot.get("http_status")
        if type(status) is int and not 200 <= status < 300:
            reasons.append(f"Website returned HTTP {status}")
        page_content = snapshot.get("page_content")
        if isinstance(page_content, dict) and (
            page_content.get("partial") is True or page_content.get("comparison_eligible") is False
        ):
            reasons.append("Page content was partial or not eligible for comparison")
        if snapshot.get("page_html_truncated") is True:
            reasons.append("Page HTML exceeded the collection limit")
        for key, label in (("header_observations", "security header"), ("cookie_observations", "cookie")):
            observation = snapshot.get(key)
            if isinstance(observation, dict) and observation.get("analysis_partial") is True:
                reasons.append(f"{label.title()} analysis was partial")
    if check_type == "web-active" and snapshot.get("coverage_complete") is not True:
        reasons.append("Website exposure coverage was incomplete; missing findings remain unknown")
    if check_type == "web-nikto" and snapshot.get("coverage_complete") is not True:
        reasons.append("Nikto does not confirm that every test was exhausted; missing findings remain unknown")
    return reasons


def external_check_warning_signature(check_type: str, snapshot: dict[str, Any]) -> str:
    """Stable coverage evidence; transient resolver error text is not a new warning."""
    errors = snapshot.get("resolver_errors")
    return json.dumps({
        "reasons": external_check_warning_reasons(check_type, snapshot),
        "failed_dns_queries": sorted(errors) if check_type == "dns" and isinstance(errors, dict) else [],
        "preset_version": snapshot.get("preset_version") if check_type in {"web-active", "web-nikto"} else None,
    }, sort_keys=True)


def _execute_external_check(
    organization_id: int,
    user_id: int | None,
    check_type: str,
    trigger_source: str,
    enqueue_only: bool = False,
    reserved_run_id: int | None = None,
) -> dict[str, Any]:
    """Persist a check run and its stable result before returning to the request."""
    if reserved_run_id is not None:
        with SessionLocal() as db:
            run = db.get(ExternalCheckRun, reserved_run_id)
            if run is None or run.status != "running" or run.check_type != check_type or run.organization_id != organization_id or run.triggered_by_user_id != user_id:
                raise HTTPException(status_code=409, detail="Queued audit claim is no longer valid")
            run_id, domain = run.id, run.domain
        started_clock = time.perf_counter()
    else:
        with SessionLocal() as db:
            if enqueue_only:
                db.execute(text("BEGIN IMMEDIATE"))
                pending = db.scalar(select(func.count(ExternalCheckRun.id)).where(ExternalCheckRun.check_type == "web-nikto", ExternalCheckRun.status.in_(("queued", "running"))))
                if pending >= 25:
                    raise HTTPException(status_code=429, detail="Website audit queue is full. Try again later.")
            membership = None
            if user_id is not None:
                membership = db.scalar(
                    select(Membership).where(
                        Membership.organization_id == organization_id,
                        Membership.user_id == user_id,
                        Membership.role == "admin",
                        Membership.status == "approved",
                    )
                )
            organization = db.get(Organization, organization_id)
            if organization is None or (user_id is not None and membership is None):
                raise HTTPException(status_code=403, detail="Workspace admin role required")
            if user_id is None and trigger_source != "schedule":
                raise HTTPException(status_code=403, detail="Scheduled checks require an internal actor")
            if check_type in {"web-active", "web-nikto"}:
                if user_id is None or not workspace_controls_available(db, organization):
                    raise HTTPException(status_code=403, detail="Active website checks require domain verification or an active override")
                if db.scalar(select(ExternalCheckRun.id).where(
                    ExternalCheckRun.organization_id == organization_id,
                    ExternalCheckRun.check_type == check_type,
                    ExternalCheckRun.status.in_(("queued", "running")),
                ).limit(1)) is not None:
                    raise HTTPException(status_code=409, detail="An active website check is already running for this workspace.")
            if trigger_source == "schedule" and organization.verification_status != "verified":
                raise HTTPException(status_code=403, detail="Scheduled checks require a verified domain")
            if trigger_source == "schedule":
                schedule = db.scalar(
                    select(ExternalCheckSchedule).where(
                        ExternalCheckSchedule.organization_id == organization_id,
                        ExternalCheckSchedule.check_type == check_type,
                        ExternalCheckSchedule.enabled.is_(True),
                    )
                )
                if schedule is None:
                    raise HTTPException(status_code=409, detail="The recurring check schedule was disabled.")
            run = ExternalCheckRun(
                organization_id=organization.id,
                check_type=check_type,
                domain=organization.domain,
                status="queued" if enqueue_only else "running",
                trigger_source=trigger_source,
                triggered_by_user_id=user_id,
                started_at=utcnow(),
                snapshot=None,
                change_count=0,
            )
            if enqueue_only:
                run.queued_at = run.started_at
            else:
                run.collection_started_at = run.started_at
            db.add(run)
            db.flush()
            if check_type in {"web-active", "web-nikto"}:
                audit(db, organization_id, user_id, "external_check.queued", {
                    "run_id": run.id, "check_type": check_type, "domain": organization.domain,
                    "source": trigger_source,
                })
            db.commit()
            db.refresh(run)
            run_id = run.id
            domain = organization.domain
            started_clock = time.perf_counter()
            if enqueue_only:
                return serialize_external_run(run, db.get(User, user_id))

    try:
        if check_type in {"web-active", "web-nikto"}:
            with SessionLocal() as db:
                current_organization = db.get(Organization, organization_id)
                approved_admin = db.scalar(select(Membership.id).where(
                    Membership.organization_id == organization_id,
                    Membership.user_id == user_id, Membership.role == "admin",
                    Membership.status == "approved",
                ))
                if current_organization is None or current_organization.domain != domain or approved_admin is None or not workspace_controls_available(db, current_organization):
                    raise PermissionError("Active website authorization expired before collection")
            snapshot = run_nikto_check(domain) if check_type == "web-nikto" else run_active_website_check(domain)
        else:
            snapshot = run_dns_check(domain, nameservers=AUDIT_DNS_NAMESERVERS) if check_type == "dns" else run_website_check(domain)
        failure = ("Active website collection could not validate a public target." if snapshot.get("error_code") else None) if check_type in {"web-active", "web-nikto"} else None
        if check_type == "web-nikto" and snapshot.get("error_code"):
            failure = "Nikto runtime is unavailable on this server." if snapshot["error_code"] == "nikto_runtime_unavailable" else "Nikto collection failed; check the recorded coverage state."
    except ExternalCheckFailure as exc:
        snapshot = exc.snapshot
        failure = str(exc)
    except Exception as exc:
        snapshot = {}
        failure = f"Check failed ({type(exc).__name__})."

    completed_at = utcnow()
    duration_ms = max(0, int((time.perf_counter() - started_clock) * 1000))
    with SessionLocal() as db:
        run = db.get(ExternalCheckRun, run_id)
        if run is None:
            raise RuntimeError("Persisted external check run disappeared")
        run.completed_at = completed_at
        run.duration_ms = duration_ms
        run.snapshot = snapshot
        run.error_summary = failure[:500] if failure else None
        run.status = "failed" if failure else (
            "completed_with_warnings"
            if (check_type == "dns" and snapshot.get("resolver_errors")) or (check_type in {"web-active", "web-nikto"} and snapshot.get("coverage_complete") is not True)
            else "completed"
        )
        changes: list[tuple[str, Any, Any]] = []
        if run.status in {"completed", "completed_with_warnings"}:
            prior = db.scalar(
                select(ExternalCheckRun)
                .where(
                    ExternalCheckRun.organization_id == organization_id,
                    ExternalCheckRun.check_type == check_type,
                    ExternalCheckRun.id < run.id,
                    ExternalCheckRun.status.in_(("completed", "completed_with_warnings")),
                )
                .order_by(ExternalCheckRun.id.desc())
            )
            if prior and prior.snapshot:
                if check_type in {"web-active", "web-nikto"}:
                    previous_snapshot = prior.snapshot
                    if (previous_snapshot.get("preset_version") == snapshot.get("preset_version")
                            and snapshot.get("preset_version")
                            and previous_snapshot.get("coverage_complete") is True
                            and snapshot.get("coverage_complete") is True):
                        before = {(finding["signature_id"], finding["path"]): finding for finding in previous_snapshot.get("findings", [])}
                        after = {(finding["signature_id"], finding["path"]): finding for finding in snapshot.get("findings", [])}
                        changes = [
                            (f"findings.{key[0]}:{key[1]}", before.get(key), after.get(key))
                            for key in sorted(before.keys() | after.keys())
                            if key not in before or key not in after
                            or before[key].get("http_status") != after[key].get("http_status")
                        ]
                    elif check_type == "web-nikto" and previous_snapshot.get("preset_version") == snapshot.get("preset_version") and snapshot.get("preset_version"):
                        before = {(finding["signature_id"], finding["path"]): finding for finding in previous_snapshot.get("findings", [])}
                        after = {(finding["signature_id"], finding["path"]): finding for finding in snapshot.get("findings", [])}
                        changes = [(f"findings.{key[0]}:{key[1]}", None, after[key]) for key in sorted(after.keys() - before.keys())]
                        snapshot["comparison_scope"] = "new_observations_only"
                else:
                    changes = compare_snapshots(prior.snapshot, snapshot)
            for field_path, previous_value, current_value in changes:
                db.add(
                    ExternalCheckChange(
                        organization_id=organization_id,
                        run_id=run.id,
                        check_type=check_type,
                        field_path=field_path,
                        previous_value=previous_value,
                        current_value=current_value,
                        detected_at=completed_at,
                    )
                )
        run.change_count = len(changes)
        warning_reasons = external_check_warning_reasons(check_type, snapshot) if run.status in {
            "completed", "completed_with_warnings"
        } else []
        latest_terminal = db.scalar(select(ExternalCheckRun).where(
            ExternalCheckRun.organization_id == organization_id,
            ExternalCheckRun.check_type == check_type,
            ExternalCheckRun.id < run.id,
            ExternalCheckRun.status.in_(("completed", "completed_with_warnings", "failed")),
        ).order_by(ExternalCheckRun.id.desc()).limit(1))
        repeated_warning = bool(
            warning_reasons and latest_terminal
            and latest_terminal.status in {"completed", "completed_with_warnings"}
            and external_check_warning_signature(check_type, latest_terminal.snapshot or {})
                == external_check_warning_signature(check_type, snapshot)
        )
        repeated_failure = bool(failure and latest_terminal and latest_terminal.status == "failed"
            and latest_terminal.error_summary == run.error_summary)
        action = "external_check.failed" if failure else "external_check.completed"
        details: dict[str, Any] = {
            "run_id": run.id,
            "check_type": check_type,
            "domain": domain,
            "status": run.status,
            "duration_ms": duration_ms,
            "change_count": len(changes),
            "source": trigger_source,
            "repeated_warning_notice_suppressed": repeated_warning and not bool(changes),
            "repeated_failure_notice_suppressed": repeated_failure,
        }
        if failure:
            details["error"] = run.error_summary
        audit(db, organization_id, user_id, action, details)
        if changes:
            audit(
                db,
                organization_id,
                user_id,
                "external_check.changes_detected",
                {
                    "run_id": run.id,
                    "check_type": check_type,
                    "domain": domain,
                    "change_count": len(changes),
                    "fields": [change[0] for change in changes],
                    "detected_at": iso_utc(completed_at),
                    "source": trigger_source,
                },
            )
        if (failure and not repeated_failure) or (run.status in {"completed", "completed_with_warnings"} and (changes or (warning_reasons and not repeated_warning))):
            # The source run and comparison are already saved in this transaction.
            # A unique source key makes request/scheduler retries idempotent.
            existing_notice = db.scalar(select(WorkspaceNotification.id).where(
                WorkspaceNotification.organization_id == organization_id,
                WorkspaceNotification.source_type == "external_check_run",
                WorkspaceNotification.source_id == run.id,
            ))
            if existing_notice is None:
                reason = "check_failed" if failure else "changes_and_warnings" if changes and warning_reasons else "changes" if changes else "warnings"
                parts = ["Collection failed. This run provides no fresh assessment. Review its saved error; previous evidence remains in history"] if failure else []
                if changes:
                    groups = list(dict.fromkeys(
                        external_check_change_group(check_type, field_path)
                        for field_path, _, _ in changes
                    ))
                    fields = ", ".join(groups[:3])
                    count_label = "change" if len(changes) == 1 else "changes"
                    parts.append(f"{len(changes)} material {count_label} detected" + (f": {fields}" if fields else ""))
                    if len(changes) > 3:
                        parts.append(f"and {len(changes) - 3} more field changes")
                if warning_reasons:
                    parts.append("Check warning: " + "; ".join(warning_reasons))
                    if not changes:
                        parts.append("No confirmed changes were detected")
                try:
                    with db.begin_nested():
                        db.add(WorkspaceNotification(
                            organization_id=organization_id,
                            source_type="external_check_run",
                            source_id=run.id,
                            title=f"{check_type_label(check_type)} check{' failed' if failure else ''} · {domain}",
                            summary=". ".join(parts)[:1000],
                            reason=reason,
                            detected_at=completed_at,
                        ))
                        db.flush()
                except IntegrityError:
                    # Another worker may have committed the same run's notice.
                    # The unique key is the final guard against duplicate delivery.
                    pass
        db.commit()
        db.refresh(run)
        actor = db.get(User, user_id) if user_id is not None else None
        result = serialize_external_run(run, actor)
        result["changed_fields"] = [change[0] for change in changes]
        result["notice_suppressed"] = repeated_failure or (repeated_warning and not bool(changes))
        return result


_external_check_lock = threading.Lock()
_active_external_checks: set[tuple[int, str]] = set()


def execute_external_check(
    organization_id: int,
    user_id: int | None,
    check_type: str,
    trigger_source: str = "manual",
) -> dict[str, Any]:
    """Serialize each workspace/check pair so manual and scheduled runs cannot overlap."""
    key = (organization_id, check_type)
    with _external_check_lock:
        if key in _active_external_checks:
            raise HTTPException(status_code=409, detail="A check is already running for this workspace.")
        _active_external_checks.add(key)
    try:
        return _execute_external_check(organization_id, user_id, check_type, trigger_source)
    finally:
        with _external_check_lock:
            _active_external_checks.discard(key)


def process_next_website_audit() -> tuple[int, dict[str, Any]] | None:
    with SessionLocal() as db:
        run = db.scalar(select(ExternalCheckRun).where(
            ExternalCheckRun.check_type == "web-nikto", ExternalCheckRun.status == "queued",
        ).order_by(ExternalCheckRun.id).limit(1))
        if run is None:
            return None
        claimed = db.execute(update(ExternalCheckRun).where(
            ExternalCheckRun.id == run.id, ExternalCheckRun.status == "queued",
        ).values(status="running", collection_started_at=utcnow()))
        if claimed.rowcount != 1:
            db.rollback()
            return None
        org_id, user_id, run_id = run.organization_id, run.triggered_by_user_id, run.id
        db.commit()
    result = _execute_external_check(org_id, user_id, "web-nikto", "manual", reserved_run_id=run_id)
    return org_id, result


async def website_audit_worker() -> None:
    while True:
        try:
            completed = await run_in_threadpool(process_next_website_audit)
            if completed is not None:
                await publish_external_check_result(*completed)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Website audit worker failed")
        await asyncio.sleep(2)


def claim_due_external_check_schedules(limit: int = 25) -> list[dict[str, Any]]:
    """Atomically advance due schedules so multiple app workers cannot claim one twice."""
    now = utcnow()
    claimed: list[dict[str, Any]] = []
    with SessionLocal() as db:
        candidates = db.execute(
            select(ExternalCheckSchedule, Organization)
            .join(Organization, Organization.id == ExternalCheckSchedule.organization_id)
            .where(
                ExternalCheckSchedule.enabled.is_(True),
                ExternalCheckSchedule.next_run_at <= now,
                Organization.verification_status == "verified",
            )
            .order_by(ExternalCheckSchedule.next_run_at.asc())
            .limit(limit)
        ).all()
        for schedule, organization in candidates:
            scheduled_for = schedule.next_run_at
            next_run_at = now + timedelta(hours=schedule.interval_hours)
            result = db.execute(
                update(ExternalCheckSchedule)
                .where(
                    ExternalCheckSchedule.id == schedule.id,
                    ExternalCheckSchedule.enabled.is_(True),
                    ExternalCheckSchedule.next_run_at <= now,
                )
                .values(
                    next_run_at=next_run_at,
                    last_started_at=now,
                    last_run_status="running",
                )
            )
            if result.rowcount != 1:
                continue
            claimed.append(
                {
                    "schedule_id": schedule.id,
                    "organization_id": organization.id,
                    "check_type": schedule.check_type,
                    "scheduled_for": scheduled_for,
                }
            )
            audit(
                db,
                organization.id,
                None,
                "external_check.schedule_started",
                {
                    "check_type": schedule.check_type,
                    "scheduled_for": iso_utc(scheduled_for),
                    "next_run_at": iso_utc(next_run_at),
                },
            )
        db.commit()
    return claimed


def recover_interrupted_external_check_schedules() -> int:
    """Reconcile claims left running by a process exit before schedule completion."""
    now = utcnow()
    recovered = 0
    with SessionLocal() as db:
        schedules = db.scalars(
            select(ExternalCheckSchedule).where(
                ExternalCheckSchedule.last_run_status == "running"
            )
        ).all()
        for schedule in schedules:
            run = None
            if schedule.last_started_at is not None:
                run = db.scalar(
                    select(ExternalCheckRun)
                    .where(
                        ExternalCheckRun.organization_id == schedule.organization_id,
                        ExternalCheckRun.check_type == schedule.check_type,
                        ExternalCheckRun.trigger_source == "schedule",
                        ExternalCheckRun.started_at >= schedule.last_started_at,
                    )
                    .order_by(ExternalCheckRun.id.desc())
                    .limit(1)
                )

            if run is not None:
                status = run.status if run.status != "running" else "failed"
                completed_at = run.completed_at or now
                retry_at = schedule.next_run_at
                outcome = "run_reconciled"
            elif not schedule.enabled:
                status = "cancelled"
                completed_at = now
                retry_at = schedule.next_run_at
                outcome = "disabled_claim_cancelled"
            else:
                # The claim committed but no ExternalCheckRun was created. Make
                # the missed check due immediately so the normal scheduler retries.
                status = "failed"
                completed_at = now
                retry_at = now
                outcome = "claim_requeued"

            changed = db.execute(
                update(ExternalCheckSchedule)
                .where(
                    ExternalCheckSchedule.id == schedule.id,
                    ExternalCheckSchedule.last_run_status == "running",
                )
                .values(
                    last_run_status=status,
                    last_completed_at=completed_at,
                    next_run_at=retry_at,
                )
            )
            if changed.rowcount != 1:
                continue
            audit(
                db,
                schedule.organization_id,
                None,
                "external_check.schedule_recovered",
                {
                    "schedule_id": schedule.id,
                    "check_type": schedule.check_type,
                    "outcome": outcome,
                    "run_id": run.id if run is not None else None,
                    "retry_at": iso_utc(retry_at) if retry_at is not None else None,
                },
            )
            recovered += 1
        if recovered:
            db.commit()
    return recovered


def finish_external_check_schedule(schedule_id: int, status: str) -> None:
    now = utcnow()
    with SessionLocal() as db:
        schedule = db.get(ExternalCheckSchedule, schedule_id)
        if schedule is None:
            return
        schedule.last_completed_at = now
        schedule.last_run_status = status
        db.commit()


def fail_external_check_schedule(schedule_id: int, reason: str) -> None:
    now = utcnow()
    with SessionLocal() as db:
        schedule = db.get(ExternalCheckSchedule, schedule_id)
        if schedule is None:
            return
        schedule.last_completed_at = now
        schedule.last_run_status = "failed"
        audit(
            db,
            schedule.organization_id,
            None,
            "external_check.schedule_failed",
            {"check_type": schedule.check_type, "reason": reason[:250]},
        )
        db.commit()


def defer_external_check_schedule(schedule_id: int) -> None:
    """Retry shortly when a manual run already owns the workspace/check pair."""
    now = utcnow()
    with SessionLocal() as db:
        schedule = db.get(ExternalCheckSchedule, schedule_id)
        if schedule is None or not schedule.enabled:
            return
        retry_at = now + timedelta(minutes=1)
        schedule.next_run_at = retry_at
        schedule.last_completed_at = now
        schedule.last_run_status = "deferred"
        audit(
            db,
            schedule.organization_id,
            None,
            "external_check.schedule_deferred",
            {"check_type": schedule.check_type, "retry_at": iso_utc(retry_at)},
        )
        db.commit()


async def publish_external_check_result(
    organization_id: int,
    result: dict[str, Any],
) -> None:
    await live_hub.publish(
        organization_id,
        {
            "type": "external_check_finished",
            "run_id": result["id"],
            "check_type": result["check_type"],
            "domain": result["domain"],
            "status": result["status"],
            "change_count": result["change_count"],
            "fields": result.get("changed_fields", []),
            "actor": result.get("actor") or "Scheduled check",
            "source": result.get("source", "manual"),
            "notice_suppressed": result.get("notice_suppressed", False),
            "completed_at": result["completed_at"],
        },
    )


async def external_check_scheduler() -> None:
    while True:
        try:
            await run_in_threadpool(expire_scanner_commands)
            due_schedules = await run_in_threadpool(claim_due_external_check_schedules)
            for schedule in due_schedules:
                try:
                    result = await run_in_threadpool(
                        execute_external_check,
                        schedule["organization_id"],
                        None,
                        schedule["check_type"],
                        "schedule",
                    )
                except HTTPException as exc:
                    if exc.status_code == 409 and "already running" in str(exc.detail):
                        await run_in_threadpool(
                            defer_external_check_schedule, schedule["schedule_id"]
                        )
                    elif exc.status_code == 409 and "schedule was disabled" in str(exc.detail):
                        await run_in_threadpool(
                            finish_external_check_schedule,
                            schedule["schedule_id"],
                            "cancelled",
                        )
                    else:
                        await run_in_threadpool(
                            fail_external_check_schedule,
                            schedule["schedule_id"],
                            str(exc.detail),
                        )
                    continue
                except Exception as exc:
                    logger.exception("Scheduled external check failed before completion")
                    await run_in_threadpool(
                        fail_external_check_schedule,
                        schedule["schedule_id"],
                        f"Scheduler error ({type(exc).__name__})",
                    )
                    continue
                await run_in_threadpool(
                    finish_external_check_schedule,
                    schedule["schedule_id"],
                    result["status"],
                )
                await publish_external_check_result(schedule["organization_id"], result)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("External-check scheduler cycle failed")
        await asyncio.sleep(30)


def close_scanner_controls(
    db: Session,
    organization_id: int,
    *,
    actor_user_id: int | None,
    reason: str,
    now: datetime | None = None,
) -> None:
    """Cancel queued scans and queue one safety cancellation for active scans."""
    current_time = now or utcnow()
    queued_scans = db.scalars(
        select(AgentCommand).where(
            AgentCommand.organization_id == organization_id,
            AgentCommand.action == "start_scan",
            AgentCommand.status == "queued",
        )
    ).all()
    cancelled_ids: list[int] = []
    for command in queued_scans:
        command.status = "cancelled"
        command.result = "Cancelled because scanner controls closed."
        command.updated_at = current_time
        cancelled_ids.append(command.id)
    if cancelled_ids:
        audit(
            db,
            organization_id,
            actor_user_id,
            "scanner.commands_cancelled",
            {"command_ids": cancelled_ids, "reason": reason},
        )

    active_scans = db.scalars(
        select(AgentCommand)
        .where(
            AgentCommand.organization_id == organization_id,
            AgentCommand.action == "start_scan",
            AgentCommand.status.in_(("delivered", "accepted")),
        )
        .order_by(AgentCommand.agent_id, AgentCommand.id.desc())
    ).all()
    latest_by_agent: dict[int, AgentCommand] = {}
    for command in active_scans:
        latest_by_agent.setdefault(command.agent_id, command)
    if not latest_by_agent:
        return

    creator_id = actor_user_id
    if creator_id is None:
        creator_id = db.scalar(
            select(Membership.user_id)
            .where(
                Membership.organization_id == organization_id,
                Membership.role == "admin",
                Membership.status == "approved",
            )
            .order_by(Membership.id)
            .limit(1)
        )
    if creator_id is None:
        return

    queued_cancel_agent_ids: list[int] = []
    for agent_id, scan in latest_by_agent.items():
        cancellation = db.scalar(
            select(AgentCommand)
            .where(
                AgentCommand.organization_id == organization_id,
                AgentCommand.agent_id == agent_id,
                AgentCommand.action == "cancel_scan",
                AgentCommand.created_at >= scan.created_at,
                AgentCommand.status.in_(("queued", "delivered", "accepted")),
            )
            .order_by(AgentCommand.id.desc())
            .limit(1)
        )
        if cancellation is not None:
            continue
        db.add(
            AgentCommand(
                organization_id=organization_id,
                agent_id=agent_id,
                action="cancel_scan",
                target=None,
                status="queued",
                created_by_user_id=creator_id,
                result=None,
                created_at=current_time,
                updated_at=current_time,
            )
        )
        queued_cancel_agent_ids.append(agent_id)
    if queued_cancel_agent_ids:
        audit(
            db,
            organization_id,
            actor_user_id,
            "scanner.safety_cancel_queued",
            {"agent_ids": queued_cancel_agent_ids, "reason": reason},
        )


def _network_is_internal(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    if network.version == 4:
        allowed_ranges = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("127.0.0.0/8"),
            ipaddress.ip_network("169.254.0.0/16"),
        )
    else:
        allowed_ranges = (
            ipaddress.ip_network("fc00::/7"),
            ipaddress.ip_network("fe80::/10"),
            ipaddress.ip_network("::1/128"),
        )
    return any(network.subnet_of(allowed_range) for allowed_range in allowed_ranges)


def validate_internal_scan_target(raw_target: str) -> str:
    value = raw_target.strip()
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValueError(
            "NmapUI accepts private IP addresses or subnets only. Website names and public ranges are blocked."
        ) from exc
    if not _network_is_internal(network) or network.num_addresses > 65_536:
        raise ValueError(
            "NmapUI accepts private IP addresses or subnets of at most 65,536 addresses. Public website targets are blocked."
        )
    return value


def validate_scanner_network_scopes(raw_scopes: list[str]) -> list[str]:
    """Normalize a bounded allowlist of private CIDRs for one scanner node."""
    if len(raw_scopes) > 32:
        raise ValueError("A scanner can have at most 32 authorized network scopes.")
    normalized: set[str] = set()
    for raw_scope in raw_scopes:
        if not isinstance(raw_scope, str) or not raw_scope.strip():
            raise ValueError("Every authorized scanner network must be a private IP or CIDR.")
        try:
            network = ipaddress.ip_network(raw_scope.strip(), strict=False)
        except ValueError as exc:
            raise ValueError("Authorized networks must be IP addresses or CIDRs.") from exc
        if not _network_is_internal(network):
            raise ValueError("Only private, loopback, or link-local scanner networks are allowed.")
        normalized.add(str(network))
    return sorted(
        normalized,
        key=lambda value: (
            ipaddress.ip_network(value).version,
            int(ipaddress.ip_network(value).network_address),
            ipaddress.ip_network(value).prefixlen,
        ),
    )


def scan_target_within_agent_scope(raw_target: str, authorized_networks: list[str] | None) -> str:
    target = validate_internal_scan_target(raw_target)
    network = ipaddress.ip_network(target, strict=False)
    scopes = authorized_networks if isinstance(authorized_networks, list) else []
    for scope in scopes:
        try:
            authorized = ipaddress.ip_network(scope, strict=False)
        except ValueError:
            continue
        if authorized.version == network.version and network.subnet_of(authorized):
            return target
    raise ValueError(
        "This target is outside the scanner's approved networks. Update its authorized CIDR scope before scanning."
    )


def issue_workspace_challenge(
    db: Session,
    organization: Organization,
    user: User,
) -> dict[str, Any]:
    now = utcnow()
    # A rotated TXT token replaces the previous active challenge. Keeping older
    # tokens valid would let a copied or superseded DNS value verify the domain.
    previous_challenges = db.scalars(
        select(DomainChallenge).where(
            DomainChallenge.organization_id == organization.id,
            DomainChallenge.verified_at.is_(None),
            DomainChallenge.expires_at > now,
        )
    ).all()
    for previous in previous_challenges:
        previous.expires_at = now

    clear_token = secrets.token_urlsafe(24)
    challenge = issue_challenge(
        db=db,
        organization_id=organization.id,
        user_id=user.id,
        token_hash=token_digest(clear_token),
        now=now,
    )
    db.flush()
    return {
        "record_name": challenge_record_name(organization.domain),
        "record_value": challenge_record_value(clear_token),
        "expires_at": challenge.expires_at.isoformat() + "Z",
    }


def require_agent(
    db: Session,
    agent_id: int,
    authorization: str | None,
) -> Agent:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Agent token required")
    presented = token_digest(authorization.removeprefix("Bearer ").strip())
    agent = db.get(Agent, agent_id)
    if (
        agent is None
        or not agent.enabled
        or not secrets.compare_digest(agent.token_hash, presented)
    ):
        raise HTTPException(status_code=401, detail="Invalid agent token")
    return agent


def serialize_event(event: ScanEvent) -> dict[str, Any]:
    return {
        "id": event.id,
        "agent_id": event.agent_id,
        "source_job_id": event.source_job_id,
        "source_job_type": event.source_job_type,
        "event_name": event.event_name,
        "payload": event.payload,
        "created_at": event.created_at.isoformat() + "Z",
        "occurred_at": iso_utc(event.occurred_at or event.created_at),
        "artifact_download_url": f"/api/events/{event.id}/artifact" if event.artifact_sha256 else None,
        "artifact_size_bytes": event.artifact_size_bytes,
        "artifact_sha256": event.artifact_sha256,
    }


def agent_status(agent: Agent) -> str:
    if not agent.enabled:
        return "disabled"
    if not agent_bridge_online(agent):
        return "offline"
    return "online" if agent.nmapui_connected else "NmapUI offline"


def agent_bridge_online(agent: Agent, *, now: datetime | None = None) -> bool:
    current_time = now or utcnow()
    return bool(
        agent.enabled
        and agent.last_seen_at is not None
        and agent.last_seen_at >= current_time - timedelta(seconds=45)
    )


@app.get("/healthz")
def healthz():
    return {"status": "ok", "app": "daedalus", "version": __version__}


@app.get("/readyz")
def readyz(db: Session = Depends(get_db)):
    """Report whether the service can reach its database and save reports."""
    database_ready = False
    try:
        db.execute(text("SELECT 1"))
        database_ready = True
    except Exception:
        logger.warning("Readiness database probe failed")

    report_storage = REPORTS_DIR if REPORTS_DIR.exists() else REPORTS_DIR.parent
    storage_ready = (
        report_storage.is_dir()
        and os.access(report_storage, os.R_OK | os.W_OK | os.X_OK)
    )
    checks = {
        "database": "ok" if database_ready else "unavailable",
        "report_storage": "ok" if storage_ready else "unavailable",
    }
    ready = database_ready and storage_ready
    return JSONResponse(
        status_code=200 if ready else 503,
        content={
            "status": "ready" if ready else "not_ready",
            "app": "daedalus",
            "checks": checks,
        },
    )


@app.get("/", response_class=HTMLResponse)
def login_page(request: Request, db: Session = Depends(get_db)):
    if request.session.get("user_id"):
        try:
            get_session_user(request, db)
            return RedirectResponse("/dashboard", status_code=303)
        except HTTPException:
            pass
    return templates.TemplateResponse(
        request,
        "login.html",
        {
            "demo_mode": DEMO_MODE,
            "google_configured": bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET),
        },
    )


class UserKeyInput(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    expires_days: int = Field(default=30, ge=1, le=90)


class TokenLoginInput(BaseModel):
    token: str = Field(min_length=40, max_length=200)


@app.post("/auth/token")
def token_login(payload: TokenLoginInput, request: Request, db: Session = Depends(get_db)):
    key = validate_user_key(db, db.scalar(select(UserAPIKey).where(
        UserAPIKey.token_hash == token_digest(payload.token)
    )))
    request.session.clear()
    request.session.update(user_id=key.user_id, organization_id=key.organization_id, api_key_id=key.id)
    audit(db, key.organization_id, key.user_id, "user_key.login", {"key_id": key.id})
    db.commit()
    response = JSONResponse({"redirect": "/dashboard"})
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/account/keys", response_class=HTMLResponse)
def user_keys_page(request: Request, db: Session = Depends(get_db)):
    user, org, _ = get_org_context(request, db)
    return templates.TemplateResponse(request, "user_keys.html", {"user": user, "organization": org})


@app.get("/api/user-keys")
def list_user_keys(request: Request, db: Session = Depends(get_db)):
    user, org, _ = get_org_context(request, db)
    keys = db.scalars(select(UserAPIKey).where(UserAPIKey.user_id == user.id, UserAPIKey.organization_id == org.id)).all()
    return {"keys": [{"id": k.id, "name": k.name, "expires_at": iso_utc(k.expires_at), "revoked_at": iso_utc(k.revoked_at)} for k in keys]}


@app.post("/api/user-keys")
def create_user_key(payload: UserKeyInput, request: Request, db: Session = Depends(get_db)):
    user, org, _ = get_org_context(request, db)
    if getattr(request.state, "user_api_key", None) is not None:
        raise HTTPException(status_code=403, detail="Use Google sign-in to create access keys")
    token = "dd_user_" + secrets.token_urlsafe(48)
    key = UserAPIKey(user_id=user.id, organization_id=org.id, name=payload.name,
        token_hash=token_digest(token), created_at=utcnow(), expires_at=utcnow()+timedelta(days=payload.expires_days))
    db.add(key)
    db.flush()
    audit(db, org.id, user.id, "user_key.created", {"key_id": key.id, "name": key.name})
    db.commit()
    response = JSONResponse({"id": key.id, "token": token, "expires_at": iso_utc(key.expires_at)})
    response.headers["Cache-Control"] = "no-store"
    return response


@app.delete("/api/user-keys/{key_id}")
def revoke_user_key(key_id: int, request: Request, db: Session = Depends(get_db)):
    user, org, _ = get_org_context(request, db)
    key = db.get(UserAPIKey, key_id)
    if key is None or key.user_id != user.id or key.organization_id != org.id:
        raise HTTPException(status_code=404, detail="Access key not found")
    key.revoked_at = utcnow()
    audit(db, org.id, user.id, "user_key.revoked", {"key_id": key.id})
    db.commit()
    return {"status": "revoked"}


@app.post("/dev/login")
def demo_login(request: Request, db: Session = Depends(get_db)):
    client_host = request.client.host if request.client else ""
    if not DEMO_MODE or client_host not in {"127.0.0.1", "::1", "testclient"}:
        raise HTTPException(status_code=404, detail="Not found")
    user = db.scalar(
        select(User).where(User.google_subject == "daedalus-local-demo-admin")
    )
    if user is None:
        raise HTTPException(status_code=503, detail="Demo workspace is not initialized")
    request.session.clear()
    request.session["user_id"] = user.id
    membership = db.scalar(
        select(Membership).where(
            Membership.user_id == user.id,
            Membership.status == "approved",
        )
    )
    if membership:
        request.session["organization_id"] = membership.organization_id
    return RedirectResponse("/dashboard", status_code=303)


@app.post("/dev/login/member")
def demo_member_login(request: Request, db: Session = Depends(get_db)):
    client_host = request.client.host if request.client else ""
    if not DEMO_MODE or client_host not in {"127.0.0.1", "::1", "testclient"}:
        raise HTTPException(status_code=404, detail="Not found")
    user = db.scalar(
        select(User).where(User.google_subject == "daedalus-local-demo-member")
    )
    if user is None:
        raise HTTPException(status_code=503, detail="Demo member is not initialized")
    request.session.clear()
    request.session["user_id"] = user.id
    return RedirectResponse("/dashboard", status_code=303)


@app.get("/auth/google")
async def google_login(request: Request):
    if not (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET):
        raise HTTPException(status_code=503, detail="Google login is not configured")
    google = oauth.create_client("google")
    return await google.authorize_redirect(
        request,
        BASE_URL + "/oauth2/callback",
    )


@app.get("/oauth2/callback")
@app.get("/auth/google/callback", name="google_callback")
async def google_callback(request: Request, db: Session = Depends(get_db)):
    if not (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET):
        raise HTTPException(status_code=503, detail="Google login is not configured")
    google = oauth.create_client("google")
    token = await google.authorize_access_token(request)
    profile = token.get("userinfo") or {}
    if not profile.get("sub") or not profile.get("email") or profile.get("email_verified") is not True:
        raise HTTPException(status_code=401, detail="Google did not return a verified email")

    user = db.scalar(
        select(User).where(User.google_subject == str(profile["sub"]))
    )
    if user is None:
        user = User(
            google_subject=str(profile["sub"]),
            email=str(profile["email"]).lower(),
            display_name=str(profile.get("name") or profile["email"])[:200],
            created_at=utcnow(),
        )
        db.add(user)
    else:
        user.email = str(profile["email"]).lower()
        user.display_name = str(profile.get("name") or user.display_name)[:200]
    db.commit()
    db.refresh(user)

    membership = db.scalar(
        select(Membership)
        .where(Membership.user_id == user.id, Membership.status == "approved")
        .order_by(Membership.organization_id)
    )
    request.session.clear()
    request.session["user_id"] = user.id
    if membership:
        request.session["organization_id"] = membership.organization_id
    return RedirectResponse("/dashboard", status_code=303)


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/", status_code=303)


@app.post("/api/workspaces")
def create_workspace(
    payload: WorkspaceCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    user = get_session_user(request, db)
    try:
        domain = normalize_domain(payload.domain)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    existing = db.scalar(select(Organization).where(Organization.domain == domain))
    if existing is not None:
        raise HTTPException(
            status_code=409,
            detail="This domain already has a workspace. Request access from its administrator.",
        )

    slug_base = re.sub(r"[^a-z0-9]+", "-", domain).strip("-")[:68] or "workspace"
    slug = slug_base
    if db.scalar(select(Organization).where(Organization.slug == slug)) is not None:
        slug = slug_base + "-" + secrets.token_hex(3)
    now = utcnow()
    organization = Organization(
        name=payload.name.strip(),
        slug=slug,
        domain=domain,
        verification_status="pending",
        verification_expires_at=now + timedelta(days=30),
        created_at=now,
    )
    db.add(organization)
    try:
        db.flush()
        db.add(
            Membership(
                user_id=user.id,
                organization_id=organization.id,
                role="admin",
                status="approved",
                created_at=now,
            )
        )
        challenge = issue_workspace_challenge(db, organization, user)
        audit(
            db,
            organization.id,
            user.id,
            "workspace.created",
            {"domain": domain, "verification_status": "pending"},
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="This domain is already claimed.") from exc
    request.session["organization_id"] = organization.id
    return {
        "organization_id": organization.id,
        "name": organization.name,
        "domain": organization.domain,
        "verification_status": organization.verification_status,
        "probation_expires_at": organization.verification_expires_at.isoformat() + "Z",
        "txt": challenge,
    }


@app.post("/api/workspaces/{organization_id}/domain-challenge")
def create_domain_challenge(
    organization_id: int,
    request: Request,
    db: Session = Depends(get_db),
):
    user, organization, _ = get_org_context(request, db, admin=True)
    if organization.id != organization_id:
        raise HTTPException(status_code=404, detail="Workspace not found")
    if organization.verification_status == "verified":
        return {"verified": True, "domain": organization.domain}
    challenge = issue_workspace_challenge(db, organization, user)
    audit(
        db,
        organization.id,
        user.id,
        "domain_challenge.issued",
        {"record_name": challenge_record_name(organization.domain)},
    )
    db.commit()
    return {
        "verified": False,
        "domain": organization.domain,
        "txt": challenge,
    }


@app.post("/api/workspaces/{organization_id}/verify-domain")
async def verify_workspace_domain(
    organization_id: int,
    request: Request,
    db: Session = Depends(get_db),
):
    user, organization, _ = get_org_context(request, db, admin=True)
    if organization.id != organization_id:
        raise HTTPException(status_code=404, detail="Workspace not found")
    if organization.verification_status == "verified":
        return {"verified": True, "domain": organization.domain}
    now = utcnow()
    challenges = db.scalars(
        select(DomainChallenge)
        .where(
            DomainChallenge.organization_id == organization.id,
            DomainChallenge.verified_at.is_(None),
            DomainChallenge.expires_at > now,
        )
        .order_by(DomainChallenge.id.desc())
    ).all()
    if not challenges:
        raise HTTPException(
            status_code=409,
            detail="The TXT challenge expired. Create a new challenge and add its record.",
        )
    try:
        matched = await run_in_threadpool(
            has_matching_txt,
            organization.domain,
            {challenge.token_hash for challenge in challenges},
            token_digest,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if not matched:
        return {
            "verified": False,
            "domain": organization.domain,
            "record_name": challenge_record_name(organization.domain),
            "detail": "The verification TXT record was not found yet.",
        }
    organization.verification_status = "verified"
    organization.verification_expires_at = None
    for challenge in challenges:
        challenge.verified_at = now
    audit(
        db,
        organization.id,
        user.id,
        "domain.verified",
        {"domain": organization.domain},
    )
    db.commit()
    await live_hub.publish(
        organization.id,
        {
            "type": "domain_status",
            "verification_status": "verified",
            "domain": organization.domain,
        },
    )
    return {"verified": True, "domain": organization.domain}


@app.post("/api/membership-requests")
async def request_workspace_membership(
    payload: AccessRequestInput,
    request: Request,
    db: Session = Depends(get_db),
):
    user = get_session_user(request, db)
    try:
        domain = normalize_domain(payload.domain)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    organization = db.scalar(select(Organization).where(Organization.domain == domain))
    if organization is None:
        raise HTTPException(status_code=404, detail="No workspace is registered for that domain.")
    membership = db.scalar(
        select(Membership).where(
            Membership.user_id == user.id,
            Membership.organization_id == organization.id,
        )
    )
    if membership is not None:
        if membership.status == "approved":
            return {"status": "approved", "organization": organization.name}
        if membership.status == "pending":
            return {"status": "pending", "organization": organization.name}
        existing_membership_id = membership.id
        changed = db.execute(
            update(Membership)
            .where(Membership.id == existing_membership_id, Membership.status == membership.status)
            .values(status="pending", role="user")
            .execution_options(synchronize_session=False)
        )
        if changed.rowcount != 1:
            db.rollback()
            saved = db.get(Membership, existing_membership_id)
            if saved is not None and saved.status in {"pending", "approved"}:
                return {"status": saved.status, "organization": organization.name}
            raise HTTPException(status_code=409, detail="Workspace access changed during this request. Refresh and try again.")
        db.refresh(membership)
    else:
        membership = Membership(
            user_id=user.id,
            organization_id=organization.id,
            role="user",
            status="pending",
            created_at=utcnow(),
        )
        db.add(membership)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        saved = db.scalar(select(Membership).where(
            Membership.user_id == user.id,
            Membership.organization_id == organization.id,
        ))
        if saved is not None and saved.status in {"pending", "approved"}:
            return {"status": saved.status, "organization": organization.name}
        raise HTTPException(status_code=409, detail="Workspace access changed during this request. Refresh and try again.") from exc
    membership_id = membership.id
    audit(
        db,
        organization.id,
        user.id,
        "membership.requested",
        {"membership_id": membership_id, "email": user.email},
    )
    admin_user_ids = set(db.scalars(
        select(Membership.user_id).where(
            Membership.organization_id == organization.id,
            Membership.role == "admin",
            Membership.status == "approved",
        )
    ).all())
    db.commit()
    await live_hub.publish_to_users(
        organization.id,
        admin_user_ids,
        {"type": "membership_request_received"},
    )
    return {"status": "pending", "organization": organization.name}


@app.get("/api/memberships")
def list_workspace_memberships(
    request: Request,
    db: Session = Depends(get_db),
):
    user, organization, membership = get_org_context(request, db)
    query = (
        select(Membership, User)
        .join(User, User.id == Membership.user_id)
        .where(Membership.organization_id == organization.id)
        .order_by(Membership.created_at)
    )
    if membership.role != "admin":
        query = query.where(Membership.user_id == membership.user_id)
    rows = db.execute(query).all()
    approved_admin_count = db.scalar(select(func.count(Membership.id)).where(
        Membership.organization_id == organization.id,
        Membership.role == "admin",
        Membership.status == "approved",
    )) or 0
    return {
        "organization": organization.name,
        "verification_status": organization.verification_status,
        "approved_admin_count": approved_admin_count,
        "members": [
            {
                "id": item.id,
                "name": member.display_name,
                "email": member.email,
                "role": item.role,
                "status": item.status,
                "is_self": item.user_id == user.id,
            }
            for item, member in rows
        ],
    }


@app.get("/api/my-workspaces")
def list_my_workspaces(request: Request, db: Session = Depends(get_db)):
    user = get_session_user(request, db)
    rows = db.execute(
        select(Membership, Organization)
        .join(Organization, Organization.id == Membership.organization_id)
        .where(Membership.user_id == user.id)
        .order_by(Organization.name)
    ).all()
    return {
        "workspaces": [
            {
                "id": membership.organization_id,
                "name": organization.name,
                "domain": organization.domain,
                "role": membership.role,
                "status": membership.status,
            }
            for membership, organization in rows
        ]
    }


@app.post("/api/memberships/{membership_id}/decision")
async def decide_membership_request(
    membership_id: int,
    payload: MembershipDecisionRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    _, organization, _ = get_org_context(request, db, admin=True)
    if not workspace_controls_available(db, organization):
        raise HTTPException(
            status_code=403,
            detail="Verify the domain or grant a 14-day probation override before sharing access.",
        )
    membership = db.get(Membership, membership_id)
    if membership is None or membership.organization_id != organization.id:
        raise HTTPException(status_code=404, detail="Membership request not found")
    if membership.status not in {"pending", "denied"}:
        raise HTTPException(status_code=409, detail="This membership is already decided.")
    membership.status = "approved" if payload.approve else "denied"
    membership.role = "user"
    requester_user_id = membership.user_id
    decided_status = membership.status
    actor = get_session_user(request, db)
    audit(
        db,
        organization.id,
        actor.id,
        "membership.approved" if payload.approve else "membership.denied",
        {"membership_id": membership.id, "user_id": membership.user_id, "role": "user"},
    )
    admin_user_ids = set(db.scalars(
        select(Membership.user_id).where(
            Membership.organization_id == organization.id,
            Membership.role == "admin",
            Membership.status == "approved",
        )
    ).all())
    db.commit()
    await live_hub.publish_to_users(
        organization.id,
        admin_user_ids,
        {"type": "membership_list_changed"},
    )
    await live_hub.publish_to_user(
        organization.id,
        requester_user_id,
        {
            "type": "membership_decision",
            "organization_id": organization.id,
            "organization": organization.name,
            "domain": organization.domain,
            "status": decided_status,
        },
    )
    return {"id": membership.id, "status": decided_status, "role": membership.role}


@app.post("/api/memberships/{membership_id}/role")
async def change_workspace_membership_role(
    membership_id: int,
    payload: MembershipRoleRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    actor, organization, _ = get_org_context(request, db, admin=True)
    if not workspace_controls_available(db, organization):
        raise HTTPException(
            status_code=403,
            detail="Verify the domain or grant a 14-day probation override before changing administrator access.",
        )
    membership = db.get(Membership, membership_id)
    if membership is None or membership.organization_id != organization.id:
        raise HTTPException(status_code=404, detail="Workspace membership not found")
    if membership.status != "approved":
        raise HTTPException(status_code=409, detail="Only an approved member can change roles")

    previous_role = membership.role
    if previous_role == payload.role:
        return {"id": membership.id, "role": previous_role, "changed": False}

    conditions = [
        Membership.id == membership.id,
        Membership.organization_id == organization.id,
        Membership.status == "approved",
        Membership.role == previous_role,
    ]
    if payload.role == "user" and previous_role == "admin":
        approved_admin_count = select(func.count(Membership.id)).where(
            Membership.organization_id == organization.id,
            Membership.role == "admin",
            Membership.status == "approved",
        ).scalar_subquery()
        conditions.append(approved_admin_count > 1)

    changed = db.execute(
        update(Membership)
        .where(*conditions)
        .values(role=payload.role)
        .execution_options(synchronize_session=False)
    )
    if changed.rowcount != 1:
        raise HTTPException(
            status_code=409,
            detail="The last approved workspace admin cannot be demoted. Promote another approved member first.",
        )
    user_id = membership.user_id
    audit(db, organization.id, actor.id, "membership.role_changed", {
        "membership_id": membership.id,
        "user_id": user_id,
        "from_role": previous_role,
        "to_role": payload.role,
    })
    db.commit()

    admin_user_ids = set(db.scalars(select(Membership.user_id).where(
        Membership.organization_id == organization.id,
        Membership.role == "admin",
        Membership.status == "approved",
    )).all())
    await live_hub.publish_to_users(organization.id, admin_user_ids, {
        "type": "membership_list_changed",
    })
    await live_hub.publish_to_user(organization.id, user_id, {
        "type": "membership_role_changed",
        "organization_id": organization.id,
        "role": payload.role,
    })
    return {"id": membership.id, "role": payload.role, "changed": True}


@app.post("/api/memberships/{membership_id}/revoke")
async def revoke_workspace_membership(
    membership_id: int,
    request: Request,
    db: Session = Depends(get_db),
):
    user, organization, _ = get_org_context(request, db, admin=True)
    membership = db.get(Membership, membership_id)
    if membership is None or membership.organization_id != organization.id:
        raise HTTPException(status_code=404, detail="Workspace membership not found")
    if membership.user_id == user.id:
        raise HTTPException(status_code=409, detail="Workspace admins cannot revoke their own access")
    if membership.role == "admin":
        raise HTTPException(
            status_code=409,
            detail="Admin access cannot be revoked through shared-user management.",
        )
    if membership.status != "approved":
        raise HTTPException(status_code=409, detail="Only an approved user can be removed")

    membership.status = "revoked"
    audit(
        db,
        organization.id,
        user.id,
        "membership.revoked",
        {"membership_id": membership.id, "user_id": membership.user_id, "role": membership.role},
    )
    db.commit()
    await live_hub.revoke_user_access(organization.id, membership.user_id)
    return {"id": membership.id, "status": membership.status, "role": membership.role}


@app.get("/api/workspaces/{organization_id}/probation-overrides")
def list_probation_overrides(
    organization_id: int,
    request: Request,
    db: Session = Depends(get_db),
):
    _, organization, _ = get_org_context(request, db, admin=True)
    if organization.id != organization_id:
        raise HTTPException(status_code=404, detail="Workspace not found")
    rows = db.execute(
        select(ProbationOverride, User)
        .join(User, User.id == ProbationOverride.granted_by_user_id)
        .where(ProbationOverride.organization_id == organization.id)
        .order_by(ProbationOverride.id.desc())
    ).all()
    return {
        "overrides": [
            {
                "id": item.id,
                "granted_by": user.email,
                "reason": item.reason,
                "starts_at": item.starts_at.isoformat() + "Z",
                "expires_at": item.expires_at.isoformat() + "Z",
                "revoked_at": item.revoked_at.isoformat() + "Z" if item.revoked_at else None,
                "active": (
                    item.revoked_at is None
                    and item.starts_at <= utcnow()
                    and item.expires_at > utcnow()
                ),
            }
            for item, user in rows
        ]
    }


@app.post("/api/workspaces/{organization_id}/probation-overrides")
async def grant_probation_override(
    organization_id: int,
    payload: ProbationOverrideRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    user, organization, _ = get_org_context(request, db, admin=True)
    if organization.id != organization_id:
        raise HTTPException(status_code=404, detail="Workspace not found")
    if organization.verification_status == "verified":
        raise HTTPException(status_code=409, detail="Verified workspaces do not need a probation override.")
    if active_probation_override(db, organization.id):
        raise HTTPException(status_code=409, detail="A probation override is already active.")
    reason = payload.reason.strip()
    if len(reason) < 8:
        raise HTTPException(status_code=422, detail="Enter a reason of at least 8 characters.")
    now = utcnow()
    close_scanner_controls(
        db,
        organization.id,
        actor_user_id=user.id,
        reason="probation_override_regranted",
        now=now,
    )
    override = ProbationOverride(
        organization_id=organization.id,
        granted_by_user_id=user.id,
        reason=reason,
        starts_at=now,
        expires_at=now + timedelta(days=14),
        created_at=now,
    )
    db.add(override)
    db.flush()
    audit(
        db,
        organization.id,
        user.id,
        "probation_override.granted",
        {
            "override_id": override.id,
            "reason": reason,
            "expires_at": override.expires_at.isoformat() + "Z",
            "duration_days": 14,
        },
    )
    notification_created = record_probation_override_notification(
        db,
        organization_id=organization.id,
        override_id=override.id,
        action="granted",
        actor_name=user.display_name or user.email,
        detected_at=now,
        expires_at=override.expires_at,
    )
    db.commit()
    if notification_created:
        await live_hub.publish(organization.id, {
            "type": "workspace_notification_created",
            "source_type": "probation_override_granted",
            "source_id": override.id,
        })
    return {
        "id": override.id,
        "active": True,
        "reason": override.reason,
        "starts_at": override.starts_at.isoformat() + "Z",
        "expires_at": override.expires_at.isoformat() + "Z",
    }


@app.post("/api/workspaces/{organization_id}/probation-overrides/{override_id}/revoke")
async def revoke_probation_override(
    organization_id: int,
    override_id: int,
    request: Request,
    db: Session = Depends(get_db),
):
    user, organization, _ = get_org_context(request, db, admin=True)
    if organization.id != organization_id:
        raise HTTPException(status_code=404, detail="Workspace not found")
    override = db.get(ProbationOverride, override_id)
    if (
        override is None
        or override.organization_id != organization.id
        or override.revoked_at is not None
        or override.expires_at <= utcnow()
    ):
        raise HTTPException(status_code=404, detail="Active override not found")
    now = utcnow()
    override.revoked_at = now
    override.revoked_by_user_id = user.id
    close_scanner_controls(
        db,
        organization.id,
        actor_user_id=user.id,
        reason="probation_override_revoked",
        now=now,
    )
    audit(
        db,
        organization.id,
        user.id,
        "probation_override.revoked",
        {"override_id": override.id, "granted_by_user_id": override.granted_by_user_id},
    )
    notification_created = record_probation_override_notification(
        db,
        organization_id=organization.id,
        override_id=override.id,
        action="revoked",
        actor_name=user.display_name or user.email,
        detected_at=now,
        expires_at=override.expires_at,
    )
    db.commit()
    if notification_created:
        await live_hub.publish(organization.id, {
            "type": "workspace_notification_created",
            "source_type": "probation_override_revoked",
            "source_id": override.id,
        })
    return {"id": override.id, "active": False, "revoked_at": now.isoformat() + "Z"}


@app.get("/api/audit-log")
def list_audit_log(request: Request, limit: int = 100, db: Session = Depends(get_db)):
    _, organization, _ = get_org_context(request, db, admin=True)
    rows = db.execute(
        select(AuditLog, User)
        .outerjoin(User, User.id == AuditLog.actor_user_id)
        .where(AuditLog.organization_id == organization.id)
        .order_by(AuditLog.id.desc())
        .limit(max(1, min(limit, 200)))
    ).all()
    return {
        "events": [
            {
                "id": item.id,
                "actor": user.email if user else "system",
                "action": item.action,
                "details": item.details,
                "created_at": item.created_at.isoformat() + "Z",
            }
            for item, user in rows
        ]
    }


@app.get("/api/external-checks/{check_type}")
def external_check_history(
    check_type: str,
    request: Request,
    runs_limit: int = 12,
    changes_limit: int = 40,
    runs_before: int | None = None,
    changes_before: int | None = None,
    db: Session = Depends(get_db),
):
    if check_type not in {"dns", "web", "web-active", "web-nikto"}:
        raise HTTPException(status_code=404, detail="Unknown external check")
    _, organization, _ = get_org_context(request, db)
    runs_page_size = max(1, min(runs_limit, 100))
    changes_page_size = max(1, min(changes_limit, 100))
    run_query = (
        select(ExternalCheckRun, User)
        .outerjoin(User, User.id == ExternalCheckRun.triggered_by_user_id)
        .where(
            ExternalCheckRun.organization_id == organization.id,
            ExternalCheckRun.check_type == check_type,
        )
    )
    if runs_before is not None:
        run_query = run_query.where(ExternalCheckRun.id < max(1, runs_before))
    run_rows = db.execute(
        run_query.order_by(ExternalCheckRun.id.desc()).limit(runs_page_size + 1)
    ).all()
    runs_has_more = len(run_rows) > runs_page_size
    run_rows = run_rows[:runs_page_size]
    recent_runs = [serialize_external_run(run, actor) for run, actor in run_rows]
    latest_snapshot_row = db.execute(
        select(ExternalCheckRun, User)
        .outerjoin(User, User.id == ExternalCheckRun.triggered_by_user_id)
        .where(
            ExternalCheckRun.organization_id == organization.id,
            ExternalCheckRun.check_type == check_type,
            ExternalCheckRun.status.in_(["completed", "completed_with_warnings"]),
            ExternalCheckRun.snapshot.is_not(None),
        )
        .order_by(ExternalCheckRun.id.desc())
        .limit(1)
    ).first()
    latest_snapshot = (
        serialize_external_run(*latest_snapshot_row)["snapshot"]
        if latest_snapshot_row else None
    )
    schedule = db.scalar(
        select(ExternalCheckSchedule).where(
            ExternalCheckSchedule.organization_id == organization.id,
            ExternalCheckSchedule.check_type == check_type,
        )
    )
    change_query = (
        select(ExternalCheckChange, ExternalCheckRun, User)
        .join(ExternalCheckRun, ExternalCheckRun.id == ExternalCheckChange.run_id)
        .outerjoin(User, User.id == ExternalCheckRun.triggered_by_user_id)
        .where(
            ExternalCheckChange.organization_id == organization.id,
            ExternalCheckChange.check_type == check_type,
        )
    )
    if changes_before is not None:
        change_query = change_query.where(ExternalCheckChange.id < max(1, changes_before))
    change_rows = db.execute(
        change_query.order_by(ExternalCheckChange.id.desc()).limit(changes_page_size + 1)
    ).all()
    changes_has_more = len(change_rows) > changes_page_size
    change_rows = change_rows[:changes_page_size]
    return {
        "check_type": check_type,
        "domain": organization.domain,
        "schedule": serialize_external_schedule(schedule, check_type),
        "latest_snapshot": latest_snapshot,
        "latest_snapshot_run_id": latest_snapshot_row[0].id if latest_snapshot_row else None,
        "runs": recent_runs,
        "runs_has_more": runs_has_more,
        "runs_next_before": run_rows[-1][0].id if runs_has_more and run_rows else None,
        "changes": [
            {
                "id": change.id,
                "run_id": run.id,
                "field_path": change.field_path,
                "field_label": external_check_field_label(change.field_path),
                "previous_value": change.previous_value,
                "current_value": change.current_value,
                "detected_at": iso_utc(change.detected_at),
                "actor": actor.email if actor else (
                    "Scheduled check" if run.trigger_source == "schedule" else "former user"
                ),
            }
            for change, run, actor in change_rows
        ],
        "changes_has_more": changes_has_more,
        "changes_next_before": change_rows[-1][0].id if changes_has_more and change_rows else None,
    }


@app.get("/api/notifications")
def list_workspace_notifications(
    request: Request,
    limit: int = 50,
    db: Session = Depends(get_db),
):
    user, organization, _ = get_org_context(request, db)
    limit = max(1, min(limit, 100))
    rows = db.execute(
        select(WorkspaceNotification, WorkspaceNotificationRead)
        .outerjoin(
            WorkspaceNotificationRead,
            (WorkspaceNotificationRead.notification_id == WorkspaceNotification.id)
            & (WorkspaceNotificationRead.user_id == user.id),
        )
        .where(WorkspaceNotification.organization_id == organization.id)
        .order_by(WorkspaceNotification.detected_at.desc(), WorkspaceNotification.id.desc())
        .limit(limit)
    ).all()
    unread_count = db.scalar(
        select(func.count(WorkspaceNotification.id))
        .outerjoin(
            WorkspaceNotificationRead,
            (WorkspaceNotificationRead.notification_id == WorkspaceNotification.id)
            & (WorkspaceNotificationRead.user_id == user.id),
        )
        .where(
            WorkspaceNotification.organization_id == organization.id,
            WorkspaceNotificationRead.id.is_(None),
        )
    ) or 0
    return {
        "unread_count": unread_count,
        "notifications": [
            {
                "id": notification.id,
                "source_type": notification.source_type,
                "source_id": notification.source_id,
                "title": notification.title,
                "summary": notification.summary,
                "reason": notification.reason,
                "detected_at": iso_utc(notification.detected_at),
                "read_at": iso_utc(receipt.read_at) if receipt else None,
                "tab": (
                    "reports" if notification.source_type == "report_job_failure"
                    else "meraki" if notification.source_type == "meraki_report"
                    else "cis" if notification.source_type == "cis_report"
                    else "scanners" if notification.source_type == "scanner_comparison"
                    else "members" if notification.source_type in {
                        "probation_override_granted", "probation_override_revoked"
                    }
                    else "dns" if notification.title.startswith("DNS and email")
                    else "web"
                ),
            }
            for notification, receipt in rows
        ],
    }


@app.post("/api/notifications/{notification_id}/read")
def mark_workspace_notification_read(
    notification_id: int,
    request: Request,
    db: Session = Depends(get_db),
):
    user, organization, _ = get_org_context(request, db)
    notification = db.scalar(select(WorkspaceNotification).where(
        WorkspaceNotification.id == notification_id,
        WorkspaceNotification.organization_id == organization.id,
    ))
    if notification is None:
        raise HTTPException(status_code=404, detail="Notification not found")
    receipt = db.scalar(select(WorkspaceNotificationRead).where(
        WorkspaceNotificationRead.notification_id == notification_id,
        WorkspaceNotificationRead.user_id == user.id,
    ))
    if receipt is None:
        receipt = WorkspaceNotificationRead(
            notification_id=notification_id, user_id=user.id, read_at=utcnow()
        )
        try:
            with db.begin_nested():
                db.add(receipt)
                db.flush()
            db.commit()
        except IntegrityError:
            db.rollback()
            receipt = db.scalar(select(WorkspaceNotificationRead).where(
                WorkspaceNotificationRead.notification_id == notification_id,
                WorkspaceNotificationRead.user_id == user.id,
            ))
            if receipt is None:
                raise
    return {"notification_id": notification_id, "read_at": iso_utc(receipt.read_at)}


def serialize_cis_profile(profile: CISProfile) -> dict[str, Any]:
    content = profile.content or {}
    return {
        "id": profile.id,
        "slug": profile.slug,
        "name": profile.name,
        "version": profile.version,
        "platform": profile.platform,
        "description": profile.description,
        "benchmark": content.get("benchmark"),
        "checksum": profile.checksum,
        "check_count": len(content.get("checks") or []),
        "published_at": iso_utc(profile.published_at),
        "download_url": f"/api/cis/profiles/{profile.id}/download",
        "yaml_download_url": None if content.get("benchmark") else f"/api/cis/profiles/{profile.id}/download?format=checklist-yaml",
    }


def get_cis_workspace_from_key(db: Session, api_key: str | None) -> tuple[CISAPIKey | UserAPIKey, Organization]:
    if not api_key or len(api_key) > 256:
        raise HTTPException(status_code=401, detail="A valid CIS upload key is required.")
    if api_key.startswith("dd_user_"):
        stored_key = validate_user_key(db, db.scalar(select(UserAPIKey).where(
            UserAPIKey.token_hash == token_digest(api_key)
        )))
        organization = db.get(Organization, stored_key.organization_id)
        if organization is None:
            raise HTTPException(status_code=401, detail="A valid CIS upload key is required.")
        return stored_key, organization
    stored_key = db.scalar(select(CISAPIKey).where(CISAPIKey.token_hash == token_digest(api_key)))
    if stored_key is None or not hmac.compare_digest(
        stored_key.token_hash, token_digest(api_key)
    ):
        raise HTTPException(status_code=401, detail="A valid CIS upload key is required.")
    organization = db.get(Organization, stored_key.organization_id)
    if organization is None:
        raise HTTPException(status_code=401, detail="A valid CIS upload key is required.")
    return stored_key, organization


def cis_device_fingerprint(organization_id: int, device_identifier: str) -> str:
    stable_instance_key = f"{SESSION_SECRET}:cis-device:{organization_id}".encode("utf-8")
    return hmac.new(stable_instance_key, device_identifier.encode("utf-8"), hashlib.sha256).hexdigest()


class CISHeartbeatOptions(BaseModel):
    model_config = {"extra": "forbid"}
    device_identifier: str = Field(min_length=1, max_length=256)


@app.post("/api/cis/client/heartbeat")
def receive_cis_heartbeat(
    payload: CISHeartbeatOptions,
    api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: Session = Depends(get_db),
):
    _, organization = get_cis_workspace_from_key(db, api_key)
    identifier = payload.device_identifier.strip()
    if not identifier:
        raise HTTPException(status_code=422, detail="A device identifier is required.")
    device = db.scalar(select(CISDevice).where(
        CISDevice.organization_id == organization.id,
        CISDevice.device_fingerprint == cis_device_fingerprint(organization.id, identifier),
    ))
    if device is None:
        raise HTTPException(status_code=404, detail="Upload the first endpoint report before sending check-ins.")
    now = utcnow()
    device.last_client_heartbeat_at = now
    db.commit()
    return JSONResponse({"accepted": True, "received_at": iso_utc(now), "next_check_in_seconds": 300}, headers={"Cache-Control": "no-store"})


@app.get("/api/cis/status")
def cis_status(request: Request, db: Session = Depends(get_db)):
    _user, organization, membership = get_org_context(request, db)
    api_key = db.scalar(
        select(CISAPIKey).where(CISAPIKey.organization_id == organization.id)
    )
    profiles = db.scalar(
        select(func.count(CISProfile.id)).where(CISProfile.organization_id == organization.id)
    ) or 0
    devices = db.scalar(
        select(func.count(CISDevice.id)).where(CISDevice.organization_id == organization.id)
    ) or 0
    now = utcnow()
    online_cutoff = now - timedelta(hours=36)
    online_device_count = db.scalar(
        select(func.count(CISDevice.id)).where(
            CISDevice.organization_id == organization.id,
            CISDevice.last_seen_at >= online_cutoff,
        )
    ) or 0
    device_rows = db.scalars(
        select(CISDevice)
        .where(CISDevice.organization_id == organization.id)
        .order_by(CISDevice.last_seen_at.desc(), CISDevice.id.desc())
        .limit(250)
    ).all()
    latest_reports = _cis_latest_assessments(db, organization.id)
    def assessment_state(report):
        return _cis_assessment_state(report, now)
    assessment_counts = {state: 0 for state in ("current", "stale", "unknown", "missing")}
    assessment_counts["missing"] = max(0, devices - len(latest_reports))
    for report in latest_reports.values():
        assessment_counts[assessment_state(report)] += 1
    device_statuses = [
        {
            "id": device.id,
            "name": device.name,
            "platform": device.platform,
            "os_version": device.os_version,
            "last_seen_at": iso_utc(device.last_seen_at),
            "state": "online" if device.last_seen_at >= online_cutoff else "offline",
            "presence_source": "report_receipt",
            "latest_report_id": latest_reports[device.id].id if device.id in latest_reports else None,
            "last_collected_at": iso_utc(latest_reports[device.id].collected_at) if device.id in latest_reports else None,
            "assessment_state": assessment_state(latest_reports.get(device.id)),
            "last_client_heartbeat_at": iso_utc(device.last_client_heartbeat_at),
            "client_state": "unknown" if device.last_client_heartbeat_at is None else "online" if device.last_client_heartbeat_at >= now - timedelta(minutes=15) else "offline",
        }
        for device in device_rows
    ]
    return {
        "key_configured": api_key is not None,
        "key_hint": api_key.key_hint if api_key and membership.role == "admin" else None,
        "profile_count": profiles,
        "device_count": devices,
        "online_device_count": online_device_count,
        "offline_device_count": max(0, devices - online_device_count),
        "report_recency_seconds": 36 * 60 * 60,
        "assessment_counts": assessment_counts,
        "client_presence_seconds": 15 * 60,
        "online_client_count": db.scalar(select(func.count(CISDevice.id)).where(CISDevice.organization_id == organization.id, CISDevice.last_client_heartbeat_at >= now - timedelta(minutes=15))) or 0,
        "devices_truncated": devices > len(device_rows),
        "devices": device_statuses,
        "can_manage": membership.role == "admin",
    }


@app.post("/api/cis/profiles/install-starter")
def install_cis_starter_profile(request: Request, db: Session = Depends(get_db)):
    user, organization, _ = get_org_context(request, db, admin=True)
    try:
        content = load_starter_profile()
    except CISDataError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    existing = db.scalar(
        select(CISProfile).where(
            CISProfile.organization_id == organization.id,
            CISProfile.slug == content["slug"],
            CISProfile.version == content["version"],
        )
    )
    if existing is not None:
        raise HTTPException(status_code=409, detail="The CSP starter profile is already installed.")
    now = utcnow()
    profile = CISProfile(
        organization_id=organization.id,
        slug=content["slug"],
        name=content["name"],
        version=content["version"],
        platform=content["platform"],
        description=content["description"],
        checksum=profile_checksum(content),
        content=content,
        published_at=now,
        created_by_user_id=user.id,
        created_at=now,
    )
    db.add(profile)
    db.flush()
    audit(
        db,
        organization.id,
        user.id,
        "cis.profile.published",
        {"profile_id": profile.id, "slug": profile.slug, "version": profile.version, "check_count": len(content["checks"])},
    )
    db.commit()
    db.refresh(profile)
    return {"profile": serialize_cis_profile(profile)}


@app.post("/api/cis/profiles/install-macos26")
def install_cis_macos26_profiles(request: Request, db: Session = Depends(get_db)):
    user, organization, _ = get_org_context(request, db, admin=True)
    try:
        contents = load_macos26_starter_profiles()
    except CISDataError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    installed: list[CISProfile] = []
    already_present: list[str] = []
    now = utcnow()
    for content in contents:
        existing = db.scalar(
            select(CISProfile).where(
                CISProfile.organization_id == organization.id,
                CISProfile.slug == content["slug"],
                CISProfile.version == content["version"],
            )
        )
        if existing is not None:
            already_present.append(existing.slug)
            continue
        profile = CISProfile(
            organization_id=organization.id,
            slug=content["slug"],
            name=content["name"],
            version=content["version"],
            platform=content["platform"],
            description=content["description"],
            checksum=profile_checksum(content),
            content=content,
            published_at=now,
            created_by_user_id=user.id,
            created_at=now,
        )
        db.add(profile)
        db.flush()
        installed.append(profile)
        audit(
            db,
            organization.id,
            user.id,
            "cis.profile.published",
            {
                "profile_id": profile.id,
                "slug": profile.slug,
                "version": profile.version,
                "check_count": len(content["checks"]),
                "benchmark": content.get("benchmark"),
            },
        )
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="A macOS 26 CIS profile version already exists.") from exc
    for profile in installed:
        db.refresh(profile)
    return {
        "profiles": [serialize_cis_profile(profile) for profile in installed],
        "installed_count": len(installed),
        "already_present": already_present,
    }


@app.post("/api/cis/profiles")
def publish_cis_profile(
    payload: CISProfileInput,
    request: Request,
    db: Session = Depends(get_db),
):
    user, organization, _ = get_org_context(request, db, admin=True)
    try:
        content = validate_profile(payload.model_dump())
    except CISDataError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    existing = db.scalar(
        select(CISProfile).where(
            CISProfile.organization_id == organization.id,
            CISProfile.slug == content["slug"],
            CISProfile.version == content["version"],
        )
    )
    if existing is not None:
        raise HTTPException(status_code=409, detail="That profile version already exists. Publish a new version to preserve history.")
    now = utcnow()
    profile = CISProfile(
        organization_id=organization.id,
        slug=content["slug"],
        name=content["name"],
        version=content["version"],
        platform=content["platform"],
        description=content["description"],
        checksum=profile_checksum(content),
        content=content,
        published_at=now,
        created_by_user_id=user.id,
        created_at=now,
    )
    db.add(profile)
    db.flush()
    audit(
        db,
        organization.id,
        user.id,
        "cis.profile.published",
        {"profile_id": profile.id, "slug": profile.slug, "version": profile.version, "check_count": len(content["checks"])},
    )
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="That profile version already exists.") from exc
    db.refresh(profile)
    return {"profile": serialize_cis_profile(profile)}


@app.get("/api/cis/profiles")
def list_cis_profiles(request: Request, db: Session = Depends(get_db)):
    _user, organization, _ = get_org_context(request, db)
    profiles = db.scalars(
        select(CISProfile)
        .where(CISProfile.organization_id == organization.id)
        .order_by(CISProfile.published_at.desc(), CISProfile.id.desc())
        .limit(100)
    ).all()
    return {"profiles": [serialize_cis_profile(profile) for profile in profiles]}


@app.get("/api/cis/client-package/download")
def download_cis_demo_client(request: Request, db: Session = Depends(get_db)):
    user, organization, _ = get_org_context(request, db)
    if not DEMO_MODE or APP_ENV == "production":
        raise HTTPException(status_code=404, detail="No distributable CIS client package is available.")
    directory = PACKAGE_DIR / "client_bundle"
    filename = "CSP-CIS_Audit-local-unsigned.zip"
    try:
        manifest = json.loads((directory / "manifest.json").read_text())
        if not isinstance(manifest, dict) or manifest.get("architecture") != "arm64" or manifest.get("signing") != "unsigned":
            raise ValueError("Unsupported demo package metadata")
        contents = (directory / filename).read_bytes()
        checksum = hashlib.sha256(contents).hexdigest()
        if manifest.get("filename") != filename or manifest.get("sha256") != checksum:
            raise ValueError("Package checksum mismatch")
        with zipfile.ZipFile(io.BytesIO(contents)) as package:
            if package.testzip() is not None or any(
                Path(name).name.lower() in {"config.yaml", "cis-client.yaml", "cis-client.yml"}
                for name in package.namelist()
            ):
                raise ValueError("Invalid public package")
    except (OSError, ValueError, zipfile.BadZipFile):
        raise HTTPException(status_code=503, detail="The demo client package is unavailable or failed integrity checks.")
    audit(db, organization.id, user.id, "cis.client_package.downloaded",
          {"sha256": checksum, "architecture": "arm64", "signing": "unsigned", "build": manifest.get("build")})
    db.commit()
    return Response(contents, media_type="application/zip", headers={
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
        "X-Content-SHA256": checksum,
    })


@app.get("/api/cis/profiles/{profile_id}/download")
def download_cis_profile(profile_id: int, request: Request, db: Session = Depends(get_db)):
    user, organization, _ = get_org_context(request, db)
    profile = db.scalar(
        select(CISProfile).where(
            CISProfile.id == profile_id,
            CISProfile.organization_id == organization.id,
        )
    )
    if profile is None:
        raise HTTPException(status_code=404, detail="CIS profile not found.")
    if request.query_params.get("format") == "checklist-yaml" and (profile.content or {}).get("benchmark"):
        raise HTTPException(
            status_code=409,
            detail="CIS benchmark profiles must retain their stable rule and recommendation IDs; download the JSON profile.",
        )
    audit(
        db,
        organization.id,
        user.id,
        "cis.profile.downloaded",
        {"profile_id": profile.id, "slug": profile.slug, "version": profile.version},
    )
    db.commit()
    safe_version = re.sub(r"[^A-Za-z0-9._-]", "-", profile.version)
    if request.query_params.get("format") == "checklist-yaml":
        checks = profile.content.get("checks") or []
        categories = {
            category: [row["description"] for row in checks if row.get("category") == category]
            for category in ("macos", "chrome", "safari")
        }
        lines = [
            f"# Daedalus profile {profile.slug} v{safe_version}",
            "# Drop this checklist into the CSP CIS client bundle and rebuild it.",
        ]
        for category, descriptions in categories.items():
            lines.append(f"{category}:")
            if descriptions:
                lines.extend("  - " + json.dumps(description, ensure_ascii=False) for description in descriptions)
            else:
                lines[-1] += " []"
        response = Response("\n".join(lines) + "\n", media_type="application/yaml")
        response.headers["Content-Disposition"] = f'attachment; filename="checklist-{profile.slug}-{safe_version}.yaml"'
        return response
    document = {
        **profile.content,
        "checksum": profile.checksum,
        "published_at": iso_utc(profile.published_at),
    }
    response = JSONResponse(document)
    response.headers["Content-Disposition"] = f'attachment; filename="{profile.slug}-{safe_version}.json"'
    return response


@app.post("/api/cis/api-key")
def issue_cis_api_key(request: Request, db: Session = Depends(get_db)):
    user, organization, _ = get_org_context(request, db, admin=True)
    clear_key = secrets.token_urlsafe(40)
    now = utcnow()
    existing = db.scalar(
        select(CISAPIKey).where(CISAPIKey.organization_id == organization.id)
    )
    if existing is None:
        existing = CISAPIKey(
            organization_id=organization.id,
            token_hash=token_digest(clear_key),
            key_hint=clear_key[-4:],
            created_by_user_id=user.id,
            created_at=now,
        )
        db.add(existing)
        rotated = False
    else:
        existing.token_hash = token_digest(clear_key)
        existing.key_hint = clear_key[-4:]
        existing.created_by_user_id = user.id
        existing.created_at = now
        rotated = True
    audit(
        db,
        organization.id,
        user.id,
        "cis.api_key.issued" if not rotated else "cis.api_key.rotated",
        {"key_hint": clear_key[-4:]},
    )
    db.commit()
    return {
        "api_key": clear_key,
        "key_hint": clear_key[-4:],
        "rotated": rotated,
        "domain": organization.domain,
        "report_endpoint": BASE_URL + "/api/cis/report",
        "profiles_endpoint": BASE_URL + "/api/cis/client/profiles",
        "key_header": "X-API-Key",
    }


@app.delete("/api/cis/api-key")
def revoke_cis_api_key(request: Request, db: Session = Depends(get_db)):
    user, organization, _ = get_org_context(request, db, admin=True)
    key = db.scalar(select(CISAPIKey).where(CISAPIKey.organization_id == organization.id))
    if key is None:
        raise HTTPException(status_code=404, detail="No CIS upload key is configured.")
    hint = key.key_hint
    db.delete(key)
    audit(db, organization.id, user.id, "cis.api_key.revoked", {"key_hint": hint})
    db.commit()
    return {"key_configured": False}


@app.get("/api/cis/client/profiles")
def list_cis_client_profiles(
    api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: Session = Depends(get_db),
):
    _stored_key, organization = get_cis_workspace_from_key(db, api_key)
    profiles = db.scalars(
        select(CISProfile)
        .where(CISProfile.organization_id == organization.id)
        .order_by(CISProfile.published_at.desc(), CISProfile.id.desc())
        .limit(100)
    ).all()
    return {
        "domain": organization.domain,
        "profiles": [
            {
                **profile.content,
                "checksum": profile.checksum,
                "published_at": iso_utc(profile.published_at),
            }
            for profile in profiles
        ],
    }


def serialize_cis_report(
    report: CISReport,
    device: CISDevice,
    *,
    include_results: bool = False,
) -> dict[str, Any]:
    endpoint = (report.summary or {}).get("endpoint", {})
    serialized = {
        "id": report.id,
        "device_name": endpoint.get("name", device.name),
        "platform": endpoint.get("platform", device.platform),
        "os_version": endpoint.get("os_version", device.os_version),
        "profile_slug": report.profile_slug,
        "profile_version": report.profile_version,
        "collected_at": iso_utc(report.collected_at),
        "summary": report.summary,
    }
    if include_results:
        serialized["results"] = report.results
    return serialized


@app.get("/api/cis/reports")
def list_cis_reports(request: Request, db: Session = Depends(get_db)):
    _user, organization, _ = get_org_context(request, db)
    rows = db.execute(
        select(CISReport, CISDevice)
        .join(CISDevice, CISDevice.id == CISReport.device_id)
        .where(CISReport.organization_id == organization.id)
        .order_by(CISReport.collected_at.desc(), CISReport.id.desc())
        .limit(50)
    ).all()
    return {"reports": [serialize_cis_report(report, device) for report, device in rows]}


@app.get("/api/cis/reports/{report_id}")
def get_cis_report(report_id: int, request: Request, db: Session = Depends(get_db)):
    _user, organization, _ = get_org_context(request, db)
    row = db.execute(
        select(CISReport, CISDevice)
        .join(CISDevice, CISDevice.id == CISReport.device_id)
        .where(
            CISReport.id == report_id,
            CISReport.organization_id == organization.id,
        )
    ).first()
    if row is None:
        raise HTTPException(status_code=404, detail="CIS report not found.")
    report, device = row
    return serialize_cis_report(report, device, include_results=True)


@app.get("/api/cis/changes")
def list_cis_changes(request: Request, db: Session = Depends(get_db)):
    _user, organization, _ = get_org_context(request, db)
    rows = db.execute(
        select(CISReportChange, CISReport, CISDevice)
        .join(CISReport, CISReport.id == CISReportChange.report_id)
        .join(CISDevice, CISDevice.id == CISReport.device_id)
        .where(CISReportChange.organization_id == organization.id)
        .order_by(CISReportChange.detected_at.desc(), CISReportChange.id.desc())
        .limit(100)
    ).all()
    return {
        "changes": [
            {
                "id": change.id,
                "device_name": serialize_cis_report(report, device)["device_name"],
                "report_id": report.id,
                "check_id": change.check_id,
                "previous_status": change.previous_status,
                "current_status": change.current_status,
                "detected_at": iso_utc(change.detected_at),
            }
            for change, report, device in rows
        ]
    }


@app.post("/api/cis/reports/{report_id}/pdf")
def create_cis_endpoint_pdf(
    report_id: int,
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    user, organization, _ = get_org_context(request, db)
    row = db.execute(
        select(CISReport, CISDevice)
        .join(CISDevice, CISDevice.id == CISReport.device_id)
        .where(
            CISReport.id == report_id,
            CISReport.organization_id == organization.id,
        )
    ).first()
    if row is None:
        raise HTTPException(status_code=404, detail="CIS report not found.")
    report, device = row
    historical = serialize_cis_report(report, device)
    profile = db.scalar(
        select(CISProfile).where(
            CISProfile.organization_id == organization.id,
            CISProfile.slug == report.profile_slug,
            CISProfile.version == report.profile_version,
        )
    ) if report.profile_slug and report.profile_version else None
    changes = db.scalars(
        select(CISReportChange)
        .where(CISReportChange.report_id == report.id)
        .order_by(CISReportChange.id.asc())
        .limit(500)
    ).all()
    active_count = db.scalar(
        select(func.count(ReportJob.id)).where(
            ReportJob.organization_id == organization.id,
            ReportJob.status.in_(("queued", "running")),
        )
    ) or 0
    if active_count >= 3:
        raise HTTPException(status_code=429, detail="Three report jobs are already running for this workspace.")

    now = utcnow()
    job = ReportJob(
        organization_id=organization.id,
        created_by_user_id=user.id,
        report_type="cis_endpoint",
        domain=organization.domain,
        status="queued",
        progress=0,
        stage="Queued",
        file_name="pending.pdf",
        report_snapshot={
            "domain": organization.domain,
            "organization_name": organization.name,
            "requested_by": user.email,
            "generated_at": iso_utc(now),
            "cis": {
                "report_id": report.id,
                "device_name": historical["device_name"],
                "platform": historical["platform"],
                "os_version": historical["os_version"],
                "profile_name": profile.name if profile else None,
                "profile_slug": report.profile_slug,
                "profile_version": report.profile_version,
                "benchmark": (profile.content or {}).get("benchmark") if profile else None,
                "collected_at": iso_utc(report.collected_at),
                "summary": report.summary,
                "results": report.results,
                "changes": [
                    {
                        "check_id": change.check_id,
                        "previous_status": change.previous_status,
                        "current_status": change.current_status,
                        "detected_at": iso_utc(change.detected_at),
                    }
                    for change in changes
                ],
            },
        },
        created_at=now,
        updated_at=now,
    )
    db.add(job)
    db.flush()
    job.file_name = f"daedalus-cis-endpoint-{report.id}-{job.id}.pdf"
    audit(
        db,
        organization.id,
        user.id,
        "report.requested",
        {
            "report_id": job.id,
            "report_type": job.report_type,
            "cis_report_id": report.id,
            "device_id": device.id,
        },
    )
    db.commit()
    db.refresh(job)
    background_tasks.add_task(generate_report_job, job.id)
    return serialize_report_job(job, user)


@app.post("/api/cis/report")
async def receive_cis_report(
    request: Request,
    api_key: str | None = Header(default=None, alias="X-API-Key"),
    device_header: str | None = Header(default=None, alias="X-Device-UUID"),
    report_header: str | None = Header(default=None, alias="X-Report-ID"),
    db: Session = Depends(get_db),
):
    _stored_key, organization = get_cis_workspace_from_key(db, api_key)
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > 5 * 1024 * 1024:
                raise HTTPException(status_code=413, detail="The CIS report exceeds the 5 MiB limit.")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid report content length.") from exc
    raw_body = await request.body()
    if len(raw_body) > 5 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="The CIS report exceeds the 5 MiB limit.")
    try:
        payload = json.loads(raw_body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail="The CIS report must contain valid JSON.") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=422, detail="The CIS report must be a JSON object.")
    payload = dict(payload)
    if device_header:
        payload["device_uuid"] = device_header
    if report_header:
        payload["report_id"] = report_header
    try:
        normalized = normalize_cis_report(payload, api_key=api_key)
        if normalized["profile_slug"]:
            profile = db.scalar(select(CISProfile).where(
                CISProfile.organization_id == organization.id,
                CISProfile.slug == normalized["profile_slug"],
                CISProfile.version == normalized["profile_version"],
            ))
            if profile is None:
                raise CISDataError("The report profile and version must match a published workspace profile.")
            bind_report_to_profile(normalized, profile.content)
            validate_report_target_os(normalized, profile.content)
            apply_profile_coverage_limits(normalized, profile.content)
    except CISDataError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    fingerprint = cis_device_fingerprint(organization.id, normalized["device_identifier"])
    report_identity = normalized["client_report_id"] or (
        normalized["profile_slug"] + ":" + normalized["profile_version"] + ":"
        + normalized["collected_at"].isoformat()
        + ":"
        + json.dumps(normalized["results"], ensure_ascii=False, sort_keys=True)
    )
    client_report_hash = hmac.new(
        f"{SESSION_SECRET}:cis-report:{organization.id}".encode("utf-8"),
        (fingerprint + ":" + report_identity).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    duplicate = db.scalar(
        select(CISReport).where(
            CISReport.organization_id == organization.id,
            CISReport.client_report_hash == client_report_hash,
        )
    )
    if duplicate is not None:
        if (
            duplicate.collected_at != normalized["collected_at"]
            or duplicate.profile_slug != normalized["profile_slug"]
            or duplicate.profile_version != normalized["profile_version"]
            or duplicate.results != normalized["results"]
        ):
            raise HTTPException(status_code=409, detail="This report ID was already used for different evidence.")
        return {"accepted": True, "duplicate": True, "report_id": duplicate.id}

    now = utcnow()
    device = db.scalar(
        select(CISDevice).where(
            CISDevice.organization_id == organization.id,
            CISDevice.device_fingerprint == fingerprint,
        )
    )
    if device is None:
        device = CISDevice(
            organization_id=organization.id,
            device_fingerprint=fingerprint,
            name=normalized["device_name"],
            platform=normalized["platform"],
            os_version=normalized["os_version"],
            first_seen_at=now,
            last_seen_at=now,
        )
        db.add(device)
        db.flush()
    else:
        latest_collection = db.scalar(select(func.max(CISReport.collected_at)).where(
            CISReport.device_id == device.id,
            CISReport.organization_id == organization.id,
        ))
        if latest_collection is None or normalized["collected_at"] >= latest_collection:
            device.name = normalized["device_name"]
            device.platform = normalized["platform"]
            device.os_version = normalized["os_version"]
        device.last_seen_at = now

    previous = db.scalar(
        select(CISReport)
        .where(
            CISReport.organization_id == organization.id,
            CISReport.device_id == device.id,
            CISReport.profile_slug == normalized["profile_slug"],
            CISReport.profile_version == normalized["profile_version"],
        )
        .order_by(CISReport.collected_at.desc(), CISReport.id.desc())
    )
    # Late queued reports remain in history but do not create backwards change alerts.
    if previous and previous.collected_at >= normalized["collected_at"]:
        previous = None
    normalized["summary"]["endpoint"] = {
        "name": normalized["device_name"],
        "platform": normalized["platform"],
        "os_version": normalized["os_version"],
    }
    report = CISReport(
        organization_id=organization.id,
        device_id=device.id,
        client_report_hash=client_report_hash,
        profile_slug=normalized["profile_slug"],
        profile_version=normalized["profile_version"],
        collected_at=normalized["collected_at"],
        summary=normalized["summary"],
        results=normalized["results"],
        created_at=now,
    )
    db.add(report)
    db.flush()
    previous_statuses = {
        item["id"]: item["status"]
        for item in ((previous.results or []) if previous else [])
        if isinstance(item, dict) and item.get("id") and item.get("status")
    }
    changes = []
    for result in normalized["results"]:
        old_status = previous_statuses.get(result["id"])
        if old_status and old_status != result["status"]:
            changes.append(
                CISReportChange(
                    organization_id=organization.id,
                    report_id=report.id,
                    check_id=result["id"],
                    previous_status=old_status,
                    current_status=result["status"],
                    detected_at=now,
                )
            )
    db.add_all(changes)
    audit(
        db,
        organization.id,
        None,
        "cis.report.received",
        {
            "cis_report_id": report.id,
            "device_id": device.id,
            "profile_slug": report.profile_slug,
            "profile_version": report.profile_version,
            "summary": report.summary,
            "changed_check_count": len(changes),
        },
    )
    if changes:
        audit(
            db,
            organization.id,
            None,
            "cis.report.changes_detected",
            {"cis_report_id": report.id, "changed_check_count": len(changes)},
        )
    notification_created = record_cis_report_notification(
        db,
        organization_id=organization.id,
        report_id=report.id,
        device_name=device.name,
        profile_slug=report.profile_slug,
        profile_version=report.profile_version,
        changed_check_count=len(changes),
        detected_at=now,
    )
    db.commit()
    await live_hub.publish(
        organization.id,
        {
            "type": "cis_report_received",
            "report_id": report.id,
            "device_name": device.name,
            "score": report.summary.get("score"),
            "changed_check_count": len(changes),
            "notification_created": notification_created,
        },
    )
    return {
        "accepted": True,
        "duplicate": False,
        "report_id": report.id,
        "score": report.summary.get("score"),
        "changed_check_count": len(changes),
        "notification_created": notification_created,
    }


def list_meraki_organizations(api_key: str) -> list[dict[str, str]]:
    with MerakiClient(api_key) as client:
        return client.list_organizations()


def meraki_http_error(error: MerakiAPIError) -> HTTPException:
    status_code = 502
    if error.status_code in (401, 403):
        status_code = 400
    elif error.status_code == 429:
        status_code = 429
    return HTTPException(status_code=status_code, detail=str(error))


def clear_meraki_organization_grants(
    db: Session,
    organization_id: int,
    actor_user_id: int,
    *,
    reason: str,
) -> None:
    grants = db.scalars(
        select(MerakiOrganizationGrant).where(
            MerakiOrganizationGrant.organization_id == organization_id
        )
    ).all()
    if not grants:
        return
    audit(
        db,
        organization_id,
        actor_user_id,
        "meraki.organization_scopes.cleared",
        {
            "reason": reason,
            "organizations": [
                {
                    "id": grant.meraki_organization_id,
                    "name": grant.meraki_organization_name,
                }
                for grant in grants
            ],
        },
    )
    for grant in grants:
        db.delete(grant)


@app.get("/api/meraki/status")
def meraki_status(request: Request, db: Session = Depends(get_db)):
    _user, organization, membership = get_org_context(request, db)
    credential = db.scalar(
        select(MerakiCredential).where(
            MerakiCredential.organization_id == organization.id
        )
    )
    return {
        "configured": credential is not None,
        "key_hint": credential.key_hint if credential and membership.role == "admin" else None,
        "last_verified_at": iso_utc(credential.last_verified_at) if credential else None,
        "can_manage": membership.role == "admin",
    }


@app.put("/api/meraki/credential")
async def save_meraki_credential(
    payload: MerakiCredentialInput,
    request: Request,
    db: Session = Depends(get_db),
):
    user, organization, _ = get_org_context(request, db, admin=True)
    api_key = payload.api_key.strip()
    if len(api_key) < 16:
        raise HTTPException(status_code=422, detail="Enter a valid Meraki API key.")
    try:
        organizations = await run_in_threadpool(list_meraki_organizations, api_key)
    except MerakiAPIError as exc:
        raise meraki_http_error(exc) from exc
    try:
        encrypted_key = encrypt_secret(api_key)
    except CredentialEncryptionError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    now = utcnow()
    credential = db.scalar(
        select(MerakiCredential).where(
            MerakiCredential.organization_id == organization.id
        )
    )
    if credential is not None:
        try:
            existing_api_key = decrypt_secret(credential.encrypted_api_key)
        except CredentialEncryptionError:
            existing_api_key = None
        if existing_api_key != api_key:
            clear_meraki_organization_grants(
                db,
                organization.id,
                user.id,
                reason="credential_replaced",
            )
    if credential is None:
        credential = MerakiCredential(
            organization_id=organization.id,
            encrypted_api_key=encrypted_key,
            key_hint=api_key[-4:],
            configured_by_user_id=user.id,
            created_at=now,
            updated_at=now,
            last_verified_at=now,
        )
        db.add(credential)
    else:
        credential.encrypted_api_key = encrypted_key
        credential.key_hint = api_key[-4:]
        credential.configured_by_user_id = user.id
        credential.updated_at = now
        credential.last_verified_at = now
    audit(
        db,
        organization.id,
        user.id,
        "meraki.credential.saved",
        {"key_hint": api_key[-4:], "organization_count": len(organizations)},
    )
    db.commit()
    return {
        "configured": True,
        "organizations": organizations,
        "last_verified_at": iso_utc(now),
    }


@app.delete("/api/meraki/credential")
def delete_meraki_credential(request: Request, db: Session = Depends(get_db)):
    user, organization, _ = get_org_context(request, db, admin=True)
    active_job = db.scalar(
        select(ReportJob.id).where(
            ReportJob.organization_id == organization.id,
            ReportJob.report_type == "meraki_security",
            ReportJob.status.in_(("queued", "running")),
        )
    )
    if active_job:
        raise HTTPException(status_code=409, detail="Wait for the active Meraki report to finish before removing its key.")
    credential = db.scalar(
        select(MerakiCredential).where(
            MerakiCredential.organization_id == organization.id
        )
    )
    if credential is None:
        raise HTTPException(status_code=404, detail="No Meraki key is configured.")
    hint = credential.key_hint
    clear_meraki_organization_grants(
        db,
        organization.id,
        user.id,
        reason="credential_removed",
    )
    db.delete(credential)
    audit(db, organization.id, user.id, "meraki.credential.removed", {"key_hint": hint})
    db.commit()
    return {"configured": False}


@app.post("/api/meraki/organizations")
async def get_meraki_organizations(request: Request, db: Session = Depends(get_db)):
    _user, organization, _ = get_org_context(request, db, admin=True)
    credential = db.scalar(
        select(MerakiCredential).where(
            MerakiCredential.organization_id == organization.id
        )
    )
    if credential is None:
        raise HTTPException(status_code=409, detail="Connect a Meraki API key first.")
    try:
        api_key = decrypt_secret(credential.encrypted_api_key)
    except CredentialEncryptionError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    try:
        organizations = await run_in_threadpool(list_meraki_organizations, api_key)
    except MerakiAPIError as exc:
        raise meraki_http_error(exc) from exc
    grants = {
        grant.meraki_organization_id: grant
        for grant in db.scalars(
            select(MerakiOrganizationGrant).where(
                MerakiOrganizationGrant.organization_id == organization.id
            )
        )
    }
    credential.last_verified_at = utcnow()
    db.commit()
    return {
        "organizations": [
            {
                **item,
                "authorized": item["id"] in grants,
                "granted_at": iso_utc(grants[item["id"]].granted_at)
                if item["id"] in grants
                else None,
            }
            for item in organizations
        ]
    }


@app.post("/api/meraki/organization-scope")
async def grant_meraki_organization_scope(
    payload: MerakiOrganizationScopeInput,
    request: Request,
    db: Session = Depends(get_db),
):
    user, organization, _ = get_org_context(request, db, admin=True)
    credential = db.scalar(
        select(MerakiCredential).where(
            MerakiCredential.organization_id == organization.id
        )
    )
    if credential is None:
        raise HTTPException(status_code=409, detail="Connect a Meraki API key first.")
    try:
        api_key = decrypt_secret(credential.encrypted_api_key)
    except CredentialEncryptionError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    try:
        available = await run_in_threadpool(list_meraki_organizations, api_key)
    except MerakiAPIError as exc:
        raise meraki_http_error(exc) from exc
    selected = next(
        (
            item
            for item in available
            if item["id"] == payload.meraki_organization_id
        ),
        None,
    )
    if selected is None:
        raise HTTPException(
            status_code=422,
            detail="Select an organization currently available to this Meraki key.",
        )

    grant = db.scalar(
        select(MerakiOrganizationGrant).where(
            MerakiOrganizationGrant.organization_id == organization.id,
            MerakiOrganizationGrant.meraki_organization_id
            == payload.meraki_organization_id,
        )
    )
    now = utcnow()
    if grant is None:
        grant = MerakiOrganizationGrant(
            organization_id=organization.id,
            meraki_organization_id=selected["id"],
            meraki_organization_name=selected["name"],
            granted_by_user_id=user.id,
            granted_at=now,
        )
        db.add(grant)
        audit(
            db,
            organization.id,
            user.id,
            "meraki.organization_scope.granted",
            {
                "meraki_organization_id": selected["id"],
                "meraki_organization_name": selected["name"],
            },
        )
    else:
        grant.meraki_organization_name = selected["name"]
    credential.last_verified_at = now
    db.commit()
    return {
        "authorized": True,
        "meraki_organization_id": selected["id"],
        "meraki_organization_name": selected["name"],
        "granted_at": iso_utc(grant.granted_at),
    }


@app.delete("/api/meraki/organization-scope")
def revoke_meraki_organization_scope(
    payload: MerakiOrganizationScopeInput,
    request: Request,
    db: Session = Depends(get_db),
):
    user, organization, _ = get_org_context(request, db, admin=True)
    active_meraki_job = db.scalar(
        select(ReportJob.id).where(
            ReportJob.organization_id == organization.id,
            ReportJob.report_type == "meraki_security",
            ReportJob.status.in_(("queued", "running")),
        )
    )
    if active_meraki_job:
        raise HTTPException(
            status_code=409,
            detail="Wait for the active Meraki report to finish before changing organization access.",
        )
    grant = db.scalar(
        select(MerakiOrganizationGrant).where(
            MerakiOrganizationGrant.organization_id == organization.id,
            MerakiOrganizationGrant.meraki_organization_id
            == payload.meraki_organization_id,
        )
    )
    if grant is None:
        raise HTTPException(status_code=404, detail="This organization is not authorized for the workspace.")
    audit(
        db,
        organization.id,
        user.id,
        "meraki.organization_scope.revoked",
        {
            "meraki_organization_id": grant.meraki_organization_id,
            "meraki_organization_name": grant.meraki_organization_name,
        },
    )
    db.delete(grant)
    db.commit()
    return {"authorized": False, "meraki_organization_id": payload.meraki_organization_id}


@app.post("/api/meraki/reports")
async def create_meraki_report(
    payload: MerakiReportInput,
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    user, organization, _ = get_org_context(request, db, admin=True)
    credential = db.scalar(
        select(MerakiCredential).where(
            MerakiCredential.organization_id == organization.id
        )
    )
    if credential is None:
        raise HTTPException(status_code=409, detail="Connect a Meraki API key first.")
    grant = db.scalar(
        select(MerakiOrganizationGrant).where(
            MerakiOrganizationGrant.organization_id == organization.id,
            MerakiOrganizationGrant.meraki_organization_id
            == payload.organization_id,
        )
    )
    if grant is None:
        raise HTTPException(
            status_code=403,
            detail="Authorize this Meraki organization for the workspace before generating a report.",
        )
    try:
        api_key = decrypt_secret(credential.encrypted_api_key)
    except CredentialEncryptionError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    try:
        organizations = await run_in_threadpool(list_meraki_organizations, api_key)
    except MerakiAPIError as exc:
        raise meraki_http_error(exc) from exc
    selected = next(
        (item for item in organizations if item["id"] == payload.organization_id),
        None,
    )
    if selected is None:
        raise HTTPException(status_code=422, detail="Select an organization available to this Meraki key.")

    active_meraki_count = db.scalar(
        select(func.count(ReportJob.id)).where(
            ReportJob.organization_id == organization.id,
            ReportJob.report_type == "meraki_security",
            ReportJob.status.in_(("queued", "running")),
        )
    ) or 0
    if active_meraki_count >= 1:
        raise HTTPException(status_code=429, detail="A Meraki report is already running for this workspace.")
    active_count = db.scalar(
        select(func.count(ReportJob.id)).where(
            ReportJob.organization_id == organization.id,
            ReportJob.status.in_(("queued", "running")),
        )
    ) or 0
    if active_count >= 3:
        raise HTTPException(status_code=429, detail="Three report jobs are already running for this workspace.")

    now = utcnow()
    credential.last_verified_at = now
    job = ReportJob(
        organization_id=organization.id,
        created_by_user_id=user.id,
        report_type="meraki_security",
        domain=organization.domain,
        status="queued",
        progress=0,
        stage="Queued",
        file_name="pending.pdf",
        report_snapshot={
            "domain": organization.domain,
            "organization_name": organization.name,
            "requested_by": user.email,
            "meraki_organization_id": payload.organization_id,
            "meraki_organization_name": selected["name"],
        },
        created_at=now,
        updated_at=now,
    )
    db.add(job)
    db.flush()
    job.file_name = f"daedalus-meraki-security-{job.id}.pdf"
    audit(
        db,
        organization.id,
        user.id,
        "report.requested",
        {
            "report_id": job.id,
            "report_type": job.report_type,
            "meraki_organization_id": payload.organization_id,
        },
    )
    db.commit()
    db.refresh(job)
    background_tasks.add_task(generate_report_job, job.id)
    return serialize_report_job(job, user)


@app.get("/api/reports")
def list_reports(request: Request, db: Session = Depends(get_db)):
    _, organization, _ = get_org_context(request, db)
    rows = db.execute(
        select(ReportJob, User)
        .outerjoin(User, User.id == ReportJob.created_by_user_id)
        .where(ReportJob.organization_id == organization.id)
        .order_by(ReportJob.id.desc())
        .limit(50)
    ).all()
    return {"reports": [serialize_report_job(job, actor) for job, actor in rows]}


@app.get("/api/meraki/reports/{report_id}/changes")
def meraki_report_changes(report_id: int, request: Request, db: Session = Depends(get_db)):
    _user, organization, _membership = get_org_context(request, db)
    job = db.scalar(select(ReportJob).where(
        ReportJob.id == report_id, ReportJob.organization_id == organization.id,
        ReportJob.report_type == "meraki_security", ReportJob.status == "completed",
    ))
    if job is None:
        raise HTTPException(status_code=404, detail="Completed Meraki report not found.")
    comparison = (job.report_snapshot or {}).get("meraki_comparison")
    if comparison is None:
        raise HTTPException(status_code=409, detail="This older report does not contain a saved comparison.")
    return {"report_id": job.id, "comparison": comparison}


@app.get("/api/meraki/reports/{report_id}/details")
def meraki_report_details(
    report_id: int,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    response.headers["Cache-Control"] = "no-store"
    _user, organization, _membership = get_org_context(request, db)
    job = db.scalar(select(ReportJob).where(
        ReportJob.id == report_id,
        ReportJob.organization_id == organization.id,
        ReportJob.report_type == "meraki_security",
        ReportJob.status == "completed",
    ))
    if job is None:
        raise HTTPException(status_code=404, detail="Completed Meraki report not found.")

    snapshot = (job.report_snapshot or {}).get("meraki")
    if not isinstance(snapshot, dict):
        raise HTTPException(status_code=404, detail="Saved Meraki evidence is unavailable.")

    summary = snapshot.get("summary") if isinstance(snapshot.get("summary"), dict) else {}
    summary_fields = (
        "network_count", "device_count", "appliance_network_count", "switch_network_count",
        "switch_device_count", "wireless_network_count", "wireless_device_count",
        "rf_profile_count", "rf_assignments_collected", "security_controls_collected",
        "security_controls_unavailable", "security_controls_unsupported",
        "topology_networks_collected", "licensing_status", "client_usage_status",
    )

    def text_field(item: dict[str, Any], key: str, limit: int = 200) -> str | None:
        value = item.get(key)
        return value[:limit] if isinstance(value, str) else None

    def bounded_rows(key: str, limit: int) -> tuple[list[Any], int]:
        rows = snapshot.get(key)
        rows = rows if isinstance(rows, list) else []
        return rows[:limit], max(0, len(rows) - limit)

    networks, more_networks = bounded_rows("networks", 100)
    devices, more_devices = bounded_rows("devices", 200)
    controls, more_controls = bounded_rows("security_controls", 200)
    topology, more_topology = bounded_rows("topology", 100)
    findings, more_findings = bounded_rows("findings", 100)
    warnings, more_warnings = bounded_rows("warnings", 100)

    client_usage = snapshot.get("client_usage") if isinstance(snapshot.get("client_usage"), dict) else {}
    client_usage_data = client_usage.get("data") if isinstance(client_usage.get("data"), dict) else {}
    raw_usage = client_usage_data.get("usage") if isinstance(client_usage_data.get("usage"), dict) else {}

    def safe_count(value: Any) -> int | None:
        return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 1_000_000_000 else None

    def safe_measure(value: Any) -> int | float | None:
        return value if isinstance(value, (int, float)) and not isinstance(value, bool) and 0 <= value <= 1_000_000_000_000 else None

    topology_summary = []
    for row in topology:
        if not isinstance(row, dict):
            continue
        data = row.get("data") if isinstance(row.get("data"), dict) else {}
        nodes = data.get("nodes") if isinstance(data.get("nodes"), list) else []
        links = data.get("links") if isinstance(data.get("links"), list) else []
        topology_summary.append({
            "network_name": text_field(row, "network_name"),
            "status": text_field(row, "status", 40),
            "node_count": len(nodes),
            "link_count": len(links),
            "omitted_node_count": safe_count(data.get("omitted_node_count")) or 0,
            "omitted_link_count": safe_count(data.get("omitted_link_count")) or 0,
            "reported_error_count": safe_count(data.get("reported_error_count")) or 0,
            "scope": text_field(data, "scope", 240),
        })

    serialized_controls = []
    for control in controls:
        if not isinstance(control, dict):
            continue
        data = control.get("data")
        preview, preview_truncated = bounded_meraki_evidence_preview(data)
        serialized_controls.append({
            "network_name": text_field(control, "network_name"),
            "control": text_field(control, "control"),
            "status": text_field(control, "status", 40),
            "evidence_preview": preview,
            "evidence_truncated": preview_truncated,
        })

    return {
        "report_id": job.id,
        "organization": {
            "id": text_field(snapshot.get("organization", {}) if isinstance(snapshot.get("organization"), dict) else {}, "id"),
            "name": text_field(snapshot.get("organization", {}) if isinstance(snapshot.get("organization"), dict) else {}, "name"),
        },
        "collected_at": text_field(snapshot, "collected_at", 80),
        "summary": {key: summary.get(key) for key in summary_fields if key in summary},
        "networks": [{
            "name": text_field(item, "name"),
            "product_types": [value[:80] for value in item.get("productTypes", [])[:20] if isinstance(value, str)] if isinstance(item.get("productTypes"), list) else [],
            "time_zone": text_field(item, "timeZone", 100),
        } for item in networks if isinstance(item, dict)],
        "devices": [{
            "name": text_field(item, "name"),
            "model": text_field(item, "model", 100),
            "status": text_field(item, "status", 40),
            "product_type": text_field(item, "productType", 80),
            "firmware": text_field(item, "firmware", 100),
            "network_id": text_field(item, "networkId", 128),
        } for item in devices if isinstance(item, dict)],
        "client_usage": {
            "status": text_field(client_usage, "status", 40) or "not_collected",
            "clients_with_usage_count": safe_count(client_usage_data.get("clients_with_usage_count")),
            "usage": {key: safe_measure(raw_usage.get(key)) for key in ("total", "downstream", "upstream") if safe_measure(raw_usage.get(key)) is not None},
            "usage_unit": text_field(client_usage_data, "usage_unit", 40),
            "requested_timespan_seconds": safe_count(client_usage_data.get("requested_timespan_seconds")),
        },
        "topology": topology_summary,
        "controls": serialized_controls,
        "findings": [{
            "title": text_field(item, "title"),
            "status": text_field(item, "status", 60),
            "detail": text_field(item, "detail", 500),
        } for item in findings if isinstance(item, dict)],
        "warnings": [item[:500] for item in warnings if isinstance(item, str)],
        "truncated": {
            "networks": more_networks,
            "devices": more_devices,
            "controls": more_controls,
            "topology": more_topology,
            "findings": more_findings,
            "warnings": more_warnings,
        },
    }


def bounded_meraki_evidence_preview(value: Any, *, max_chars: int = 3000) -> tuple[str, bool]:
    """Project only a bounded amount of stored JSON before encoding a UI preview."""
    state = {"nodes": 0, "truncated": False}

    def bounded(item: Any, depth: int = 0) -> Any:
        if state["nodes"] >= 256:
            state["truncated"] = True
            return "[preview truncated]"
        state["nodes"] += 1
        if depth >= 8 and isinstance(item, (dict, list)):
            state["truncated"] = True
            return "[preview depth limit]"
        if isinstance(item, str):
            if len(item) > 500:
                state["truncated"] = True
                return item[:500] + "…"
            return item
        if isinstance(item, dict):
            result = {}
            for index, (key, nested) in enumerate(item.items()):
                if index >= 64 or state["nodes"] >= 256:
                    state["truncated"] = True
                    break
                safe_key = str(key)[:128]
                if len(str(key)) > 128:
                    state["truncated"] = True
                result[safe_key] = bounded(nested, depth + 1)
            return result
        if isinstance(item, list):
            result = []
            for nested in item[:64]:
                if state["nodes"] >= 256:
                    state["truncated"] = True
                    break
                result.append(bounded(nested, depth + 1))
            if len(item) > len(result):
                state["truncated"] = True
            return result
        if item is None or isinstance(item, (bool, int, float)):
            return item
        state["truncated"] = True
        return str(type(item).__name__)

    safe_value = bounded(value)
    if value is None:
        return "No configuration data returned.", False
    encoded = json.dumps(safe_value, ensure_ascii=False, sort_keys=True)
    if len(encoded) > max_chars:
        encoded = encoded[:max_chars]
        state["truncated"] = True
    return encoded, bool(state["truncated"])


@app.get("/api/meraki/reports/{report_id}/snapshot")
def download_meraki_snapshot(report_id: int, request: Request, db: Session = Depends(get_db)):
    _user, organization, _membership = get_org_context(request, db)
    job = db.scalar(select(ReportJob).where(
        ReportJob.id == report_id, ReportJob.organization_id == organization.id,
        ReportJob.report_type == "meraki_security", ReportJob.status == "completed",
    ))
    if job is None or not (job.report_snapshot or {}).get("meraki"):
        raise HTTPException(status_code=404, detail="Completed Meraki evidence not found.")
    return Response(json.dumps(job.report_snapshot, ensure_ascii=False), media_type="application/json",
                    headers={"Cache-Control": "no-store", "Content-Disposition": f'attachment; filename="daedalus-meraki-evidence-{job.id}.json"'})


@app.post("/api/reports/external-posture")
def create_external_posture_report(
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    user, organization, _ = get_org_context(request, db)
    active_count = db.scalar(
        select(func.count(ReportJob.id)).where(
            ReportJob.organization_id == organization.id,
            ReportJob.status.in_(("queued", "running")),
        )
    ) or 0
    if active_count >= 3:
        raise HTTPException(status_code=429, detail="Three report jobs are already running for this workspace")

    now = utcnow()
    job = ReportJob(
        organization_id=organization.id,
        created_by_user_id=user.id,
        report_type="external_posture",
        domain=organization.domain,
        status="queued",
        progress=0,
        stage="Queued",
        file_name="pending.pdf",
        report_snapshot=capture_external_report_snapshot(db, organization, user),
        created_at=now,
        updated_at=now,
    )
    db.add(job)
    db.flush()
    job.file_name = f"daedalus-external-posture-{job.id}.pdf"
    audit(
        db,
        organization.id,
        user.id,
        "report.requested",
        {"report_id": job.id, "report_type": job.report_type},
    )
    db.commit()
    db.refresh(job)
    background_tasks.add_task(generate_report_job, job.id)
    return serialize_report_job(job, user)


@app.get("/api/reports/{report_id}/download")
def download_report(report_id: int, request: Request, db: Session = Depends(get_db)):
    _, organization, _ = get_org_context(request, db)
    job = db.scalar(
        select(ReportJob).where(
            ReportJob.id == report_id,
            ReportJob.organization_id == organization.id,
        )
    )
    if job is None:
        raise HTTPException(status_code=404, detail="Report not found")
    if job.status != "completed" or not job.artifact_path:
        raise HTTPException(status_code=409, detail="Report PDF is not ready yet")
    try:
        artifact = report_artifact(REPORTS_DIR, organization.id, job.file_name)
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=404, detail="Report PDF is unavailable") from exc
    return FileResponse(
        artifact,
        media_type="application/pdf",
        filename=job.file_name,
        headers={"Cache-Control": "no-store"},
    )


@app.post("/api/external-checks/{check_type}/run")
async def start_external_check(
    check_type: str,
    request: Request,
    db: Session = Depends(get_db),
):
    if check_type not in {"dns", "web", "web-active", "web-nikto"}:
        raise HTTPException(status_code=404, detail="Unknown external check")
    user, organization, _ = get_org_context(request, db, admin=True)
    if check_type in {"web-active", "web-nikto"} and not workspace_controls_available(db, organization):
        raise HTTPException(status_code=403, detail="Active website checks require domain verification or an active override")
    if check_type == "web-nikto":
        result = await run_in_threadpool(_execute_external_check, organization.id, user.id, check_type, "manual", True)
        return JSONResponse(result, status_code=202)
    result = await run_in_threadpool(
        execute_external_check, organization.id, user.id, check_type
    )
    await publish_external_check_result(organization.id, result)
    return result


@app.post("/api/external-checks/{check_type}/runs/{run_id}/cancel")
def cancel_queued_website_audit(
    check_type: str, run_id: int, request: Request, db: Session = Depends(get_db),
):
    user, organization, _ = get_org_context(request, db, admin=True)
    if check_type != "web-nikto":
        raise HTTPException(status_code=404, detail="Unknown queued website audit")
    run = db.scalar(select(ExternalCheckRun).where(
        ExternalCheckRun.id == run_id, ExternalCheckRun.organization_id == organization.id,
        ExternalCheckRun.check_type == check_type,
    ))
    if run is None:
        raise HTTPException(status_code=404, detail="Website audit not found")
    if run.status == "cancelled":
        return serialize_external_run(run, db.get(User, run.triggered_by_user_id))
    cancelled = db.execute(update(ExternalCheckRun).where(
        ExternalCheckRun.id == run_id, ExternalCheckRun.organization_id == organization.id,
        ExternalCheckRun.status == "queued",
    ).values(status="cancelled", completed_at=utcnow(), error_summary="Cancelled before collection by a workspace admin."))
    if cancelled.rowcount != 1:
        db.rollback()
        raise HTTPException(status_code=409, detail="Only queued audits can be cancelled. Collection may already have started.")
    audit(db, organization.id, user.id, "external_check.cancelled", {
        "run_id":run_id, "check_type":check_type, "phase":"queued",
    })
    db.commit()
    db.refresh(run)
    return serialize_external_run(run, db.get(User, run.triggered_by_user_id))


@app.put("/api/external-checks/{check_type}/schedule")
async def update_external_check_schedule(
    check_type: str,
    payload: ExternalCheckScheduleInput,
    request: Request,
    db: Session = Depends(get_db),
):
    if check_type not in {"dns", "web"}:
        raise HTTPException(status_code=404, detail="Unknown external check")
    user, organization, _ = get_org_context(request, db, admin=True)
    if payload.enabled and organization.verification_status != "verified":
        raise HTTPException(
            status_code=403,
            detail="Verify this domain before enabling recurring checks.",
        )

    now = utcnow()
    schedule = db.scalar(
        select(ExternalCheckSchedule).where(
            ExternalCheckSchedule.organization_id == organization.id,
            ExternalCheckSchedule.check_type == check_type,
        )
    )
    if schedule is None:
        schedule = ExternalCheckSchedule(
            organization_id=organization.id,
            check_type=check_type,
            enabled=payload.enabled,
            interval_hours=payload.interval_hours,
            next_run_at=now + timedelta(hours=payload.interval_hours) if payload.enabled else None,
            updated_by_user_id=user.id,
            updated_at=now,
        )
        db.add(schedule)
    else:
        schedule.enabled = payload.enabled
        schedule.interval_hours = payload.interval_hours
        schedule.next_run_at = (
            now + timedelta(hours=payload.interval_hours) if payload.enabled else None
        )
        schedule.updated_by_user_id = user.id
        schedule.updated_at = now
    audit(
        db,
        organization.id,
        user.id,
        "external_check.schedule_updated",
        {
            "check_type": check_type,
            "enabled": payload.enabled,
            "interval_hours": payload.interval_hours,
            "next_run_at": iso_utc(schedule.next_run_at),
        },
    )
    db.commit()
    db.refresh(schedule)
    response = serialize_external_schedule(schedule, check_type)
    await live_hub.publish(
        organization.id,
        {"type": "external_check_schedule_updated", "schedule": response},
    )
    return response


@app.post("/api/workspaces/select")
def select_workspace(
    payload: WorkspaceSelectRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    user = get_session_user(request, db)
    membership = db.scalar(
        select(Membership).where(
            Membership.user_id == user.id,
            Membership.organization_id == payload.organization_id,
            Membership.status == "approved",
        )
    )
    if membership is None:
        raise HTTPException(status_code=403, detail="Approved workspace membership required")
    request.session["organization_id"] = payload.organization_id
    return {"ok": True}


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    try:
        user = get_session_user(request, db)
    except HTTPException:
        return RedirectResponse("/", status_code=303)
    organization_id = request.session.get("organization_id")
    row = None
    if organization_id:
        row = db.execute(
            select(Membership, Organization)
            .join(Organization, Organization.id == Membership.organization_id)
            .where(
                Membership.user_id == user.id,
                Membership.organization_id == int(organization_id),
                Membership.status == "approved",
            )
        ).first()
    if row is None:
        row = db.execute(
            select(Membership, Organization)
            .join(Organization, Organization.id == Membership.organization_id)
            .where(Membership.user_id == user.id, Membership.status == "approved")
            .order_by(Organization.id)
        ).first()
    if row is None:
        user_memberships = db.execute(
            select(Membership, Organization)
            .join(Organization, Organization.id == Membership.organization_id)
            .where(Membership.user_id == user.id)
            .order_by(Organization.name)
        ).all()
        return templates.TemplateResponse(
            request,
            "dashboard.html",
            {
                "user": user,
                "organization": None,
                "membership": None,
                "agents": [],
                "recent_events": [],
                "workspaces": user_memberships,
                "demo_mode": DEMO_MODE,
            },
        )
    membership, organization = row
    request.session["organization_id"] = organization.id
    user_memberships = db.execute(
        select(Membership, Organization)
        .join(Organization, Organization.id == Membership.organization_id)
        .where(Membership.user_id == user.id, Membership.status == "approved")
        .order_by(Organization.name)
    ).all()
    scoped_key = getattr(request.state, "user_api_key", None)
    if scoped_key is not None:
        user_memberships = [(m, o) for m, o in user_memberships if o.id == scoped_key.organization_id]
    agents = db.scalars(
        select(Agent)
        .where(Agent.organization_id == organization.id)
        .order_by(Agent.created_at.desc())
    ).all()
    recent_events = db.scalars(
        select(ScanEvent)
        .where(ScanEvent.organization_id == organization.id)
        .order_by(ScanEvent.id.desc())
        .limit(25)
    ).all()
    probation_override = active_probation_override(db, organization.id)
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "user": user,
            "organization": organization,
            "membership": membership,
            "agents": agents,
            "recent_events": recent_events,
            "agent_status": agent_status,
            "workspaces": user_memberships,
            "demo_mode": DEMO_MODE,
            "workspace_controls_enabled": (
                organization.verification_status == "verified" or probation_override is not None
            ),
            "probation_override": probation_override,
        },
    )


def _website_certificate_summary(snapshot, now):
    tls = snapshot.get("tls")
    expiry = tls.get("valid_until") if isinstance(tls, dict) else None
    try:
        expires = datetime.fromisoformat(expiry.replace("Z", "+00:00")) if isinstance(expiry, str) else None
        if expires is None or expires.tzinfo is None:
            return "Certificate expiry unknown", True
        current = now.replace(tzinfo=UTC) if now.tzinfo is None else now
        remaining = expires - current
    except (ValueError, OverflowError):
        return "Certificate expiry unknown", True
    date = expires.astimezone(UTC).date().isoformat()
    if remaining <= timedelta(0):
        return f"Saved certificate expired {date}", True
    if remaining < timedelta(days=30):
        return f"Saved certificate expires soon: {date}", True
    return f"Saved certificate expires {date}", False


def _cis_latest_assessments(db: Session, organization_id: int):
    ranked = select(
        CISReport.id, CISReport.device_id, CISReport.collected_at, CISReport.summary,
        func.row_number().over(
            partition_by=CISReport.device_id,
            order_by=(CISReport.collected_at.desc(), CISReport.id.desc()),
        ).label("recency_rank"),
    ).where(CISReport.organization_id == organization_id).subquery()
    return {row.device_id: row for row in db.execute(select(ranked).where(ranked.c.recency_rank == 1))}


def _cis_assessment_state(report, now):
    if report is None:
        return "missing"
    if report.collected_at > now:
        return "unknown"
    return "current" if report.collected_at >= now - timedelta(hours=36) else "stale"


class VendorReviewInput(BaseModel):
    run_id: int = Field(gt=0, strict=True)
    resource_index: int = Field(ge=0, lt=100, strict=True)
    request_id: UUID
    status: Literal["reviewed", "needs_action", "monitor"]
    note: str = Field(min_length=8, max_length=2000)


def _vendor_review_run(db, organization_id, run_id):
    run = db.get(ExternalCheckRun, run_id)
    if run is None or run.organization_id != organization_id or run.check_type != "web" or run.status not in {"completed", "completed_with_warnings"}:
        raise HTTPException(status_code=404, detail="Saved website inventory not found")
    return run


def _serialize_vendor_review(row):
    return {"id": row.id, "run_id": row.run_id, "resource_index": row.resource_index,
            "origin": row.origin, "status": row.status, "note": row.note,
            "actor_user_id": row.actor_user_id, "created_at": iso_utc(row.created_at)}


@app.get("/api/vendor-reviews")
def list_vendor_reviews(run_id: int, request: Request, before: int | None = None, db: Session = Depends(get_db)):
    _, organization, _ = get_org_context(request, db)
    _vendor_review_run(db, organization.id, run_id)
    scope = (VendorReview.organization_id == organization.id, VendorReview.run_id == run_id)
    ranked = select(VendorReview.id, func.row_number().over(partition_by=VendorReview.resource_index, order_by=VendorReview.id.desc()).label("rank")).where(*scope).subquery()
    latest = db.scalars(select(VendorReview).join(ranked, ranked.c.id == VendorReview.id).where(ranked.c.rank == 1).order_by(VendorReview.resource_index)).all()
    query = select(VendorReview).where(*scope)
    if before is not None:
        query = query.where(VendorReview.id < max(1, before))
    rows = db.scalars(query.order_by(VendorReview.id.desc()).limit(101)).all()
    more = len(rows) > 100
    rows = rows[:100]
    return {"reviews": [_serialize_vendor_review(row) for row in latest],
            "history": [_serialize_vendor_review(row) for row in rows],
            "history_has_more": more, "history_next_before": rows[-1].id if more else None,
            "security_assessment": False}


@app.post("/api/vendor-reviews")
def save_vendor_review(payload: VendorReviewInput, request: Request, db: Session = Depends(get_db)):
    user, organization, _ = get_org_context(request, db, admin=True)
    run = _vendor_review_run(db, organization.id, payload.run_id)
    resources = (run.snapshot or {}).get("external_resources")
    if not isinstance(resources, list) or payload.resource_index >= len(resources):
        raise HTTPException(status_code=422, detail="Choose an origin in this saved inventory")
    resource = resources[payload.resource_index]
    if not isinstance(resource, dict) or not resource.get("host") or resource.get("scheme") not in {"http", "https"}:
        raise HTTPException(status_code=422, detail="This inventory origin cannot be reviewed")
    note = payload.note.strip()
    if len(note) < 8:
        raise HTTPException(status_code=422, detail="Provide a review rationale of at least eight characters")
    origin = {name: resource.get(name) for name in ("host", "scheme", "port")}
    def existing():
        return db.scalar(select(VendorReview).where(VendorReview.organization_id == organization.id, VendorReview.request_id == str(payload.request_id)))
    def replay(row):
        if (row.run_id, row.resource_index, row.status, row.note, row.actor_user_id, row.origin) != (run.id, payload.resource_index, payload.status, note, user.id, origin):
            raise HTTPException(status_code=409, detail="Review request identifier already used")
        return {"review": _serialize_vendor_review(row), "created": False}
    prior = existing()
    if prior is not None:
        return replay(prior)
    row = VendorReview(organization_id=organization.id, run_id=run.id, resource_index=payload.resource_index,
                      request_id=str(payload.request_id), actor_user_id=user.id, origin=origin,
                      status=payload.status, note=note, created_at=utcnow())
    db.add(row)
    audit(db, organization.id, user.id, "vendor.review.recorded", {"run_id": run.id, "resource_index": payload.resource_index, "status": payload.status, "request_id": str(payload.request_id)})
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        prior = existing()
        if prior is None:
            raise
        return replay(prior)
    return {"review": _serialize_vendor_review(row), "created": True}


@app.get("/api/workspace-posture")
def workspace_posture(request: Request, db: Session = Depends(get_db)):
    """Summarize saved workspace evidence without exposing raw results or credentials."""
    _, org, _ = get_org_context(request, db)
    areas = []
    for kind, title in (("dns", "DNS & email"), ("web", "Website")):
        conditions = (ExternalCheckRun.organization_id == org.id, ExternalCheckRun.check_type == kind)
        latest = db.scalar(select(ExternalCheckRun).where(*conditions).order_by(ExternalCheckRun.id.desc()).limit(1))
        saved = db.scalar(select(ExternalCheckRun).where(*conditions, ExternalCheckRun.status.in_(("completed", "completed_with_warnings"))).order_by(ExternalCheckRun.id.desc()).limit(1))
        snapshot = (saved.snapshot or {}) if saved else {}
        state = "not_assessed" if saved is None else "recorded"
        summary = "No completed assessment yet."
        if saved and kind == "dns":
            assessment = snapshot.get("email_authentication_assessment") or {}
            spf = (assessment.get("spf") or {}).get("label") or "Not assessed"
            dmarc = (assessment.get("dmarc") or {}).get("label") or "Not assessed"
            unknown = len(snapshot.get("resolver_errors") or {})
            summary = f"SPF: {spf} · DMARC: {dmarc} · {unknown} unknown lookup(s)"
            if unknown or saved.status == "completed_with_warnings" or any((assessment.get(policy) or {}).get("tone") != "good" for policy in ("spf", "dmarc")): state = "attention"
        elif saved:
            headers = snapshot.get("security_headers") or {}
            absent = sum(not value for value in headers.values())
            certificate_label, certificate_review = _website_certificate_summary(snapshot, utcnow())
            summary = f"HTTPS {snapshot.get('http_status') or 'unknown'} · {certificate_label} · {absent} selected header(s) absent"
            if certificate_review or absent or not headers or not (200 <= int(snapshot.get("http_status") or 0) < 400): state = "attention"
        if latest and latest.status in {"queued", "running", "failed"}:
            state = "running" if latest.status in {"queued", "running"} else "unavailable"
        areas.append({"key":kind, "title":title, "state":state, "summary":summary,
            "updated_at":iso_utc(saved.completed_at) if saved else None,
            "latest_attempt_status":latest.status if latest else None})
    nikto = db.scalar(select(ExternalCheckRun).where(
        ExternalCheckRun.organization_id == org.id, ExternalCheckRun.check_type == "web-nikto",
        ExternalCheckRun.status.in_(("completed", "completed_with_warnings"))
    ).order_by(ExternalCheckRun.id.desc()).limit(1))
    if nikto:
        areas[1]["audit_summary"] = f"Deeper audit: {len((nikto.snapshot or {}).get('findings') or [])} observations · coverage remains unconfirmed"
        areas[1]["audit_updated_at"] = iso_utc(nikto.completed_at)
        if areas[1]["state"] in {"recorded", "not_assessed"}: areas[1]["state"] = "attention"
    agents = db.scalars(select(Agent).where(Agent.organization_id == org.id, Agent.enabled.is_(True))).all()
    online = sum(agent_status(agent) == "online" for agent in agents)
    scoped = sum(bool(agent.authorized_networks) for agent in agents)
    ready = sum(agent_status(agent) == "online" and agent.nmapui_ready is True for agent in agents)
    completed_scans = 0
    scan_attempts = 0
    scan_times = []
    for agent in agents:
        occurred = func.coalesce(ScanEvent.occurred_at, ScanEvent.created_at)
        job_id = db.scalar(select(ScanEvent.source_job_id).where(
            ScanEvent.organization_id == org.id, ScanEvent.agent_id == agent.id,
            ScanEvent.source_job_type == "scan", ScanEvent.source_job_id.is_not(None),
        ).group_by(ScanEvent.source_job_id).order_by(func.max(occurred).desc(), func.max(ScanEvent.id).desc()).limit(1))
        if job_id:
            scan_attempts += 1
            run = scanner_run_summary(db, agent, job_id)
            if run["status"] == "completed" and not run["group_metadata_conflict"]:
                completed_scans += 1
                scan_times.append(run["last_occurred_at"])
    scanner_state = "not_assessed" if not scan_attempts else "recorded" if completed_scans == len(agents) else "attention"
    if agents and (ready != len(agents) or scoped != len(agents) or (completed_scans and completed_scans != len(agents))):
        scanner_state = "attention"
    areas.append({"key":"scanners", "title":"Internal network", "state":scanner_state,
        "summary":f"{ready}/{len(agents)} scan engines ready · {online} online · {scoped} with approved ranges · {completed_scans} with a completed latest scan. Saved runs do not establish coverage of all approved ranges." if agents else "No enabled scanners in this workspace.",
        "updated_at":max(scan_times, default=None),
        "availability_updated_at":iso_utc(max((a.last_seen_at for a in agents if a.last_seen_at), default=None))})
    devices = db.scalars(select(CISDevice).where(CISDevice.organization_id == org.id)).all()
    now = utcnow()
    latest_assessments = _cis_latest_assessments(db, org.id)
    coverage = {state: 0 for state in ("current", "stale", "unknown", "missing")}
    for device in devices:
        coverage[_cis_assessment_state(latest_assessments.get(device.id), now)] += 1
    reporting = coverage["current"]
    cis = db.scalar(select(CISReport).where(CISReport.organization_id == org.id).order_by(CISReport.collected_at.desc(), CISReport.id.desc()).limit(1))
    cis_summary = f"{reporting}/{len(devices)} devices with current assessments · {coverage['stale']} stale · {coverage['missing']} missing · {coverage['unknown']} unknown"
    review_devices = sum(any(
        type((report.summary or {}).get(name)) is not int or (report.summary or {}).get(name, 0) != 0
        for name in ("fail", "manual", "error")
    ) for report in latest_assessments.values())
    cis_needs_review = review_devices > 0
    cis_summary += f" · {review_devices} devices with checks needing review"
    if cis:
        counts = {name: value if type(value) is int and value >= 0 else None
                  for name in ("fail", "manual", "error") for value in [(cis.summary or {}).get(name)]}
        cis_needs_review = cis_needs_review or any(value is None or value > 0 for value in counts.values())
        cis_summary += f" · latest report pass rate: {(cis.summary or {}).get('score', 'unknown')}%"
        cis_summary += " · " + " · ".join(
            f"{counts[name] if counts[name] is not None else 'unknown'} {label}"
            for name, label in (("fail", "failed"), ("manual", "manual"), ("error", "errors"))
        )
    else:
        cis_summary += " · no baseline results yet"
    areas.append({"key":"cis", "title":"Endpoint checks", "state":"recorded" if cis and reporting == len(devices) and not cis_needs_review else "attention" if devices or cis else "not_assessed",
        "summary":cis_summary, "updated_at":iso_utc(cis.collected_at) if cis else None})
    meraki = db.scalar(select(ReportJob).where(ReportJob.organization_id == org.id, ReportJob.report_type == "meraki_security", ReportJob.status == "completed").order_by(ReportJob.id.desc()).limit(1))
    totals = meraki_review_summary((meraki.report_snapshot or {}).get("meraki")) if meraki else {}
    meraki_attempt = db.scalar(select(ReportJob).where(ReportJob.organization_id == org.id, ReportJob.report_type == "meraki_security").order_by(ReportJob.id.desc()).limit(1))
    review = totals.get("review_observation_count")
    unavailable = totals.get("security_controls_unavailable")
    meraki_state = "attention" if meraki and (review is None or review > 0 or unavailable is None or unavailable > 0) else "recorded" if meraki else "not_assessed"
    if meraki_attempt and meraki_attempt.status in {"queued", "running"}:
        meraki_state = "running"
    elif meraki_attempt and meraki_attempt.status == "failed":
        meraki_state = "unavailable"
    areas.append({"key":"meraki", "title":"Meraki network", "state":meraki_state,
        "summary":f"{review if review is not None else 'Unknown'} review observations · {unavailable if unavailable is not None else 'unknown'} controls unavailable · {totals.get('network_count', 'Unknown')} networks · {totals.get('device_count', 'unknown')} assigned devices" if meraki else "No completed network report yet.",
        "latest_attempt_status":meraki_attempt.status if meraki_attempt else None,
        "updated_at":iso_utc(meraki.completed_at) if meraki else None})
    return JSONResponse({"domain":org.domain, "areas":areas, "assessed_at":iso_utc(utcnow())}, headers={"Cache-Control":"no-store"})


@app.get("/api/dashboard")
def dashboard_data(request: Request, db: Session = Depends(get_db)):
    _, organization, membership = get_org_context(request, db)
    probation_override = active_probation_override(db, organization.id)
    agents = db.scalars(
        select(Agent)
        .where(Agent.organization_id == organization.id)
        .order_by(Agent.created_at.desc())
    ).all()
    events = db.scalars(
        select(ScanEvent)
        .where(ScanEvent.organization_id == organization.id)
        .order_by(ScanEvent.id.desc())
        .limit(50)
    ).all()
    return {
        "organization": {
            "id": organization.id,
            "name": organization.name,
            "domain": organization.domain,
            "verification_status": organization.verification_status,
            "controls_enabled": (
                organization.verification_status == "verified" or probation_override is not None
            ),
            "probation_override_expires_at": (
                probation_override.expires_at.isoformat() + "Z" if probation_override else None
            ),
        },
        "role": membership.role,
        "agents": [
            {
                "id": agent.id,
                "name": agent.name,
                "enabled": bool(agent.enabled),
                "status": agent_status(agent),
                "bridge_online": agent_bridge_online(agent),
                "last_seen_at": (
                    agent.last_seen_at.isoformat() + "Z" if agent.last_seen_at else None
                ),
                "bridge_version": agent.bridge_version,
                "platform": agent.host_platform,
                "nmapui_version": agent.nmapui_version,
                "nmapui_ready": agent.nmapui_ready,
                "nmapui_restart_supported": bool(agent.nmapui_restart_supported),
            "detected_networks": agent.detected_networks or [],
            "command_protocol_version": agent.command_protocol_version or 0,
                "authorized_networks": agent.authorized_networks or [],
                "detected_networks": agent.detected_networks or [],
            }
            for agent in agents
        ],
        "events": [serialize_event(event) for event in events],
    }


@app.post("/api/enrollment-tokens")
def create_enrollment_token(
    request: Request,
    payload: ScannerEnrollmentOptions | None = None,
    db: Session = Depends(get_db),
):
    user, organization, _ = get_org_context(request, db, admin=True)
    if not workspace_controls_available(db, organization):
        raise HTTPException(
            status_code=403,
            detail="Verify the domain or grant a 14-day probation override before enrolling scanners.",
        )
    clear_code = secrets.token_urlsafe(24)
    now = utcnow()
    token = EnrollmentToken(
        organization_id=organization.id,
        code_hash=token_digest(clear_code),
        created_by_user_id=user.id,
        scanner_name=payload.name if payload else None,
        authorized_networks=payload.authorized_networks if payload else None,
        expires_at=now + timedelta(minutes=15),
        created_at=now,
    )
    db.add(token)
    audit(
        db,
        organization.id,
        user.id,
        "scanner.enrollment_token_issued",
        {
            "expires_at": token.expires_at.isoformat() + "Z",
            "scanner_name": token.scanner_name,
            "authorized_networks": token.authorized_networks or [],
        },
    )
    db.commit()
    return JSONResponse({
        "code": clear_code,
        "expires_at": token.expires_at.isoformat() + "Z",
        "organization": organization.name,
        "scanner_name": token.scanner_name,
        "authorized_networks": token.authorized_networks or [],
    }, headers={"Cache-Control": "no-store"})


@app.get("/api/agents/bridge/download")
def download_agent_bundle(request: Request, db: Session = Depends(get_db)):
    user, organization, _ = get_org_context(request, db, admin=True)
    if not workspace_controls_available(db, organization):
        raise HTTPException(
            status_code=403,
            detail="Verify the domain or grant a 14-day probation override before downloading a scanner bridge.",
        )
    bundle = build_agent_bundle()
    source_bundle_path = PACKAGE_DIR / "agent_bundle" / "nmapui-source.zip"
    with zipfile.ZipFile(io.BytesIO(source_bundle_path.read_bytes())) as source_archive:
        source_manifest = json.loads(
            source_archive.read("daedalus-nmapui-source/manifest.json")
        )
    audit(
        db,
        organization.id,
        user.id,
        "scanner.bridge_bundle_downloaded",
        {
            "bridge_version": __version__,
            "nmapui_version": source_manifest["version"],
            "nmapui_source_sha256": source_manifest["source_tree_sha256"],
            "bundle_sha256": hashlib.sha256(bundle).hexdigest(),
        },
    )
    db.commit()
    return Response(
        content=bundle,
        media_type="application/zip",
        headers={
            "Content-Disposition": 'attachment; filename="daedalus-scanner-kit.zip"',
            "Cache-Control": "no-store",
        },
    )


@app.post("/api/agents/enroll")
def enroll_agent(payload: EnrollmentRequest, db: Session = Depends(get_db)):
    code_hash = token_digest(payload.code.strip())
    enrollment = db.scalar(
        select(EnrollmentToken).where(EnrollmentToken.code_hash == code_hash)
    )
    now = utcnow()
    if (
        enrollment is None
        or enrollment.used_at is not None
        or enrollment.expires_at < now
    ):
        raise HTTPException(status_code=401, detail="Enrollment code is invalid or expired")
    organization = db.get(Organization, enrollment.organization_id)
    if organization is None or not workspace_controls_available(db, organization):
        raise HTTPException(status_code=403, detail="Workspace verification or active override required")
    if enrollment.scanner_name and enrollment.scanner_name != payload.name.strip():
        raise HTTPException(status_code=409, detail="The scanner name does not match this enrollment code.")

    clear_agent_token = secrets.token_urlsafe(40)
    agent = Agent(
        organization_id=organization.id,
        name=payload.name.strip(),
        authorized_networks=enrollment.authorized_networks or [],
        token_hash=token_digest(clear_agent_token),
        enabled=True,
        nmapui_connected=False,
        last_seen_at=now,
        created_at=now,
    )
    enrollment.used_at = now
    db.add(agent)
    db.flush()
    audit(
        db,
        organization.id,
        enrollment.created_by_user_id,
        "scanner.enrolled",
        {"agent_id": agent.id, "name": agent.name},
    )
    db.commit()
    db.refresh(agent)
    return {
        "agent_id": agent.id,
        "agent_name": agent.name,
        "organization_id": organization.id,
        "organization": organization.name,
        "agent_token": clear_agent_token,
        "authorized_networks": agent.authorized_networks or [],
                "detected_networks": agent.detected_networks or [],
    }


@app.post("/api/agents/{agent_id}/heartbeat")
async def agent_heartbeat(
    agent_id: int,
    payload: AgentHeartbeatRequest,
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    agent = require_agent(db, agent_id, authorization)
    agent.last_seen_at = utcnow()
    if payload.detected_networks is not None:
        previous_networks = agent.detected_networks or []
        if previous_networks != payload.detected_networks:
            audit(db, agent.organization_id, None, "scanner.connection_changed",
                  {"agent_id": agent.id, "previous_networks": previous_networks,
                   "detected_networks": payload.detected_networks})
        agent.detected_networks = payload.detected_networks
    agent.nmapui_connected = payload.nmapui_connected
    agent.nmapui_restart_supported = payload.nmapui_restart_supported
    agent.command_protocol_version = payload.command_protocol_version
    if payload.version:
        agent.bridge_version = payload.version
    if payload.platform:
        agent.host_platform = payload.platform
    if payload.nmapui_version:
        agent.nmapui_version = payload.nmapui_version
    if payload.nmapui_ready is not None:
        agent.nmapui_ready = payload.nmapui_ready
    db.commit()
    await live_hub.publish(
        agent.organization_id,
        {
            "type": "agent_status",
            "agent_id": agent.id,
            "name": agent.name,
            "status": agent_status(agent),
            "bridge_online": agent_bridge_online(agent),
            "nmapui_connected": agent.nmapui_connected,
            "bridge_version": agent.bridge_version,
            "platform": agent.host_platform,
            "nmapui_version": agent.nmapui_version,
            "nmapui_ready": agent.nmapui_ready,
            "nmapui_restart_supported": bool(agent.nmapui_restart_supported),
                "command_protocol_version": agent.command_protocol_version or 0,
        },
    )
    return {"ok": True, "status": agent_status(agent)}


@app.post("/api/agents/{agent_id}/events")
async def receive_agent_event(
    agent_id: int,
    payload: AgentEventRequest,
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    agent = require_agent(db, agent_id, authorization)
    serialized = json.dumps(payload.payload, separators=(",", ":"), ensure_ascii=False)
    if len(serialized.encode("utf-8")) > 512_000:
        raise HTTPException(status_code=413, detail="Event payload exceeds 512 KB")
    now = utcnow()
    client_event_id = str(payload.client_event_id) if payload.client_event_id else None
    occurred_at = payload.occurred_at
    if occurred_at is not None:
        occurred_at = occurred_at.replace(tzinfo=occurred_at.tzinfo or UTC).astimezone(UTC).replace(tzinfo=None)
    source_job_id = str(payload.source_job_id) if payload.source_job_id else None
    duplicate = db.scalar(select(ScanEvent).where(
        ScanEvent.agent_id == agent.id, ScanEvent.client_event_id == client_event_id,
    )) if client_event_id else None
    if duplicate:
        if duplicate.event_name != payload.event_name or duplicate.payload != payload.payload or duplicate.occurred_at != occurred_at or duplicate.source_job_id != source_job_id or duplicate.source_job_type != payload.source_job_type:
            raise HTTPException(status_code=409, detail="This scanner event ID already contains different evidence.")
        db.commit()
        await notify_scanner_run_comparison(db, agent, duplicate)
        return {"ok": True, "duplicate": True, "event_id": duplicate.id}
    event = ScanEvent(
        organization_id=agent.organization_id,
        agent_id=agent.id,
        event_name=payload.event_name,
        client_event_id=client_event_id,
        source_job_id=source_job_id, source_job_type=payload.source_job_type,
        occurred_at=occurred_at,
        payload=payload.payload,
        created_at=now,
    )
    db.add(event)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        duplicate = db.scalar(select(ScanEvent).where(
            ScanEvent.agent_id == agent.id, ScanEvent.client_event_id == client_event_id,
        )) if client_event_id else None
        if duplicate and duplicate.event_name == payload.event_name and duplicate.payload == payload.payload and duplicate.occurred_at == occurred_at and duplicate.source_job_id == source_job_id and duplicate.source_job_type == payload.source_job_type:
            await notify_scanner_run_comparison(db, agent, duplicate)
            return {"ok": True, "duplicate": True, "event_id": duplicate.id}
        raise HTTPException(status_code=409, detail="A scanner event identity conflicted with existing evidence.")
    db.refresh(event)
    message = {"type": "scan_event", **serialize_event(event)}
    await live_hub.publish(agent.organization_id, message)
    await notify_scanner_run_comparison(db, agent, event)
    return {"ok": True, "duplicate": False, "event_id": event.id}


MAX_SCANNER_ARTIFACT_BYTES = 32 * 1024 * 1024


def scanner_artifact_path(event: ScanEvent) -> Path:
    if not event.client_event_id or not event.artifact_sha256:
        raise HTTPException(status_code=404, detail="Scanner artifact not found.")
    return DATA_DIR / "scanner-artifacts" / str(event.organization_id) / str(event.agent_id) / (str(UUID(event.client_event_id)) + ".json")


def load_scanner_event_payload(event: ScanEvent) -> Any:
    """Read saved scanner evidence after checking its immutable size and digest."""
    if not event.artifact_sha256:
        return event.payload
    path = scanner_artifact_path(event)
    try:
        if path.is_symlink() or path.stat().st_size != event.artifact_size_bytes or path.stat().st_size > MAX_SCANNER_ARTIFACT_BYTES:
            raise OSError("Artifact size does not match saved evidence")
        contents = path.read_bytes()
        if hashlib.sha256(contents).hexdigest() != event.artifact_sha256:
            raise OSError("Artifact digest does not match saved evidence")
        return json.loads(contents)
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=409, detail="Saved scanner evidence is missing or has changed.") from exc


@app.post("/api/agents/{agent_id}/event-artifacts")
async def receive_scanner_artifact(
    agent_id: int, request: Request,
    authorization: str | None = Header(default=None), db: Session = Depends(get_db),
):
    agent = require_agent(db, agent_id, authorization)
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            length = int(content_length)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid artifact content length.") from exc
        if length < 0 or length > MAX_SCANNER_ARTIFACT_BYTES:
            raise HTTPException(status_code=413, detail="Scanner artifacts are limited to 32 MiB of uncompressed JSON.")
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > MAX_SCANNER_ARTIFACT_BYTES:
            raise HTTPException(status_code=413, detail="Scanner artifacts are limited to 32 MiB of uncompressed JSON.")
        body.extend(chunk)
    try:
        payload = AgentEventRequest.model_validate(json.loads(body))
        if payload.client_event_id is None or payload.occurred_at is None:
            raise ValueError("Artifact identity and collection timestamp are required")
        contents = json.dumps(payload.payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (ValueError, UnicodeDecodeError, ValidationError, TypeError) as exc:
        raise HTTPException(status_code=422, detail="The scanner artifact needs valid JSON, an event UUID and collection timestamp.") from exc
    digest = hashlib.sha256(contents).hexdigest()
    occurred_at = payload.occurred_at.replace(tzinfo=payload.occurred_at.tzinfo or UTC).astimezone(UTC).replace(tzinfo=None)
    client_id = str(payload.client_event_id)

    def find_duplicate():
        return db.scalar(select(ScanEvent).where(ScanEvent.agent_id == agent.id, ScanEvent.client_event_id == client_id))

    def matches(event):
        return event.artifact_sha256 == digest and event.event_name == payload.event_name and event.occurred_at == occurred_at and event.source_job_id == (str(payload.source_job_id) if payload.source_job_id else None) and event.source_job_type == payload.source_job_type

    duplicate = find_duplicate()
    if duplicate:
        if not matches(duplicate):
            raise HTTPException(status_code=409, detail="This scanner event ID already contains different evidence.")
        load_scanner_event_payload(duplicate)
        await notify_scanner_run_comparison(db, agent, duplicate)
        return {"ok": True, "duplicate": True, "event_id": duplicate.id}

    event = ScanEvent(
        organization_id=agent.organization_id, agent_id=agent.id, client_event_id=client_id,
        event_name=payload.event_name, occurred_at=occurred_at, created_at=utcnow(),
        source_job_id=str(payload.source_job_id) if payload.source_job_id else None, source_job_type=payload.source_job_type,
        artifact_sha256=digest, artifact_size_bytes=len(contents),
        payload={"artifact": True, "payload_type": type(payload.payload).__name__,
                 "item_count": len(payload.payload) if isinstance(payload.payload, (dict, list)) else None,
                 "summary": "Full scanner evidence is available as a saved JSON artifact."},
    )
    path = scanner_artifact_path(event)
    try:
        for directory in (DATA_DIR / "scanner-artifacts", path.parent.parent, path.parent):
            if directory.is_symlink():
                raise OSError("Artifact directory cannot be a symbolic link")
            directory.mkdir(parents=True, mode=0o700, exist_ok=True)
            directory.chmod(0o700)
        temporary = path.with_suffix("." + secrets.token_hex(8) + ".tmp")
        try:
            with temporary.open("xb") as output:
                temporary.chmod(0o600)
                output.write(contents)
                output.flush()
                os.fsync(output.fileno())
            try:
                os.link(temporary, path)  # Atomic creation without replacing immutable evidence.
            except FileExistsError:
                if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                    raise HTTPException(status_code=409, detail="This scanner artifact identity conflicts with saved evidence.")
        finally:
            temporary.unlink(missing_ok=True)
    except OSError as exc:
        raise HTTPException(status_code=503, detail="Scanner artifact storage is unavailable; retry this upload.") from exc
    db.add(event)
    audit(db, agent.organization_id, None, "scanner.artifact.received", {
        "agent_id": agent.id, "client_event_id": client_id,
        "size_bytes": len(contents), "sha256": digest,
    })
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        duplicate = find_duplicate()
        if duplicate and matches(duplicate):
            await notify_scanner_run_comparison(db, agent, duplicate)
            return {"ok": True, "duplicate": True, "event_id": duplicate.id}
        raise HTTPException(status_code=409, detail="A scanner artifact identity conflicted with existing evidence.")
    db.refresh(event)
    await live_hub.publish(agent.organization_id, {"type": "scan_event", **serialize_event(event)})
    await notify_scanner_run_comparison(db, agent, event)
    return {"ok": True, "duplicate": False, "event_id": event.id}


@app.get("/api/events/{event_id}/artifact")
def download_scanner_artifact(event_id: int, request: Request, db: Session = Depends(get_db)):
    _user, organization, _membership = get_org_context(request, db)
    event = db.scalar(select(ScanEvent).where(ScanEvent.id == event_id, ScanEvent.organization_id == organization.id))
    if event is None or not event.artifact_sha256:
        raise HTTPException(status_code=404, detail="Scanner artifact not found.")
    load_scanner_event_payload(event)
    return FileResponse(scanner_artifact_path(event), media_type="application/json",
                        filename=f"daedalus-scanner-{event.agent_id}-event-{event.id}.json",
                        headers={"Cache-Control": "no-store", "X-Artifact-SHA256": event.artifact_sha256})


@app.post("/api/agents/events/{event_id}/pdf")
def create_scanner_results_pdf(event_id: int, request: Request, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    user, organization, _membership = get_org_context(request, db)
    row = db.execute(select(ScanEvent, Agent).join(Agent, Agent.id == ScanEvent.agent_id).where(
        ScanEvent.id == event_id, ScanEvent.organization_id == organization.id,
    )).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Scanner evidence not found.")
    event, agent = row
    if event.event_name not in {"scan_results", "quickscan_results", "deep_scan_results"}:
        raise HTTPException(status_code=422, detail="Choose a saved scan_results, quickscan_results or deep_scan_results event.")
    saved_payload = load_scanner_event_payload(event)
    try:
        scanner_result_hosts(saved_payload)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    active_count = db.scalar(select(func.count(ReportJob.id)).where(
        ReportJob.organization_id == organization.id, ReportJob.status.in_(("queued", "running")),
    )) or 0
    if active_count >= 3:
        raise HTTPException(status_code=429, detail="Three report jobs are already running for this workspace.")
    now = utcnow()
    job = ReportJob(
        organization_id=organization.id, created_by_user_id=user.id, report_type="scanner_results",
        domain=organization.domain, status="queued", progress=0, stage="Queued", file_name="pending.pdf",
        created_at=now, updated_at=now,
        report_snapshot={"domain": organization.domain, "organization_name": organization.name,
            "requested_by": user.email, "generated_at": iso_utc(now),
            "scanner": {"name": agent.name, "agent_id": agent.id, "event_id": event.id,
                "event_name": event.event_name, "occurred_at": iso_utc(event.occurred_at or event.created_at),
                "artifact_sha256": event.artifact_sha256, "payload": saved_payload}},
    )
    db.add(job)
    db.flush()
    job.file_name = f"daedalus-scanner-{agent.id}-event-{event.id}-{job.id}.pdf"
    audit(db, organization.id, user.id, "report.requested", {"report_id": job.id, "report_type": job.report_type, "event_id": event.id, "agent_id": agent.id})
    db.commit()
    db.refresh(job)
    background_tasks.add_task(generate_report_job, job.id)
    return serialize_report_job(job, user)


def command_timeout(action: str) -> timedelta:
    return timedelta(hours=2) if action == "start_scan" else timedelta(minutes=5)


def serialize_command(command: AgentCommand) -> dict[str, Any]:
    return {"id": command.id, "action": command.action, "target": command.target,
            "skip_host_discovery": command.skip_host_discovery,
            "status": command.status, "result": command.result,
            **{field: iso_utc(getattr(command, field)) if getattr(command, field) else None
               for field in ("created_at", "updated_at", "delivered_at", "deadline_at", "completed_at")}}


def expire_scanner_commands_in_session(db: Session, *, agent_id: int | None = None,
                                       now: datetime | None = None) -> None:
    now = now or utcnow()
    queued = select(AgentCommand).where(AgentCommand.status == "queued",
                                        AgentCommand.created_at < now - timedelta(minutes=5))
    if agent_id is not None:
        queued = queued.where(AgentCommand.agent_id == agent_id)
    for command in db.scalars(queued).all():
        changed = db.execute(update(AgentCommand).where(
            AgentCommand.id == command.id, AgentCommand.status == "queued",
        ).values(status="expired", updated_at=now, completed_at=now),
            execution_options={"synchronize_session": False})
        db.refresh(command)
        if changed.rowcount == 1:
            audit(db, command.organization_id, None, "scanner.command_expired",
                  {"agent_id": command.agent_id, "command_id": command.id, "action": command.action})
    query = select(AgentCommand).where(AgentCommand.status.in_(("delivered", "accepted")))
    if agent_id is not None:
        query = query.where(AgentCommand.agent_id == agent_id)
    for command in db.scalars(query).all():
        # Older commands have no delivery snapshot; use their last known acknowledgement.
        if command.deadline_at is None:
            inferred_delivery = command.delivered_at or command.updated_at
            db.execute(update(AgentCommand).where(
                AgentCommand.id == command.id, AgentCommand.deadline_at.is_(None),
                AgentCommand.status == command.status, AgentCommand.updated_at == command.updated_at,
            ).values(delivered_at=inferred_delivery,
                     deadline_at=inferred_delivery + command_timeout(command.action)),
                execution_options={"synchronize_session": False})
            db.refresh(command)
        # A concurrent result/backfill wins; never add timing to a terminal row.
        if command.status not in {"delivered", "accepted"} or command.deadline_at is None:
            continue
        if command.deadline_at <= now:
            db.flush()
            changed = db.execute(update(AgentCommand).where(
                AgentCommand.id == command.id, AgentCommand.status == command.status,
                AgentCommand.deadline_at <= now,
            ).values(status="timed_out", result="Completion was not confirmed before the command deadline.",
                     completed_at=now, updated_at=now), execution_options={"synchronize_session": False})
            db.refresh(command)
            if changed.rowcount == 1:
                audit(db, command.organization_id, None, "scanner.command_timed_out",
                      {"agent_id": command.agent_id, "command_id": command.id, "action": command.action})


def expire_scanner_commands() -> None:
    with SessionLocal() as db:
        expire_scanner_commands_in_session(db)
        db.commit()


@app.get("/api/agents/{agent_id}/commands")
def list_agent_commands(agent_id: int, request: Request, limit: int = 50, db: Session = Depends(get_db)):
    _, organization, _ = get_org_context(request, db, admin=True)
    agent = db.get(Agent, agent_id)
    if agent is None or agent.organization_id != organization.id:
        raise HTTPException(status_code=404, detail="Scanner not found in this workspace")
    expire_scanner_commands_in_session(db, agent_id=agent.id)
    db.commit()
    commands = db.scalars(select(AgentCommand).where(AgentCommand.agent_id == agent.id)
                          .order_by(AgentCommand.id.desc()).limit(max(1, min(limit, 200)))).all()
    return {"commands": [serialize_command(command) for command in commands]}


@app.put("/api/agents/{agent_id}/network-scope")
def update_agent_network_scope(
    agent_id: int,
    payload: ScannerNetworkScopeInput,
    request: Request,
    db: Session = Depends(get_db),
):
    user, organization, _ = get_org_context(request, db, admin=True)
    if not workspace_controls_available(db, organization):
        raise HTTPException(status_code=403, detail="Verify the domain or grant a 14-day probation override before managing scanners.")
    agent = db.get(Agent, agent_id)
    if agent is None or agent.organization_id != organization.id:
        raise HTTPException(status_code=404, detail="Scanner not found in this workspace")
    agent.authorized_networks = payload.authorized_networks
    now = utcnow()
    expire_scanner_commands_in_session(db, agent_id=agent.id, now=now)
    cancelled_count = 0
    queued = db.scalars(select(AgentCommand).where(
        AgentCommand.organization_id == organization.id,
        AgentCommand.agent_id == agent.id,
        AgentCommand.status == "queued",
        AgentCommand.action == "start_scan",
    )).all()
    for command in queued:
        try:
            scan_target_within_agent_scope(command.target or "", agent.authorized_networks)
        except ValueError:
            command.status = "cancelled"
            command.result = "Cancelled because the scanner's approved network scope changed before delivery."
            command.updated_at = now
            command.completed_at = now
            cancelled_count += 1
    active = db.scalars(select(AgentCommand).where(
        AgentCommand.organization_id == organization.id,
        AgentCommand.agent_id == agent.id,
        AgentCommand.status.in_(("delivered", "accepted")),
        AgentCommand.action == "start_scan",
    )).all()
    out_of_scope_active: list[AgentCommand] = []
    in_scope_active: list[AgentCommand] = []
    for command in active:
        try:
            scan_target_within_agent_scope(command.target or "", agent.authorized_networks)
        except ValueError:
            out_of_scope_active.append(command)
        else:
            in_scope_active.append(command)

    cancellation_request_queued_count = 0
    cancellation_request_skipped_offline_count = 0
    cancellation_request_skipped_mixed_scope_count = 0
    if out_of_scope_active and not in_scope_active:
        latest_affected_scan_at = max(command.created_at for command in out_of_scope_active)
        prior_request = db.scalar(select(AgentCommand.id).where(
            AgentCommand.organization_id == organization.id,
            AgentCommand.agent_id == agent.id,
            AgentCommand.action == "cancel_scan",
            AgentCommand.created_at >= latest_affected_scan_at,
        ).limit(1))
        if prior_request is None and agent_bridge_online(agent, now=now):
            cancellation = AgentCommand(
                organization_id=organization.id,
                agent_id=agent.id,
                action="cancel_scan",
                target=None,
                status="queued",
                created_by_user_id=user.id,
                result=None,
                created_at=now,
                updated_at=now,
            )
            db.add(cancellation)
            db.flush()
            audit(db, organization.id, user.id, "scanner.scope_cancel_requested", {
                "agent_id": agent.id,
                "cancel_command_id": cancellation.id,
                "affected_scan_command_ids": [command.id for command in out_of_scope_active],
                "confirmed_stopped": False,
            })
            cancellation_request_queued_count = 1
        elif prior_request is None:
            cancellation_request_skipped_offline_count = 1
    elif out_of_scope_active and in_scope_active:
        # cancel_scan applies to every scan currently running in NmapUI. Avoid
        # stopping an in-scope scan to enforce a change to another scan's scope.
        cancellation_request_skipped_mixed_scope_count = 1
    audit(db, organization.id, user.id, "scanner.network_scope.updated", {
        "agent_id": agent.id,
        "authorized_networks": agent.authorized_networks,
        "cancelled_queued_scan_count": cancelled_count,
        "unconfirmed_active_scan_count": len(out_of_scope_active),
        "cancellation_request_queued_count": cancellation_request_queued_count,
        "cancellation_request_skipped_offline_count": cancellation_request_skipped_offline_count,
        "cancellation_request_skipped_mixed_scope_count": cancellation_request_skipped_mixed_scope_count,
    })
    db.commit()
    return {
        "agent_id": agent.id,
        "authorized_networks": agent.authorized_networks,
        "cancelled_queued_scan_count": cancelled_count,
        "unconfirmed_active_scan_count": len(out_of_scope_active),
        "cancellation_request_queued_count": cancellation_request_queued_count,
        "cancellation_request_skipped_offline_count": cancellation_request_skipped_offline_count,
        "cancellation_request_skipped_mixed_scope_count": cancellation_request_skipped_mixed_scope_count,
    }


@app.post("/api/agents/{agent_id}/disable")
async def disable_scanner(agent_id: int, request: Request, db: Session = Depends(get_db)):
    user, organization, _membership = get_org_context(request, db, admin=True)
    agent = db.get(Agent, agent_id)
    if agent is None or agent.organization_id != organization.id:
        raise HTTPException(status_code=404, detail="Scanner not found in this workspace")
    disabled = db.execute(update(Agent).where(Agent.id == agent.id, Agent.organization_id == organization.id,
        Agent.enabled.is_(True)).values(enabled=False, nmapui_connected=False),
        execution_options={"synchronize_session": False})
    duplicate = disabled.rowcount != 1
    cancelled_count = 0
    now = utcnow()
    if not duplicate:
        cancelled = db.execute(update(AgentCommand).where(AgentCommand.organization_id == organization.id,
            AgentCommand.agent_id == agent.id, AgentCommand.status == "queued").values(
            status="cancelled", result="Scanner portal access was disabled before command delivery.",
            updated_at=now, completed_at=now), execution_options={"synchronize_session": False})
        cancelled_count = cancelled.rowcount
    active_count = db.scalar(select(func.count(AgentCommand.id)).where(
        AgentCommand.organization_id == organization.id, AgentCommand.agent_id == agent.id,
        AgentCommand.status.in_(("delivered", "accepted")))) or 0
    if not duplicate:
        audit(db, organization.id, user.id, "scanner.disabled", {"agent_id": agent.id,
            "cancelled_queued_command_count": cancelled_count,
            "unconfirmed_active_command_count": active_count,
            "local_execution_stopped": False})
    db.commit()
    db.refresh(agent)
    if not duplicate:
        try:
            await live_hub.publish(organization.id, {"type": "agent_status", "agent_id": agent.id,
                "name": agent.name, "enabled": False, "status": "disabled", "bridge_online": False,
                "nmapui_connected": False})
        except Exception:
            logger.exception("Scanner access was disabled; live fleet notification could not finish")
    return {"ok": True, "agent_id": agent.id, "enabled": False, "status": "disabled", "duplicate": duplicate,
            "cancelled_queued_command_count": cancelled_count, "unconfirmed_active_command_count": active_count}


@app.post("/api/agents/{agent_id}/commands")
def create_agent_command(
    agent_id: int,
    payload: NewCommandRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    user, organization, _ = get_org_context(request, db, admin=True)
    if not workspace_controls_available(db, organization):
        raise HTTPException(
            status_code=403,
            detail="Verify the domain or grant a 14-day probation override before managing scanners.",
        )
    agent = db.get(Agent, agent_id)
    if agent is None or agent.organization_id != organization.id:
        raise HTTPException(status_code=404, detail="Scanner not found in this workspace")
    if not agent.enabled:
        raise HTTPException(status_code=409, detail="Scanner portal access is disabled. Enroll a new scanner before queuing commands.")
    if payload.skip_host_discovery and (agent.command_protocol_version or 0) < 2:
        raise HTTPException(
            status_code=409,
            detail="Update this scanner with the current Daedalus/NmapUI kit before using per-scan host-discovery options.",
        )
    if payload.action in {"refresh_health", "collect_diagnostics"}:
        if (agent.command_protocol_version or 0) < 1 or not agent_bridge_online(agent):
            raise HTTPException(status_code=409, detail="An online bridge with command protocol version 1 is required.")
    elif payload.action == "check_os_updates":
        if agent.host_platform != "Darwin":
            raise HTTPException(status_code=409, detail="Read-only OS update checks are currently supported on macOS scanners only.")
        if (agent.command_protocol_version or 0) < 3:
            raise HTTPException(status_code=409, detail="Update this scanner kit to protocol version 3 before checking macOS updates.")
        if not agent_bridge_online(agent):
            raise HTTPException(status_code=409, detail="An online protocol v3 bridge is required to check macOS updates.")
    elif payload.action == "restart_nmapui":
        if not agent.nmapui_restart_supported:
            raise HTTPException(
                status_code=409,
                detail="This scanner was not installed with managed NmapUI service controls.",
            )
        if not agent_bridge_online(agent):
            raise HTTPException(
                status_code=409,
                detail="The scanner bridge must be online before NmapUI can be restarted.",
            )
    elif agent_status(agent) != "online":
        raise HTTPException(
            status_code=409,
            detail="The scanner must be online before a command can be queued.",
        )
    target = (payload.target or "").strip()
    if payload.action == "start_scan" and not target:
        raise HTTPException(status_code=422, detail="A scan target is required")
    if payload.action == "start_scan":
        try:
            target = scan_target_within_agent_scope(target, agent.authorized_networks)
        except ValueError as exc:
            audit(
                db,
                organization.id,
                user.id,
                "scanner.command_rejected",
                {"agent_id": agent.id, "action": payload.action, "target": target, "reason": str(exc)},
            )
            db.commit()
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    command = AgentCommand(
        organization_id=organization.id,
        agent_id=agent.id,
        action=payload.action,
        target=target or None,
        skip_host_discovery=payload.skip_host_discovery,
        status="queued",
        created_by_user_id=user.id,
        created_at=utcnow(),
        updated_at=utcnow(),
    )
    db.add(command)
    db.flush()
    audit(
        db,
        organization.id,
        user.id,
        "scanner.command_queued",
        {"agent_id": agent.id, "command_id": command.id, "action": command.action, "target": target,
         "skip_host_discovery": command.skip_host_discovery},
    )
    db.commit()
    db.refresh(command)
    return {"id": command.id, "status": command.status, "action": command.action}


@app.get("/api/agents/{agent_id}/commands/next")
def next_agent_command(
    agent_id: int,
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    agent = require_agent(db, agent_id, authorization)
    organization = db.get(Organization, agent.organization_id)
    controls_open = organization is not None and workspace_controls_available(db, organization)
    if not controls_open and organization is not None:
        close_scanner_controls(
            db,
            organization.id,
            actor_user_id=None,
            reason="probation_controls_expired_or_revoked",
        )
    now = utcnow()
    expire_scanner_commands_in_session(db, agent_id=agent.id, now=now)
    queue_cutoff = now - timedelta(minutes=5)
    command_query = select(AgentCommand).where(
        AgentCommand.agent_id == agent.id,
        AgentCommand.status == "queued",
        AgentCommand.created_at >= queue_cutoff,
    )
    if not controls_open:
        command_query = command_query.where(AgentCommand.action == "cancel_scan")
    command = db.scalar(
        command_query
        .order_by(AgentCommand.id)
        .limit(1)
    )
    if command is None:
        db.commit()
        return {"command": None}
    db.flush()
    claimed = db.execute(update(AgentCommand).where(
        AgentCommand.id == command.id, AgentCommand.status == "queued",
    ).values(status="delivered", delivered_at=now, deadline_at=now + command_timeout(command.action),
             updated_at=now), execution_options={"synchronize_session": False})
    if claimed.rowcount == 1:
        audit(db, command.organization_id, None, "scanner.command_delivered",
              {"agent_id": agent.id, "command_id": command.id, "action": command.action,
               "deadline_at": iso_utc(now + command_timeout(command.action))})
    db.commit()
    if claimed.rowcount != 1:
        return {"command": None}
    db.refresh(command)
    return {
        "command": {
            "id": command.id,
            "action": command.action,
            "target": command.target,
            "skip_host_discovery": command.skip_host_discovery,
            "deadline_at": iso_utc(command.deadline_at),
        }
    }


@app.post("/api/agents/{agent_id}/commands/{command_id}/result")
def agent_command_result(
    agent_id: int,
    command_id: int,
    payload: CommandResultRequest,
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    agent = require_agent(db, agent_id, authorization)
    command = db.get(AgentCommand, command_id)
    if command is None or command.agent_id != agent.id:
        raise HTTPException(status_code=404, detail="Command not found")
    expire_scanner_commands_in_session(db, agent_id=agent.id)
    db.commit()
    if command.status == payload.status and command.result == payload.result:
        return {"ok": True, "command_id": command.id, "status": command.status, "duplicate": True}
    if command.status not in {"delivered", "accepted"}:
        raise HTTPException(status_code=409, detail="Command is terminal or has not been delivered.")
    if command.status == "accepted" and payload.status == "accepted":
        raise HTTPException(status_code=409, detail="Conflicting command acknowledgement replay.")
    now = utcnow()
    previous_status, previous_result = command.status, command.result
    changed = db.execute(update(AgentCommand).where(
        AgentCommand.id == command.id, AgentCommand.status == previous_status,
        AgentCommand.result == previous_result,
    ).values(status=payload.status, result=payload.result, updated_at=now,
             completed_at=now if payload.status in {"succeeded", "failed", "timed_out"} else None),
        execution_options={"synchronize_session": False})
    if changed.rowcount != 1:
        db.rollback()
        db.refresh(command)
        if command.status == payload.status and command.result == payload.result:
            return {"ok": True, "command_id": command.id, "status": command.status, "duplicate": True}
        raise HTTPException(status_code=409, detail="Conflicting command result replay.")
    db.refresh(command)
    audit(db, command.organization_id, command.created_by_user_id, "scanner.command_result_reported",
          {"agent_id": agent.id, "command_id": command.id, "action": command.action, "status": payload.status})
    db.commit()
    return {"ok": True, "command_id": command.id, "status": command.status, "duplicate": False}


SCANNER_RESULT_EVENTS = ("scan_results", "quickscan_results", "deep_scan_results", "report_complete", "report_saved")


def scanner_run_summary(db: Session, agent: Agent, source_job_id: str) -> dict[str, Any]:
    scope = (ScanEvent.organization_id == agent.organization_id, ScanEvent.agent_id == agent.id,
             ScanEvent.source_job_id == source_job_id)
    occurred = func.coalesce(ScanEvent.occurred_at, ScanEvent.created_at)
    count, first, last, job_types = db.execute(select(func.count(ScanEvent.id), func.min(occurred),
        func.max(occurred), func.count(func.distinct(ScanEvent.source_job_type))).where(*scope)).one()
    if not count:
        raise HTTPException(status_code=404, detail="Scanner run not found in this workspace")
    job_type = db.scalar(select(ScanEvent.source_job_type).where(*scope).limit(1)) if job_types == 1 else None
    result_count = db.scalar(select(func.count(ScanEvent.id)).where(*scope, ScanEvent.event_name.in_(SCANNER_RESULT_EVENTS))) or 0
    evidence = db.scalar(select(ScanEvent).where(*scope, ScanEvent.event_name == "job_status")
                         .order_by(occurred.desc(), ScanEvent.id.desc()).limit(1))
    status = "unknown"
    if evidence and isinstance(evidence.payload, dict) and not evidence.artifact_sha256 and job_type in {"scan", "report"}:
        candidate = evidence.payload.get("status")
        declared_type = evidence.payload.get("job_type")
        if isinstance(candidate, str) and candidate in {"queued", "running", "cancelling", "completed", "failed", "cancelled", "interrupted"} and (declared_type is None or declared_type == job_type):
            status = candidate
    return {"source_job_id": source_job_id, "source_job_type": job_type, "agent_id": agent.id,
            "first_occurred_at": iso_utc(first), "last_occurred_at": iso_utc(last),
            "event_count": count, "result_count": result_count, "status": status,
            "status_evidence_event_id": evidence.id if evidence and status != "unknown" else None,
            "group_metadata_conflict": job_types != 1 or job_type not in {"scan", "report"}}


def scoped_scanner(request: Request, db: Session, agent_id: int) -> Agent:
    _, organization, _ = get_org_context(request, db)
    agent = db.get(Agent, agent_id)
    if agent is None or agent.organization_id != organization.id:
        raise HTTPException(status_code=404, detail="Scanner not found in this workspace")
    return agent


@app.get("/api/agents/{agent_id}/client-status")
def scanner_client_status(agent_id: int, authorization: str | None = Header(default=None),
                          db: Session = Depends(get_db)):
    """Read-only status for this enrolled device's local indicator."""
    agent = require_agent(db, agent_id, authorization)
    scope = (ScanEvent.organization_id == agent.organization_id, ScanEvent.agent_id == agent.id,
             ScanEvent.source_job_id.is_not(None))
    job_ids = db.scalars(select(ScanEvent.source_job_id).where(*scope)
                        .group_by(ScanEvent.source_job_id).order_by(func.max(ScanEvent.id).desc()).limit(5)).all()
    def local_run(job_id):
        summary = scanner_run_summary(db, agent, job_id)
        event = db.scalar(select(ScanEvent).where(*scope, ScanEvent.source_job_id == job_id,
                          ScanEvent.event_name == "job_status").order_by(ScanEvent.id.desc()).limit(1))
        details = event.payload.get("details") if event and isinstance(event.payload, dict) else None
        target = details.get("target") if isinstance(details, dict) else None
        summary["reported_target"] = target[:255] if isinstance(target, str) else None
        return summary
    command = db.scalar(select(AgentCommand).where(AgentCommand.agent_id == agent.id,
                        AgentCommand.organization_id == agent.organization_id, AgentCommand.action == "start_scan")
                        .order_by(AgentCommand.id.desc()).limit(1))
    last_request = {"status": command.status, "target": command.target, "result": command.result} if command else None
    return JSONResponse({"name": agent.name, "status": agent_status(agent),
                         "last_scan_request": last_request,
                         "bridge_online": agent_bridge_online(agent),
                         "last_seen_at": iso_utc(agent.last_seen_at) if agent.last_seen_at else None,
                         "recent_runs": [local_run(job_id) for job_id in job_ids]},
                        headers={"Cache-Control": "no-store"})


@app.get("/api/agents/{agent_id}/assessment")
def scanner_assessment(agent_id: int, request: Request, db: Session = Depends(get_db)):
    from daedalus.scanner_comparison import normalize_snapshot
    agent = scoped_scanner(request, db, agent_id)
    occurred = func.coalesce(ScanEvent.occurred_at, ScanEvent.created_at)
    job_id = db.scalar(select(ScanEvent.source_job_id).where(
        ScanEvent.organization_id == agent.organization_id, ScanEvent.agent_id == agent.id,
        ScanEvent.source_job_type == "scan", ScanEvent.source_job_id.is_not(None),
    ).group_by(ScanEvent.source_job_id).order_by(func.max(occurred).desc(), func.max(ScanEvent.id).desc()).limit(1))
    if job_id is None:
        return {"state": "not_assessed", "run": None, "observations": None}
    run = scanner_run_summary(db, agent, job_id)
    response = {"state": "attention", "run": run, "observations": None}
    if run["group_metadata_conflict"]:
        response["reason"] = "Saved run metadata conflicts."
        return response
    events = db.scalars(select(ScanEvent).options(defer(ScanEvent.payload)).where(
        ScanEvent.organization_id == agent.organization_id, ScanEvent.agent_id == agent.id,
        ScanEvent.source_job_id == job_id, ScanEvent.event_name == "deep_scan_results",
    ).order_by(occurred.asc(), ScanEvent.id.asc()).limit(201)).all()
    if not events:
        response["reason"] = "Latest run has no saved detailed results."
        return response
    if len(events) > 200:
        response["reason"] = "Detailed results exceed the summary event limit; review the saved run."
        return response
    snapshot = {"hosts": {}, "covered_targets": []}
    total_bytes = 0
    for event in events:
        if event.artifact_size_bytes and total_bytes + event.artifact_size_bytes > 8 * 1024 * 1024:
            response["reason"] = "Latest detailed results exceed the summary size limit; review the saved artifact."
            return response
        try:
            payload = load_scanner_event_payload(event)
            total_bytes += len(json.dumps(payload).encode("utf-8"))
            if total_bytes > 8 * 1024 * 1024:
                response["reason"] = "Latest detailed results exceed the summary size limit; review the saved artifact."
                return response
            observed = normalize_snapshot(payload)
        except (TypeError, ValueError):
            response["reason"] = "Latest detailed results cannot be interpreted; earlier results were not substituted."
            return response
        # Each host result is a snapshot. A later result replaces that host's
        # earlier ports rather than retaining ports it no longer reported.
        snapshot["hosts"].update(observed["hosts"])
        if observed["covered_targets"] is None:
            snapshot["covered_targets"] = None
        elif snapshot["covered_targets"] is not None:
            snapshot["covered_targets"] = sorted(set(snapshot["covered_targets"]) | set(observed["covered_targets"]))
    event = events[-1]
    ports = [port for host in snapshot["hosts"].values() for port in host["ports"].values()]
    response["observations"] = {
        "host_count": len(snapshot["hosts"]),
        "open_port_count": sum(port["state"] == "open" for port in ports),
        "unknown_port_state_count": sum(port["state"] is None for port in ports),
        "covered_targets": snapshot["covered_targets"],
        "result_event_id": event.id, "result_event_count": len(events),
        "collected_at": iso_utc(event.occurred_at or event.created_at),
        "coverage_complete": False,
    }
    response["state"] = "recorded" if run["status"] == "completed" else "attention"
    return response


@app.get("/api/agents/{agent_id}/runs")
def list_scanner_runs(agent_id: int, request: Request, limit: int = 20, db: Session = Depends(get_db)):
    agent = scoped_scanner(request, db, agent_id)
    limit = max(1, min(limit, 50))
    scope = (ScanEvent.organization_id == agent.organization_id, ScanEvent.agent_id == agent.id,
             ScanEvent.source_job_id.is_not(None))
    total = db.scalar(select(func.count(func.distinct(ScanEvent.source_job_id))).where(*scope)) or 0
    run_ids = db.scalars(select(ScanEvent.source_job_id).where(*scope).group_by(ScanEvent.source_job_id)
                        .order_by(func.max(ScanEvent.id).desc()).limit(limit)).all()
    return {"runs": [scanner_run_summary(db, agent, job_id) for job_id in run_ids],
            "total_runs": total, "truncated": total > limit, "limit": limit}


@app.get("/api/agents/{agent_id}/runs/{source_job_id}")
def scanner_run_detail(agent_id: int, source_job_id: UUID, request: Request, db: Session = Depends(get_db)):
    agent = scoped_scanner(request, db, agent_id)
    job_id = str(source_job_id)
    summary = scanner_run_summary(db, agent, job_id)
    events = db.scalars(select(ScanEvent).where(ScanEvent.organization_id == agent.organization_id,
        ScanEvent.agent_id == agent.id, ScanEvent.source_job_id == job_id)
        .order_by(func.coalesce(ScanEvent.occurred_at, ScanEvent.created_at).desc(), ScanEvent.id.desc()).limit(200)).all()
    serialized_events = []
    serialized_bytes = 0
    byte_limit = 4 * 1024 * 1024
    for event in events:
        serialized = serialize_event(event)
        event_bytes = len(json.dumps(serialized, ensure_ascii=False).encode("utf-8"))
        if serialized_bytes + event_bytes > byte_limit:
            break
        serialized_events.append(serialized)
        serialized_bytes += event_bytes
    return {"run": summary, "events": list(reversed(serialized_events)),
            "truncated": summary["event_count"] > len(serialized_events), "returned_event_count": len(serialized_events),
            "event_limit": 200, "event_byte_limit": byte_limit}


def trusted_single_ip_scan_scope(db: Session, agent: Agent, summary: dict[str, Any]) -> str | None:
    """Return an exact /32 or /128 scope only when a saved Daedalus command proves it.

    NmapUI's deep-result event contains observations but not the target request.
    For one explicitly selected IP, pair its completed status event with the
    successful workspace command before using the target to compare host
    presence. This does not establish complete port coverage.
    """
    if summary.get("status") != "completed" or summary.get("source_job_type") != "scan":
        return None
    completion = db.get(ScanEvent, summary.get("status_evidence_event_id"))
    if (
        completion is None
        or completion.source_job_id != summary.get("source_job_id")
        or completion.source_job_type != "scan"
    ):
        return None
    evidence = completion.payload
    if not isinstance(evidence, dict):
        return None
    details = evidence.get("details")
    if not isinstance(details, dict) or details.get("skip_host_discovery") is not True:
        return None
    command_id = details.get("daedalus_command_id")
    if type(command_id) is not int or command_id <= 0:
        return None
    command = db.get(AgentCommand, command_id)
    target = details.get("target")
    if (
        command is None
        or command.organization_id != agent.organization_id
        or command.agent_id != agent.id
        or command.action != "start_scan"
        or command.status != "succeeded"
        or command.skip_host_discovery is not True
        or not isinstance(target, str)
        or command.target != target
    ):
        return None
    try:
        network = ipaddress.ip_network(target, strict=False)
        if network.num_addresses != 1:
            return None
        # Reuse the command endpoint's private-address rules as a second check.
        validate_internal_scan_target(target)
    except ValueError:
        return None
    return str(network)


def build_scanner_run_comparison(db: Session, agent: Agent, source_job_id: UUID, previous_run_id: UUID) -> dict[str, Any]:
    from daedalus.scanner_comparison import normalize_snapshot, compare_snapshots
    summaries = [scanner_run_summary(db, agent, str(job_id)) for job_id in (previous_run_id, source_job_id)]
    selected = []
    selection_complete = True
    selection_limits = []
    for summary in summaries:
        candidates = db.scalars(select(ScanEvent).options(defer(ScanEvent.payload)).where(
            ScanEvent.organization_id == agent.organization_id, ScanEvent.agent_id == agent.id,
            ScanEvent.source_job_id == summary["source_job_id"], ScanEvent.event_name == "deep_scan_results")
            .order_by(func.coalesce(ScanEvent.occurred_at, ScanEvent.created_at).desc(), ScanEvent.id.desc())
            .limit(201)).all()
        examined_bytes = 0
        skipped = []
        snapshot = None
        for event in candidates[:200]:
            if event.artifact_size_bytes and examined_bytes + event.artifact_size_bytes > 64 * 1024 * 1024:
                selection_limits.append("Saved result search reached the 64 MiB evidence limit.")
                selection_complete = False
                break
            payload = load_scanner_event_payload(event)
            examined_bytes += len(json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
            if examined_bytes > 64 * 1024 * 1024:
                selection_limits.append("Saved result search reached the 64 MiB evidence limit.")
                selection_complete = False
                break
            try:
                snapshot = normalize_snapshot(payload)
            except (TypeError, ValueError):
                skipped.append(event.id)
                selection_complete = False
                continue
            inferred_scope = trusted_single_ip_scan_scope(db, agent, summary)
            if (
                snapshot["covered_targets"] is None
                and inferred_scope is not None
                and set(snapshot["hosts"]) == {str(ipaddress.ip_interface(inferred_scope).ip)}
            ):
                snapshot["covered_targets"] = [inferred_scope]
                summary["covered_targets_source"] = "successful_daedalus_single_ip_command"
            summary["selected_result_event_id"] = event.id
            summary["selected_result_artifact_sha256"] = event.artifact_sha256
            summary["selected_result_occurred_at"] = iso_utc(event.occurred_at or event.created_at)
            break
        if snapshot is None and len(candidates) > 200:
            selection_limits.append("Saved result search reached the 200-event selection limit.")
            selection_complete = False
        summary.setdefault("selected_result_event_id", None)
        summary["skipped_invalid_result_event_ids"] = skipped
        selected.append(snapshot)
    context = {"previous_run": summaries[0], "current_run": summaries[1]}
    if any(snapshot is None for snapshot in selected):
        return {**context, "available": False, "reason": "Both runs need a valid saved deep-scan result snapshot.",
                "limitations": selection_limits + ["No empty snapshot or completion was inferred."]}
    result = compare_snapshots(selected[0], selected[1], previous_status=summaries[0]["status"],
                               current_status=summaries[1]["status"], selection_complete=selection_complete)
    result["limitations"].extend(selection_limits)
    return {**context, **result}


@app.get("/api/agents/{agent_id}/runs/{source_job_id}/comparison")
def compare_scanner_runs(agent_id: int, source_job_id: UUID, previous_run_id: UUID, request: Request,
                         db: Session = Depends(get_db)):
    agent = scoped_scanner(request, db, agent_id)
    if source_job_id == previous_run_id:
        raise HTTPException(status_code=422, detail="Choose two different explicit scanner runs.")
    return build_scanner_run_comparison(db, agent, source_job_id, previous_run_id)


def serialize_scanner_comparison(row: ScannerRunComparison) -> dict[str, Any]:
    return {"id": row.id, "agent_id": row.agent_id, "current_run_id": row.current_run_id,
            "previous_run_id": row.previous_run_id, "current_result_event_id": row.current_result_event_id,
            "previous_result_event_id": row.previous_result_event_id, "detected_at": iso_utc(row.detected_at),
            "meaningful_change_count": row.meaningful_change_count, "comparison": row.comparison}


def record_scanner_run_comparison(db: Session, agent: Agent, event: ScanEvent) -> dict[str, Any] | None:
    if not event.source_job_id or event.source_job_type != "scan" or event.event_name not in {"job_status", "deep_scan_results"}:
        return None
    current = scanner_run_summary(db, agent, event.source_job_id)
    if current["status"] != "completed" or current["source_job_type"] != "scan":
        return None
    completed = db.get(ScanEvent, current["status_evidence_event_id"])
    completed_time = completed.occurred_at or completed.created_at
    occurred = func.coalesce(ScanEvent.occurred_at, ScanEvent.created_at)
    candidates = db.scalars(select(ScanEvent).where(
        ScanEvent.organization_id == agent.organization_id, ScanEvent.agent_id == agent.id,
        ScanEvent.source_job_id.is_not(None), ScanEvent.source_job_id != event.source_job_id,
        ScanEvent.source_job_type == "scan", ScanEvent.event_name == "job_status",
        ScanEvent.payload["status"].as_string() == "completed",
        (occurred < completed_time) | ((occurred == completed_time) & (ScanEvent.id < completed.id)),
    ).order_by(occurred.desc(), ScanEvent.id.desc()).limit(200)).all()
    previous = None
    seen = set()
    for candidate in candidates:
        if candidate.source_job_id in seen:
            continue
        seen.add(candidate.source_job_id)
        summary = scanner_run_summary(db, agent, candidate.source_job_id)
        if summary["status"] == "completed" and summary["source_job_type"] == "scan" and summary["status_evidence_event_id"] == candidate.id:
            previous = candidate.source_job_id
            break
    if previous is None:
        return None
    comparison = build_scanner_run_comparison(db, agent, UUID(event.source_job_id), UUID(previous))
    if not comparison.get("available"):
        return None
    identity = {"agent_id": agent.id, "current_run_id": event.source_job_id,
                "previous_run_id": previous,
                "current_result_event_id": comparison["current_run"]["selected_result_event_id"],
                "previous_result_event_id": comparison["previous_run"]["selected_result_event_id"]}
    if db.scalar(select(ScannerRunComparison.id).filter_by(**identity)) is not None:
        return None
    counts = comparison["counts"]
    meaningful = (counts["hosts_added"] + counts["hosts_removed"] + counts["newly_observed_ports"]
        + counts["reported_port_changes"] + counts["confirmed_removed_ports"])
    row = ScannerRunComparison(**identity, organization_id=agent.organization_id,
        detected_at=utcnow(), meaningful_change_count=meaningful, comparison=comparison)
    db.add(row)
    db.flush()
    audit(db, agent.organization_id, None, "scanner.run_comparison_saved", {"agent_id": agent.id,
        "comparison_id": row.id, "current_run_id": event.source_job_id, "previous_run_id": previous,
        "meaningful_change_count": meaningful})
    record_scanner_comparison_notification(
        db,
        agent=agent,
        comparison_id=row.id,
        comparison=comparison,
        detected_at=row.detected_at,
        meaningful_change_count=meaningful,
    )
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        return None
    db.refresh(row)
    return serialize_scanner_comparison(row)


def next_completed_scanner_run(db: Session, agent: Agent, event: ScanEvent) -> ScanEvent | None:
    """Reconcile only the next completed run affected by this late baseline."""
    if not event.source_job_id or event.source_job_type != "scan" or event.event_name not in {"job_status", "deep_scan_results"}:
        return None
    summary = scanner_run_summary(db, agent, event.source_job_id)
    if summary["status"] != "completed" or summary["source_job_type"] != "scan":
        return None
    completion = db.get(ScanEvent, summary["status_evidence_event_id"])
    completed_time = completion.occurred_at or completion.created_at
    occurred = func.coalesce(ScanEvent.occurred_at, ScanEvent.created_at)
    candidates = db.scalars(select(ScanEvent).where(
        ScanEvent.organization_id == agent.organization_id, ScanEvent.agent_id == agent.id,
        ScanEvent.source_job_id.is_not(None), ScanEvent.source_job_id != event.source_job_id,
        ScanEvent.source_job_type == "scan", ScanEvent.event_name == "job_status",
        ScanEvent.payload["status"].as_string() == "completed",
        (occurred > completed_time) | ((occurred == completed_time) & (ScanEvent.id > completion.id)),
    ).order_by(occurred, ScanEvent.id).limit(200)).all()
    for candidate in candidates:
        successor = scanner_run_summary(db, agent, candidate.source_job_id)
        if successor["status"] == "completed" and successor["source_job_type"] == "scan" and successor["status_evidence_event_id"] == candidate.id:
            return candidate
    return None


async def notify_scanner_run_comparison(db: Session, agent: Agent, event: ScanEvent) -> None:
    # Evidence has already committed. Never reject that upload for a derivative failure.
    affected_events = [event]
    try:
        successor = next_completed_scanner_run(db, agent, event)
        if successor is not None:
            affected_events.append(successor)
    except Exception:
        db.rollback()
        logger.exception("Saved scanner event retained; successor reconciliation could not be selected")
    for affected in affected_events:
        try:
            row = record_scanner_run_comparison(db, agent, affected)
            if row and row["meaningful_change_count"]:
                await live_hub.publish(agent.organization_id, {"type": "scanner_comparison_detected",
                    **{key: row[key] for key in ("agent_id", "current_run_id", "previous_run_id", "meaningful_change_count", "detected_at")},
                    "comparison_id": row["id"]})
        except Exception:
            db.rollback()
            logger.exception("Saved scanner event retained; comparison or notification could not finish")


MAX_SCANNER_COMPARISON_HISTORY_BYTES = 4 * 1024 * 1024


def scanner_comparison_history_entry(row: ScannerRunComparison, *, summary_only: bool = False) -> dict[str, Any]:
    entry = serialize_scanner_comparison(row)
    url = f"/api/agents/{row.agent_id}/run-comparisons/{row.id}/snapshot"
    entry.update(detail_url=url, full_evidence_url=url, comparison_truncated=summary_only)
    if summary_only:
        saved = row.comparison
        counts = saved.get("counts") if isinstance(saved.get("counts"), dict) else {}
        coverage = saved.get("coverage") if isinstance(saved.get("coverage"), dict) else {}
        entry["comparison"] = {"available": saved.get("available") is True,
            "counts": {field: counts.get(field) for field in ("hosts_added", "hosts_removed", "hosts_not_observed",
                "port_changes", "newly_observed_ports", "reported_port_changes", "confirmed_removed_ports") if type(counts.get(field)) is int},
            "coverage": {"comparable": coverage.get("comparable") is True},
            "limitations": ["History summary only: full saved comparison evidence is available from the JSON download."]}
    return entry


@app.get("/api/agents/{agent_id}/run-comparisons")
def list_scanner_run_comparisons(agent_id: int, request: Request, limit: int = 20, db: Session = Depends(get_db)):
    agent = scoped_scanner(request, db, agent_id)
    limit = max(1, min(limit, 50))
    # Defer JSON so a large history page does not load every saved snapshot into memory.
    rows = db.scalars(select(ScannerRunComparison).options(defer(ScannerRunComparison.comparison)).where(
        ScannerRunComparison.organization_id == agent.organization_id, ScannerRunComparison.agent_id == agent.id)
        .order_by(ScannerRunComparison.id.desc()).limit(limit + 1)).all()
    entries = []
    reasons = ["entry_limit"] if len(rows) > limit else []
    used = 0
    # Reserve room for array separators and the response envelope/truncation metadata.
    budget = max(0, MAX_SCANNER_COMPARISON_HISTORY_BYTES - 2048)
    for row in rows[:limit]:
        entry = scanner_comparison_history_entry(row)
        size = len(json.dumps(entry, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")) + 1
        if size > budget:
            summary = scanner_comparison_history_entry(row, summary_only=True)
            summary_size = len(json.dumps(summary, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")) + 1
            if used + summary_size <= budget:
                entries.append(summary)
                used += summary_size
            reasons.append("oversized_entry_summary")
            if len(entries) < min(len(rows), limit):
                reasons.append("response_byte_limit")
            break
        if used + size > budget:
            reasons.append("response_byte_limit")
            break
        entries.append(entry)
        used += size
    return {"comparisons": entries, "returned_count": len(entries), "truncated": bool(reasons),
            "truncation_reasons": list(dict.fromkeys(reasons)), "limit": limit,
            "byte_limit": MAX_SCANNER_COMPARISON_HISTORY_BYTES}


@app.get("/api/agents/{agent_id}/run-comparisons/{comparison_id}/snapshot")
def download_scanner_comparison_snapshot(agent_id: int, comparison_id: int, request: Request,
                                         db: Session = Depends(get_db)):
    agent = scoped_scanner(request, db, agent_id)
    row = db.scalar(select(ScannerRunComparison).where(ScannerRunComparison.id == comparison_id,
        ScannerRunComparison.organization_id == agent.organization_id, ScannerRunComparison.agent_id == agent.id))
    if row is None:
        raise HTTPException(status_code=404, detail="Saved scanner comparison not found in this workspace")
    return JSONResponse(serialize_scanner_comparison(row), headers={"Cache-Control": "no-store",
        "Content-Disposition": f'attachment; filename="daedalus-scanner-{agent.id}-comparison-{row.id}.json"'})


MAX_SCANNER_RUN_PDF_EVENTS = 2000
MAX_SCANNER_RUN_PDF_BYTES = 64 * 1024 * 1024


def validate_scanner_run_result(event_name: str, payload: Any) -> None:
    if event_name not in {"scan_results", "quickscan_results", "deep_scan_results"}:
        return
    if event_name == "quickscan_results" and isinstance(payload, dict) and "hosts" not in payload:
        counts = [payload.get("total_ips"), payload.get("hosts_up")]
        duration = payload.get("time_taken")
        if all(type(value) is int and value >= 0 for value in counts) and counts[1] <= counts[0] and type(duration) in {int, float} and 0 <= duration < float("inf"):
            return
        raise ValueError("Quick scan summary needs valid nonnegative host counts and duration.")
    scanner_result_hosts(payload)


@app.post("/api/agents/{agent_id}/runs/{source_job_id}/pdf")
def create_scanner_run_pdf(agent_id: int, source_job_id: UUID, request: Request,
                           background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    user, organization, _membership = get_org_context(request, db)
    agent = db.get(Agent, agent_id)
    if agent is None or agent.organization_id != organization.id:
        raise HTTPException(status_code=404, detail="Scanner not found in this workspace")
    scope = (ScanEvent.organization_id == organization.id, ScanEvent.agent_id == agent.id,
             ScanEvent.source_job_id == str(source_job_id))
    count = db.scalar(select(func.count(ScanEvent.id)).where(*scope)) or 0
    if not count:
        raise HTTPException(status_code=404, detail="Scanner run not found in this workspace")
    if count > MAX_SCANNER_RUN_PDF_EVENTS:
        raise HTTPException(status_code=413, detail=f"Run PDFs support at most {MAX_SCANNER_RUN_PDF_EVENTS} saved events; no partial report was created.")
    active_count = db.scalar(select(func.count(ReportJob.id)).where(
        ReportJob.organization_id == organization.id, ReportJob.status.in_(("queued", "running")))) or 0
    if active_count >= 3:
        raise HTTPException(status_code=429, detail="Three report jobs are already running for this workspace.")
    events = db.scalars(select(ScanEvent).options(defer(ScanEvent.payload)).where(*scope)
        .order_by(func.coalesce(ScanEvent.occurred_at, ScanEvent.created_at), ScanEvent.id)
        .limit(MAX_SCANNER_RUN_PDF_EVENTS + 1)).all()
    if len(events) > MAX_SCANNER_RUN_PDF_EVENTS:
        raise HTTPException(status_code=413, detail="Run event count exceeded the full snapshot limit; no partial report was created.")
    saved_events = []
    payload_bytes = 0
    for event in events:
        if event.artifact_size_bytes and payload_bytes + event.artifact_size_bytes > MAX_SCANNER_RUN_PDF_BYTES:
            raise HTTPException(status_code=413, detail="Run PDF snapshots are limited to 64 MiB of saved evidence; no partial report was created.")
        saved_payload = load_scanner_event_payload(event)
        try:
            validate_scanner_run_result(event.event_name, saved_payload)
            saved = {**serialize_event(event), "client_event_id": event.client_event_id, "payload": saved_payload}
            payload_bytes += len(json.dumps(saved, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8"))
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=f"Saved scanner result event {event.id} is invalid: {exc}") from exc
        if payload_bytes > MAX_SCANNER_RUN_PDF_BYTES:
            raise HTTPException(status_code=413, detail="Run PDF snapshots are limited to 64 MiB of saved evidence; no partial report was created.")
        saved_events.append(saved)
    # Derive metadata from the exact frozen event set, not a later concurrent upload.
    job_types = {event.source_job_type for event in events}
    job_type = next(iter(job_types)) if len(job_types) == 1 else None
    status_events = [event for event in saved_events if event["event_name"] == "job_status"]
    status = "unknown"
    evidence = status_events[-1] if status_events else None
    if evidence and isinstance(evidence["payload"], dict) and job_type in {"scan", "report"}:
        candidate = evidence["payload"].get("status")
        declared_type = evidence["payload"].get("job_type")
        if isinstance(candidate, str) and candidate in {"queued", "running", "cancelling", "completed", "failed", "cancelled", "interrupted"} and (declared_type is None or declared_type == job_type):
            status = candidate
    run = {"source_job_id": str(source_job_id), "source_job_type": job_type, "agent_id": agent.id,
           "first_occurred_at": saved_events[0]["occurred_at"], "last_occurred_at": saved_events[-1]["occurred_at"],
           "event_count": len(saved_events), "result_count": sum(event["event_name"] in SCANNER_RESULT_EVENTS for event in saved_events),
           "status": status, "status_evidence_event_id": evidence["id"] if evidence and status != "unknown" else None,
           "group_metadata_conflict": len(job_types) != 1 or job_type not in {"scan", "report"}, "snapshot_cutoff_event_id": max(event.id for event in events),
           "snapshot_payload_bytes": payload_bytes, "snapshot_event_limit": MAX_SCANNER_RUN_PDF_EVENTS,
           "snapshot_byte_limit": MAX_SCANNER_RUN_PDF_BYTES, "truncated": False}
    now = utcnow()
    job = ReportJob(organization_id=organization.id, created_by_user_id=user.id, report_type="scanner_results",
        domain=organization.domain, status="queued", progress=0, stage="Queued", file_name="pending.pdf",
        created_at=now, updated_at=now,
        report_snapshot={"domain": organization.domain, "organization_name": organization.name,
            "requested_by": user.email, "generated_at": iso_utc(now),
            "scanner": {"name": agent.name, "agent_id": agent.id, "source_job_id": str(source_job_id),
                        "run": run, "events": saved_events, "payload": []}})
    db.add(job)
    db.flush()
    job.file_name = f"daedalus-scanner-{agent.id}-run-{source_job_id}-{job.id}.pdf"
    audit(db, organization.id, user.id, "report.requested", {"report_id": job.id, "report_type": job.report_type,
        "source_job_id": str(source_job_id), "agent_id": agent.id, "event_count": len(saved_events), "snapshot_payload_bytes": payload_bytes})
    db.commit()
    db.refresh(job)
    background_tasks.add_task(generate_report_job, job.id)
    return serialize_report_job(job, user)


@app.get("/api/events")
def list_events(
    request: Request,
    limit: int = 50,
    db: Session = Depends(get_db),
):
    _, organization, _ = get_org_context(request, db)
    events = db.scalars(
        select(ScanEvent)
        .where(ScanEvent.organization_id == organization.id)
        .order_by(ScanEvent.id.desc())
        .limit(max(1, min(limit, 200)))
    ).all()
    return {"events": [serialize_event(event) for event in events]}


def websocket_origin_matches_host(origin: str | None, host_header: str, *, production: bool) -> bool:
    """Require browser live subscriptions to originate from their exact portal host."""
    if not origin or not host_header:
        return False
    try:
        parsed_origin = urlsplit(origin)
        parsed_host = urlsplit("//" + host_header)
        default_port = 443 if parsed_origin.scheme.lower() == "https" else 80
        origin_port = parsed_origin.port or default_port
        host_port = parsed_host.port or default_port
    except ValueError:
        return False
    scheme = parsed_origin.scheme.lower()
    if scheme not in {"http", "https"} or (production and scheme != "https"):
        return False
    if (
        parsed_origin.username is not None
        or parsed_origin.password is not None
        or parsed_origin.path not in {"", "/"}
        or parsed_origin.query
        or parsed_origin.fragment
        or parsed_host.username is not None
        or parsed_host.password is not None
        or parsed_host.path
        or parsed_host.query
        or parsed_host.fragment
    ):
        return False
    origin_host = (parsed_origin.hostname or "").lower().rstrip(".")
    request_host = (parsed_host.hostname or "").lower().rstrip(".")
    return bool(origin_host and origin_host == request_host and origin_port == host_port)


@app.websocket("/ws/live")
async def live_updates(websocket: WebSocket):
    if not websocket_origin_matches_host(
        websocket.headers.get("origin"),
        websocket.headers.get("host", ""),
        production=APP_ENV == "production",
    ):
        await websocket.close(code=4403)
        return
    session = websocket.scope.get("session", {})
    user_id = session.get("user_id")
    organization_id = websocket.query_params.get("organization_id")
    membership_updates_only = websocket.query_params.get("membership_updates") == "1"
    if not user_id or not organization_id or not organization_id.isdigit():
        await websocket.close(code=4401)
        return
    with SessionLocal() as db:
        if session.get("api_key_id"):
            try:
                key = validate_user_key(db, db.get(UserAPIKey, session["api_key_id"]))
                if key.user_id != int(user_id) or key.organization_id != int(organization_id):
                    raise HTTPException(status_code=403)
            except HTTPException:
                await websocket.close(code=4401)
                return
        membership = db.scalar(
            select(Membership).where(
                Membership.user_id == int(user_id),
                Membership.organization_id == int(organization_id),
                Membership.status.in_(("approved", "pending", "denied")),
            )
        )
        membership_status = membership.status if membership is not None else None
        organization = (
            db.get(Organization, int(organization_id))
            if membership_updates_only and membership_status in {"approved", "denied"}
            else None
        )
        organization_name = organization.name if organization is not None else "Workspace"
    if membership is None or (
        membership_status in {"pending", "denied"} and not membership_updates_only
    ):
        await websocket.close(code=4403)
        return
    organization_id_int = int(organization_id)
    await live_hub.connect(
        organization_id_int,
        int(user_id),
        websocket,
        receive_workspace_events=(
            membership_status == "approved" and not membership_updates_only
        ),
    )
    if membership_updates_only and membership_status in {"approved", "denied"}:
        # Recover a decision that committed between the page's workspace fetch
        # and this private subscription being established.
        await live_hub.publish_to_user(
            organization_id_int,
            int(user_id),
            {
                "type": "membership_decision",
                "organization_id": organization_id_int,
                "organization": organization_name,
                "domain": organization.domain if organization is not None else "",
                "status": membership_status,
            },
        )
    try:
        while True:
            if session.get("api_key_id"):
                with SessionLocal() as db:
                    try:
                        validate_user_key(db, db.get(UserAPIKey, session["api_key_id"]))
                    except HTTPException:
                        await websocket.close(code=4401)
                        break
                try:
                    await asyncio.wait_for(websocket.receive_text(), timeout=5)
                except TimeoutError:
                    continue
            else:
                await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        live_hub.disconnect(organization_id_int, websocket)


if __name__ == "__main__":
    import uvicorn

    if DEMO_MODE and HOST not in {"127.0.0.1", "::1", "localhost"}:
        raise SystemExit(
            "The demo login can only run on loopback. Set DAEDALUS_DEMO_MODE=false before binding publicly."
        )
    uvicorn.run("daedalus.server:app", host=HOST, port=PORT, reload=APP_ENV != "production")
