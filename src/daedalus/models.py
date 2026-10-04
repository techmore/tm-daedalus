from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from daedalus.db import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    google_subject: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(320), index=True)
    display_name: Mapped[str] = mapped_column(String(200), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    memberships: Mapped[list["Membership"]] = relationship(back_populates="user")


class UserAPIKey(Base):
    __tablename__ = "user_api_keys"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Organization(Base):
    __tablename__ = "organizations"
    __table_args__ = (UniqueConstraint("domain", name="uq_organization_domain"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    domain: Mapped[str] = mapped_column(String(253), nullable=False, index=True)
    verification_status: Mapped[str] = mapped_column(String(32), default="pending")
    verification_expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    memberships: Mapped[list["Membership"]] = relationship(back_populates="organization")
    agents: Mapped[list["Agent"]] = relationship(back_populates="organization")


class Membership(Base):
    __tablename__ = "memberships"
    __table_args__ = (
        UniqueConstraint("user_id", "organization_id", name="uq_membership_user_org"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    role: Mapped[str] = mapped_column(String(24), default="user")
    status: Mapped[str] = mapped_column(String(24), default="approved")
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    user: Mapped[User] = relationship(back_populates="memberships")
    organization: Mapped[Organization] = relationship(back_populates="memberships")


class Agent(Base):
    __tablename__ = "agents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    nmapui_connected: Mapped[bool] = mapped_column(Boolean, default=False)
    bridge_version: Mapped[str | None] = mapped_column(String(80), nullable=True)
    host_platform: Mapped[str | None] = mapped_column(String(80), nullable=True)
    nmapui_version: Mapped[str | None] = mapped_column(String(80), nullable=True)
    nmapui_ready: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    nmapui_restart_supported: Mapped[bool] = mapped_column(Boolean, default=False)
    command_protocol_version: Mapped[int] = mapped_column(Integer, default=0)
    authorized_networks: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    organization: Mapped[Organization] = relationship(back_populates="agents")


class EnrollmentToken(Base):
    __tablename__ = "enrollment_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    code_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_by_user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    scanner_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    authorized_networks: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


class DomainChallenge(Base):
    __tablename__ = "domain_challenges"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), index=True)
    created_by_user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


class ProbationOverride(Base):
    __tablename__ = "probation_overrides"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    granted_by_user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    reason: Mapped[str] = mapped_column(String(500), nullable=False)
    starts_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    actor_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    details: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)


class ScanEvent(Base):
    __tablename__ = "scan_events"
    __table_args__ = (Index("ux_scan_event_client_id", "agent_id", "client_event_id", unique=True),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    agent_id: Mapped[int] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"), index=True)
    event_name: Mapped[str] = mapped_column(String(100), nullable=False)
    client_event_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    source_job_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    source_job_type: Mapped[str | None] = mapped_column(String(16), nullable=True)
    occurred_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    artifact_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    artifact_size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    payload: Mapped[dict[str, Any] | list[Any] | str | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)


class AgentCommand(Base):
    __tablename__ = "agent_commands"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    agent_id: Mapped[int] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"), index=True)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    target: Mapped[str | None] = mapped_column(String(255), nullable=True)
    skip_host_discovery: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    status: Mapped[str] = mapped_column(String(24), default="queued")
    created_by_user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    result: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    deadline_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class ExternalCheckRun(Base):
    __tablename__ = "external_check_runs"
    __table_args__ = (
        Index("ix_external_check_runs_workspace_type_started", "organization_id", "check_type", "started_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    check_type: Mapped[str] = mapped_column(String(24), nullable=False)
    domain: Mapped[str] = mapped_column(String(253), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="running")
    trigger_source: Mapped[str] = mapped_column(String(24), nullable=False, default="manual")
    triggered_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    started_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    snapshot: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    error_summary: Mapped[str | None] = mapped_column(String(500), nullable=True)
    change_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class ExternalCheckSchedule(Base):
    __tablename__ = "external_check_schedules"
    __table_args__ = (
        UniqueConstraint("organization_id", "check_type", name="uq_external_check_schedule_workspace_type"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    check_type: Mapped[str] = mapped_column(String(24), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    interval_hours: Mapped[int] = mapped_column(Integer, nullable=False, default=24)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_run_status: Mapped[str | None] = mapped_column(String(24), nullable=True)
    updated_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


class ExternalCheckChange(Base):
    __tablename__ = "external_check_changes"
    __table_args__ = (
        Index("ix_external_check_changes_workspace_detected", "organization_id", "detected_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    run_id: Mapped[int] = mapped_column(
        ForeignKey("external_check_runs.id", ondelete="CASCADE"), index=True
    )
    check_type: Mapped[str] = mapped_column(String(24), nullable=False)
    field_path: Mapped[str] = mapped_column(String(500), nullable=False)
    previous_value: Mapped[Any | None] = mapped_column(JSON, nullable=True)
    current_value: Mapped[Any | None] = mapped_column(JSON, nullable=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


class WorkspaceNotification(Base):
    """Durable workspace inbox item, deduplicated by completed source evidence."""

    __tablename__ = "workspace_notifications"
    __table_args__ = (
        UniqueConstraint("organization_id", "source_type", "source_id", name="uq_workspace_notification_source"),
        Index("ix_workspace_notifications_workspace_detected", "organization_id", "detected_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    source_type: Mapped[str] = mapped_column(String(40), nullable=False)
    source_id: Mapped[int] = mapped_column(Integer, nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    summary: Mapped[str] = mapped_column(String(1000), nullable=False)
    reason: Mapped[str] = mapped_column(String(80), nullable=False)
    detected_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


class WorkspaceNotificationRead(Base):
    """Per-member read receipt for a workspace notification."""

    __tablename__ = "workspace_notification_reads"
    __table_args__ = (
        UniqueConstraint("notification_id", "user_id", name="uq_workspace_notification_read_user"),
        Index("ix_workspace_notification_reads_user", "user_id", "read_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    notification_id: Mapped[int] = mapped_column(ForeignKey("workspace_notifications.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    read_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


class ReportJob(Base):
    __tablename__ = "report_jobs"
    __table_args__ = (
        Index("ix_report_jobs_workspace_created", "organization_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    created_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    report_type: Mapped[str] = mapped_column(String(40), nullable=False)
    domain: Mapped[str] = mapped_column(String(253), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="queued")
    progress: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    stage: Mapped[str] = mapped_column(String(120), nullable=False, default="Queued")
    file_name: Mapped[str] = mapped_column(String(255), nullable=False)
    artifact_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_summary: Mapped[str | None] = mapped_column(String(500), nullable=True)
    report_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class MerakiCredential(Base):
    __tablename__ = "meraki_credentials"
    __table_args__ = (UniqueConstraint("organization_id", name="uq_meraki_credential_workspace"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    encrypted_api_key: Mapped[str] = mapped_column(Text, nullable=False)
    key_hint: Mapped[str] = mapped_column(String(4), nullable=False)
    configured_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    last_verified_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


class MerakiOrganizationGrant(Base):
    """Explicitly approved Cisco organization scope for one Daedalus workspace."""

    __tablename__ = "meraki_organization_grants"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "meraki_organization_id",
            name="uq_meraki_org_grant_workspace_org",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    meraki_organization_id: Mapped[str] = mapped_column(String(128), nullable=False)
    meraki_organization_name: Mapped[str] = mapped_column(String(200), nullable=False)
    granted_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    granted_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


class CISAPIKey(Base):
    __tablename__ = "cis_api_keys"
    __table_args__ = (UniqueConstraint("organization_id", name="uq_cis_api_key_workspace"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    key_hint: Mapped[str] = mapped_column(String(4), nullable=False)
    created_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


class CISProfile(Base):
    __tablename__ = "cis_profiles"
    __table_args__ = (
        UniqueConstraint("organization_id", "slug", "version", name="uq_cis_profile_version"),
        Index("ix_cis_profiles_workspace_published", "organization_id", "published_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    slug: Mapped[str] = mapped_column(String(100), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    platform: Mapped[str] = mapped_column(String(32), nullable=False)
    description: Mapped[str] = mapped_column(String(1000), nullable=False, default="")
    checksum: Mapped[str] = mapped_column(String(64), nullable=False)
    content: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    published_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    created_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


class CISDevice(Base):
    __tablename__ = "cis_devices"
    __table_args__ = (
        UniqueConstraint("organization_id", "device_fingerprint", name="uq_cis_device_fingerprint"),
        Index("ix_cis_devices_workspace_seen", "organization_id", "last_seen_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    device_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False, default="CIS endpoint")
    platform: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    os_version: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


class CISReport(Base):
    __tablename__ = "cis_reports"
    __table_args__ = (
        UniqueConstraint("organization_id", "client_report_hash", name="uq_cis_client_report"),
        Index("ix_cis_reports_workspace_collected", "organization_id", "collected_at"),
        Index("ix_cis_reports_device_collected", "device_id", "collected_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    device_id: Mapped[int] = mapped_column(
        ForeignKey("cis_devices.id", ondelete="CASCADE"), index=True
    )
    client_report_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    profile_slug: Mapped[str] = mapped_column(String(100), nullable=False, default="")
    profile_version: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    collected_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    summary: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    results: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


class CISReportChange(Base):
    __tablename__ = "cis_report_changes"
    __table_args__ = (
        UniqueConstraint("report_id", "check_id", name="uq_cis_change_report_check"),
        Index("ix_cis_report_changes_workspace_detected", "organization_id", "detected_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    report_id: Mapped[int] = mapped_column(
        ForeignKey("cis_reports.id", ondelete="CASCADE"), index=True
    )
    check_id: Mapped[str] = mapped_column(String(120), nullable=False)
    previous_status: Mapped[str] = mapped_column(String(24), nullable=False)
    current_status: Mapped[str] = mapped_column(String(24), nullable=False)
    detected_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


class ScannerRunComparison(Base):
    __tablename__ = "scanner_run_comparisons"
    __table_args__ = (UniqueConstraint("agent_id", "current_run_id", "current_result_event_id",
        "previous_run_id", "previous_result_event_id", name="uq_scanner_comparison_evidence"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    agent_id: Mapped[int] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"), index=True)
    current_run_id: Mapped[str] = mapped_column(String(36), nullable=False)
    previous_run_id: Mapped[str] = mapped_column(String(36), nullable=False)
    current_result_event_id: Mapped[int] = mapped_column(ForeignKey("scan_events.id"), nullable=False)
    previous_result_event_id: Mapped[int] = mapped_column(ForeignKey("scan_events.id"), nullable=False)
    detected_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    meaningful_change_count: Mapped[int] = mapped_column(Integer, nullable=False)
    comparison: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
