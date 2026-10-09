"""Workspace-authorized OAuth, immutable reports and opt-in audit scheduling."""
from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, Field, StrictBool, StrictInt
from sqlalchemy import delete, func, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from daedalus import google_admin as api
from daedalus.config import GOOGLE_ADMIN_CLIENT_ID, GOOGLE_ADMIN_CLIENT_SECRET
from daedalus.credential_store import CredentialEncryptionError, decrypt_secret, encrypt_secret, encryption_available
from daedalus.db import get_db
from daedalus.models import GoogleAdminConnection, GoogleAdminConsent, GoogleAdminReview, Membership, Organization, ReportJob, WorkspaceNotification

def require_same_origin_mutation(request: Request):
    if request.method not in {"POST", "DELETE"}:
        return
    origin = request.headers.get("origin")
    if request.headers.get("sec-fetch-site") in {"cross-site", "same-site"} or origin and not host().websocket_origin_matches_host(origin, request.headers.get("host", ""), production=host().APP_ENV == "production"):
        raise HTTPException(403, "Google Admin audit changes must originate from this portal.")


router = APIRouter(dependencies=[Depends(require_same_origin_mutation)])


def host():
    from daedalus import server
    return server


def configured() -> bool:
    s = host()
    return bool(GOOGLE_ADMIN_CLIENT_ID and GOOGLE_ADMIN_CLIENT_SECRET and GOOGLE_ADMIN_CLIENT_ID != s.GOOGLE_CLIENT_ID and encryption_available())


def require_verified(org):
    if org.verification_status != "verified":
        raise HTTPException(403, "Verify workspace domain ownership before authorizing Google Admin audit access.")


def latest_manual_evidence(db: Session, organization_id: int, connection_id: str) -> dict:
    """Read the latest append-only evidence per check on this connection."""
    ids = select(func.max(GoogleAdminReview.id)).where(
        GoogleAdminReview.organization_id == organization_id,
        GoogleAdminReview.connection_id == connection_id,
    ).group_by(GoogleAdminReview.check_id)
    rows = db.scalars(select(GoogleAdminReview).where(GoogleAdminReview.id.in_(ids)).order_by(GoogleAdminReview.id.desc())).all()
    return {review.check_id: {"review_id": review.id, "reviewer_user_id": review.reviewer_user_id,
        "captured_at": review.evidence["evidence_collected_at"], "recorded_at": host().iso_utc(review.captured_at), **review.evidence}
        for review in rows}


def require_connection_reference(request: Request, db: Session, organization_id: int) -> None:
    """Keep a browser action on the connection its administrator reviewed."""
    expected = request.headers.get("X-Daedalus-Audit-Connection")
    if expected is None:
        return  # Existing authorized API clients retain their established contract.
    if db.get_bind().dialect.name == "sqlite":
        db.execute(text("BEGIN IMMEDIATE"))
    connection = db.scalar(select(GoogleAdminConnection).where(
        GoogleAdminConnection.organization_id == organization_id).with_for_update())
    actual = host().token_digest(connection.connection_id) if connection else "none"
    if expected != actual:
        raise HTTPException(409, "The audit connection changed. Refresh saved Google Admin data before retrying.")


@router.get("/api/google-admin")
def status(request: Request, db: Session = Depends(get_db)):
    s = host()
    _, org, member = s.get_org_context(request, db)
    connection = db.get(GoogleAdminConnection, org.id)
    latest = db.scalar(select(ReportJob).where(ReportJob.organization_id == org.id, ReportJob.report_type == "google_admin_security", ReportJob.status == "completed").order_by(ReportJob.id.desc()))
    attempt = db.scalar(select(ReportJob).where(ReportJob.organization_id == org.id, ReportJob.report_type == "google_admin_security").order_by(ReportJob.id.desc()))
    matches = bool(latest and connection and latest.report_snapshot.get("connection_id") == connection.connection_id)
    frozen_manual = latest.report_snapshot.get("google_admin", {}).get("manual_evidence", {}) if matches else {}
    pending = {key: evidence for key, evidence in latest_manual_evidence(db, org.id, connection.connection_id).items()
        if frozen_manual.get(key, {}).get("review_id") != evidence["review_id"]} if connection else {}
    return JSONResponse({"organization_id": org.id, "observed_at": s.iso_utc(s.utcnow()),
        "latest_matches_connection": matches, "pending_manual_evidence": pending,
        "configured": configured(), "connected": connection is not None, "is_admin": member.role == "admin", "verified": org.verification_status == "verified",
        "customer_id": connection.customer_id if connection else None, "binding": connection.approved_binding if connection else None,
        "last_verified_at": s.iso_utc(connection.last_verified_at) if connection else None,
        "connected_at": s.iso_utc(connection.connected_at) if connection else None,
        "connection_reference": s.token_digest(connection.connection_id) if connection else None,
        "last_error": connection.last_error if connection else None, "schedule_days": connection.schedule_days if connection else 0,
        "next_run_at": s.iso_utc(connection.next_run_at) if connection else None,
        "latest": {"report_id": latest.id, "assessment": {key: value for key, value in latest.report_snapshot.get("google_admin", {}).items() if key != "collections"}, "comparison": latest.report_snapshot.get("google_admin_comparison"), "completed_at": s.iso_utc(latest.completed_at)} if latest else None,
        "latest_attempt": s.serialize_report_job(attempt) if attempt else None,
        "checklist": [{"id": cid, "title": title, "cis_controls": controls, "expected": target, "status": "not_assessed"} for cid, title, controls, target in api.CHECKS]}, headers={"Cache-Control": "no-store"})


class ConnectInput(BaseModel):
    authorize_entire_customer: StrictBool


@router.post("/api/google-admin/connect")
async def connect(payload: ConnectInput, request: Request, db: Session = Depends(get_db)):
    s = host()
    user, org, _ = s.get_org_context(request, db, admin=True)
    require_verified(org)
    if not configured():
        raise HTTPException(503, "Configure a dedicated Google Admin OAuth project and integration encryption first.")
    if payload.authorize_entire_customer is not True:
        raise HTTPException(422, "Authorize the entire Google Workspace customer, including other domains and customer-wide roles, to use this audit.")
    state = secrets.token_urlsafe(32)
    now = s.utcnow()
    db.execute(delete(GoogleAdminConsent).where(GoogleAdminConsent.expires_at < now))
    db.add(GoogleAdminConsent(state_digest=s.token_digest(state), organization_id=org.id, user_id=user.id, domain=org.domain, expires_at=now + timedelta(minutes=10)))
    s.audit(db, org.id, user.id, "google_admin.consent_started", {"scope": "entire_customer", "domain": org.domain})
    db.commit()
    client = s.oauth.create_client("google_admin")
    response = await client.authorize_redirect(request, s.BASE_URL + "/auth/google-admin/callback", state=state, access_type="offline", prompt="consent", include_granted_scopes="false")
    return JSONResponse({"authorization_url": response.headers["location"]}, headers={"Cache-Control": "no-store"})


@router.get("/auth/google-admin/callback")
async def callback(request: Request, db: Session = Depends(get_db)):
    s = host()
    user, org, _ = s.get_org_context(request, db, admin=True)
    require_verified(org)
    if not configured():
        raise HTTPException(503, "The dedicated Google Admin OAuth project is unavailable.")
    state = request.query_params.get("state", "")
    digest = s.token_digest(state)
    now = s.utcnow()
    claimed = db.execute(update(GoogleAdminConsent).where(GoogleAdminConsent.state_digest == digest,
        GoogleAdminConsent.organization_id == org.id, GoogleAdminConsent.user_id == user.id, GoogleAdminConsent.domain == org.domain,
        GoogleAdminConsent.expires_at > now, GoogleAdminConsent.consumed_at.is_(None)).values(consumed_at=now))
    db.commit()
    if claimed.rowcount != 1:
        raise HTTPException(400, "Audit consent expired, was already used or belongs to another user/workspace. Start again.")
    if request.query_params.get("error"):
        s.audit(db, org.id, user.id, "google_admin.consent_cancelled", {})
        db.commit()
        return RedirectResponse("/dashboard#google-admin", status_code=303)
    try:
        token = await s.oauth.create_client("google_admin").authorize_access_token(request)
        scopes = api.validate_scopes(token.get("scope"))
        identity = token.get("userinfo")
        if not isinstance(token.get("id_token"), str) or not isinstance(identity, dict) or not identity.get("sub") or identity.get("email_verified") is not True or not identity.get("hd"):
            raise api.GoogleAdminError("Google did not confirm a verified Workspace identity.")
        refresh, access = token.get("refresh_token"), token.get("access_token")
        if not isinstance(refresh, str) or not refresh or not isinstance(access, str) or not access:
            raise api.GoogleAdminError("Google did not grant offline audit access. Start consent again.")
        def probe():
            with api.GoogleAdminClient(access) as client:
                return client.binding(org.domain)
        binding = await s.run_in_threadpool(probe)
        if str(identity["hd"]).lower().rstrip(".") not in binding["domains"]:
            raise api.GoogleAdminError("Google identity does not belong to the validated customer domains.")
        db.expire_all()
        user, org, _ = s.get_org_context(request, db, admin=True)
        require_verified(org)
        existing = db.get(GoogleAdminConnection, org.id)
        if existing and existing.active_report_id is not None:
            raise api.GoogleAdminError("An audit report is still running. Reconnect after it finishes.")
        # Customer-wide snapshots cannot be silently shared across domain workspaces.
        other = db.scalar(select(GoogleAdminConnection).where(GoogleAdminConnection.customer_id == binding["customer_id"], GoogleAdminConnection.organization_id != org.id))
        if other:
            raise api.GoogleAdminError("This Google customer is already connected to another workspace. Review customer-wide sharing before reconnecting it here.")
        if existing and existing.customer_id != binding["customer_id"]:
            raise api.GoogleAdminError("Disconnect the previous customer before replacing its binding.")
        values = dict(customer_id=binding["customer_id"], connection_id=secrets.token_hex(24), connected_by_user_id=user.id,
            google_subject=str(identity["sub"]), encrypted_refresh_token=encrypt_secret(refresh), granted_scopes=scopes,
            approved_binding=binding, connected_at=now, last_verified_at=now, last_error=None, schedule_days=0, next_run_at=None)
        if existing:
            for key, value in values.items():
                setattr(existing, key, value)
        else:
            db.add(GoogleAdminConnection(organization_id=org.id, **values))
        s.audit(db, org.id, user.id, "google_admin.connected", {"customer_id": binding["customer_id"], "scope": "entire_customer", "granted_scopes": scopes})
        db.commit()
    except (api.GoogleAdminError, CredentialEncryptionError) as exc:
        db.rollback()
        raise HTTPException(400, str(exc)) from exc
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "This Google customer was connected concurrently. Review its workspace binding.") from exc
    except Exception as exc:
        db.rollback()
        raise HTTPException(400, "Google Admin consent could not be validated. Start again.") from exc
    return RedirectResponse("/dashboard#google-admin", status_code=303)


def queue_report(db: Session, org: Organization, actor_id: int | None) -> ReportJob:
    s = host()
    require_verified(org)
    connection = db.get(GoogleAdminConnection, org.id)
    if not connection:
        raise HTTPException(409, "Connect Google Admin audit access first.")
    if db.scalar(select(ReportJob.id).where(ReportJob.organization_id == org.id, ReportJob.report_type == "google_admin_security", ReportJob.status.in_(("queued", "running")))):
        raise HTTPException(429, "A Google Admin report is already running.")
    active_count = db.scalar(select(func.count(ReportJob.id)).where(ReportJob.organization_id == org.id, ReportJob.status.in_(("queued", "running")))) or 0
    if active_count >= 3:
        raise HTTPException(429, "Three report jobs are already running for this workspace.")
    now = s.utcnow()
    job = ReportJob(organization_id=org.id, created_by_user_id=actor_id, report_type="google_admin_security", domain=org.domain,
        status="queued", progress=0, stage="Queued", file_name="pending.pdf", created_at=now, updated_at=now,
        report_snapshot={"domain": org.domain, "organization_name": org.name, "connection_id": connection.connection_id,
            "google_customer_id": connection.customer_id, "approved_binding": connection.approved_binding,
            "requested_by": "scheduled audit" if actor_id is None else "workspace administrator"})
    db.add(job)
    db.flush()
    lock = db.execute(update(GoogleAdminConnection).where(GoogleAdminConnection.organization_id == org.id,
        GoogleAdminConnection.connection_id == connection.connection_id, GoogleAdminConnection.active_report_id.is_(None)).values(active_report_id=job.id))
    if lock.rowcount != 1:
        db.rollback()
        raise HTTPException(429, "A Google Admin report is already running or the connection changed.")
    job.file_name = f"daedalus-google-admin-{job.id}.pdf"
    s.audit(db, org.id, actor_id, "report.requested", {"report_id": job.id, "report_type": job.report_type})
    return job


@router.post("/api/google-admin/reports")
def create_report(request: Request, tasks: BackgroundTasks, db: Session = Depends(get_db)):
    s = host()
    user, org, _ = s.get_org_context(request, db, admin=True)
    require_connection_reference(request, db, org.id)
    if not configured():
        raise HTTPException(503, "Google Admin audit OAuth is not configured.")
    job = queue_report(db, org, user.id)
    db.commit()
    tasks.add_task(s.generate_report_job, job.id)
    return s.serialize_report_job(job, user)


@router.get("/api/google-admin/reports/{report_id}/snapshot")
def snapshot(report_id: int, request: Request, db: Session = Depends(get_db)):
    import json
    s = host()
    _, org, _ = s.get_org_context(request, db)
    job = db.scalar(select(ReportJob).where(ReportJob.id == report_id, ReportJob.organization_id == org.id, ReportJob.report_type == "google_admin_security", ReportJob.status == "completed"))
    if not job:
        raise HTTPException(404, "Completed Google Admin evidence not found.")
    evidence = {key: value for key, value in job.report_snapshot.items() if key != "connection_id"}
    return Response(json.dumps(evidence, ensure_ascii=False), media_type="application/json", headers={"Cache-Control": "no-store", "Content-Disposition": f'attachment; filename="daedalus-google-admin-{job.id}.json"'})


class ReviewInput(BaseModel):
    check_id: str = Field(min_length=5, max_length=5)
    evidence_collected_at: datetime
    policy_scope: str = Field(min_length=3, max_length=300)
    observed: str = Field(min_length=3, max_length=1000)
    expected: str = Field(min_length=3, max_length=1000)
    rationale: str = Field(min_length=3, max_length=1000)
    source_reference: str = Field(min_length=3, max_length=500)
    owner: str = Field(min_length=3, max_length=200)
    validation: str = Field(min_length=3, max_length=1000)


@router.post("/api/google-admin/reviews")
def record_review(payload: ReviewInput, request: Request, db: Session = Depends(get_db)):
    s = host()
    user, org, _ = s.get_org_context(request, db, admin=True)
    require_connection_reference(request, db, org.id)
    require_verified(org)
    connection = db.get(GoogleAdminConnection, org.id)
    if not connection:
        raise HTTPException(409, "Connect the audit customer before recording its evidence.")
    if payload.check_id not in {row[0] for row in api.CHECKS}:
        raise HTTPException(422, "Select a check from the current Google Admin checklist.")
    if payload.evidence_collected_at.tzinfo is None or payload.evidence_collected_at > s.utcnow().replace(tzinfo=UTC) + timedelta(minutes=5):
        raise HTTPException(422, "Source evidence time must include a timezone and cannot be in the future.")
    values = payload.model_dump(mode="json", exclude={"check_id"})
    if any(not value.strip() for value in values.values()):
        raise HTTPException(422, "Evidence fields must contain meaningful text.")
    review = GoogleAdminReview(organization_id=org.id, connection_id=connection.connection_id, check_id=payload.check_id,
        reviewer_user_id=user.id, captured_at=s.utcnow(), evidence=values)
    db.add(review)
    db.flush()
    s.audit(db, org.id, user.id, "google_admin.manual_evidence_recorded", {"review_id": review.id, "check_id": payload.check_id})
    db.commit()
    return {"review_id": review.id, "status": "manual_review", "message": "Evidence saved for the next assessment; historical reports and API results are unchanged."}


class ScheduleInput(BaseModel):
    days: StrictInt
    reviewed_report_id: StrictInt | None = None


@router.post("/api/google-admin/schedule")
def schedule(payload: ScheduleInput, request: Request, db: Session = Depends(get_db)):
    s = host()
    user, org, _ = s.get_org_context(request, db, admin=True)
    require_connection_reference(request, db, org.id)
    connection = db.get(GoogleAdminConnection, org.id)
    if not connection:
        raise HTTPException(409, "Connect Google Admin first.")
    if payload.days not in (0, 1, 7, 30):
        raise HTTPException(422, "Choose off, daily, weekly or every 30 days.")
    if payload.days:
        require_verified(org)
        if payload.reviewed_report_id is None or not db.scalar(select(ReportJob.id).where(ReportJob.id == payload.reviewed_report_id, ReportJob.organization_id == org.id, ReportJob.report_type == "google_admin_security", ReportJob.status == "completed", ReportJob.report_snapshot["connection_id"].as_string() == connection.connection_id)):
            raise HTTPException(409, "Complete and review an audit on this connection before enabling its schedule.")
    connection.schedule_days = payload.days
    connection.next_run_at = s.utcnow() + timedelta(days=payload.days) if payload.days else None
    s.audit(db, org.id, user.id, "google_admin.schedule_changed", {"days": payload.days, "reviewed_report_id": payload.reviewed_report_id})
    db.commit()
    return {"schedule_days": connection.schedule_days, "next_run_at": s.iso_utc(connection.next_run_at)}


@router.delete("/api/google-admin")
async def disconnect(request: Request, db: Session = Depends(get_db)):
    s = host()
    user, org, _ = s.get_org_context(request, db, admin=True)
    require_connection_reference(request, db, org.id)
    connection = db.get(GoogleAdminConnection, org.id)
    if not connection:
        return {"connected": False}
    try:
        refresh = decrypt_secret(connection.encrypted_refresh_token)
    except CredentialEncryptionError:
        refresh = None
    db.delete(connection)
    now = s.utcnow()
    db.execute(update(ReportJob).where(ReportJob.organization_id == org.id, ReportJob.report_type == "google_admin_security", ReportJob.status.in_(("queued", "running"))).values(status="failed", stage="Audit disconnected", error_summary="Audit access was disconnected; collection stopped.", completed_at=now, updated_at=now))
    s.audit(db, org.id, user.id, "google_admin.disconnected", {})
    db.commit()
    revoked = await s.run_in_threadpool(api.revoke, refresh) if refresh else False
    s.audit(db, org.id, user.id, "google_admin.revocation_result", {"confirmed": revoked})
    db.commit()
    return {"connected": False, "revocation_confirmed": revoked}


def authorized_connection(db: Session, job: ReportJob) -> GoogleAdminConnection:
    connection = db.get(GoogleAdminConnection, job.organization_id)
    org = db.get(Organization, job.organization_id)
    actor = job.created_by_user_id or (connection.connected_by_user_id if connection else None)
    membership = db.scalar(select(Membership).where(Membership.organization_id == job.organization_id, Membership.user_id == actor, Membership.status == "approved", Membership.role == "admin"))
    if not connection or not org or org.verification_status != "verified" or not membership or connection.connection_id != job.report_snapshot.get("connection_id") or connection.active_report_id != job.id or job.status != "running":
        raise api.GoogleAdminError("Audit authorization changed or was disconnected; collection cannot continue.")
    # Hold a write fence through persistence/completion so a concurrent disconnect
    # cannot commit between the authorization check and the saved assessment.
    fenced = db.execute(update(GoogleAdminConnection).where(
        GoogleAdminConnection.organization_id == job.organization_id,
        GoogleAdminConnection.connection_id == job.report_snapshot.get("connection_id"),
        GoogleAdminConnection.active_report_id == job.id,
        select(Membership.id).where(Membership.organization_id == job.organization_id, Membership.user_id == actor,
            Membership.status == "approved", Membership.role == "admin").exists(),
        select(Organization.id).where(Organization.id == job.organization_id, Organization.verification_status == "verified").exists(),
    ).values(active_report_id=job.id).execution_options(synchronize_session=False))
    if fenced.rowcount != 1:
        raise api.GoogleAdminError("Audit authorization changed or was disconnected; collection cannot continue.")
    return connection


def collect_job(report_id: int) -> dict:
    s = host()
    with s.SessionLocal() as db:
        job = db.get(ReportJob, report_id)
        connection = authorized_connection(db, job)
        cid, domain, revision = connection.customer_id, job.domain, connection.connection_id
        if connection.approved_binding != job.report_snapshot.get("approved_binding"):
            raise api.GoogleAdminError("The approved customer scope changed; start a new audit.")
        encrypted_refresh = connection.encrypted_refresh_token
        snapshot = dict(job.report_snapshot)
        manual_evidence = latest_manual_evidence(db, job.organization_id, revision)
    try:
        refresh = decrypt_secret(encrypted_refresh)
        access = api.refresh_access_token(GOOGLE_ADMIN_CLIENT_ID, GOOGLE_ADMIN_CLIENT_SECRET, refresh)
        s.update_report_progress(report_id, 30, "Validating customer and collecting read-only account evidence")
        with api.GoogleAdminClient(access) as client:
            assessment = client.collect(domain, cid)
        assessment["manual_evidence"] = manual_evidence
        if assessment["binding"] != snapshot["approved_binding"]:
            raise api.GoogleAdminError("Google customer domains changed. Review and reconnect to approve the new scope.")
        with s.SessionLocal() as db:
            job = db.get(ReportJob, report_id)
            connection = authorized_connection(db, job)
            previous = db.scalar(select(ReportJob).where(ReportJob.organization_id == job.organization_id,
                ReportJob.report_type == "google_admin_security", ReportJob.status == "completed", ReportJob.id < job.id).order_by(ReportJob.id.desc()))
            comparison = api.compare(previous.report_snapshot.get("google_admin") if previous else None, assessment)
            comparison["previous_report_id"] = previous.id if previous else None
            snapshot.update(google_admin=assessment, google_admin_comparison=comparison)
            job.report_snapshot = snapshot
            connection.last_error, connection.last_verified_at = None, s.utcnow()
            db.commit()
        return snapshot
    except (api.GoogleAdminError, CredentialEncryptionError) as exc:
        with s.SessionLocal() as db:
            connection = db.get(GoogleAdminConnection, job.organization_id)
            if connection and connection.connection_id == revision:
                connection.last_error = str(exc)[:300]
                db.commit()
        raise


def release_job(db: Session, job: ReportJob):
    db.execute(update(GoogleAdminConnection).where(GoogleAdminConnection.organization_id == job.organization_id, GoogleAdminConnection.active_report_id == job.id).values(active_report_id=None))


def completion(db: Session, job: ReportJob):
    s = host()
    comparison = job.report_snapshot["google_admin_comparison"]
    counts = {key: len(comparison[key]) for key in ("configuration_changes", "coverage_changes", "baseline_changes")}
    if any(counts.values()):
        db.add(WorkspaceNotification(organization_id=job.organization_id, source_type="google_admin_report", source_id=job.id,
            title="Google Admin audit changes", summary=f"Report {job.id}: {counts['configuration_changes']} account/role observations changed; {counts['coverage_changes']} coverage changes; {counts['baseline_changes']} baseline changes. Review saved evidence.", reason="audit_comparison", detected_at=job.completed_at))
        s.audit(db, job.organization_id, job.created_by_user_id, "google_admin.changes_detected", {"report_id": job.id, **counts})
    release_job(db, job)


def run_due() -> list[int]:
    s = host()
    if not configured():
        return []
    ids = []
    with s.SessionLocal() as db:
        now = s.utcnow()
        due = db.scalars(select(GoogleAdminConnection).where(GoogleAdminConnection.schedule_days > 0, GoogleAdminConnection.next_run_at <= now)).all()
        for connection in due:
            org = db.get(Organization, connection.organization_id)
            if connection.active_report_id is not None:
                continue
            claimed = db.execute(update(GoogleAdminConnection).where(GoogleAdminConnection.organization_id == connection.organization_id,
                GoogleAdminConnection.connection_id == connection.connection_id, GoogleAdminConnection.next_run_at == connection.next_run_at).values(next_run_at=now + timedelta(days=connection.schedule_days)))
            if claimed.rowcount != 1:
                continue
            member = db.scalar(select(Membership).where(Membership.organization_id == org.id, Membership.user_id == connection.connected_by_user_id, Membership.role == "admin", Membership.status == "approved"))
            if org.verification_status != "verified" or not member:
                connection.schedule_days, connection.next_run_at = 0, None
                connection.last_error = "Schedule paused because workspace or consenting administrator authorization changed."
                s.audit(db, org.id, None, "google_admin.schedule_paused", {})
                db.commit()
                continue
            try:
                job = queue_report(db, org, None)
                db.commit()
                ids.append(job.id)
            except HTTPException:
                db.rollback()
    return ids
