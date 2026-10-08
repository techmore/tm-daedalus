"""Platform-admin-approved complimentary onboarding, without DNS verification."""
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from daedalus.db import get_db
from daedalus.models import CustomerOnboarding, Membership, Organization, WorkspaceNotification

router = APIRouter()


def host():
    from daedalus import server
    return server


def platform_admin(request, db):
    server = host()
    user = server.get_session_user(request, db)
    if getattr(request.state, "user_api_key", None) is not None:
        raise HTTPException(403, "Platform onboarding requires Google sign-in")
    if user.email.lower() not in server.PLATFORM_ADMIN_EMAILS:
        raise HTTPException(403, "Platform administrator required")
    return user


def mutation_origin(request):
    from urllib.parse import urlsplit
    origin = request.headers.get("origin")
    expected = urlsplit(host().BASE_URL)
    if request.headers.get("sec-fetch-site") == "cross-site" or (origin and origin.rstrip("/") != f"{expected.scheme}://{expected.netloc}"):
        raise HTTPException(403, "Same-origin request required")


def approved_workspace(db, user, organization_id):
    org = db.scalar(select(Organization).join(Membership).where(
        Organization.id == organization_id, Membership.user_id == user.id,
        Membership.status == "approved", Membership.role == "admin"))
    if org is None:
        raise HTTPException(404, "Customer workspace not found")
    return org


def active(db, organization_id, now=None):
    now = now or host().utcnow()
    return db.scalar(select(CustomerOnboarding).where(
        CustomerOnboarding.organization_id == organization_id,
        CustomerOnboarding.status == "onboarding", CustomerOnboarding.review_due_at > now))


def summary(db, organization_id):
    row = db.get(CustomerOnboarding, organization_id)
    if row is None:
        return None
    return {"status": row.status, "version": row.version, "complimentary": row.status == "onboarding",
            "reason": row.reason, "review_due_at": host().iso_utc(row.review_due_at),
            "review_required": row.status == "onboarding" and row.review_due_at <= host().utcnow()}


def start(db, org, user, reason):
    now = host().utcnow()
    row = CustomerOnboarding(organization_id=org.id, approved_by_user_id=user.id,
        status="onboarding", version=1, reason=reason, approved_at=now,
        review_due_at=now + timedelta(days=30))
    db.add(row)
    host().audit(db, org.id, user.id, "onboarding.approved", {
        "version": 1, "complimentary": True, "duration_days": 30,
        "review_due_at": host().iso_utc(row.review_due_at), "reason": reason})
    return row


class Decision(BaseModel):
    version: int = Field(ge=0)
    action: str = Field(pattern="^(approve|end)$")
    reason: str = Field(min_length=8, max_length=500)


@router.get("/api/admin/onboarding")
def customers(request: Request, db: Session = Depends(get_db)):
    user = platform_admin(request, db)
    rows = db.scalars(select(Organization).join(Membership).where(
        Membership.user_id == user.id, Membership.status == "approved",
        Membership.role == "admin").order_by(Organization.name)).all()
    from fastapi.responses import JSONResponse
    return JSONResponse({"customers": [{"id": org.id, "name": org.name,
        "domain": org.domain, "verification_status": org.verification_status,
        "onboarding": summary(db, org.id)} for org in rows]}, headers={"Cache-Control": "no-store"})


@router.post("/api/admin/onboarding/{organization_id}")
def decide(organization_id: int, payload: Decision, request: Request, db: Session = Depends(get_db)):
    user = platform_admin(request, db)
    mutation_origin(request)
    org = approved_workspace(db, user, organization_id)
    reason = payload.reason.strip()
    if len(reason) < 8:
        raise HTTPException(422, "Enter a reason of at least 8 characters")
    row = db.get(CustomerOnboarding, org.id)
    now = host().utcnow()
    if row is None:
        if payload.version != 0 or payload.action != "approve":
            raise HTTPException(409, "Refresh the customer list before reviewing")
        start(db, org, user, reason)
    else:
        if row.status == "onboarding" and row.review_due_at > now and payload.action == "approve":
            raise HTTPException(409, "This customer's 30-day approval is still active")
        changed = db.execute(update(CustomerOnboarding).where(
            CustomerOnboarding.organization_id == org.id, CustomerOnboarding.version == payload.version
        ).values(version=payload.version + 1, status="onboarding" if payload.action == "approve" else "ended",
                 approved_by_user_id=user.id, approved_at=now,
                 review_due_at=now + timedelta(days=30) if payload.action == "approve" else now,
                 reason=reason))
        if changed.rowcount != 1:
            raise HTTPException(409, "Another review changed this customer. Refresh before reviewing")
        host().audit(db, org.id, user.id, "onboarding.reapproved" if payload.action == "approve" else "onboarding.ended", {
            "version": payload.version + 1, "complimentary": payload.action == "approve",
            "duration_days": 30 if payload.action == "approve" else 0, "reason": reason,
            "review_due_at": host().iso_utc(now + timedelta(days=30) if payload.action == "approve" else now)})
        if payload.action == "end" and not host().workspace_controls_available(db, org):
            host().close_scanner_controls(db, org.id, actor_user_id=user.id, reason="onboarding_ended", now=now)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "Another review changed this customer. Refresh before reviewing") from exc
    db.expire_all()
    return {"organization_id": org.id, "onboarding": summary(db, org.id)}


def record_due():
    server = host()
    now = server.utcnow()
    with server.SessionLocal() as db:
        rows = db.scalars(select(CustomerOnboarding).where(
            CustomerOnboarding.status == "onboarding", CustomerOnboarding.review_due_at <= now)).all()
        for row in rows:
            exists = db.scalar(select(WorkspaceNotification.id).where(
                WorkspaceNotification.organization_id == row.organization_id,
                WorkspaceNotification.source_type == "onboarding_review_due",
                WorkspaceNotification.source_id == row.version))
            if exists:
                continue
            try:
                with db.begin_nested():
                    db.add(WorkspaceNotification(organization_id=row.organization_id,
                        source_type="onboarding_review_due", source_id=row.version,
                        title="Onboarding needs 30-day reapproval",
                        summary="The complimentary onboarding DNS exception has expired. A platform administrator must review and reapprove it. Saved reports and ordinary public checks remain available.",
                        reason="access_override", detected_at=now))
                    db.flush()
                    org = db.get(Organization, row.organization_id)
                    if org is not None and not server.workspace_controls_available(db, org):
                        server.close_scanner_controls(db, org.id, actor_user_id=None, reason="onboarding_review_due", now=now)
                    server.audit(db, row.organization_id, None, "onboarding.review_due", {
                        "version": row.version, "review_due_at": server.iso_utc(row.review_due_at)})
            except IntegrityError:
                continue
        db.commit()
