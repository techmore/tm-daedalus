import copy
import io
import json
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
from fastapi.testclient import TestClient
from pypdf import PdfReader
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from daedalus import google_admin as api, google_admin_routes as routes, server
from daedalus.db import Base, get_db
from daedalus.models import GoogleAdminConnection, GoogleAdminConsent, GoogleAdminReview, Membership, Organization, ReportJob, User, WorkspaceNotification

BINDING = {"customer_id": "C123", "domains": ["cybersecuritypilot.org"], "scope": "entire_customer"}


def account(**changes):
    return {"key": "abc", "isAdmin": True, "isDelegatedAdmin": False, "suspended": False, "archived": False,
        "isEnrolledIn2Sv": True, "isEnforcedIn2Sv": True, **changes}


def assessment(rows=None, complete=True):
    return api.assess(BINDING, {"users": {"complete": complete, "status": "collected" if complete else "unavailable", "rows": rows if rows is not None else [account()]},
        "roles": {"complete": True, "status": "collected", "rows": []}, "assignments": {"complete": True, "status": "collected", "rows": []}})


def test_2sv_requires_definitive_population_and_fields():
    assert assessment()["checks"][2]["status"] == "pass"
    assert assessment([account(isEnrolledIn2Sv=False)])["checks"][2]["status"] == "fail"
    for rows in ([], [account(isEnrolledIn2Sv=None)], [account(isAdmin=None)], [account(suspended=True)]):
        assert assessment(rows)["checks"][2]["status"] == "manual_review"
    assert assessment(complete=False)["checks"][2]["status"] == "unavailable"
    assert assessment(complete=False)["summary"]["observed_pass_rate"] is None
    assert assessment()["summary"]["coverage_percent"] == 10


def test_scope_manifest_rejects_missing_extra_and_unconfirmed_grants():
    assert api.validate_scopes(" ".join(api.SCOPES)) == sorted(api.SCOPES)
    canonical = " ".join(api.SCOPES).replace(" email ", " " + api.PREFIX + "userinfo.email ")
    assert api.validate_scopes(canonical) == sorted(api.SCOPES)
    for scope in (None, "openid email", " ".join(api.SCOPES) + " " + api.PREFIX + "admin.directory.user.security"):
        with pytest.raises(api.GoogleAdminError): api.validate_scopes(scope)


def test_binding_rejects_wrong_customer_unverified_and_malformed_domains():
    with api.GoogleAdminClient("secret") as client:
        def get(path, params):
            return {"id": "C123"} if path == "customers/my_customer" else {"domains": [{"domainName": "cybersecuritypilot.org", "verified": True}]}
        with patch.object(client, "get", get):
            assert client.binding("cybersecuritypilot.org") == BINDING
            with pytest.raises(api.GoogleAdminError): client.binding("other.test")
            with pytest.raises(api.GoogleAdminError): client.binding("cybersecuritypilot.org", "wrong")
        with patch.object(client, "get", side_effect=[{"id": "C123"}, {"domains": [{"domainName": "cybersecuritypilot.org", "verified": False}]}]):
            with pytest.raises(api.GoogleAdminError): client.binding("cybersecuritypilot.org")


def test_pagination_never_treats_repeated_or_missing_evidence_as_complete():
    with api.GoogleAdminClient("secret") as client:
        with patch.object(client, "get", side_effect=[{"users": [{"id": "1"}], "nextPageToken": "A"}, {"users": [{"id": "2"}]}]):
            assert len(client.pages("users", "users", {})) == 2
        for pages in ([{"users": [{"id": "1"}], "nextPageToken": "A"}, {"users": [{"id": "1"}]}],
                      [{"users": [], "nextPageToken": "A"}, {"users": [], "nextPageToken": "A"}], [{}], [{"users": [{"id": None}]}]):
            with patch.object(client, "get", side_effect=pages):
                with pytest.raises(api.GoogleAdminError): client.pages("users", "users", {})


def test_network_boundary_refuses_redirects_writes_and_leaked_provider_errors():
    seen = []
    def transport(request):
        seen.append(request)
        return httpx.Response(302, headers={"location": "https://evil.test/steal"}, json={"error": "secret-token"})
    with api.GoogleAdminClient("secret-token") as client:
        client.http.close()
        client.http = httpx.Client(transport=httpx.MockTransport(transport), follow_redirects=False)
        with pytest.raises(api.GoogleAdminError, match="HTTP 302") as error:
            client.get("customers/my_customer")
        assert "secret-token" not in str(error.value)
        with pytest.raises(api.GoogleAdminError): client.get("users/123/delete")
        assert len(seen) == 1


def test_collection_minimizes_personal_data_and_handles_partial_roles():
    raw = {"id": "person-id", "customerId": "C123", "primaryEmail": "private@example.test", "recoveryEmail": "secret@example.test", **{k: v for k, v in account().items() if k != "key"}}
    with api.GoogleAdminClient("token") as client, patch.object(client, "binding", return_value=BINDING), patch.object(client, "pages", side_effect=[[raw], api.GoogleAdminError("roles unavailable"), []]):
        result = client.collect("cybersecuritypilot.org", "C123")
    text = json.dumps(result)
    assert "private@example.test" not in text and "secret@example.test" not in text and "person-id" not in text
    assert result["collections"]["roles"]["complete"] is False
    assert result["checks"][1]["status"] == "manual_review"


def test_comparison_withholds_removals_when_coverage_or_baseline_changes():
    old = assessment()
    assert api.compare(None, old)["baseline"]
    assert not api.compare(old, copy.deepcopy(old))["configuration_changes"]
    partial = assessment(complete=False)
    comparison = api.compare(old, partial)
    assert not comparison["configuration_changes"] and comparison["coverage_changes"]
    changed = assessment([account(isEnforcedIn2Sv=False)])
    assert len(api.compare(old, changed)["configuration_changes"]) == 1
    changed["checklist_version"] = "new"
    assert not api.compare(old, changed)["comparable"]
    assert api.compare(old, changed)["baseline_changes"]


@pytest.fixture
def portal(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path/'test.db'}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    def dependency():
        with factory() as db: yield db
    overrides = server.app.dependency_overrides.copy()
    server.app.dependency_overrides[get_db] = dependency
    with patch.object(server, "SessionLocal", factory), patch.object(server, "REPORTS_DIR", tmp_path / "reports"), patch.object(server, "DATA_DIR", tmp_path / "data"), patch.object(routes, "configured", return_value=True):
        server.seed_demo_workspace()
        client = TestClient(server.app)
        assert client.post("/dev/login", follow_redirects=False).status_code == 303
        with factory() as db:
            org = db.scalar(select(Organization))
            org.verification_status = "verified"
            user = db.scalar(select(User))
            now = server.utcnow()
            db.add(GoogleAdminConnection(organization_id=org.id, customer_id="C123", connection_id="version1", connected_by_user_id=user.id,
                google_subject="subject", encrypted_refresh_token="encrypted", granted_scopes=list(api.SCOPES), approved_binding=BINDING,
                connected_at=now, last_verified_at=now, schedule_days=0))
            db.commit()
            org_id, user_id = org.id, user.id
        yield client, factory, org_id, user_id
        client.close()
    server.app.dependency_overrides.clear()
    server.app.dependency_overrides.update(overrides)
    engine.dispose()


def collector():
    return patch.object(api.GoogleAdminClient, "collect", return_value=assessment())


@contextmanager
def valid_collection():
    with patch.object(routes, "decrypt_secret", return_value="refresh-private"), patch.object(api, "refresh_access_token", return_value="access-private"), collector():
        yield


def test_report_flow_history_json_pdf_schedule_and_deduplication(portal):
    client, factory, org_id, _ = portal
    assert client.post("/api/google-admin/schedule", json={"days": 7}).status_code == 409
    with valid_collection():
        first = client.post("/api/google-admin/reports")
        assert first.status_code == 200, first.text
        first_id = first.json()["id"]
        second = client.post("/api/google-admin/reports")
        assert second.status_code == 200, second.text
        second_id = second.json()["id"]
    for report_id in (first_id, second_id):
        evidence = client.get(f"/api/google-admin/reports/{report_id}/snapshot")
        assert evidence.status_code == 200
        assert "connection_id" not in evidence.json()
        assert "access-private" not in evidence.text and "refresh-private" not in evidence.text
        pdf = client.get(f"/api/reports/{report_id}/download")
        assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")
        text = " ".join(p.extract_text() for p in PdfReader(io.BytesIO(pdf.content)).pages)
        assert "Google Admin security audit" in text and "not a CIS compliance attestation" in text
    assert client.get(f"/api/google-admin/reports/{second_id}/snapshot").json()["google_admin_comparison"]["previous_report_id"] == first_id
    assert client.post("/api/google-admin/schedule", json={"days": 7, "reviewed_report_id": client.get("/api/google-admin").json()["latest"]["report_id"]}).status_code == 200
    with factory() as db:
        assert db.get(GoogleAdminConnection, org_id).active_report_id is None
        assert not db.scalars(select(WorkspaceNotification).where(WorkspaceNotification.source_type == "google_admin_report")).all()
        old = db.get(ReportJob, first_id).report_snapshot
        assert old["google_admin_comparison"]["baseline"]
    assert any(a["key"] == "google-admin" for a in client.get("/api/workspace-posture").json()["areas"])


def test_manual_evidence_is_append_only_and_frozen_without_changing_api_status(portal):
    client, factory, _, _ = portal
    payload = dict(check_id="GA-07", evidence_collected_at=server.utcnow().isoformat()+"Z", policy_scope="Staff OU / edition review", observed="External sharing allowed", expected="Approved partners only", rationale="Limit unintended disclosure", source_reference="Private capture 2026-10-08", owner="Workspace administrator", validation="Review inherited staff OU policy")
    assert client.post("/api/google-admin/reviews", json=payload).status_code == 200
    with valid_collection():
        report_id = client.post("/api/google-admin/reports").json()["id"]
    saved = client.get(f"/api/google-admin/reports/{report_id}/snapshot").json()
    assert saved["google_admin"]["manual_evidence"]["GA-07"]["observed"] == payload["observed"]
    assert saved["google_admin"]["checks"][6]["status"] == "manual_review"
    assert client.post("/api/google-admin/reviews", json={**payload, "observed": "Changed observation"}).status_code == 200
    assert client.get(f"/api/google-admin/reports/{report_id}/snapshot").json() == saved
    with factory() as db: assert len(db.scalars(select(GoogleAdminReview)).all()) == 2


def test_members_and_other_workspaces_cannot_mutate_or_read_evidence(portal):
    client, factory, org_id, user_id = portal
    with valid_collection():
        report_id = client.post("/api/google-admin/reports").json()["id"]
    with factory() as db:
        member = db.scalar(select(Membership).where(Membership.user_id == user_id, Membership.organization_id == org_id))
        member.role = "user"
        db.commit()
    assert client.post("/api/google-admin/reports").status_code == 403
    assert client.delete("/api/google-admin").status_code == 403
    assert client.post("/api/google-admin/schedule", json={"days": 7}).status_code == 403
    assert client.get(f"/api/google-admin/reports/{report_id}/snapshot").status_code == 200
    # Move this user to a separately authorized domain, preserving the original report.
    with factory() as db:
        member = db.scalar(select(Membership).where(Membership.user_id == user_id, Membership.organization_id == org_id))
        member.status = "revoked"
        other = Organization(name="Other", slug="other", domain="other.test", verification_status="verified", created_at=server.utcnow())
        db.add(other); db.flush()
        db.add(Membership(organization_id=other.id, user_id=user_id, role="admin", status="approved", created_at=server.utcnow()))
        db.commit(); other_id = other.id
    assert client.post("/api/workspaces/select", json={"organization_id": other_id}).status_code == 200
    assert client.get(f"/api/google-admin/reports/{report_id}/snapshot").status_code == 404
    assert client.get(f"/api/reports/{report_id}/download").status_code == 404


def test_failed_refresh_preserves_last_good_report_and_releases_lock(portal):
    client, factory, org_id, _ = portal
    with valid_collection():
        good = client.post("/api/google-admin/reports").json()["id"]
    with patch.object(routes, "decrypt_secret", return_value="private"), patch.object(api, "refresh_access_token", side_effect=api.GoogleAdminError("Audit consent expired. Reconnect.")):
        failed = client.post("/api/google-admin/reports").json()["id"]
    data = client.get("/api/google-admin").json()
    assert data["latest"]["report_id"] == good and data["latest_attempt"]["status"] == "failed"
    assert "Reconnect" in data["last_error"]
    with factory() as db:
        assert db.get(GoogleAdminConnection, org_id).active_report_id is None
        assert db.get(ReportJob, failed).status == "failed"


def test_disconnect_discards_inflight_collection_and_stops_schedules(portal):
    client, factory, org_id, _ = portal
    with patch.object(server, "generate_report_job"):
        report_id = client.post("/api/google-admin/reports").json()["id"]
    with patch.object(routes, "decrypt_secret", return_value="refresh"), patch.object(api, "revoke", return_value=False):
        response = client.delete("/api/google-admin")
    assert response.json() == {"connected": False, "revocation_confirmed": False}
    with factory() as db:
        assert db.get(GoogleAdminConnection, org_id) is None
        assert db.get(ReportJob, report_id).status == "failed"
    server.generate_report_job(report_id)
    with factory() as db: assert db.get(ReportJob, report_id).status == "failed"


def test_one_time_oauth_state_binds_actor_workspace_and_expiry(portal):
    client, factory, org_id, user_id = portal
    now = server.utcnow()
    for state, expires, actor in (("expired", now-timedelta(seconds=1), user_id), ("valid", now+timedelta(minutes=5), user_id)):
        with factory() as db:
            db.add(GoogleAdminConsent(state_digest=server.token_digest(state), organization_id=org_id, user_id=actor, domain=BINDING["domains"][0], expires_at=expires))
            db.commit()
    assert client.get("/auth/google-admin/callback?state=expired&error=access_denied").status_code == 400
    assert client.get("/auth/google-admin/callback?state=valid&error=access_denied", follow_redirects=False).status_code == 303
    assert client.get("/auth/google-admin/callback?state=valid&error=access_denied").status_code == 400


def test_scheduler_claims_once_and_blocks_lost_admin_authority(portal):
    client, factory, org_id, user_id = portal
    with valid_collection(): client.post("/api/google-admin/reports")
    assert client.post("/api/google-admin/schedule", json={"days": 7, "reviewed_report_id": client.get("/api/google-admin").json()["latest"]["report_id"]}).status_code == 200
    with factory() as db:
        db.get(GoogleAdminConnection, org_id).next_run_at = server.utcnow()-timedelta(seconds=1)
        db.commit()
    ids = routes.run_due()
    assert len(ids) == 1 and routes.run_due() == []
    with valid_collection(): server.generate_report_job(ids[0])
    with factory() as db:
        db.get(GoogleAdminConnection, org_id).next_run_at = server.utcnow()-timedelta(seconds=1)
        db.scalar(select(Membership).where(Membership.organization_id == org_id, Membership.user_id == user_id)).role = "user"
        db.commit()
    assert routes.run_due() == []
    with factory() as db: assert db.get(GoogleAdminConnection, org_id).schedule_days == 0


def test_oauth_callback_validates_grants_and_tenant_before_encrypting(portal):
    client, factory, org_id, user_id = portal
    class OAuthClient:
        token = {"scope": " ".join(api.SCOPES), "id_token": "library-validated-token", "userinfo": {"sub": "google-subject", "hd": "cybersecuritypilot.org", "email_verified": True}, "refresh_token": "refresh-private", "access_token": "access-private"}
        async def authorize_access_token(self, request): return self.token
    fake = OAuthClient()
    for state, expected_code, binding in (("right", 303, BINDING), ("wrong", 400, {**BINDING, "domains": ["other.test"]})):
        with factory() as db:
            db.add(GoogleAdminConsent(state_digest=server.token_digest(state), organization_id=org_id, user_id=user_id, domain="cybersecuritypilot.org", expires_at=server.utcnow()+timedelta(minutes=5)))
            db.commit()
        with patch.object(server.oauth, "create_client", return_value=fake), patch.object(api.GoogleAdminClient, "binding", return_value=binding), patch.object(routes, "encrypt_secret", return_value="ciphertext") as encrypt:
            response = client.get(f"/auth/google-admin/callback?state={state}&code=code", follow_redirects=False)
            assert response.status_code == expected_code, response.text
            assert encrypt.call_count == (1 if expected_code == 303 else 0)
    with factory() as db:
        stored = db.get(GoogleAdminConnection, org_id)
        assert stored.encrypted_refresh_token == "ciphertext" and stored.google_subject == "google-subject"
    fake.token = {**fake.token, "scope": " ".join(api.SCOPES)+" "+api.PREFIX+"admin.directory.user.security"}
    with factory() as db:
        db.add(GoogleAdminConsent(state_digest=server.token_digest("extra"), organization_id=org_id, user_id=user_id, domain="cybersecuritypilot.org", expires_at=server.utcnow()+timedelta(minutes=5))); db.commit()
    with patch.object(server.oauth, "create_client", return_value=fake), patch.object(api.GoogleAdminClient, "binding") as probe:
        assert client.get("/auth/google-admin/callback?state=extra&code=code").status_code == 400
        probe.assert_not_called()


def test_missing_fields_are_coverage_changes_not_configuration_drift():
    comparison = api.compare(assessment(), assessment([account(isEnforcedIn2Sv=None)]))
    assert not comparison["configuration_changes"]
    assert comparison["coverage_changes"][0]["field"] == "isEnforcedIn2Sv"


def test_inflight_disconnect_prevents_persisting_new_assessment(portal):
    client, factory, org_id, _ = portal
    def collect(*args):
        with factory() as db:
            connection = db.get(GoogleAdminConnection, org_id)
            db.delete(connection)
            db.commit()
        return assessment()
    with patch.object(routes, "decrypt_secret", return_value="refresh"), patch.object(api, "refresh_access_token", return_value="access"), patch.object(api.GoogleAdminClient, "collect", side_effect=collect):
        report_id = client.post("/api/google-admin/reports").json()["id"]
    with factory() as db:
        job = db.get(ReportJob, report_id)
        assert job.status == "failed" and "google_admin" not in job.report_snapshot
    assert client.get(f"/api/google-admin/reports/{report_id}/snapshot").status_code == 404


def test_cross_origin_browser_requests_cannot_mutate_audit_access(portal):
    client, _, _, _ = portal
    assert client.post("/api/google-admin/reports", headers={"Origin": "https://evil.test"}).status_code == 403
    assert client.delete("/api/google-admin", headers={"Sec-Fetch-Site": "same-site", "Origin": "http://sibling.test"}).status_code == 403
    assert client.post("/api/google-admin/schedule", json={"days": 0}, headers={"Origin": "http://testserver"}).status_code == 200


def test_collection_deadline_prevents_unbounded_api_work():
    with api.GoogleAdminClient("secret") as client:
        client.deadline = 0
        with patch.object(client.http, "stream") as network:
            with pytest.raises(api.GoogleAdminError, match="deadline"):
                client.get("customers/my_customer")
            network.assert_not_called()


def review_payload(check_id="GA-07", observed="External sharing allowed"):
    return dict(check_id=check_id, evidence_collected_at=server.utcnow().isoformat()+"Z", policy_scope="Staff OU / edition review", observed=observed,
        expected="Approved partners only", rationale="Limit unintended disclosure", source_reference="Private fixture capture", owner="Workspace administrator", validation="Review inherited staff OU policy")


def test_status_identifies_scope_and_previous_connection_without_exposing_credentials(portal):
    client, factory, org_id, _ = portal
    response = client.get("/api/google-admin")
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["organization_id"] == org_id
    assert response.json()["observed_at"].endswith("Z")
    assert response.json()["connected_at"].endswith("Z")
    assert response.json()["latest_matches_connection"] is False
    with valid_collection():
        report_id = client.post("/api/google-admin/reports").json()["id"]
    assert client.get("/api/google-admin").json()["latest_matches_connection"] is True
    with factory() as db:
        db.get(GoogleAdminConnection, org_id).connection_id = "version2"
        db.commit()
    status = client.get("/api/google-admin")
    assert status.json()["latest"]["report_id"] == report_id
    assert status.json()["latest_matches_connection"] is False
    assert "encrypted" not in status.text and "access-private" not in status.text and "connection_id" not in status.text
    client.cookies.clear()
    assert client.get("/api/google-admin").status_code == 401


def test_pending_manual_evidence_reload_collect_revision_and_scope_preserve_frozen_reports(portal):
    client, factory, org_id, _ = portal
    created = client.post("/api/google-admin/reviews", json=review_payload())
    assert created.status_code == 200
    pending = client.get("/api/google-admin").json()["pending_manual_evidence"]
    assert pending["GA-07"]["review_id"] == created.json()["review_id"]
    assert pending["GA-07"]["observed"] == "External sharing allowed"
    assert pending["GA-07"]["captured_at"].endswith("Z")
    assert pending["GA-07"]["recorded_at"].endswith("Z")
    with valid_collection():
        report_id = client.post("/api/google-admin/reports").json()["id"]
    frozen = client.get(f"/api/google-admin/reports/{report_id}/snapshot").json()
    assert client.get("/api/google-admin").json()["pending_manual_evidence"] == {}
    revised = client.post("/api/google-admin/reviews", json=review_payload(observed="Revised staff sharing observation"))
    pending = client.get("/api/google-admin").json()["pending_manual_evidence"]
    assert pending["GA-07"]["review_id"] == revised.json()["review_id"]
    assert pending["GA-07"]["observed"] == "Revised staff sharing observation"
    assert client.get(f"/api/google-admin/reports/{report_id}/snapshot").json() == frozen
    with factory() as db:
        connection = db.get(GoogleAdminConnection, org_id)
        connection.connection_id = "version2"
        db.commit()
    assert client.get("/api/google-admin").json()["pending_manual_evidence"] == {}
    assert client.get(f"/api/google-admin/reports/{report_id}/snapshot").json() == frozen
    other = client.post("/api/workspaces", json={"name":"Other review fixture", "domain":"other-review.example"})
    assert other.status_code == 200
    assert client.get("/api/google-admin").json()["pending_manual_evidence"] == {}
    assert client.get(f"/api/google-admin/reports/{report_id}/snapshot").status_code == 404


def test_latest_manual_per_check_survives_more_than_a_thousand_revisions_of_another_check(portal):
    client, factory, org_id, user_id = portal
    created = client.post("/api/google-admin/reviews", json=review_payload(check_id="GA-08"))
    old_id = created.json()["review_id"]
    with factory() as db:
        values = review_payload()
        values.pop("check_id")
        for _ in range(1001):
            db.add(GoogleAdminReview(organization_id=org_id, connection_id="version1", check_id="GA-07", reviewer_user_id=user_id, captured_at=server.utcnow(), evidence=values))
        db.commit()
    pending = client.get("/api/google-admin").json()["pending_manual_evidence"]
    assert set(pending) == {"GA-07", "GA-08"}
    assert pending["GA-08"]["review_id"] == old_id
    with valid_collection():
        report_id = client.post("/api/google-admin/reports").json()["id"]
    frozen = client.get(f"/api/google-admin/reports/{report_id}/snapshot").json()["google_admin"]["manual_evidence"]
    assert frozen == pending
    assert client.get("/api/google-admin").json()["pending_manual_evidence"] == {}


def test_browser_mutations_refuse_a_replaced_connection_and_accept_current_reference(portal):
    client, factory, org_id, _ = portal
    prior = client.get("/api/google-admin").json()["connection_reference"]
    with factory() as db:
        db.get(GoogleAdminConnection, org_id).connection_id = "replaced-version"
        db.commit()
    headers = {"X-Daedalus-Audit-Connection": prior}
    for method, path, body in (("POST", "/reviews", review_payload()), ("POST", "/schedule", {"days":0}), ("POST", "/reports", None), ("DELETE", "", None)):
        response = client.request(method, "/api/google-admin"+path, headers=headers, json=body)
        assert response.status_code == 409, response.text
        assert "connection changed" in response.json()["detail"]
    with factory() as db:
        assert db.get(GoogleAdminConnection, org_id).connection_id == "replaced-version"
        assert not db.scalars(select(GoogleAdminReview)).all()
        assert not db.scalars(select(ReportJob).where(ReportJob.report_type=="google_admin_security")).all()
    current = client.get("/api/google-admin").json()["connection_reference"]
    assert current != prior and len(current) == 64
    headers = {"X-Daedalus-Audit-Connection": current}
    assert client.post("/api/google-admin/reviews", headers=headers, json=review_payload()).status_code == 200
    assert client.post("/api/google-admin/schedule", headers=headers, json={"days":0}).status_code == 200
    with valid_collection():
        assert client.post("/api/google-admin/reports", headers=headers).status_code == 200
    with patch.object(routes, "decrypt_secret", return_value="fixture-refresh"), patch.object(api, "revoke", return_value=True):
        assert client.delete("/api/google-admin", headers=headers).status_code == 200


def test_pending_notes_are_scoped_even_when_connections_share_a_fixture_revision(portal):
    client, factory, org_id, user_id = portal
    assert client.post("/api/google-admin/reviews", json=review_payload()).status_code == 200
    with factory() as db:
        now = server.utcnow()
        other = Organization(name="Other evidence fixture", slug="other-evidence", domain="other-evidence.example", verification_status="verified", created_at=now)
        db.add(other);db.flush()
        db.add(Membership(organization_id=other.id,user_id=user_id,role="admin",status="approved",created_at=now))
        db.add(GoogleAdminConnection(organization_id=other.id,customer_id="C456",connection_id="version1",connected_by_user_id=user_id,google_subject="other-subject",encrypted_refresh_token="other-encrypted",granted_scopes=list(api.SCOPES),approved_binding={"customer_id":"C456","domains":[other.domain],"scope":"entire_customer"},connected_at=now,last_verified_at=now,schedule_days=0))
        values=review_payload(observed="Other customer evidence only");values.pop("check_id")
        db.add(GoogleAdminReview(organization_id=other.id,connection_id="version1",check_id="GA-07",reviewer_user_id=user_id,captured_at=now,evidence=values))
        db.commit();other_id=other.id
    assert client.post("/api/workspaces/select",json={"organization_id":other_id}).status_code == 200
    status=client.get("/api/google-admin").json()
    assert status["organization_id"] == other_id
    assert status["pending_manual_evidence"]["GA-07"]["observed"] == "Other customer evidence only"
    assert client.post("/api/workspaces/select",json={"organization_id":org_id}).status_code == 200
    assert client.get("/api/google-admin").json()["pending_manual_evidence"]["GA-07"]["observed"] == "External sharing allowed"


def test_actual_scoped_status_payload_renders_in_the_real_ui_with_retry_retention(portal):
    import shutil
    if not shutil.which('node'):
        pytest.skip('Node.js required')
    try:
        from .test_google_admin_refresh_ui import GoogleAdminRefreshUITests
    except ImportError:
        from test_google_admin_refresh_ui import GoogleAdminRefreshUITests
    client, _, _, _ = portal
    assert client.post('/api/google-admin/reviews', json=review_payload()).status_code == 200
    with valid_collection():
        assert client.post('/api/google-admin/reports').status_code == 200
    assert client.post('/api/google-admin/reviews', json=review_payload(observed='Revised evidence awaiting collection')).status_code == 200
    payload = client.get('/api/google-admin').json()
    GoogleAdminRefreshUITests().run_node('data=' + json.dumps(payload) + r''';
await load();assert.match(n('summary').textContent,/checks assessed/);assert.match(n('pending-evidence').textContent,/Revised evidence awaiting collection/);
const summary=n('summary').textContent,card=n('checklist').children[0],pending=n('pending-evidence').children[0];card.open=true;
failure=true;await load();assert.equal(n('summary').textContent,summary);assert.equal(n('checklist').children[0],card);assert.equal(n('pending-evidence').children[0],pending);
failure=false;await n('refresh').emit('click');assert.equal(n('refresh-status').textContent,'');assert.equal(n('checklist').children[0],card);assert.equal(card.open,true);
''')
