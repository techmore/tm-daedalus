import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select, update
from sqlalchemy.orm import Session, sessionmaker
from starlette.websockets import WebSocketDisconnect

from daedalus import server
from daedalus.db import Base, get_db
from daedalus.models import AuditLog, DomainChallenge, Membership, Organization, User


class FakeGoogleClient:
    def __init__(self, profile):
        self.profile = profile

    async def authorize_access_token(self, _request):
        return {"userinfo": self.profile}

    async def authorize_redirect(self, _request, redirect_uri):
        from starlette.responses import RedirectResponse

        return RedirectResponse(redirect_uri, status_code=307)


class AuthAndWorkspaceFlowTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="daedalus-auth-flow-")
        self.root = Path(self.temp_dir.name)
        self.engine = create_engine(
            f"sqlite:///{self.root / 'test.db'}",
            connect_args={"check_same_thread": False},
        )
        Base.metadata.create_all(self.engine)
        self.session_factory = sessionmaker(
            bind=self.engine,
            autoflush=False,
            expire_on_commit=False,
        )

        self.dependency_overrides = server.app.dependency_overrides.copy()

        def override_get_db():
            db = self.session_factory()
            try:
                yield db
            finally:
                db.close()

        server.app.dependency_overrides[get_db] = override_get_db
        self.session_local_patch = patch.object(server, "SessionLocal", self.session_factory)
        self.session_local_patch.start()
        server.seed_demo_workspace()
        self.client = TestClient(server.app)
        self.admin_client = TestClient(server.app)
        login = self.admin_client.post("/dev/login", follow_redirects=False)
        self.assertEqual(login.status_code, 303)

    def tearDown(self):
        self.client.close()
        self.admin_client.close()
        server.app.dependency_overrides.clear()
        server.app.dependency_overrides.update(self.dependency_overrides)
        self.session_local_patch.stop()
        self.engine.dispose()
        self.temp_dir.cleanup()

    def google_callback(self, profile):
        fake_google = FakeGoogleClient(profile)
        with (
            patch.object(server, "GOOGLE_CLIENT_ID", "test-client-id"),
            patch.object(server, "GOOGLE_CLIENT_SECRET", "test-client-secret"),
            patch.object(server.oauth, "create_client", return_value=fake_google),
        ):
            return self.client.get("/auth/google/callback", follow_redirects=False)

    def test_google_login_uses_registered_oauth_callback_uri(self):
        with (
            patch.object(server, "GOOGLE_CLIENT_ID", "test-client-id"),
            patch.object(server, "GOOGLE_CLIENT_SECRET", "test-client-secret"),
            patch.object(server, "BASE_URL", "https://daedalus.cybersecuritypilot.org"),
            patch.object(server.oauth, "create_client", return_value=FakeGoogleClient({})),
        ):
            response = self.client.get("/auth/google", follow_redirects=False)

        self.assertEqual(response.status_code, 307)
        self.assertEqual(
            response.headers["location"],
            "https://daedalus.cybersecuritypilot.org/oauth2/callback",
        )

    def test_security_headers_and_host_allowlist(self):
        response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        self.assertIn("default-src 'self'", response.headers["content-security-policy"])
        self.assertIn("object-src 'none'", response.headers["content-security-policy"])
        self.assertIn("frame-ancestors 'none'", response.headers["content-security-policy"])
        self.assertEqual(response.headers["x-content-type-options"], "nosniff")
        self.assertEqual(response.headers["x-frame-options"], "DENY")
        self.assertEqual(response.headers["referrer-policy"], "same-origin")
        self.assertNotIn("strict-transport-security", response.headers)

        with patch.object(server, "APP_ENV", "production"):
            production_response = self.client.get("/healthz")
        self.assertEqual(
            production_response.headers["strict-transport-security"],
            "max-age=31536000; includeSubDomains",
        )

        untrusted_host = self.client.get("/healthz", headers={"host": "attacker.example"})
        self.assertEqual(untrusted_host.status_code, 400)

    def test_readiness_checks_database_and_report_storage(self):
        ready = self.client.get("/readyz")
        self.assertEqual(ready.status_code, 200, ready.text)
        self.assertEqual(ready.json(), {
            "status": "ready",
            "app": "daedalus",
            "checks": {"database": "ok", "report_storage": "ok"},
        })
        with patch.object(server, "REPORTS_DIR", self.root / "missing" / "reports"):
            storage_unavailable = self.client.get("/readyz")
        self.assertEqual(storage_unavailable.status_code, 503)
        self.assertEqual(storage_unavailable.json()["checks"]["report_storage"], "unavailable")

        class UnavailableDatabase:
            @staticmethod
            def execute(_statement):
                raise RuntimeError("database details must not escape")

        with patch.object(server, "REPORTS_DIR", self.root / "reports"):
            database_unavailable = server.readyz(UnavailableDatabase())
        self.assertEqual(database_unavailable.status_code, 503)
        self.assertEqual(database_unavailable.body, b'{"status":"not_ready","app":"daedalus","checks":{"database":"unavailable","report_storage":"ok"}}')

    def test_websocket_origin_must_match_portal_host_and_secure_production_scheme(self):
        matches = server.websocket_origin_matches_host
        self.assertTrue(matches("http://testserver", "testserver", production=False))
        self.assertTrue(matches("https://app.example.org", "app.example.org", production=True))
        for origin, host in (
            (None, "app.example.org"),
            ("null", "app.example.org"),
            ("https://attacker.example", "app.example.org"),
            ("https://app.example.org:444", "app.example.org"),
            ("https://user@app.example.org", "app.example.org"),
            ("https://app.example.org/path", "app.example.org"),
            ("not a host", "app.example.org"),
        ):
            with self.subTest(origin=origin, host=host):
                self.assertFalse(matches(origin, host, production=True))
        self.assertFalse(matches("http://app.example.org", "app.example.org", production=True))

    def test_concurrent_access_requests_return_one_pending_membership_and_notice(self):
        login=self.google_callback({'sub':'concurrent-requester','email':'requester@outside.example','email_verified':True,'name':'Requesting User'})
        self.assertEqual(login.status_code,303)
        barrier=threading.Barrier(2)
        original_flush=Session.flush
        def synchronized_flush(db,*args,**kwargs):
            if any(isinstance(row,Membership) for row in db.new):
                barrier.wait(timeout=5)
            return original_flush(db,*args,**kwargs)
        clients=[TestClient(server.app),TestClient(server.app)]
        for client in clients:
            client.cookies.update(self.client.cookies)
        try:
            with patch.object(Session,'flush',synchronized_flush), patch.object(server.live_hub,'publish_to_users',new_callable=AsyncMock) as publish:
                with ThreadPoolExecutor(max_workers=2) as pool:
                    futures=[pool.submit(client.post,'/api/membership-requests',json={'domain':'cybersecuritypilot.org'}) for client in clients]
                    responses=[future.result(timeout=15) for future in futures]
            self.assertEqual([response.status_code for response in responses],[200,200])
            self.assertTrue(all(response.json()['status']=='pending' for response in responses))
            publish.assert_awaited_once()
            with self.session_factory() as db:
                requester=db.scalar(select(User).where(User.google_subject=='concurrent-requester'))
                org=db.scalar(select(Organization).where(Organization.domain=='cybersecuritypilot.org'))
                memberships=db.scalars(select(Membership).where(Membership.user_id==requester.id,Membership.organization_id==org.id)).all()
                self.assertEqual(len(memberships),1)
                self.assertEqual(memberships[0].role,'user')
                self.assertEqual(memberships[0].status,'pending')
                events=db.scalars(select(AuditLog).where(AuditLog.action=='membership.requested',AuditLog.actor_user_id==requester.id)).all()
                self.assertEqual(len(events),1)
        finally:
            for client in clients: client.close()

    def test_concurrent_revoked_access_requests_publish_one_new_request(self):
        self.google_callback({'sub':'revoked-requester','email':'revoked@outside.example','email_verified':True,'name':'Requesting User'})
        with self.session_factory() as db:
            requester = db.scalar(select(User).where(User.google_subject == 'revoked-requester'))
            org = db.scalar(select(Organization).where(Organization.domain == 'cybersecuritypilot.org'))
            requester_id, org_id = requester.id, org.id
            db.add(Membership(user_id=requester_id, organization_id=org_id, role='admin', status='revoked', created_at=server.utcnow()))
            db.commit()
        barrier = threading.Barrier(2)
        original_execute = Session.execute
        def synchronized_execute(db, statement, *args, **kwargs):
            if getattr(statement, 'is_update', False) and statement.table.name == Membership.__tablename__:
                barrier.wait(timeout=5)
            return original_execute(db, statement, *args, **kwargs)
        clients = [TestClient(server.app), TestClient(server.app)]
        for client in clients:
            client.cookies.update(self.client.cookies)
        try:
            with patch.object(Session, 'execute', synchronized_execute), patch.object(server.live_hub, 'publish_to_users', new_callable=AsyncMock) as publish:
                with ThreadPoolExecutor(max_workers=2) as pool:
                    responses = list(pool.map(lambda client: client.post('/api/membership-requests', json={'domain':'cybersecuritypilot.org'}), clients))
            self.assertEqual([response.status_code for response in responses], [200, 200])
            self.assertTrue(all(response.json()['status'] == 'pending' for response in responses))
            publish.assert_awaited_once()
            with self.session_factory() as db:
                membership = db.scalar(select(Membership).where(Membership.user_id == requester_id, Membership.organization_id == org_id))
                self.assertEqual((membership.status, membership.role), ('pending', 'user'))
                self.assertEqual(db.scalar(select(func.count(AuditLog.id)).where(AuditLog.action == 'membership.requested', AuditLog.actor_user_id == requester_id)), 1)
        finally:
            for client in clients:
                client.close()

    def test_rejoining_does_not_overwrite_a_concurrent_approval(self):
        self.google_callback({'sub':'approved-race-requester','email':'approved@outside.example','email_verified':True,'name':'Requesting User'})
        with self.session_factory() as db:
            user = db.scalar(select(User).where(User.google_subject == 'approved-race-requester'))
            org = db.scalar(select(Organization).where(Organization.domain == 'cybersecuritypilot.org'))
            membership = Membership(user_id=user.id, organization_id=org.id, role='user', status='revoked', created_at=server.utcnow())
            db.add(membership)
            db.commit()
            membership_id, user_id = membership.id, user.id
        original_execute = Session.execute
        approved = False
        def approve_before_update(db, statement, *args, **kwargs):
            nonlocal approved
            if not approved and getattr(statement, 'is_update', False) and statement.table.name == Membership.__tablename__:
                approved = True
                with self.session_factory() as approval_db:
                    original_execute(approval_db, update(Membership).where(Membership.id == membership_id).values(status='approved', role='admin'))
                    approval_db.commit()
            return original_execute(db, statement, *args, **kwargs)
        with patch.object(Session, 'execute', approve_before_update), patch.object(server.live_hub, 'publish_to_users', new_callable=AsyncMock) as publish:
            response = self.client.post('/api/membership-requests', json={'domain':'cybersecuritypilot.org'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['status'], 'approved')
        publish.assert_not_awaited()
        with self.session_factory() as db:
            membership = db.get(Membership, membership_id)
            self.assertEqual((membership.status, membership.role), ('approved', 'admin'))
            self.assertEqual(db.scalar(select(func.count(AuditLog.id)).where(AuditLog.action == 'membership.requested', AuditLog.actor_user_id == user_id)), 0)

    def test_membership_request_and_decision_publish_after_commit_to_scoped_recipients(self):
        login = self.google_callback(
            {
                "sub": "membership-notification-requester",
                "email": "requester@example.net",
                "email_verified": True,
                "name": "Requesting User",
            }
        )
        self.assertEqual(login.status_code, 303)
        with self.session_factory() as db:
            requester = db.scalar(select(User).where(User.google_subject == "membership-notification-requester"))
            organization = db.scalar(select(Organization).where(Organization.domain == "cybersecuritypilot.org"))
            admin_ids = set(db.scalars(select(Membership.user_id).where(
                Membership.organization_id == organization.id,
                Membership.role == "admin",
                Membership.status == "approved",
            )).all())
            requester_id = requester.id
            organization_id = organization.id

        async def assert_request_committed_before_publish(org_id, recipients, message):
            self.assertEqual(org_id, organization_id)
            self.assertEqual(set(recipients), admin_ids)
            self.assertEqual(message, {"type": "membership_request_received"})
            with self.session_factory() as db:
                membership = db.scalar(select(Membership).where(
                    Membership.user_id == requester_id,
                    Membership.organization_id == organization_id,
                ))
                audit_event = db.scalar(select(AuditLog).where(
                    AuditLog.organization_id == organization_id,
                    AuditLog.action == "membership.requested",
                    AuditLog.actor_user_id == requester_id,
                ))
                self.assertIsNotNone(membership)
                self.assertEqual(membership.status, "pending")
                self.assertIsNotNone(audit_event)

        with patch.object(
            server.live_hub,
            "publish_to_users",
            new_callable=AsyncMock,
            side_effect=assert_request_committed_before_publish,
        ) as request_publish:
            response = self.client.post(
                "/api/membership-requests", json={"domain": "cybersecuritypilot.org"}
            )
        self.assertEqual(response.status_code, 200, response.text)
        request_publish.assert_awaited_once()

        with self.session_factory() as db:
            membership = db.scalar(select(Membership).where(
                Membership.user_id == requester_id,
                Membership.organization_id == organization_id,
            ))
            membership_id = membership.id

        async def assert_admin_refresh_committed(org_id, recipients, message):
            self.assertEqual(org_id, organization_id)
            self.assertEqual(set(recipients), admin_ids)
            self.assertEqual(message, {"type": "membership_list_changed"})
            with self.session_factory() as db:
                current = db.get(Membership, membership_id)
                self.assertEqual(current.status, "approved")
                self.assertIsNotNone(db.scalar(select(AuditLog).where(
                    AuditLog.organization_id == organization_id,
                    AuditLog.action == "membership.approved",
                    AuditLog.actor_user_id.in_(admin_ids),
                )))

        async def assert_requester_decision_committed_before_publish(org_id, target_id, message):
            self.assertEqual(org_id, organization_id)
            self.assertEqual(target_id, requester_id)
            self.assertEqual(message["type"], "membership_decision")
            self.assertEqual(message["status"], "approved")
            self.assertEqual(message["organization_id"], organization_id)
            self.assertEqual(message["domain"], "cybersecuritypilot.org")
            with self.session_factory() as db:
                self.assertEqual(db.get(Membership, membership_id).status, "approved")

        with (
            patch.object(
                server.live_hub,
                "publish_to_users",
                new_callable=AsyncMock,
                side_effect=assert_admin_refresh_committed,
            ) as admin_publish,
            patch.object(
                server.live_hub,
                "publish_to_user",
                new_callable=AsyncMock,
                side_effect=assert_requester_decision_committed_before_publish,
            ) as requester_publish,
        ):
            response = self.admin_client.post(
                f"/api/memberships/{membership_id}/decision", json={"approve": True}
            )
        self.assertEqual(response.status_code, 200, response.text)
        admin_publish.assert_awaited_once()
        requester_publish.assert_awaited_once()

    def test_pending_member_feed_is_private_and_receives_the_requesters_decision(self):
        self.assertEqual(self.google_callback({
            "sub": "membership-private-feed-requester",
            "email": "private-feed@example.net",
            "email_verified": True,
            "name": "Private Feed Requester",
        }).status_code, 303)
        requested = self.client.post(
            "/api/membership-requests", json={"domain": "cybersecuritypilot.org"}
        )
        self.assertEqual(requested.status_code, 200, requested.text)
        with self.session_factory() as db:
            requester = db.scalar(select(User).where(User.google_subject == "membership-private-feed-requester"))
            organization = db.scalar(select(Organization).where(Organization.domain == "cybersecuritypilot.org"))
            membership = db.scalar(select(Membership).where(
                Membership.user_id == requester.id,
                Membership.organization_id == organization.id,
            ))
            requester_id = requester.id
            organization_id = organization.id
            membership_id = membership.id

        with self.assertRaises(WebSocketDisconnect) as denied_feed:
            with self.client.websocket_connect(
                f"/ws/live?organization_id={organization_id}",
                headers={"origin": "http://testserver"},
            ) as feed:
                feed.receive_text()
        self.assertEqual(denied_feed.exception.code, 4403)

        private_url = f"/ws/live?organization_id={organization_id}&membership_updates=1"
        with self.assertRaises(WebSocketDisconnect) as cross_origin_feed:
            with self.client.websocket_connect(
                private_url,
                headers={"origin": "https://attacker.example"},
            ) as feed:
                feed.receive_text()
        self.assertEqual(cross_origin_feed.exception.code, 4403)

        with self.client.websocket_connect(
            private_url,
            headers={"origin": "http://testserver"},
        ) as requester_feed:
            response = self.admin_client.post(
                f"/api/memberships/{membership_id}/decision", json={"approve": False}
            )
            self.assertEqual(response.status_code, 200, response.text)
            notice = requester_feed.receive_json()

        self.assertEqual(notice["type"], "membership_decision")
        self.assertEqual(notice["status"], "denied")
        self.assertEqual(notice["organization_id"], organization_id)
        self.assertEqual(notice["domain"], "cybersecuritypilot.org")
        with self.session_factory() as db:
            self.assertEqual(db.get(Membership, membership_id).status, "denied")

    def test_workspace_admin_cannot_decide_membership_from_another_workspace(self):
        created = self.admin_client.post(
            "/api/workspaces",
            json={"name": "Foreign Workspace", "domain": "foreign.example.org"},
        )
        self.assertEqual(created.status_code, 200, created.text)
        foreign_organization_id = created.json()["organization_id"]

        self.assertEqual(
            self.google_callback(
                {
                    "sub": "foreign-workspace-requester",
                    "email": "requester@outside.example",
                    "email_verified": True,
                }
            ).status_code,
            303,
        )
        request_access = self.client.post(
            "/api/membership-requests", json={"domain": "foreign.example.org"}
        )
        self.assertEqual(request_access.status_code, 200, request_access.text)
        with self.session_factory() as db:
            workspace = db.get(Organization, foreign_organization_id)
            foreign_membership = db.scalar(
                select(Membership).where(
                    Membership.organization_id == foreign_organization_id,
                    Membership.status == "pending",
                )
            )
            csp_workspace = db.scalar(
                select(Organization).where(
                    Organization.domain == "cybersecuritypilot.org"
                )
            )
            membership_id = foreign_membership.id
            csp_workspace_id = csp_workspace.id
            self.assertEqual(workspace.verification_status, "pending")

        switched = self.admin_client.post(
            "/api/workspaces/select", json={"organization_id": csp_workspace_id}
        )
        self.assertEqual(switched.status_code, 200, switched.text)
        cross_workspace_decision = self.admin_client.post(
            f"/api/memberships/{membership_id}/decision", json={"approve": True}
        )
        self.assertEqual(cross_workspace_decision.status_code, 404)
        with self.session_factory() as db:
            foreign_membership = db.get(Membership, membership_id)
            self.assertEqual(foreign_membership.status, "pending")
            self.assertEqual(foreign_membership.role, "user")
            self.assertIsNone(
                db.scalar(
                    select(AuditLog).where(
                        AuditLog.organization_id == foreign_organization_id,
                        AuditLog.action == "membership.approved",
                    )
                )
            )

    def test_google_callback_rejects_truthy_nonboolean_verification_claims(self):
        for claim in ("false", "true", 1, [True], {"verified": True}, None):
            with self.subTest(claim=claim):
                response = self.google_callback({"sub": "malformed-verification-subject", "email": "malformed@example.org", "email_verified": claim})
                self.assertEqual(response.status_code, 401)
                self.assertEqual(self.client.get("/api/dashboard").status_code, 401)
        with self.session_factory() as db:
            self.assertIsNone(db.scalar(select(User).where(User.google_subject == "malformed-verification-subject")))

    def test_google_callback_requires_verified_email_and_never_auto_joins_by_domain(self):
        unverified = self.google_callback(
            {
                "sub": "unverified-google-subject",
                "email": "person@cybersecuritypilot.org",
                "email_verified": False,
                "name": "Unverified User",
            }
        )
        self.assertEqual(unverified.status_code, 401)

        verified = self.google_callback(
            {
                "sub": "verified-google-subject",
                "email": "person@cybersecuritypilot.org",
                "email_verified": True,
                "name": "Verified User",
            }
        )
        self.assertEqual(verified.status_code, 303)
        self.assertEqual(verified.headers["location"], "/dashboard")

        with self.session_factory() as db:
            unverified_user = db.scalar(
                select(User).where(User.google_subject == "unverified-google-subject")
            )
            user = db.scalar(
                select(User).where(User.google_subject == "verified-google-subject")
            )
            self.assertIsNone(unverified_user)
            self.assertIsNotNone(user)
            self.assertEqual(user.email, "person@cybersecuritypilot.org")
            self.assertEqual(
                db.scalars(select(Membership).where(Membership.user_id == user.id)).all(),
                [],
            )

        requested = self.client.post(
            "/api/membership-requests",
            json={"domain": "CYBERSECURITYPILOT.ORG."},
        )
        self.assertEqual(requested.status_code, 200, requested.text)
        self.assertEqual(requested.json()["status"], "pending")

        with self.session_factory() as db:
            user = db.scalar(
                select(User).where(User.google_subject == "verified-google-subject")
            )
            membership = db.scalar(
                select(Membership).where(Membership.user_id == user.id)
            )
            self.assertEqual(membership.role, "user")
            self.assertEqual(membership.status, "pending")

        approved = self.admin_client.post(
            f"/api/memberships/{membership.id}/decision",
            json={"approve": True},
        )
        self.assertEqual(approved.status_code, 200, approved.text)
        self.assertEqual(approved.json()["role"], "user")

        self.assertEqual(self.client.get("/api/dashboard").status_code, 200)
        member_cannot_revoke = self.client.post(
            f"/api/memberships/{membership.id}/revoke"
        )
        self.assertEqual(member_cannot_revoke.status_code, 403)

        with patch.object(
            server.live_hub, "revoke_user_access", new=AsyncMock()
        ) as close_workspace_feed:
            revoked = self.admin_client.post(
                f"/api/memberships/{membership.id}/revoke"
            )
        close_workspace_feed.assert_awaited_once_with(
            membership.organization_id, membership.user_id
        )
        self.assertEqual(revoked.status_code, 200, revoked.text)
        self.assertEqual(revoked.json()["status"], "revoked")
        self.assertEqual(self.client.get("/api/dashboard").status_code, 403)

        with self.session_factory() as db:
            membership = db.get(Membership, membership.id)
            self.assertEqual(membership.status, "revoked")
            revoked_event = db.scalar(
                select(AuditLog).where(
                    AuditLog.organization_id == membership.organization_id,
                    AuditLog.action == "membership.revoked",
                )
            )
            self.assertIsNotNone(revoked_event)
            self.assertEqual(revoked_event.details["user_id"], membership.user_id)

        requested_again = self.client.post(
            "/api/membership-requests",
            json={"domain": "cybersecuritypilot.org"},
        )
        self.assertEqual(requested_again.status_code, 200, requested_again.text)
        self.assertEqual(requested_again.json()["status"], "pending")
        approved_again = self.admin_client.post(
            f"/api/memberships/{membership.id}/decision",
            json={"approve": True},
        )
        self.assertEqual(approved_again.status_code, 200, approved_again.text)

        with self.session_factory() as db:
            admin_membership = db.scalar(
                select(Membership).where(
                    Membership.organization_id == membership.organization_id,
                    Membership.role == "admin",
                )
            )
            self_remove = self.admin_client.post(
                f"/api/memberships/{admin_membership.id}/revoke"
            )
        self.assertEqual(self_remove.status_code, 409, self_remove.text)

    def test_admin_can_promote_transfer_and_preserve_last_admin(self):
        login = self.google_callback({
            "sub": "admin-succession-requester",
            "email": "successor@example.net",
            "email_verified": True,
            "name": "Workspace Successor",
        })
        self.assertEqual(login.status_code, 303)
        request_access = self.client.post(
            "/api/membership-requests", json={"domain": "cybersecuritypilot.org"}
        )
        self.assertEqual(request_access.status_code, 200, request_access.text)
        with self.session_factory() as db:
            successor = db.scalar(select(User).where(User.google_subject == "admin-succession-requester"))
            organization = db.scalar(select(Organization).where(Organization.domain == "cybersecuritypilot.org"))
            successor_membership = db.scalar(select(Membership).where(
                Membership.user_id == successor.id,
                Membership.organization_id == organization.id,
            ))
            original_admin = db.scalar(select(Membership).where(
                Membership.organization_id == organization.id,
                Membership.user_id != successor.id,
                Membership.role == "admin",
                Membership.status == "approved",
            ))
            successor_membership_id = successor_membership.id
            original_admin_membership_id = original_admin.id
            successor_user_id = successor.id
            original_admin_user_id = original_admin.user_id

        approved = self.admin_client.post(
            f"/api/memberships/{successor_membership_id}/decision", json={"approve": True}
        )
        self.assertEqual(approved.status_code, 200, approved.text)
        self.assertEqual(approved.json()["role"], "user")

        denied_promotion = self.client.post(
            f"/api/memberships/{successor_membership_id}/role", json={"role": "admin"}
        )
        self.assertEqual(denied_promotion.status_code, 403)

        async def assert_promotion_published(org_id, recipients, message):
            self.assertEqual(org_id, organization.id)
            self.assertEqual(recipients, {successor_user_id, original_admin_user_id})
            self.assertEqual(message, {"type": "membership_list_changed"})
            with self.session_factory() as db:
                self.assertEqual(db.get(Membership, successor_membership_id).role, "admin")
                self.assertIsNotNone(db.scalar(select(AuditLog).where(
                    AuditLog.organization_id == org_id,
                    AuditLog.action == "membership.role_changed",
                    AuditLog.actor_user_id == original_admin_user_id,
                )))

        async def assert_successor_role_notice(org_id, target_id, message):
            self.assertEqual(org_id, organization.id)
            self.assertEqual(target_id, successor_user_id)
            self.assertEqual(message, {
                "type": "membership_role_changed",
                "organization_id": organization.id,
                "role": "admin",
            })

        with (
            patch.object(server.live_hub, "publish_to_users", new_callable=AsyncMock,
                         side_effect=assert_promotion_published) as refresh_admins,
            patch.object(server.live_hub, "publish_to_user", new_callable=AsyncMock,
                         side_effect=assert_successor_role_notice) as successor_notice,
        ):
            promoted = self.admin_client.post(
                f"/api/memberships/{successor_membership_id}/role", json={"role": "admin"}
            )
        self.assertEqual(promoted.status_code, 200, promoted.text)
        self.assertEqual(promoted.json(), {
            "id": successor_membership_id, "role": "admin", "changed": True,
        })
        refresh_admins.assert_awaited_once()
        successor_notice.assert_awaited_once()

        transferred = self.admin_client.post(
            f"/api/memberships/{original_admin_membership_id}/role", json={"role": "user"}
        )
        self.assertEqual(transferred.status_code, 200, transferred.text)
        self.assertEqual(transferred.json()["role"], "user")
        with self.session_factory() as db:
            self.assertEqual(db.get(Membership, original_admin_membership_id).role, "user")
            self.assertEqual(db.get(Membership, successor_membership_id).role, "admin")
            self.assertEqual(db.scalar(select(func.count(Membership.id)).where(
                Membership.organization_id == organization.id,
                Membership.role == "admin",
                Membership.status == "approved",
            )), 1)
        former_admin_view = self.admin_client.get("/api/memberships")
        self.assertEqual(former_admin_view.status_code, 200, former_admin_view.text)
        self.assertEqual([item["id"] for item in former_admin_view.json()["members"]], [original_admin_membership_id])
        former_admin_cannot_promote = self.admin_client.post(
            f"/api/memberships/{successor_membership_id}/role", json={"role": "admin"}
        )
        self.assertEqual(former_admin_cannot_promote.status_code, 403)

        last_admin_demotion = self.client.post(
            f"/api/memberships/{successor_membership_id}/role", json={"role": "user"}
        )
        self.assertEqual(last_admin_demotion.status_code, 409, last_admin_demotion.text)
        with self.session_factory() as db:
            self.assertEqual(db.get(Membership, successor_membership_id).role, "admin")
            self.assertEqual(db.scalar(select(func.count(Membership.id)).where(
                Membership.organization_id == organization.id,
                Membership.role == "admin",
                Membership.status == "approved",
            )), 1)

    def test_rotating_domain_challenge_invalidates_superseded_txt_token(self):
        created = self.admin_client.post(
            "/api/workspaces",
            json={"name": "Rotating Challenge", "domain": "rotate.example.org"},
        )
        self.assertEqual(created.status_code, 200, created.text)
        organization_id = created.json()["organization_id"]

        with self.session_factory() as db:
            original = db.scalar(
                select(DomainChallenge).where(
                    DomainChallenge.organization_id == organization_id
                )
            )
            original_id = original.id
            original_hash = original.token_hash

        rotated = self.admin_client.post(
            f"/api/workspaces/{organization_id}/domain-challenge"
        )
        self.assertEqual(rotated.status_code, 200, rotated.text)
        self.assertFalse(rotated.json()["verified"])

        with self.session_factory() as db:
            challenges = db.scalars(
                select(DomainChallenge)
                .where(DomainChallenge.organization_id == organization_id)
                .order_by(DomainChallenge.id)
            ).all()
            self.assertEqual(len(challenges), 2)
            self.assertEqual(challenges[0].id, original_id)
            self.assertGreater(challenges[1].id, original_id)
            self.assertEqual(challenges[0].token_hash, original_hash)
            self.assertLessEqual(challenges[0].expires_at, server.utcnow())
            self.assertGreater(challenges[1].expires_at, server.utcnow())
            active_hash = challenges[1].token_hash
            issued_event = db.scalar(
                select(AuditLog).where(
                    AuditLog.organization_id == organization_id,
                    AuditLog.action == "domain_challenge.issued",
                )
            )
            self.assertIsNotNone(issued_event)
            self.assertEqual(
                issued_event.details["record_name"],
                "_daedalus-verification.rotate.example.org",
            )

        def assert_only_latest_challenge_checked(domain, token_hashes, _digest):
            self.assertEqual(domain, "rotate.example.org")
            self.assertEqual(token_hashes, {active_hash})
            return True

        with patch.object(
            server,
            "has_matching_txt",
            side_effect=assert_only_latest_challenge_checked,
        ) as verify_txt:
            verified = self.admin_client.post(
                f"/api/workspaces/{organization_id}/verify-domain"
            )
        self.assertEqual(verified.status_code, 200, verified.text)
        self.assertTrue(verified.json()["verified"])
        verify_txt.assert_called_once()

    def test_workspace_owner_probation_override_and_txt_verification(self):
        created = self.admin_client.post(
            "/api/workspaces",
            json={"name": "Example Workspace", "domain": "new.example.org"},
        )
        self.assertEqual(created.status_code, 200, created.text)
        workspace = created.json()
        self.assertEqual(workspace["verification_status"], "pending")
        self.assertEqual(
            workspace["txt"]["record_name"],
            "_daedalus-verification.new.example.org",
        )
        self.assertTrue(
            workspace["txt"]["record_value"].startswith("daedalus-verification=")
        )

        with self.session_factory() as db:
            organization = db.get(Organization, workspace["organization_id"])
            self.assertEqual(organization.verification_status, "pending")
            self.assertAlmostEqual(
                (organization.verification_expires_at - organization.created_at).total_seconds(),
                30 * 24 * 60 * 60,
                delta=2,
            )
            owner_membership = db.scalar(
                select(Membership).where(
                    Membership.organization_id == organization.id,
                    Membership.role == "admin",
                )
            )
            self.assertEqual(owner_membership.status, "approved")
            challenge = db.scalar(
                select(DomainChallenge).where(
                    DomainChallenge.organization_id == organization.id
                )
            )
            self.assertAlmostEqual(
                (challenge.expires_at - challenge.created_at).total_seconds(),
                30 * 24 * 60 * 60,
                delta=2,
            )

        blocked = self.admin_client.post("/api/enrollment-tokens")
        self.assertEqual(blocked.status_code, 403)

        registered_user = self.google_callback(
            {
                "sub": "probation-shared-user",
                "email": "shared@example.net",
                "email_verified": True,
                "name": "Shared User",
            }
        )
        self.assertEqual(registered_user.status_code, 303)
        requested = self.client.post(
            "/api/membership-requests", json={"domain": "new.example.org"}
        )
        self.assertEqual(requested.status_code, 200, requested.text)
        self.assertEqual(requested.json()["status"], "pending")
        with self.session_factory() as db:
            shared_user = db.scalar(
                select(User).where(User.google_subject == "probation-shared-user")
            )
            shared_membership = db.scalar(
                select(Membership).where(
                    Membership.user_id == shared_user.id,
                    Membership.organization_id == organization.id,
                )
            )
            shared_membership_id = shared_membership.id
            self.assertEqual(shared_membership.role, "user")
            self.assertEqual(shared_membership.status, "pending")

        approval_before_proof = self.admin_client.post(
            f"/api/memberships/{shared_membership_id}/decision",
            json={"approve": True},
        )
        self.assertEqual(approval_before_proof.status_code, 403)

        with patch.object(server.live_hub, "publish", new_callable=AsyncMock) as publish_notice:
            override = self.admin_client.post(
                f"/api/workspaces/{workspace['organization_id']}/probation-overrides",
                json={"reason": "Local scanner integration validation"},
            )
        self.assertEqual(override.status_code, 200, override.text)
        self.assertTrue(override.json()["active"])
        publish_notice.assert_awaited_once_with(
            workspace["organization_id"],
            {
                "type": "workspace_notification_created",
                "source_type": "probation_override_granted",
                "source_id": override.json()["id"],
            },
        )
        grant_notice = self.admin_client.get("/api/notifications").json()["notifications"][0]
        self.assertEqual(grant_notice["source_type"], "probation_override_granted")
        self.assertEqual(grant_notice["reason"], "access_override")
        self.assertEqual(grant_notice["tab"], "members")
        self.assertIn("temporary 14-day probation override", grant_notice["summary"])
        self.assertNotIn("Local scanner integration validation", grant_notice["summary"])
        audit_events = self.admin_client.get("/api/audit-log").json()["events"]
        grant_audit = next(event for event in audit_events if event["action"] == "probation_override.granted")
        self.assertEqual(grant_audit["details"]["reason"], "Local scanner integration validation")
        with self.session_factory() as db:
            stored_override = db.get(server.ProbationOverride, override.json()["id"])
            self.assertAlmostEqual(
                (stored_override.expires_at - stored_override.starts_at).total_seconds(),
                14 * 24 * 60 * 60,
                delta=2,
            )
            grant_event = db.scalar(
                select(AuditLog).where(
                    AuditLog.organization_id == organization.id,
                    AuditLog.action == "probation_override.granted",
                )
            )
            self.assertIsNotNone(grant_event)
            self.assertEqual(
                grant_event.details,
                {
                    "override_id": stored_override.id,
                    "reason": "Local scanner integration validation",
                    "expires_at": stored_override.expires_at.isoformat() + "Z",
                    "duration_days": 14,
                },
            )

        duplicate_override = self.admin_client.post(
            f"/api/workspaces/{workspace['organization_id']}/probation-overrides",
            json={"reason": "Trying to overlap an active override"},
        )
        self.assertEqual(duplicate_override.status_code, 409)

        allowed = self.admin_client.post("/api/enrollment-tokens")
        self.assertEqual(allowed.status_code, 200, allowed.text)
        approved_shared_user = self.admin_client.post(
            f"/api/memberships/{shared_membership_id}/decision",
            json={"approve": True},
        )
        self.assertEqual(approved_shared_user.status_code, 200, approved_shared_user.text)
        self.assertEqual(approved_shared_user.json()["role"], "user")
        with self.session_factory() as db:
            approved_membership = db.get(Membership, shared_membership_id)
            self.assertEqual(approved_membership.status, "approved")
            self.assertEqual(approved_membership.role, "user")

        selected_shared_workspace = self.client.post(
            "/api/workspaces/select", json={"organization_id": workspace["organization_id"]}
        )
        self.assertEqual(selected_shared_workspace.status_code, 200, selected_shared_workspace.text)
        shared_inbox = self.client.get("/api/notifications").json()["notifications"]
        self.assertEqual(len(shared_inbox), 1)
        self.assertEqual(shared_inbox[0]["source_type"], "probation_override_granted")
        self.assertNotIn("Local scanner integration validation", shared_inbox[0]["summary"])

        with patch.object(server.live_hub, "publish", new_callable=AsyncMock) as publish_notice:
            revoked = self.admin_client.post(
                f"/api/workspaces/{workspace['organization_id']}/probation-overrides/{override.json()['id']}/revoke"
            )
        self.assertEqual(revoked.status_code, 200, revoked.text)
        publish_notice.assert_awaited_once_with(
            workspace["organization_id"],
            {
                "type": "workspace_notification_created",
                "source_type": "probation_override_revoked",
                "source_id": override.json()["id"],
            },
        )
        workspace_notices = self.admin_client.get("/api/notifications").json()["notifications"]
        self.assertEqual(
            {notice["source_type"] for notice in workspace_notices},
            {"probation_override_granted", "probation_override_revoked"},
        )
        self.assertTrue(any("revoked the probation override" in notice["summary"] for notice in workspace_notices))
        override_history = self.admin_client.get(
            f"/api/workspaces/{workspace['organization_id']}/probation-overrides"
        )
        self.assertEqual(override_history.status_code, 200, override_history.text)
        self.assertEqual(
            override_history.json()["overrides"][0]["reason"],
            "Local scanner integration validation",
        )
        self.assertFalse(override_history.json()["overrides"][0]["active"])
        self.assertIsNotNone(override_history.json()["overrides"][0]["revoked_at"])
        with self.session_factory() as db:
            revoke_event = db.scalar(
                select(AuditLog).where(
                    AuditLog.organization_id == organization.id,
                    AuditLog.action == "probation_override.revoked",
                )
            )
            self.assertIsNotNone(revoke_event)
            self.assertEqual(revoke_event.details["override_id"], override.json()["id"])
        blocked_again = self.admin_client.post("/api/enrollment-tokens")
        self.assertEqual(blocked_again.status_code, 403)

        with patch.object(server, "has_matching_txt", return_value=True):
            verified = self.admin_client.post(
                f"/api/workspaces/{workspace['organization_id']}/verify-domain"
            )
        self.assertEqual(verified.status_code, 200, verified.text)
        self.assertTrue(verified.json()["verified"])
        with self.session_factory() as db:
            organization = db.get(Organization, workspace["organization_id"])
            self.assertEqual(organization.verification_status, "verified")
            self.assertIsNone(organization.verification_expires_at)
        self.assertEqual(self.admin_client.post("/api/enrollment-tokens").status_code, 200)


if __name__ == "__main__":
    unittest.main()
