"""Refresh-safe ownership instructions and proof validity at verification time."""
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier, Event
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.orm import Session

from daedalus import server
from daedalus.models import AuditLog, DomainChallenge, Membership, Organization, User, UserAPIKey
import test_auth_and_workspace_flows as auth_flows


class DomainChallengeFlowTests(unittest.TestCase):
    setUp = auth_flows.AuthAndWorkspaceFlowTests.setUp
    tearDown = auth_flows.AuthAndWorkspaceFlowTests.tearDown

    def create(self, domain="instructions.example.org"):
        response = self.admin_client.post("/api/workspaces", json={"name": "Instructions fixture", "domain": domain})
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def state(self, org_id):
        with self.session_factory() as db:
            return [(row.id, row.token_hash, row.record_value, row.expires_at, row.verified_at)
                    for row in db.scalars(select(DomainChallenge).where(DomainChallenge.organization_id == org_id).order_by(DomainChallenge.id)).all()]

    def issued_count(self, org_id):
        with self.session_factory() as db:
            return db.scalar(select(func.count(AuditLog.id)).where(
                AuditLog.organization_id == org_id, AuditLog.action == "domain_challenge.issued"))

    def assert_unverified(self, org_id):
        with self.session_factory() as db:
            org = db.get(Organization, org_id)
            self.assertNotEqual(org.verification_status, "verified")
            self.assertFalse(server.workspace_controls_available(db, org))
            self.assertEqual(db.scalar(select(func.count(AuditLog.id)).where(
                AuditLog.organization_id == org_id, AuditLog.action == "domain.verified")), 0)

    def test_nullable_migration_preserves_legacy_proof_and_is_idempotent(self):
        engine = create_engine("sqlite://")
        try:
            with engine.begin() as connection:
                connection.execute(text("CREATE TABLE domain_challenges (id INTEGER PRIMARY KEY, token_hash VARCHAR(64), expires_at TIMESTAMP)"))
                connection.execute(text("INSERT INTO domain_challenges VALUES (1, :digest, '2026-11-01')"), {"digest": "a" * 64})
                server.ensure_domain_challenge_columns(connection)
                server.ensure_domain_challenge_columns(connection)
                self.assertEqual(connection.execute(text("SELECT id, token_hash, expires_at, record_value FROM domain_challenges")).one(),
                                 (1, "a" * 64, "2026-11-01", None))
        finally:
            engine.dispose()

    def test_creation_instructions_survive_reads_refresh_and_ensure_without_rotation(self):
        created = self.create()
        org_id = created["organization_id"]
        before = self.state(org_id)
        for method, path in [("get", ""), ("get", ""), ("post", "/ensure"), ("post", "/ensure")]:
            response = getattr(self.admin_client, method)(f"/api/workspaces/{org_id}/domain-challenge{path}")
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.headers["cache-control"], "no-store")
            self.assertEqual(response.json()["state"], "active")
            self.assertEqual(response.json()["txt"], created["txt"])
            self.assertTrue(response.json()["txt"]["value_available"])
            if method == "post":
                self.assertFalse(response.json()["created"])
        self.assertEqual(self.state(org_id), before)
        self.assertEqual(self.issued_count(org_id), 0)

    def test_ensure_creates_only_after_expiry_and_reuses_the_new_value(self):
        created = self.create()
        org_id = created["organization_id"]
        with self.session_factory() as db:
            row = db.get(DomainChallenge, created["txt"]["challenge_id"])
            row.expires_at = server.utcnow() - timedelta(seconds=1)
            db.commit()
        expired = self.admin_client.get(f"/api/workspaces/{org_id}/domain-challenge")
        self.assertEqual(expired.json()["state"], "expired")
        response = self.admin_client.post(f"/api/workspaces/{org_id}/domain-challenge/ensure")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(response.json()["created"])
        self.assertNotEqual(response.json()["txt"]["record_value"], created["txt"]["record_value"])
        again = self.admin_client.post(f"/api/workspaces/{org_id}/domain-challenge/ensure")
        self.assertEqual(again.json()["txt"], response.json()["txt"])
        self.assertFalse(again.json()["created"])
        self.assertEqual(self.issued_count(org_id), 1)
        self.assertEqual(len(self.state(org_id)), 2)

    def test_no_challenge_read_is_read_only_and_ensure_creates_once(self):
        with self.session_factory() as db:
            org = db.scalar(select(Organization).where(Organization.domain == "cybersecuritypilot.org"))
            org.verification_status = "pending"
            org_id = org.id
            db.commit()
        response = self.admin_client.get(f"/api/workspaces/{org_id}/domain-challenge")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["state"], "none")
        self.assertIsNone(response.json()["txt"])
        self.assertEqual(self.state(org_id), [])
        ensured = self.admin_client.post(f"/api/workspaces/{org_id}/domain-challenge/ensure")
        self.assertEqual(ensured.status_code, 200, ensured.text)
        self.assertTrue(ensured.json()["created"])
        self.assertEqual(ensured.json()["state"], "active")
        self.assertEqual(len(self.state(org_id)), 1)
        self.assertEqual(self.issued_count(org_id), 1)

    def test_hash_only_legacy_and_invalid_stored_values_are_preserved_until_explicit_replacement(self):
        created = self.create()
        org_id = created["organization_id"]
        challenge_id = created["txt"]["challenge_id"]
        for value in (None, "daedalus-verification=" + "A" * 32, "daedalus-verification=short", "wrong-prefix=" + "A" * 32, "<script>untrusted</script>"):
            with self.subTest(value=value):
                with self.session_factory() as db:
                    db.get(DomainChallenge, challenge_id).record_value = value
                    db.commit()
                before = self.state(org_id)
                for method, suffix in (("get", ""), ("post", "/ensure")):
                    response = getattr(self.admin_client, method)(f"/api/workspaces/{org_id}/domain-challenge{suffix}")
                    self.assertEqual(response.status_code, 200, response.text)
                    self.assertEqual(response.json()["state"], "active")
                    self.assertIsNone(response.json()["txt"]["record_value"])
                    self.assertFalse(response.json()["txt"]["value_available"])
                self.assertEqual(self.state(org_id), before)
                self.assertEqual(self.issued_count(org_id), 0)
        replaced = self.admin_client.post(f"/api/workspaces/{org_id}/domain-challenge")
        self.assertEqual(replaced.status_code, 200, replaced.text)
        self.assertTrue(replaced.json()["created"])
        self.assertTrue(replaced.json()["txt"]["value_available"])
        self.assertNotEqual(replaced.json()["txt"]["challenge_id"], challenge_id)
        self.assertEqual(self.issued_count(org_id), 1)

    def test_malformed_stored_hash_cannot_expose_txt_instructions(self):
        created = self.create()
        org_id = created["organization_id"]
        for malformed in ("not-a-digest", "A" * 64, "0" * 64):
            with self.subTest(digest=malformed):
                with self.session_factory() as db:
                    db.get(DomainChallenge, created["txt"]["challenge_id"]).token_hash = malformed
                    db.commit()
                response = self.admin_client.get(f"/api/workspaces/{org_id}/domain-challenge")
                self.assertEqual(response.status_code, 200, response.text)
                self.assertIsNone(response.json()["txt"]["record_value"])
                self.assertFalse(response.json()["txt"]["value_available"])

    def test_legacy_proof_remains_verifiable_without_redisplay_value(self):
        created = self.create()
        org_id = created["organization_id"]
        with self.session_factory() as db:
            db.get(DomainChallenge, created["txt"]["challenge_id"]).record_value = None
            db.commit()
        with patch.object(server, "has_matching_txt", return_value=True):
            response = self.admin_client.post(f"/api/workspaces/{org_id}/verify-domain")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(response.json()["verified"])

    def test_read_ensure_and_replace_require_current_workspace_admin(self):
        created = self.create()
        org_id = created["organization_id"]
        before = self.state(org_id)
        for method, suffix in (("get", ""), ("post", "/ensure"), ("post", "")):
            response = getattr(self.admin_client, method)(f"/api/workspaces/{org_id + 999}/domain-challenge{suffix}")
            self.assertEqual(response.status_code, 404, response.text)
        with self.session_factory() as db:
            row = db.scalar(select(Membership).where(Membership.organization_id == org_id))
            row.role = "user"
            db.commit()
        for method, suffix in (("get", ""), ("post", "/ensure"), ("post", "")):
            response = getattr(self.admin_client, method)(f"/api/workspaces/{org_id}/domain-challenge{suffix}")
            self.assertEqual(response.status_code, 403, response.text)
        self.assertEqual(self.state(org_id), before)

    def test_verified_workspace_never_creates_another_challenge(self):
        created = self.create()
        org_id = created["organization_id"]
        with self.session_factory() as db:
            db.get(Organization, org_id).verification_status = "verified"
            db.commit()
        before = self.state(org_id)
        for method, suffix in (("get", ""), ("post", "/ensure"), ("post", "")):
            response = getattr(self.admin_client, method)(f"/api/workspaces/{org_id}/domain-challenge{suffix}")
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()["state"], "verified")
            self.assertIsNone(response.json()["txt"])
        self.assertEqual(self.state(org_id), before)

    def test_concurrent_ensure_after_expiry_issues_one_challenge_and_one_audit(self):
        created = self.create()
        org_id = created["organization_id"]
        with self.session_factory() as db:
            db.get(DomainChallenge, created["txt"]["challenge_id"]).expires_at = server.utcnow() - timedelta(seconds=1)
            db.commit()
        barrier = Barrier(4)
        def ensure(_index):
            client = TestClient(server.app)
            client.cookies.update(self.admin_client.cookies)
            try:
                barrier.wait(timeout=10)
                return client.post(f"/api/workspaces/{org_id}/domain-challenge/ensure")
            finally:
                client.close()
        with ThreadPoolExecutor(max_workers=4) as pool:
            responses = list(pool.map(ensure, range(4)))
        self.assertEqual([response.status_code for response in responses], [200] * 4)
        self.assertEqual(sum(response.json()["created"] for response in responses), 1)
        self.assertEqual(len({response.json()["txt"]["challenge_id"] for response in responses}), 1)
        self.assertEqual(len(self.state(org_id)), 2)
        self.assertEqual(self.issued_count(org_id), 1)

    def test_replacement_during_dns_lookup_cannot_verify_the_superseded_proof(self):
        created = self.create()
        org_id = created["organization_id"]
        def lookup(_domain, _hashes, _digest):
            with self.session_factory() as db:
                org = db.get(Organization, org_id)
                user = db.scalar(select(User).join(Membership).where(Membership.organization_id == org_id))
                server.issue_workspace_challenge(db, org, user)
                db.commit()
            return True
        with patch.object(server, "has_matching_txt", side_effect=lookup):
            response = self.admin_client.post(f"/api/workspaces/{org_id}/verify-domain")
        self.assertEqual(response.status_code, 409, response.text)
        self.assert_unverified(org_id)
        self.assertTrue(all(row[4] is None for row in self.state(org_id)))

    def test_expiry_during_dns_lookup_cannot_verify(self):
        created = self.create()
        org_id = created["organization_id"]
        def lookup(_domain, _hashes, _digest):
            with self.session_factory() as db:
                db.get(DomainChallenge, created["txt"]["challenge_id"]).expires_at = server.utcnow() - timedelta(seconds=1)
                db.commit()
            return True
        with patch.object(server, "has_matching_txt", side_effect=lookup):
            response = self.admin_client.post(f"/api/workspaces/{org_id}/verify-domain")
        self.assertEqual(response.status_code, 409, response.text)
        self.assert_unverified(org_id)

    def test_natural_expiry_while_dns_lookup_runs_cannot_verify(self):
        created = self.create()
        org_id = created["organization_id"]
        expiry = self.state(org_id)[0][3]
        with patch.object(server, "utcnow", return_value=expiry - timedelta(seconds=1)) as clock:
            def lookup(_domain, _hashes, _digest):
                clock.return_value = expiry + timedelta(seconds=1)
                return True
            with patch.object(server, "has_matching_txt", side_effect=lookup):
                response = self.admin_client.post(f"/api/workspaces/{org_id}/verify-domain")
        self.assertEqual(response.status_code, 409, response.text)
        self.assert_unverified(org_id)

    def test_proof_expiry_while_waiting_for_workspace_write_lock_cannot_verify(self):
        created = self.create()
        org_id = created["organization_id"]
        expiry = self.state(org_id)[0][3]
        lock_attempted = Event()
        original_execute = Session.execute
        def execute(db, statement, *args, **kwargs):
            if getattr(statement, "is_update", False) and statement.table.name == "organizations":
                lock_attempted.set()
            return original_execute(db, statement, *args, **kwargs)
        # Hold a real SQLite write transaction. The request reads its original
        # valid proof, then must wait before acquiring the workspace lock.
        with self.session_factory() as writer:
            writer.get(Organization, org_id).name = "Concurrent writer fixture"
            writer.flush()
            with (patch.object(server, "utcnow", return_value=expiry - timedelta(seconds=1)) as clock,
                  patch.object(server, "has_matching_txt", return_value=True),
                  patch.object(Session, "execute", new=execute),
                  ThreadPoolExecutor(max_workers=1) as pool):
                future = pool.submit(self.admin_client.post, f"/api/workspaces/{org_id}/verify-domain")
                try:
                    self.assertTrue(lock_attempted.wait(timeout=5), "Verification never attempted to acquire the held write lock")
                    self.assertFalse(future.done(), "The request should be waiting for the held write transaction")
                    clock.return_value = expiry + timedelta(seconds=1)
                    writer.commit()
                    response = future.result(timeout=10)
                finally:
                    writer.rollback()
        self.assertEqual(response.status_code, 409, response.text)
        self.assert_unverified(org_id)

    def test_key_revoked_while_waiting_for_challenge_write_lock_cannot_mutate(self):
        created = self.create()
        org_id = created["organization_id"]
        for mode in ("bearer", "cookie"):
            for suffix in ("/ensure", ""):
                with self.subTest(mode=mode, operation=suffix or "replace"):
                    issued = self.admin_client.post("/api/user-keys", json={"name": "Lock wait fixture", "expires_days": 1})
                    self.assertEqual(issued.status_code, 200, issued.text)
                    key = issued.json()
                    before = self.state(org_id)
                    client = TestClient(server.app)
                    headers = {"Authorization": "Bearer " + key["token"]} if mode == "bearer" else {}
                    if mode == "cookie":
                        self.assertEqual(client.post("/auth/token", json={"token": key["token"]}).status_code, 200)
                    lock_attempted = Event()
                    original_execute = Session.execute
                    def execute(db, statement, *args, **kwargs):
                        if getattr(statement, "is_update", False) and statement.table.name == "organizations":
                            lock_attempted.set()
                        return original_execute(db, statement, *args, **kwargs)
                    try:
                        with self.session_factory() as writer:
                            writer.get(UserAPIKey, key["id"]).revoked_at = server.utcnow()
                            writer.flush()
                            with patch.object(Session, "execute", new=execute), ThreadPoolExecutor(max_workers=1) as pool:
                                future = pool.submit(client.post, f"/api/workspaces/{org_id}/domain-challenge{suffix}", headers=headers)
                                try:
                                    self.assertTrue(lock_attempted.wait(timeout=5), "Authenticated request never attempted the held write lock")
                                    self.assertFalse(future.done(), "The request should wait while revocation is uncommitted")
                                    writer.commit()
                                    response = future.result(timeout=10)
                                finally:
                                    writer.rollback()
                        self.assertEqual(response.status_code, 401, response.text)
                        self.assertEqual(self.state(org_id), before)
                        self.assertEqual(self.issued_count(org_id), 0)
                    finally:
                        client.close()

    def test_admin_demotion_during_dns_lookup_cannot_open_controls(self):
        created = self.create()
        org_id = created["organization_id"]
        def lookup(_domain, _hashes, _digest):
            with self.session_factory() as db:
                db.scalar(select(Membership).where(Membership.organization_id == org_id)).role = "user"
                db.commit()
            return True
        with patch.object(server, "has_matching_txt", side_effect=lookup):
            response = self.admin_client.post(f"/api/workspaces/{org_id}/verify-domain")
        self.assertEqual(response.status_code, 403, response.text)
        self.assert_unverified(org_id)
