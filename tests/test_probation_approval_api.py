"""Temporary approval decisions use current, serialized workspace authority."""
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from daedalus import server
from daedalus.models import AuditLog, Membership, Organization, ProbationOverride, UserAPIKey
import test_auth_and_workspace_flows as fixtures


class ProbationApprovalAPITests(unittest.TestCase):
    setUp = fixtures.AuthAndWorkspaceFlowTests.setUp
    tearDown = fixtures.AuthAndWorkspaceFlowTests.tearDown

    def create(self):
        reply = self.admin_client.post('/api/workspaces', json={
            'name': 'Approval review', 'domain': 'approval-review.example'})
        self.assertEqual(reply.status_code, 200, reply.text)
        return reply.json()['organization_id']

    def path(self, org):
        return f'/api/workspaces/{org}/probation-overrides'

    def read(self, org):
        reply = self.admin_client.get(self.path(org))
        self.assertEqual(reply.status_code, 200, reply.text)
        return reply

    def grant(self, org, headers=None, client=None):
        return (client or self.admin_client).post(self.path(org), headers=headers,
            json={'reason': 'Temporary access for customer workflow validation'})

    def test_list_and_saved_results_have_scope_date_reference_and_no_cache(self):
        org = self.create()
        read = self.read(org)
        self.assertEqual(read.headers.get('cache-control'), 'no-store')
        body = read.json()
        self.assertEqual(body['organization_id'], org)
        self.assertEqual(body['verification_status'], 'pending')
        self.assertFalse(body['controls_enabled'])
        self.assertTrue(body['observed_at'].endswith('Z'))
        self.assertEqual(len(body['state_reference']), 64)
        saved = self.grant(org, {'X-Daedalus-Approval-State': body['state_reference']})
        self.assertEqual(saved.status_code, 200, saved.text)
        self.assertEqual(saved.headers.get('cache-control'), 'no-store')
        self.assertEqual(saved.json()['organization_id'], org)
        self.assertNotEqual(saved.json()['state_reference'], body['state_reference'])
        self.assertTrue(saved.json()['controls_enabled'])
        revoked = self.admin_client.post(self.path(org) + f"/{saved.json()['id']}/revoke",
            headers={'X-Daedalus-Approval-State': saved.json()['state_reference']})
        self.assertEqual(revoked.status_code, 200, revoked.text)
        self.assertEqual(revoked.headers.get('cache-control'), 'no-store')
        self.assertEqual(revoked.json()['organization_id'], org)
        self.assertFalse(revoked.json()['controls_enabled'])

    def test_old_decision_cannot_grant_after_approval_was_granted_and_revoked(self):
        org = self.create()
        # The explicit header is optional for existing API consumers. Browser
        # decisions must carry it, including an observed absence of approval.
        first = self.grant(org)
        self.assertEqual(first.status_code, 200)
        old = first.json().get('state_reference', '0' * 64)
        self.assertEqual(self.admin_client.post(self.path(org) + f"/{first.json()['id']}/revoke").status_code, 200)
        rejected = self.grant(org, {'X-Daedalus-Approval-State': old})
        self.assertEqual(rejected.status_code, 409, rejected.text)
        with self.session_factory() as db:
            self.assertEqual(db.scalar(select(func.count(ProbationOverride.id)).where(
                ProbationOverride.organization_id == org)), 1)

    def test_concurrent_grants_have_one_winner_and_one_audit(self):
        org = self.create()
        barrier = threading.Barrier(2)
        original = server.get_org_context
        def context(*args, **kwargs):
            result = original(*args, **kwargs)
            if kwargs.get('admin'):
                barrier.wait(timeout=10)
            return result
        clients = [TestClient(server.app), TestClient(server.app)]
        try:
            for client in clients:
                client.cookies.update(self.admin_client.cookies)
            with patch.object(server, 'get_org_context', context), ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(self.grant, org, None, client) for client in clients]
                replies = [future.result(timeout=20) for future in futures]
            self.assertEqual(sorted(r.status_code for r in replies), [200, 409])
            with self.session_factory() as db:
                self.assertEqual(db.scalar(select(func.count(ProbationOverride.id)).where(
                    ProbationOverride.organization_id == org)), 1)
                self.assertEqual(db.scalar(select(func.count(AuditLog.id)).where(
                    AuditLog.organization_id == org, AuditLog.action == 'probation_override.granted')), 1)
        finally:
            for client in clients:
                client.close()

    def test_actor_demotion_before_write_prevents_grant(self):
        org = self.create()
        original = server.get_org_context
        def context(*args, **kwargs):
            result = original(*args, **kwargs)
            if kwargs.get('admin'):
                with self.session_factory() as other:
                    other.execute(update(Membership).where(Membership.organization_id == org).values(role='user'))
                    other.commit()
            return result
        with patch.object(server, 'get_org_context', context):
            response = self.grant(org)
        self.assertEqual(response.status_code, 403, response.text)
        with self.session_factory() as db:
            self.assertEqual(db.scalar(select(func.count(ProbationOverride.id)).where(
                ProbationOverride.organization_id == org)), 0)

    def test_key_expiration_during_lock_prevents_revocation(self):
        org = self.create()
        saved = self.grant(org).json()
        key = self.admin_client.post('/api/user-keys', json={'name': 'Approval admission fixture'}).json()
        original = Session.execute
        intervened = False
        def execute(db, statement, *args, **kwargs):
            nonlocal intervened
            if not intervened and getattr(statement, 'is_update', False) and statement.table.name == Organization.__tablename__:
                intervened = True
                with self.session_factory() as other:
                    original(other, update(UserAPIKey).where(UserAPIKey.id == key['id']).values(
                        expires_at=server.utcnow() - server.timedelta(seconds=1)))
                    other.commit()
            return original(db, statement, *args, **kwargs)
        with patch.object(Session, 'execute', execute):
            response = self.admin_client.post(self.path(org) + f"/{saved['id']}/revoke",
                headers={'Authorization': 'Bearer ' + key['token']})
        self.assertEqual(response.status_code, 401, response.text)
        with self.session_factory() as db:
            self.assertIsNone(db.get(ProbationOverride, saved['id']).revoked_at)

    def test_wrong_workspace_and_nonadmin_cannot_read_or_change_approval(self):
        org = self.create()
        self.assertEqual(self.admin_client.get(self.path(org + 999)).status_code, 404)
        self.assertEqual(self.grant(org + 999).status_code, 404)
        with self.session_factory() as db:
            db.scalar(select(Membership).where(Membership.organization_id == org)).role = 'user'
            db.commit()
        self.assertEqual(self.admin_client.get(self.path(org)).status_code, 403)
        self.assertEqual(self.grant(org).status_code, 403)

    def test_concurrent_revocations_record_one_decision(self):
        org = self.create()
        saved = self.grant(org).json()
        headers = {'X-Daedalus-Approval-State': saved['state_reference']}
        clients = [TestClient(server.app), TestClient(server.app)]
        barrier = threading.Barrier(2)
        original = server.get_org_context
        def context(*args, **kwargs):
            result = original(*args, **kwargs)
            if kwargs.get('admin'):
                barrier.wait(timeout=10)
            return result
        try:
            for client in clients:
                client.cookies.update(self.admin_client.cookies)
            with patch.object(server, 'get_org_context', context), ThreadPoolExecutor(max_workers=2) as pool:
                replies = list(pool.map(lambda c: c.post(self.path(org) + f"/{saved['id']}/revoke", headers=headers), clients))
            self.assertEqual(sorted(r.status_code for r in replies), [200, 409])
            with self.session_factory() as db:
                self.assertIsNotNone(db.get(ProbationOverride, saved['id']).revoked_at)
                self.assertEqual(db.scalar(select(func.count(AuditLog.id)).where(
                    AuditLog.organization_id == org, AuditLog.action == 'probation_override.revoked')), 1)
        finally:
            for client in clients:
                client.close()

    def test_success_reply_describes_saved_decision_before_a_following_transition(self):
        org = self.create()
        async def revoke_after_commit(*args, **kwargs):
            with self.session_factory() as db:
                override = db.scalar(select(ProbationOverride).where(ProbationOverride.organization_id == org))
                override.revoked_at = server.utcnow()
                override.revoked_by_user_id = override.granted_by_user_id
                server.audit(db, org, override.granted_by_user_id, 'probation_override.revoked', {'override_id': override.id})
                db.commit()
        with patch.object(server.live_hub, 'publish', side_effect=revoke_after_commit):
            reply = self.grant(org)
        self.assertEqual(reply.status_code, 200, reply.text)
        self.assertTrue(reply.json()['active'])
        self.assertTrue(reply.json()['controls_enabled'])
        current = self.read(org).json()
        self.assertFalse(current['overrides'][0]['active'])
        self.assertFalse(current['controls_enabled'])
        self.assertNotEqual(current['state_reference'], reply.json()['state_reference'])
