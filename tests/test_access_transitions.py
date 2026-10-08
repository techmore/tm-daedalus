"""Workspace access can be reduced even while elevated controls are closed."""
import unittest
from datetime import timedelta
from unittest.mock import AsyncMock, patch

from sqlalchemy import select

from daedalus import server
from daedalus.models import (
    Agent, AgentCommand, AuditLog, CustomerOnboarding, Membership,
    Organization, ProbationOverride, User, WorkspaceNotification,
)
import test_auth_and_workspace_flows as auth_flows


class AccessTransitionTests(unittest.TestCase):
    google_callback = auth_flows.AuthAndWorkspaceFlowTests.google_callback

    def setUp(self):
        auth_flows.AuthAndWorkspaceFlowTests.setUp(self)
        response = self.admin_client.post('/api/workspaces', json={
            'name': 'Access transition fixture', 'domain': 'transition.example.org',
        })
        self.assertEqual(response.status_code, 200, response.text)
        self.org_id = response.json()['organization_id']
        with self.session_factory() as db:
            self.admin_id = db.scalar(select(User.id).where(
                User.google_subject == 'daedalus-local-demo-admin'))
            self.assertFalse(server.workspace_controls_available(
                db, db.get(Organization, self.org_id)))

    def tearDown(self):
        auth_flows.AuthAndWorkspaceFlowTests.tearDown(self)

    def pending_member(self, organization_id=None):
        with self.session_factory() as db:
            user = User(
                google_subject='pending-access-member', email='pending@example.net',
                display_name='Pending member', created_at=server.utcnow(),
            )
            db.add(user)
            db.flush()
            membership = Membership(
                user_id=user.id, organization_id=organization_id or self.org_id,
                role='user', status='pending', created_at=server.utcnow(),
            )
            db.add(membership)
            db.commit()
            return membership.id, user.id

    def test_pending_membership_can_be_denied_with_closed_controls(self):
        membership_id, user_id = self.pending_member()
        with (
            patch.object(server.live_hub, 'publish_to_users', new_callable=AsyncMock),
            patch.object(server.live_hub, 'publish_to_user', new_callable=AsyncMock) as notice,
        ):
            response = self.admin_client.post(
                f'/api/memberships/{membership_id}/decision', json={'approve': False})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json(), {'id': membership_id, 'status': 'denied', 'role': 'user'})
        notice.assert_awaited_once()
        self.assertEqual(notice.await_args.args[:2], (self.org_id, user_id))
        self.assertEqual(notice.await_args.args[2]['status'], 'denied')
        with self.session_factory() as db:
            self.assertEqual(db.get(Membership, membership_id).status, 'denied')
            event = db.scalar(select(AuditLog).where(
                AuditLog.organization_id == self.org_id,
                AuditLog.action == 'membership.denied'))
            self.assertEqual(event.actor_user_id, self.admin_id)
            self.assertEqual(event.details['membership_id'], membership_id)
            self.assertFalse(server.workspace_controls_available(db, db.get(Organization, self.org_id)))

    def test_approval_remains_gated_and_does_not_change_pending_membership(self):
        membership_id, _ = self.pending_member()
        response = self.admin_client.post(
            f'/api/memberships/{membership_id}/decision', json={'approve': True})
        self.assertEqual(response.status_code, 403, response.text)
        with self.session_factory() as db:
            self.assertEqual(db.get(Membership, membership_id).status, 'pending')
            self.assertIsNone(db.scalar(select(AuditLog).where(
                AuditLog.organization_id == self.org_id,
                AuditLog.action == 'membership.approved')))

    def test_denial_still_requires_approved_admin_and_correct_workspace(self):
        original_org = self.admin_client.get('/api/dashboard').json()['organization']['id']
        with self.session_factory() as db:
            other_org = Organization(
                name='Other private workspace', domain='other-private.example.org',
                slug='other-private', verification_status='pending', created_at=server.utcnow(),
            )
            db.add(other_org)
            db.commit()
            other_org_id = other_org.id
        other_member_id, _ = self.pending_member(other_org_id)
        response = self.admin_client.post(
            f'/api/memberships/{other_member_id}/decision', json={'approve': False})
        self.assertEqual(response.status_code, 404, response.text)
        self.assertEqual(original_org, self.org_id)
        with self.session_factory() as db:
            admin_membership = db.scalar(select(Membership).where(
                Membership.user_id == self.admin_id,
                Membership.organization_id == self.org_id))
            admin_membership.role = 'user'
            db.commit()
        response = self.admin_client.post(
            f'/api/memberships/{other_member_id}/decision', json={'approve': False})
        self.assertEqual(response.status_code, 403, response.text)
        with self.session_factory() as db:
            self.assertEqual(db.get(Membership, other_member_id).status, 'pending')

    def scanner_fixture(self, independent_authorization):
        now = server.utcnow()
        with self.session_factory() as db:
            org = db.get(Organization, self.org_id)
            if independent_authorization == 'verified':
                org.verification_status = 'verified'
            if independent_authorization in {'onboarding', 'expired_onboarding', 'ended_onboarding'}:
                db.add(CustomerOnboarding(
                    organization_id=self.org_id, approved_by_user_id=self.admin_id,
                    status='ended' if independent_authorization == 'ended_onboarding' else 'onboarding',
                    version=1, reason='Customer access reviewed by owner', approved_at=now,
                    review_due_at=now + timedelta(days=1) if independent_authorization != 'expired_onboarding'
                    else now - timedelta(seconds=1),
                ))
            override = ProbationOverride(
                organization_id=self.org_id, granted_by_user_id=self.admin_id,
                reason='Temporary scanner access reviewed', starts_at=now - timedelta(minutes=1),
                expires_at=now + timedelta(days=1), created_at=now - timedelta(minutes=1),
            )
            db.add(override)
            scanner = Agent(
                organization_id=self.org_id, name='Transition scanner',
                token_hash='transition-scanner-token', enabled=True, created_at=now,
            )
            db.add(scanner)
            db.flush()
            queued = AgentCommand(
                organization_id=self.org_id, agent_id=scanner.id, action='start_scan',
                target='127.0.0.1/32', status='queued', created_by_user_id=self.admin_id,
                created_at=now, updated_at=now,
            )
            active = AgentCommand(
                organization_id=self.org_id, agent_id=scanner.id, action='start_scan',
                target='127.0.0.1/32', status='accepted', created_by_user_id=self.admin_id,
                created_at=now, updated_at=now,
            )
            maintenance = AgentCommand(
                organization_id=self.org_id, agent_id=scanner.id, action='restart_nmapui',
                status='queued', created_by_user_id=self.admin_id, created_at=now, updated_at=now,
            )
            db.add_all([queued, active, maintenance])
            db.commit()
            return override.id, queued.id, active.id, maintenance.id

    def assert_revocation(self, authorization, controls_remain):
        override_id, queued_id, active_id, maintenance_id = self.scanner_fixture(authorization)
        with patch.object(server.live_hub, 'publish', new_callable=AsyncMock) as publish:
            response = self.admin_client.post(
                f'/api/workspaces/{self.org_id}/probation-overrides/{override_id}/revoke')
        self.assertEqual(response.status_code, 200, response.text)
        self.assertFalse(response.json()['active'])
        publish.assert_awaited_once_with(self.org_id, {
            'type': 'workspace_notification_created',
            'source_type': 'probation_override_revoked', 'source_id': override_id,
        })
        with self.session_factory() as db:
            override = db.get(ProbationOverride, override_id)
            self.assertIsNotNone(override.revoked_at)
            self.assertEqual(override.revoked_by_user_id, self.admin_id)
            self.assertEqual(server.workspace_controls_available(
                db, db.get(Organization, self.org_id)), controls_remain)
            self.assertEqual(db.get(AgentCommand, queued_id).status,
                             'queued' if controls_remain else 'cancelled')
            self.assertEqual(db.get(AgentCommand, active_id).status, 'accepted')
            self.assertEqual(db.get(AgentCommand, maintenance_id).status, 'queued')
            cancels = db.scalars(select(AgentCommand).where(
                AgentCommand.organization_id == self.org_id,
                AgentCommand.action == 'cancel_scan')).all()
            self.assertEqual(len(cancels), 0 if controls_remain else 1)
            if cancels:
                self.assertEqual(cancels[0].status, 'queued')
            self.assertIsNotNone(db.scalar(select(AuditLog).where(
                AuditLog.organization_id == self.org_id,
                AuditLog.action == 'probation_override.revoked')))
            self.assertIsNotNone(db.scalar(select(WorkspaceNotification).where(
                WorkspaceNotification.organization_id == self.org_id,
                WorkspaceNotification.source_type == 'probation_override_revoked')))

    def test_revoking_last_authorization_cancels_scanner_controls(self):
        self.assert_revocation('none', False)

    def test_revoking_override_preserves_verified_scanner_controls(self):
        self.assert_revocation('verified', True)

    def test_revoking_override_preserves_current_onboarding_scanner_controls(self):
        self.assert_revocation('onboarding', True)

    def test_expired_onboarding_does_not_preserve_scanner_controls(self):
        self.assert_revocation('expired_onboarding', False)

    def test_ended_onboarding_does_not_preserve_scanner_controls(self):
        self.assert_revocation('ended_onboarding', False)

    def assert_regrant(self, authorization, preserve_scans):
        old_override_id, queued_id, active_id, maintenance_id = self.scanner_fixture(authorization)
        with self.session_factory() as db:
            db.get(ProbationOverride, old_override_id).expires_at = server.utcnow() - timedelta(seconds=1)
            db.commit()
        response = self.admin_client.post(
            f'/api/workspaces/{self.org_id}/probation-overrides',
            json={'reason': 'Renewed scanner access reviewed by owner'},
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(response.json()['active'])
        self.assertNotEqual(response.json()['id'], old_override_id)
        with self.session_factory() as db:
            self.assertTrue(server.workspace_controls_available(db, db.get(Organization, self.org_id)))
            self.assertEqual(db.get(AgentCommand, queued_id).status,
                             'queued' if preserve_scans else 'cancelled')
            self.assertEqual(db.get(AgentCommand, active_id).status, 'accepted')
            self.assertEqual(db.get(AgentCommand, maintenance_id).status, 'queued')
            cancels = db.scalars(select(AgentCommand).where(
                AgentCommand.organization_id == self.org_id,
                AgentCommand.action == 'cancel_scan')).all()
            self.assertEqual(len(cancels), 0 if preserve_scans else 1)
            self.assertIsNotNone(db.scalar(select(AuditLog).where(
                AuditLog.organization_id == self.org_id,
                AuditLog.action == 'probation_override.granted')))
            self.assertIsNotNone(db.scalar(select(WorkspaceNotification).where(
                WorkspaceNotification.organization_id == self.org_id,
                WorkspaceNotification.source_type == 'probation_override_granted')))

    def test_regrant_does_not_revive_scans_from_closed_controls(self):
        self.assert_regrant('none', False)

    def test_regrant_preserves_scans_when_current_onboarding_already_authorizes_them(self):
        self.assert_regrant('onboarding', True)

    def test_expired_onboarding_does_not_preserve_scans_during_regrant(self):
        self.assert_regrant('expired_onboarding', False)

    def test_verified_workspace_rejects_override_without_cancelling_scans(self):
        old_override_id, queued_id, active_id, _ = self.scanner_fixture('verified')
        with self.session_factory() as db:
            db.get(ProbationOverride, old_override_id).expires_at = server.utcnow() - timedelta(seconds=1)
            db.commit()
        response = self.admin_client.post(
            f'/api/workspaces/{self.org_id}/probation-overrides',
            json={'reason': 'Verified workspace should retain its scanner work'},
        )
        self.assertEqual(response.status_code, 409, response.text)
        with self.session_factory() as db:
            self.assertEqual(db.get(AgentCommand, queued_id).status, 'queued')
            self.assertEqual(db.get(AgentCommand, active_id).status, 'accepted')
            self.assertEqual(len(db.scalars(select(ProbationOverride).where(
                ProbationOverride.organization_id == self.org_id)).all()), 1)
            self.assertIsNone(db.scalar(select(AgentCommand).where(
                AgentCommand.organization_id == self.org_id,
                AgentCommand.action == 'cancel_scan')))
