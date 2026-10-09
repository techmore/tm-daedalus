"""Reviewed TXT proof, dated persisted outcomes and current authority."""
import unittest
from datetime import timedelta
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from daedalus import server
from daedalus.models import AuditLog, DomainChallenge, Membership, Organization, User, UserAPIKey
import test_domain_challenge_flows as fixtures


class DomainVerificationReviewAPITests(unittest.TestCase):
    setUp = fixtures.DomainChallengeFlowTests.setUp
    tearDown = fixtures.DomainChallengeFlowTests.tearDown
    create = fixtures.DomainChallengeFlowTests.create
    state = fixtures.DomainChallengeFlowTests.state
    issued_count = fixtures.DomainChallengeFlowTests.issued_count
    assert_unverified = fixtures.DomainChallengeFlowTests.assert_unverified

    def path(self, org):
        return f'/api/workspaces/{org}/domain-challenge'

    def read(self, org):
        response = self.admin_client.get(self.path(org))
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.headers['cache-control'], 'no-store')
        return response.json()

    def reference(self, org):
        return {'X-Daedalus-Domain-State': self.read(org)['state_reference']}

    def checked_count(self, org):
        with self.session_factory() as db:
            return db.scalar(select(func.count(AuditLog.id)).where(
                AuditLog.organization_id == org, AuditLog.action == 'domain.verification_checked'))

    def test_read_identity_dates_proof_and_stable_reference_without_writes(self):
        created = self.create()
        org = created['organization_id']
        before = self.state(org)
        first = self.read(org)
        self.assertEqual(first['organization_id'], org)
        self.assertIsInstance(first['user_id'], int)
        self.assertEqual(first['domain'], 'instructions.example.org')
        self.assertTrue(first['observed_at'].endswith('Z'))
        self.assertIsNone(first['verified_at'])
        self.assertIsNone(first['last_check'])
        self.assertTrue(first['txt']['created_at'].endswith('Z'))
        self.assertEqual(len(first['state_reference']), 64)
        self.assertEqual(first['state_reference'], self.read(org)['state_reference'])
        ensure = self.admin_client.post(self.path(org) + '/ensure', headers=self.reference(org))
        self.assertEqual(ensure.status_code, 200, ensure.text)
        self.assertFalse(ensure.json()['created'])
        self.assertEqual(ensure.json()['state_reference'], first['state_reference'])
        self.assertEqual(self.state(org), before)
        self.assertEqual(self.issued_count(org), 0)
        self.assertEqual(self.checked_count(org), 0)

    def test_stale_confirmation_cannot_replace_ensure_or_check_a_newer_record(self):
        org = self.create()['organization_id']
        old = self.reference(org)
        first = self.admin_client.post(self.path(org), headers=old)
        self.assertEqual(first.status_code, 200, first.text)
        after = self.state(org)
        for path in (self.path(org), self.path(org) + '/ensure', f'/api/workspaces/{org}/verify-domain'):
            with patch.object(server, 'has_matching_txt') as lookup:
                reply = self.admin_client.post(path, headers=old)
            self.assertEqual(reply.status_code, 409, reply.text)
            lookup.assert_not_called()
        self.assertEqual(self.state(org), after)
        self.assertEqual(len(after), 2)
        self.assertEqual(self.issued_count(org), 1)

    def test_concurrent_confirmations_replace_once(self):
        org = self.create()['organization_id']
        headers = self.reference(org)
        barrier = Barrier(2)
        def replace(_):
            with TestClient(server.app) as client:
                client.cookies.update(self.admin_client.cookies)
                barrier.wait(timeout=10)
                return client.post(self.path(org), headers=headers)
        with ThreadPoolExecutor(max_workers=2) as pool:
            replies = list(pool.map(replace, range(2)))
        self.assertEqual(sorted(r.status_code for r in replies), [200, 409])
        self.assertEqual(len(self.state(org)), 2)
        self.assertEqual(self.issued_count(org), 1)

    def test_saved_replacement_reply_precedes_a_following_replacement(self):
        org = self.create()['organization_id']
        original = Session.commit
        intervened = False
        def commit(db):
            nonlocal intervened
            original(db)
            if not intervened:
                intervened = True
                following = self.admin_client.post(self.path(org))
                self.assertEqual(following.status_code, 200, following.text)
        with patch.object(Session, 'commit', commit):
            response = self.admin_client.post(self.path(org), headers=self.reference(org))
        self.assertEqual(response.status_code, 200, response.text)
        self.assertNotEqual(response.json()['txt']['challenge_id'], self.read(org)['txt']['challenge_id'])
        self.assertNotEqual(response.json()['state_reference'], self.read(org)['state_reference'])

    def test_not_found_result_is_dated_persisted_and_does_not_rotate_or_verify(self):
        org = self.create()['organization_id']
        before = self.state(org)
        reference = self.reference(org)
        with patch.object(server, 'has_matching_txt', return_value=False):
            response = self.admin_client.post(f'/api/workspaces/{org}/verify-domain', headers=reference)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.headers['cache-control'], 'no-store')
        body = response.json()
        self.assertEqual(body['last_check']['outcome'], 'not_found')
        self.assertTrue(body['last_check']['checked_at'].endswith('Z'))
        self.assertEqual(body['last_check']['challenge_id'], body['txt']['challenge_id'])
        self.assertEqual(self.read(org)['last_check'], body['last_check'])
        self.assertEqual(self.reference(org), reference)
        self.assertEqual(self.state(org), before)
        self.assertEqual(self.checked_count(org), 1)
        self.assert_unverified(org)

    def test_lookup_failure_records_unknown_result_without_ownership_claim(self):
        org = self.create()['organization_id']
        before = self.state(org)
        with patch.object(server, 'has_matching_txt', side_effect=RuntimeError('Resolver unavailable')):
            response = self.admin_client.post(f'/api/workspaces/{org}/verify-domain', headers=self.reference(org))
        self.assertEqual(response.status_code, 503, response.text)
        self.assertEqual(response.headers['cache-control'], 'no-store')
        self.assertEqual(response.json()['last_check']['outcome'], 'lookup_failed')
        self.assertEqual(response.json()['detail'], 'Resolver unavailable')
        self.assertEqual(self.read(org)['last_check'], response.json()['last_check'])
        self.assertEqual(self.state(org), before)
        self.assertEqual(self.checked_count(org), 1)
        self.assert_unverified(org)

    def test_empty_lookup_error_still_records_unknown_instead_of_not_found(self):
        org = self.create()['organization_id']
        with patch.object(server, 'has_matching_txt', side_effect=RuntimeError('')):
            response = self.admin_client.post(f'/api/workspaces/{org}/verify-domain', headers=self.reference(org))
        self.assertEqual(response.status_code, 503, response.text)
        self.assertEqual(response.json()['last_check']['outcome'], 'lookup_failed')
        self.assertIn('DNS lookup failed', response.json()['detail'])
        self.assertEqual(self.read(org)['last_check']['outcome'], 'lookup_failed')
        self.assert_unverified(org)

    def test_read_observation_is_dated_after_query_not_before_a_new_proof(self):
        org = self.create()['organization_id']
        initial = server.utcnow()
        with self.session_factory() as db:
            proof = db.scalar(select(DomainChallenge).where(DomainChallenge.organization_id == org))
            proof.created_at = initial + timedelta(seconds=1)
            db.commit()
            user = db.get(User, proof.created_by_user_id)
            with patch.object(server, 'utcnow', side_effect=[initial, initial + timedelta(seconds=2)]):
                body = server.current_domain_challenge(db, db.get(Organization, org), user)
            self.assertGreaterEqual(body['observed_at'], body['txt']['created_at'])
            self.assertEqual(body['observed_at'], server.iso_utc(initial + timedelta(seconds=2)))

    def test_verified_result_and_repeated_check_have_recorded_dates_without_duplicate_transition(self):
        org = self.create()['organization_id']
        with patch.object(server, 'has_matching_txt', return_value=True):
            response = self.admin_client.post(f'/api/workspaces/{org}/verify-domain', headers=self.reference(org))
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertTrue(body['verified'])
        self.assertEqual(body['state'], 'verified')
        self.assertIsNone(body['txt'])
        self.assertTrue(body['verified_at'].endswith('Z'))
        self.assertEqual(body['last_check']['outcome'], 'verified')
        self.assertEqual(self.read(org)['verified_at'], body['verified_at'])
        with patch.object(server, 'has_matching_txt') as lookup:
            again = self.admin_client.post(f'/api/workspaces/{org}/verify-domain')
        self.assertEqual(again.status_code, 200, again.text)
        lookup.assert_not_called()
        self.assertEqual(self.checked_count(org), 1)

    def test_negative_dns_result_rechecks_administrator_after_collection(self):
        org = self.create()['organization_id']
        def lookup(*_):
            with self.session_factory() as db:
                db.scalar(select(Membership).where(Membership.organization_id == org)).role = 'user'
                db.commit()
            return False
        with patch.object(server, 'has_matching_txt', side_effect=lookup):
            response = self.admin_client.post(f'/api/workspaces/{org}/verify-domain')
        self.assertEqual(response.status_code, 403, response.text)
        self.assertEqual(self.checked_count(org), 0)
        self.assert_unverified(org)

    def test_lookup_error_rechecks_key_expiry_before_recording_a_result(self):
        org = self.create()['organization_id']
        key = self.admin_client.post('/api/user-keys', json={'name': 'DNS admission fixture'}).json()
        def lookup(*_):
            with self.session_factory() as db:
                db.get(UserAPIKey, key['id']).expires_at = server.utcnow() - server.timedelta(seconds=1)
                db.commit()
            raise RuntimeError('Resolver unavailable')
        with patch.object(server, 'has_matching_txt', side_effect=lookup):
            response = self.admin_client.post(f'/api/workspaces/{org}/verify-domain', headers={'Authorization': 'Bearer ' + key['token']})
        self.assertEqual(response.status_code, 401, response.text)
        self.assertEqual(self.checked_count(org), 0)
        self.assert_unverified(org)

    def test_negative_check_cannot_label_replaced_proof_as_current(self):
        org = self.create()['organization_id']
        def lookup(*_):
            replaced = self.admin_client.post(self.path(org))
            self.assertEqual(replaced.status_code, 200, replaced.text)
            return False
        with patch.object(server, 'has_matching_txt', side_effect=lookup):
            response = self.admin_client.post(f'/api/workspaces/{org}/verify-domain')
        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(self.checked_count(org), 0)
        self.assertEqual(len(self.state(org)), 2)
        self.assert_unverified(org)
