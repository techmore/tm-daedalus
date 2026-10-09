"""Scoped membership decisions, stale episodes and serialized admin handoff."""
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from fastapi.testclient import TestClient
from sqlalchemy import select, update, func
from sqlalchemy.orm import Session
from daedalus import server
from daedalus.models import Membership, Organization, User, UserAPIKey, AuditLog
import test_auth_and_workspace_flows as fixtures

class MembershipReviewAPITests(unittest.TestCase):
    setUp=fixtures.AuthAndWorkspaceFlowTests.setUp
    tearDown=fixtures.AuthAndWorkspaceFlowTests.tearDown
    google_callback=fixtures.AuthAndWorkspaceFlowTests.google_callback

    def member(self,status='pending',role='user'):
        with self.session_factory() as db:
            org=db.scalar(select(Organization).where(Organization.domain=='cybersecuritypilot.org'))
            user=User(google_subject='member-review-fixture',email='member-review@example.net',display_name='Member Review',created_at=server.utcnow())
            db.add(user);db.flush()
            member=Membership(user_id=user.id,organization_id=org.id,role=role,status=status,created_at=server.utcnow())
            db.add(member);db.commit()
            return org.id,member.id,user.id

    def reference(self,id):
        response=self.admin_client.get('/api/memberships')
        self.assertEqual(response.status_code,200,response.text)
        self.assertEqual(response.headers['cache-control'],'no-store')
        return next(row['state_reference'] for row in response.json()['members'] if row['id']==id)

    def headers(self,id):return {'X-Daedalus-Membership-State':self.reference(id)}

    def test_list_dates_role_controls_and_state_reference(self):
        org,id,_=self.member()
        body=self.admin_client.get('/api/memberships').json()
        self.assertEqual(body['organization_id'],org)
        self.assertIs(body['can_manage'],True)
        self.assertIs(body['controls_enabled'],True)
        self.assertTrue(body['observed_at'].endswith('Z'))
        self.assertEqual(len(self.reference(id)),64)
        self.assertEqual(self.reference(id),self.reference(id))
        result=self.admin_client.post(f'/api/memberships/{id}/decision',headers=self.headers(id),json={'approve':True})
        self.assertEqual(result.status_code,200,result.text)
        self.assertEqual(result.headers['cache-control'],'no-store')
        self.assertEqual(result.json()['organization_id'],org)
        self.assertEqual(result.json()['role'],'user')

    def test_stale_decision_cannot_apply_to_a_new_request_episode(self):
        org,id,user_id=self.member()
        old=self.headers(id)
        denied=self.admin_client.post(f'/api/memberships/{id}/decision',headers=old,json={'approve':False})
        self.assertEqual(denied.status_code,200)
        with self.session_factory() as db:
            user=db.get(User,user_id)
            email=user.email
        self.google_callback({'sub':'member-review-fixture','email':email,'email_verified':True})
        self.assertEqual(self.client.post('/api/membership-requests',json={'domain':'cybersecuritypilot.org'}).status_code,200)
        new=self.headers(id)
        self.assertNotEqual(new,old)
        rejected=self.admin_client.post(f'/api/memberships/{id}/decision',headers=old,json={'approve':True})
        self.assertEqual(rejected.status_code,409,rejected.text)
        with self.session_factory() as db:self.assertEqual(db.get(Membership,id).status,'pending')
        self.assertEqual(self.admin_client.post(f'/api/memberships/{id}/decision',headers=new,json={'approve':True}).status_code,200)

    def test_role_cycle_changes_reference_and_stale_removal_preserves_admin(self):
        org,id,_=self.member('approved')
        original=self.headers(id)
        self.assertEqual(self.admin_client.post(f'/api/memberships/{id}/role',headers=original,json={'role':'admin'}).status_code,200)
        self.assertEqual(self.admin_client.post(f'/api/memberships/{id}/revoke',headers=original).status_code,409)
        self.assertEqual(self.admin_client.post(f'/api/memberships/{id}/role',headers=self.headers(id),json={'role':'user'}).status_code,200)
        self.assertNotEqual(self.headers(id),original)
        self.assertEqual(self.admin_client.post(f'/api/memberships/{id}/role',headers=original,json={'role':'admin'}).status_code,409)
        with self.session_factory() as db:
            self.assertEqual((db.get(Membership,id).status,db.get(Membership,id).role),('approved','user'))
            self.assertEqual(db.scalar(select(func.count(AuditLog.id)).where(AuditLog.action=='membership.revoked')),0)

    def test_actor_demotion_before_lock_prevents_decision(self):
        org,id,_=self.member()
        with self.session_factory() as db:actor=db.scalar(select(Membership).where(Membership.organization_id==org,Membership.role=='admin')).id
        original=Session.execute;intervened=False
        def demote(db,statement,*args,**kwargs):
            nonlocal intervened
            if not intervened and getattr(statement,'is_update',False) and statement.table.name==Organization.__tablename__:
                intervened=True
                with self.session_factory() as other:
                    original(other,update(Membership).where(Membership.id==actor).values(role='user'))
                    original(other,update(Membership).where(Membership.id==id).values(role='admin',status='approved'))
                    other.commit()
            return original(db,statement,*args,**kwargs)
        with patch.object(Session,'execute',demote):
            response=self.admin_client.post(f'/api/memberships/{id}/decision',json={'approve':False})
        self.assertEqual(response.status_code,403,response.text)
        with self.session_factory() as db:
            self.assertEqual((db.get(Membership,id).role,db.get(Membership,id).status),('admin','approved'))
            self.assertEqual(db.scalar(select(func.count(AuditLog.id)).where(AuditLog.action=='membership.denied')),0)

    def test_key_expiration_during_lock_admission_prevents_write(self):
        org,id,_=self.member()
        issued=self.admin_client.post('/api/user-keys',json={'name':'Admission fixture'}).json()
        original=Session.execute;intervened=False
        def expire(db,statement,*args,**kwargs):
            nonlocal intervened
            if not intervened and getattr(statement,'is_update',False) and statement.table.name==Organization.__tablename__:
                intervened=True
                with self.session_factory() as other:
                    original(other,update(UserAPIKey).where(UserAPIKey.id==issued['id']).values(expires_at=server.utcnow()-server.timedelta(seconds=1)))
                    other.commit()
            return original(db,statement,*args,**kwargs)
        with patch.object(Session,'execute',expire):
            response=self.admin_client.post(f'/api/memberships/{id}/decision',headers={'Authorization':'Bearer '+issued['token']},json={'approve':True})
        self.assertEqual(response.status_code,401,response.text)
        with self.session_factory() as db:
            self.assertEqual(db.get(Membership,id).status,'pending')
            self.assertEqual(db.scalar(select(func.count(AuditLog.id)).where(AuditLog.action=='membership.approved')),0)

    def test_concurrent_promote_and_remove_cannot_revoke_an_admin(self):
        org,id,_=self.member('approved')
        headers=self.headers(id)
        token=self.admin_client.post('/api/user-keys',json={'name':'Parallel fixture'}).json()['token']
        headers['Authorization']='Bearer '+token
        clients=[TestClient(server.app),TestClient(server.app)]
        try:
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures=[pool.submit(clients[0].post,f'/api/memberships/{id}/role',headers=headers,json={'role':'admin'}),pool.submit(clients[1].post,f'/api/memberships/{id}/revoke',headers=headers)]
                responses=[future.result(timeout=15) for future in futures]
            self.assertEqual(sorted(response.status_code for response in responses),[200,409])
            with self.session_factory() as db:
                member=db.get(Membership,id)
                self.assertIn((member.status,member.role),[('approved','admin'),('revoked','user')])
                self.assertEqual(db.scalar(select(func.count(AuditLog.id)).where(AuditLog.action.in_(['membership.role_changed','membership.revoked']))),1)
        finally:
            for client in clients:client.close()

    def test_concurrent_admin_self_demotions_preserve_one_admin(self):
        org,other_id,other_user=self.member('approved','admin')
        with self.session_factory() as db:
            owner=db.scalar(select(Membership).where(Membership.organization_id==org,Membership.user_id!=other_user,Membership.role=='admin'))
            owner_id=owner.id;owner_user=owner.user_id
            tokens=['dd_user_'+'A'*64,'dd_user_'+'B'*64]
            for user,token in zip([owner_user,other_user],tokens):
                db.add(UserAPIKey(user_id=user,organization_id=org,name='Parallel fixture',token_hash=server.token_digest(token),created_at=server.utcnow(),expires_at=server.utcnow()+server.timedelta(days=1)))
            db.commit()
        clients=[TestClient(server.app),TestClient(server.app)]
        try:
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures=[pool.submit(client.post,f'/api/memberships/{id}/role',headers={'Authorization':'Bearer '+token},json={'role':'user'}) for client,id,token in zip(clients,[owner_id,other_id],tokens)]
                responses=[future.result(timeout=15) for future in futures]
            self.assertEqual(sorted(response.status_code for response in responses),[200,409])
            with self.session_factory() as db:self.assertEqual(db.scalar(select(func.count(Membership.id)).where(Membership.organization_id==org,Membership.role=='admin',Membership.status=='approved')),1)
        finally:
            for client in clients:client.close()
