import shutil
import subprocess
import unittest
from datetime import timedelta
from pathlib import Path

from sqlalchemy import select

from daedalus import server
from daedalus.models import CustomerOnboarding, Membership, Organization, User
import test_auth_and_workspace_flows as auth_flows


ROOT = Path(__file__).parents[1]


class WorkspaceAccessTemplateTests(unittest.TestCase):
    setUp = auth_flows.AuthAndWorkspaceFlowTests.setUp
    tearDown = auth_flows.AuthAndWorkspaceFlowTests.tearDown

    def create(self):
        response = self.admin_client.post('/api/workspaces', json={
            'name': 'Access fixture', 'domain': 'access.example.org'})
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()['organization_id']

    def test_pending_workspace_groups_access_and_places_assessments_first(self):
        self.create()
        page = self.admin_client.get('/dashboard').text
        self.assertLess(page.index('id="workspace-priorities"'), page.index('id="workspace-access"'))
        self.assertEqual(page.count('id="workspace-access"'), 1)
        self.assertIn('Awaiting TXT verification', page)
        self.assertIn('Controls paused', page)
        self.assertIn('id="domain-verification-details"', page)
        self.assertIn('id="replace-domain-challenge"', page)
        self.assertIn('Replacement invalidates the previous record', page)
        self.assertNotIn("workspace's Members page", (ROOT / 'src/daedalus/static/js/dashboard.js').read_text())

    def test_verified_workspace_still_allows_existing_approval_to_be_revoked(self):
        org_id = self.create()
        granted = self.admin_client.post(f'/api/workspaces/{org_id}/probation-overrides', json={
            'reason': 'Test existing approval after domain verification'})
        self.assertEqual(granted.status_code, 200, granted.text)
        with self.session_factory() as db:
            db.get(Organization, org_id).verification_status = 'verified'
            db.commit()
        page = self.admin_client.get('/dashboard').text
        self.assertIn('Controls available', page)
        self.assertIn('Manage the current 14-day approval', page)
        self.assertIn('data-revoke-override=', page)
        self.assertNotIn('id="issue-domain-challenge"', page)
        self.assertNotIn('id="grant-override-form"', page)

    def test_members_see_status_without_admin_controls(self):
        org_id = self.create()
        with self.session_factory() as db:
            membership = db.scalar(select(Membership).where(Membership.organization_id == org_id))
            membership.role = 'user'
            db.commit()
        page = self.admin_client.get('/dashboard').text
        self.assertIn('Workspace member', page)
        self.assertIn('Awaiting TXT verification', page)
        self.assertIn('A workspace admin can publish', page)
        self.assertNotIn('id="issue-domain-challenge"', page)
        self.assertNotIn('id="grant-override-form"', page)

    def test_dashboard_access_snapshot_has_current_deadlines_without_review_reason(self):
        org_id = self.create()
        with self.session_factory() as db:
            user = db.scalar(select(User).where(User.google_subject == 'daedalus-local-demo-admin'))
            now = server.utcnow()
            db.add(CustomerOnboarding(organization_id=org_id, approved_by_user_id=user.id,
                status='onboarding', version=1, reason='Private platform approval reason',
                approved_at=now, review_due_at=now + timedelta(days=30)))
            db.commit()
        organization = self.admin_client.get('/api/dashboard').json()['organization']
        self.assertTrue(organization['controls_enabled'])
        self.assertIsNotNone(organization['verification_expires_at'])
        self.assertFalse(organization['onboarding']['review_required'])
        self.assertEqual(set(organization['onboarding']), {'status', 'review_due_at', 'review_required'})
        with self.session_factory() as db:
            db.get(CustomerOnboarding, org_id).review_due_at = server.utcnow() - timedelta(seconds=1)
            db.commit()
        expired = self.admin_client.get('/api/dashboard').json()['organization']
        self.assertFalse(expired['controls_enabled'])
        self.assertTrue(expired['onboarding']['review_required'])

    def test_workspace_key_login_does_not_offer_account_level_customer_creation(self):
        self.create()
        issued = self.admin_client.post('/api/user-keys', json={'name': 'UI scope fixture', 'expires_days': 1})
        self.assertEqual(issued.status_code, 200, issued.text)
        token = issued.json()['token']
        self.assertEqual(self.client.post('/auth/token', json={'token': token}).status_code, 200)
        page = self.client.get('/dashboard').text
        self.assertIn('Workspace access', page)
        self.assertNotIn('id="create-workspace-form"', page)
        self.assertNotIn('class="sidebar-add-workspace"', page)
        self.assertNotIn('id="workspace-dialog"', page)
        self.assertIn('id="workspace-select" aria-label="Switch workspace" disabled', page)


@unittest.skipUnless(shutil.which('node'), 'Node.js required for UI contract fixtures')
class WorkspaceAccessJavaScriptTests(unittest.TestCase):
    def run_script(self, script):
        result = subprocess.run(['node', '-'], input=script, text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_access_refresh_preserves_edits_and_reports_authority_independently(self):
        source = (ROOT / 'src/daedalus/static/js/dashboard.js').read_text()
        helper = source[source.index('  function workspaceAccessPresentation('):source.index('  function updateWorkspaceControls(')]
        self.run_script(r'''
const assert=require('node:assert/strict');
const nodes={}, activeInput={value:'Unfinished reason'};
let writes=0;
const document={activeElement:activeInput,getElementById:id=>nodes[id]||(nodes[id]={textContent:'',classList:{toggle(){}}})};
function text(node,value){writes++;node.textContent=value;}
''' + helper + r'''
const now=Date.parse('2026-10-08T12:00:00Z');
let org={verification_status:'pending',controls_enabled:true,verification_expires_at:'2026-11-07T12:00:00Z',
  onboarding:{status:'onboarding',review_due_at:'2026-11-07T12:00:00Z',review_required:false}};
const approved=workspaceAccessPresentation(org,now);
assert.equal(approved.ownership,'Awaiting TXT verification');
assert.equal(approved.controls,'Controls available');assert.ok(approved.explanation.includes('Temporary approval'));
assert.ok(approved.onboarding.includes('review due'));
renderWorkspaceAccess(org);const first=writes;renderWorkspaceAccess(org);assert.equal(writes,first);
org={...org,controls_enabled:false,onboarding:{...org.onboarding,review_required:true}};
renderWorkspaceAccess(org);assert.equal(nodes['access-controls-state'].textContent,'Controls paused');
assert.ok(nodes['access-onboarding-status'].textContent.includes('overdue'));
assert.equal(document.activeElement,activeInput);assert.equal(activeInput.value,'Unfinished reason');
const verified=workspaceAccessPresentation({...org,verification_status:'verified',controls_enabled:true},now);
assert.equal(verified.controls,'Controls available');assert.equal(verified.verification,'');assert.ok(verified.onboarding.includes('overdue'));
const unknown=workspaceAccessPresentation({verification_status:'pending',controls_enabled:false,verification_expires_at:'invalid',
  onboarding:{status:'onboarding',review_required:false,review_due_at:'invalid'},probation_override_expires_at:'invalid'},now);
assert.ok(unknown.verification.includes('unavailable'));assert.ok(unknown.onboarding.includes('date unavailable'));
assert.ok(unknown.override.includes('date unavailable'));assert.ok(!JSON.stringify(unknown).includes('Invalid Date'));
nodes['probation-override-card'].dataset={overrideExpires:'2026-10-09T12:00:00Z'};
renderWorkspaceAccess({verification_status:'pending',controls_enabled:false,probation_override_expires_at:null});
assert.equal(nodes['probation-override-card'].hidden,true);assert.equal(nodes['access-actions-refresh'].hidden,false);
renderWorkspaceAccess({verification_status:'verified',controls_enabled:true,probation_override_expires_at:null});
assert.equal(nodes['domain-verification-details'].hidden,true);assert.equal(nodes['access-actions-refresh'].hidden,true);
''')

    def test_txt_refresh_reuses_proof_and_replacement_requires_explicit_action(self):
        source = (ROOT / 'src/daedalus/static/js/dashboard.js').read_text()
        helper = source[source.index('  var issueChallengeButton ='):source.index('  if (orgId && role === "admin" && window.DaedalusProbationApproval)')]
        self.run_script(r'''
const assert=require('node:assert/strict');
const nodes={};function node(id){return nodes[id]||(nodes[id]={handlers:{},textContent:'',disabled:false,
  classList:{names:new Set(),toggle(name,on){on?this.names.add(name):this.names.delete(name);}},addEventListener(name,fn){this.handlers[name]=fn;}});}
const document={getElementById:node};const orgId=9;let reloads=0;
const window={location:{reload(){reloads++;}}};function text(n,v){if(n)n.textContent=v;}
function showError(n,v){text(n,v);}
let confirmation, getCount=0, ensureCount=0, replacements=0;
const current={verified:false,state:'active',txt:{record_name:'_daedalus-verification.example.org',
  record_value:'daedalus=original',value_available:true,expires_at:'2026-11-07T12:00:00Z'}};
let readBody=current;
async function fetch(path,options){assert.equal(options.cache,'no-store');getCount++;return {ok:true,json:async()=>readBody};}
async function postJson(path){
  if(path.endsWith('/ensure')){ensureCount++;return current;}
  if(path.endsWith('/verify-domain'))return {verified:true};
  replacements++;return {...current,txt:{...current.txt,record_value:'daedalus=replacement'}};
}
function requestInlineConfirmation(button,message,label,fn){assert.ok(message.includes('previous value'));confirmation=fn;}
''' + helper + r'''
(async()=>{
  await new Promise(r=>setImmediate(r));
  assert.equal(getCount,1);assert.equal(ensureCount,0);assert.equal(replacements,0);
  assert.equal(node('challenge-record-value').textContent,'daedalus=original');
  await node('issue-domain-challenge').handlers.click();await node('issue-domain-challenge').handlers.click();
  assert.equal(ensureCount,2);assert.equal(replacements,0);assert.equal(node('challenge-record-value').textContent,'daedalus=original');
  renderDomainChallenge({...current,txt:{...current.txt,record_value:null,value_available:false}});
  assert.ok(node('verification-feedback').textContent.includes('remains valid'));
  assert.ok(node('challenge-record-value').textContent.includes('cannot be redisplayed'));assert.equal(replacements,0);
  renderDomainChallenge({verified:false,state:'expired',txt:current.txt});
  assert.ok(node('dns-challenge').classList.names.has('hidden'));assert.ok(node('verification-feedback').textContent.includes('expired'));
  node('replace-domain-challenge').handlers.click();assert.equal(replacements,0);
  await confirmation();assert.equal(replacements,1);assert.equal(node('challenge-record-value').textContent,'daedalus=replacement');
  readBody=current;renderDomainChallenge(await domainChallengeRequest('/api/workspaces/9/domain-challenge','GET'));
  assert.equal(replacements,1);assert.equal(getCount,2);
  await node('verify-domain').handlers.click();assert.equal(reloads,1);
  assert.equal(domainChallengeBusy,false);assert.equal(node('verify-domain').disabled,false);
  renderDomainChallenge({...current,txt:{...current.txt,record_value:'<script>literal</script>'}});
  assert.equal(node('challenge-record-value').textContent,'<script>literal</script>');
})().catch(e=>{console.error(e);process.exitCode=1;});
''')

    def test_paused_controls_keep_denial_enabled(self):
        source = (ROOT / 'src/daedalus/static/js/dashboard.js').read_text()
        helper = source[source.index('  function pauseRestrictedWorkspaceControls('):source.index('  function workspaceAccessPresentation(')]
        self.run_script(r'''
const assert=require('node:assert/strict');const controlsEnabled=false;
let selector;const approval={disabled:false},denial={disabled:false};
const document={querySelectorAll:s=>{selector=s;return [approval];}};
''' + helper + r'''
pauseRestrictedWorkspaceControls();assert.equal(approval.disabled,true);assert.equal(denial.disabled,false);
assert.ok(selector.includes('[data-membership-decision="true"]'));assert.ok(!selector.includes('[data-membership-decision]'));
''')
        review = (ROOT / 'src/daedalus/static/js/memberships.js').read_text()
        self.assertIn('button.disabled = requiresApproval && state.body && !state.body.controls_enabled;', review)

    def test_static_controls_reopen_without_enabling_in_flight_actions(self):
        source = (ROOT / 'src/daedalus/static/js/dashboard.js').read_text()
        helper = source[source.index('  function updateWorkspaceControls('):source.index('  function render(data)')]
        self.run_script(r'''
const assert=require('node:assert/strict');let controlsEnabled=false;
let approvalPauses=0;const membershipReview={pauseApproval(){approvalPauses++;}};
const nodes=Object.fromEntries(['add-scanner','issue-scanner-enrollment','run-nikto','scanner-access-paused','workspace-controls-notice'].map(id=>[id,{disabled:true,dataset:{},classList:{add(){},remove(){}}}]));
const exposure={disabled:true,dataset:{requestBusy:'true'}};
const document={getElementById:id=>nodes[id],querySelector:()=>exposure};
function pauseRestrictedWorkspaceControls(){}function renderWorkspaceAccess(){}
const niktoHistory={busy:false,runs:[{status:'running'}]};
nodes['issue-scanner-enrollment'].dataset.requestBusy='true';
''' + helper + r'''
updateWorkspaceControls({controls_enabled:true});
assert.equal(nodes['add-scanner'].disabled,false);
assert.equal(nodes['issue-scanner-enrollment'].disabled,true);assert.equal(exposure.disabled,true);assert.equal(nodes['run-nikto'].disabled,true);
assert.equal(nodes['scanner-access-paused'].hidden,true);
delete nodes['issue-scanner-enrollment'].dataset.requestBusy;delete exposure.dataset.requestBusy;niktoHistory.runs=[];
updateWorkspaceControls({controls_enabled:true});assert.equal(nodes['issue-scanner-enrollment'].disabled,false);assert.equal(exposure.disabled,false);assert.equal(nodes['run-nikto'].disabled,false);
updateWorkspaceControls({controls_enabled:false});assert.equal(nodes['add-scanner'].disabled,true);assert.equal(nodes['scanner-access-paused'].hidden,false);
assert.equal(approvalPauses,1);
''')
        template = (ROOT / 'src/daedalus/templates/dashboard.html').read_text()
        self.assertIn('id="add-scanner" class="button button-primary" {% if not workspace_controls_enabled %}disabled', template)
        style = (ROOT / 'src/daedalus/static/css/app.css').read_text()
        self.assertIn('.security-note[hidden] { display: none; }', style)

    def test_membership_views_use_one_shared_controller(self):
        source = (ROOT / 'src/daedalus/static/js/dashboard.js').read_text()
        template = (ROOT / 'src/daedalus/templates/dashboard.html').read_text()
        self.assertIn('return membershipReview.load(true)', source)
        self.assertIn('return membershipReview.load(background)', source)
        self.assertNotIn('var decision = event.target.closest("[data-membership-decision][data-membership-id]")', source)
        self.assertLess(template.index('/static/js/memberships.js'), template.index('/static/js/dashboard.js'))
