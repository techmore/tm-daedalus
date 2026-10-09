"""Execute the shipped approval view, transport and delegated decisions."""
import shutil
import subprocess
import unittest
from pathlib import Path
import test_workspace_requests_ui as workspace_ui

SOURCE = Path(__file__).parents[1] / 'src/daedalus/static/js/probation-approval.js'
FIXTURE = r'''
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
''' + workspace_ui.NODE + r'''
Node.prototype.replaceChildren=function(){this.children.forEach(n=>n.parentElement=null);this.children=[];this._text='';};
Node.prototype.matches=function(s){return s==='button'&&this.tagName==='button'||s==='input[name="reason"]'&&this.tagName==='input'&&this.name==='reason'||s==='[data-revoke-override]'&&this.dataset.revokeOverride;};
Node.prototype.querySelectorAll=function(s){return this.children.flatMap(c=>[c.matches(s)?c:null,...c.querySelectorAll(s)]).filter(Boolean);};
Node.prototype.closest=function(s){return this.matches(s)?this:this.parentElement?.closest(s)||null;};
const ids={};for(const id of ['probation-override-card','override-actions','override-feedback','override-read-note','override-observed','override-refresh','override-summary'])ids[id]=new Node();
const document={getElementById:id=>ids[id]||null,createElement:tag=>new Node(tag),activeElement:null};
const window={setTimeout,clearTimeout};let requests=[],responses=[],saved=0;
let transport=async(path,options)=>{requests.push({path,options});const r=responses.shift();if(r instanceof Error)throw r;if(!r)throw new Error('No fixture response');return r;};
const context=vm.createContext({window,document,AbortController,Headers,Date,Number,Map,Set,JSON,Error,Array,Promise});vm.runInContext(fs.readFileSync(SOURCE,'utf8'),context);
const review=window.DaedalusProbationApproval.create({organizationId:'1',fetch:(...args)=>transport(...args),onSaved:async()=>{saved++;}});
const active={id:11,granted_by:'admin@example.org',reason:'Approved <script>literal</script>',starts_at:'2026-10-09T00:00:00Z',expires_at:'2026-10-23T00:00:00Z',revoked_at:null,active:true};
const body=(extra={})=>({organization_id:1,observed_at:'2026-10-09T00:00:01Z',verification_status:'pending',controls_enabled:false,state_reference:'a'.repeat(64),overrides:[],...extra});
const reply=(data,status=200)=>({ok:status===200,status,json:async()=>data});
const host=ids['override-actions'],feedback=ids['override-feedback'],refresh=ids['override-refresh'];
const input=()=>host.querySelector('input[name="reason"]'),button=()=>host.querySelector('button');
const send=()=>host.events.submit({target:host.children.find(n=>n.id==='grant-override-form'),preventDefault(){}});
const click=()=>host.events.click({target:button()});
const grant=(extra={})=>body({id:11,active:true,reason:'Customer validation reason',starts_at:active.starts_at,expires_at:active.expires_at,controls_enabled:true,state_reference:'b'.repeat(64),...extra});
'''


@unittest.skipUnless(shutil.which('node'), 'Node.js required')
class ProbationApprovalUITests(unittest.TestCase):
    def run_node(self, code):
        script = 'const SOURCE=' + repr(str(SOURCE)) + ';\n' + FIXTURE + '\n(async()=>{' + code + r'''})().catch(e=>{console.error(e);process.exitCode=1;});'''
        result = subprocess.run(['node', '-e', script], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_saved_status_failed_read_retry_preserves_nodes_reason_and_focus(self):
        self.run_node(r'''
responses.push(reply(body()));await review.load();const field=input(),row=host.children[1];field.value='Unfinished approval reason';field.focus();
assert.equal(requests[0].options.cache,'no-store');assert.equal(requests[0].options.credentials,'same-origin');assert.ok(requests[0].options.signal);
responses.push(new Error('offline'));await review.load();assert.equal(input(),field);assert.equal(document.activeElement,field);assert.equal(field.value,'Unfinished approval reason');assert.equal(button().disabled,true);
assert.match(ids['override-observed'].textContent,/Last observed/);assert.match(ids['override-read-note'].textContent,/last observed approval remains visible/);
const count=requests.length;await send();assert.equal(requests.length,count);
responses.push(reply(body({observed_at:'2026-10-09T00:00:02Z'})));await refresh.events.click();assert.equal(input(),field);assert.equal(host.children[1],row);assert.equal(document.activeElement,field);assert.equal(button().disabled,false);
''')

    def test_delegated_grant_posts_once_with_reference_and_saved_feedback_survives_read_failure(self):
        self.run_node(r'''
responses.push(reply(body()));await review.load();input().value='Customer validation reason';let finish;
transport=(path,options)=>{requests.push({path,options});return new Promise(r=>finish=r);};const pending=send();assert.equal(button().disabled,true);assert.equal(refresh.disabled,true);const count=requests.length;
await send();await review.load();assert.equal(requests.length,count);assert.equal(requests.at(-1).options.headers.get('X-Daedalus-Approval-State'),'a'.repeat(64));
assert.equal(JSON.parse(requests.at(-1).options.body).reason,'Customer validation reason');
transport=async()=>{throw new Error('following read offline');};finish(reply(grant()));await pending;assert.equal(saved,1);assert.match(feedback.textContent,/Approval #11 saved through/);assert.match(feedback.textContent,/Recorded/);assert.equal(review.state.fresh,false);assert.match(ids['override-read-note'].textContent,/following read offline/);
review.observe({verification_status:'pending',probation_override_expires_at:active.expires_at});assert.match(ids['override-read-note'].textContent,/following read offline/);
responses.push(reply(body({overrides:[active],controls_enabled:true,state_reference:'b'.repeat(64)})));transport=async(path,options)=>{requests.push({path,options});return responses.shift();};await refresh.events.click();assert.match(feedback.textContent,/Approval #11 saved/);assert.match(host.textContent,/Approved <script>literal<\/script>/);assert.equal(button().textContent,'Revoke approval');
''')

    def test_changed_draft_and_lost_response_never_retry_write_automatically(self):
        self.run_node(r'''
responses.push(reply(body()));await review.load();input().value='Customer validation reason';let finish;
transport=(path,options)=>{requests.push({path,options});return new Promise(r=>finish=r);};const pending=send();input().value='Next review reason';
transport=async()=>{throw new Error('read offline');};finish(reply(grant()));await pending;assert.equal(input().value,'Next review reason');assert.equal(saved,1);
responses.push(reply(body({state_reference:'c'.repeat(64)})));transport=async(path,options)=>{requests.push({path,options});return responses.shift();};await review.load();
transport=async(path,options)=>{requests.push({path,options});throw new Error('response lost');};const count=requests.length;await send();assert.equal(requests.length,count+1);assert.equal(input().value,'Next review reason');assert.match(feedback.textContent,/check what was saved/);assert.equal(review.state.fresh,false);
await send();assert.equal(requests.length,count+1);
responses.push(reply(body({overrides:[active],controls_enabled:true,state_reference:'d'.repeat(64)})));transport=async(path,options)=>{requests.push({path,options});return responses.shift();};await review.load();assert.equal(requests.at(-1).options.method,'GET');assert.equal(button().textContent,'Revoke approval');assert.equal(saved,1);
assert.match(feedback.textContent,/Status refreshed/);assert.match(feedback.textContent,/Approval #11 is active/);assert.doesNotMatch(feedback.textContent,/before trying again/);
''')

    def test_revocation_changes_actions_without_reload_and_another_authorization_can_remain(self):
        self.run_node(r'''
responses.push(reply(body({overrides:[active],controls_enabled:true,state_reference:'b'.repeat(64)})));await review.load();button().focus();
responses.push(reply(body({id:11,active:false,revoked_at:'2026-10-09T00:00:01Z',controls_enabled:true,state_reference:'c'.repeat(64)})),reply(body({overrides:[{...active,active:false,revoked_at:'2026-10-09T00:00:01Z'}],controls_enabled:true,state_reference:'c'.repeat(64)})));
await click();assert.match(feedback.textContent,/Approval #11 revoked/);assert.equal(saved,1);assert.ok(input());assert.equal(document.activeElement,refresh);assert.match(host.textContent,/Previous approval #11 revoked/);assert.equal(button().disabled,false);assert.equal(review.state.body.controls_enabled,true);
responses.push(reply(body({verification_status:'verified',controls_enabled:true})));await review.load();assert.equal(input(),null);assert.equal(button(),null);assert.match(host.textContent,/Domain ownership is verified/);
''')

    def test_wrong_scope_malformed_or_inconsistent_reply_retains_view_and_pauses_decisions(self):
        self.run_node(r'''
responses.push(reply(body()));await review.load();input().value='Keep this reason';const field=input();
for(const extra of [{organization_id:2},{observed_at:'bad'},{observed_at:'2099-01-01T00:00:00Z'},{verification_status:'unknown'},{controls_enabled:'true'},{state_reference:'bad'}, {overrides:[active]}, {overrides:[active,active],controls_enabled:true},{overrides:[{...active,expires_at:'bad'}],controls_enabled:true},{overrides:[{...active,active:false}],controls_enabled:true}]) {
responses.push(reply(body(extra)));await review.load();assert.equal(input(),field);assert.equal(field.value,'Keep this reason');assert.equal(review.state.fresh,false);assert.equal(button().disabled,true);
}
responses.push(reply(body()));await review.load();responses.push(reply(grant({organization_id:2})));await send();assert.equal(saved,0);assert.equal(field.value,'Keep this reason');assert.equal(review.state.fresh,false);assert.match(feedback.textContent,/decision was not confirmed/);
''')

    def test_transport_and_body_deadlines_release_controls_ignore_late_responses(self):
        self.run_node(r'''
let expire;window.setTimeout=(fn,ms)=>{assert.equal(ms,20000);expire=fn;return 1;};window.clearTimeout=()=>{};
let finish;transport=(path,options)=>{requests.push({path,options});return new Promise(r=>finish=r);};const pending=review.load();expire();await pending;
assert.equal(review.state.loading,false);assert.match(ids['override-read-note'].textContent,/timed out/);assert.equal(refresh.disabled,false);
transport=async()=>reply(body());await review.load();finish(reply(body({organization_id:2})));await new Promise(r=>setImmediate(r));assert.equal(review.state.fresh,true);
let finishBody;transport=async()=>({ok:true,json:()=>new Promise(r=>finishBody=r)});input().value='Customer validation reason';const sending=send();await new Promise(r=>setImmediate(r));expire();await sending;
assert.equal(review.state.busy,false);assert.equal(review.state.fresh,false);assert.equal(refresh.disabled,false);assert.equal(input().value,'Customer validation reason');assert.match(feedback.textContent,/check what was saved/);
finishBody(grant());await new Promise(r=>setImmediate(r));assert.equal(saved,0);assert.equal(review.state.fresh,false);
''')

    def test_changed_access_during_edit_pauses_action_and_refresh_keeps_draft(self):
        self.run_node(r'''
responses.push(reply(body()));await review.load();input().value='Unfinished review reason';const field=input();field.focus();
responses.push(reply(body()));review.observe({verification_status:'pending',probation_override_expires_at:active.expires_at});assert.equal(review.state.fresh,false);assert.equal(button().disabled,true);assert.equal(document.activeElement,field);assert.equal(field.value,'Unfinished review reason');
await new Promise(r=>setImmediate(r));assert.equal(input(),field);assert.equal(field.value,'Unfinished review reason');assert.equal(button().disabled,false);assert.equal(requests.at(-1).options.method,'GET');
// A status read in progress also prevents a conflicting decision.
let finish;transport=()=>new Promise(r=>finish=r);const reading=review.load();const count=requests.length;await send();assert.equal(requests.length,count);finish(reply(body()));await reading;
''')

    def test_validation_denial_retains_reason_and_no_popup_or_automatic_reload(self):
        self.run_node(r'''
responses.push(reply(body()));await review.load();input().value='short';await send();assert.equal(requests.length,1);
input().value='Customer validation reason';responses.push(reply({detail:'Temporary approval changed. Refresh approval status before deciding again.'},409));await send();assert.equal(input().value,'Customer validation reason');assert.equal(review.state.fresh,false);assert.equal(saved,0);assert.match(feedback.textContent,/Temporary approval changed/);
''')
        self.assertNotIn('location.reload', SOURCE.read_text())
        self.assertNotIn('requestInlineConfirmation', SOURCE.read_text())
        template = (SOURCE.parents[2] / 'templates/dashboard.html').read_text()
        self.assertLess(template.index('/static/js/probation-approval.js'), template.index('/static/js/dashboard.js'))

    def test_saved_decision_restores_lost_keyboard_focus_without_stealing_a_new_edit(self):
        self.run_node(r'''
document.body=new Node('body');responses.push(reply(body()));await review.load();input().value='Customer validation reason';button().focus();
transport=async(path,options)=>{requests.push({path,options});if(options.method==='POST'){document.activeElement=document.body;return reply(grant());}return reply(body({overrides:[active],controls_enabled:true,state_reference:'b'.repeat(64)}));};
await send();assert.equal(document.activeElement,refresh);
transport=async()=>reply(body());await review.load();input().value='Customer validation reason';button().focus();let finish;
transport=()=>new Promise(r=>finish=r);const pending=send();input().value='Another reason being edited';input().focus();const field=input();transport=async()=>{throw new Error('read offline');};finish(reply(grant()));await pending;assert.equal(document.activeElement,field);assert.equal(field.value,'Another reason being edited');
''')
        style = (SOURCE.parent.parent / 'css/app.css').read_text()
        self.assertIn('#probation-override-card button { min-height: 44px; }', style)

    def test_older_dashboard_posture_reconciles_through_read_without_repeating_saved_decision(self):
        self.run_node(r'''
responses.push(reply(body()));await review.load();input().value='Customer validation reason';
const approved=body({overrides:[active],controls_enabled:true,state_reference:'b'.repeat(64)});
responses.push(reply(grant()),reply(approved));await send();assert.equal(review.state.fresh,true);const revoke=button();revoke.focus();
// A dashboard request that began before the grant can complete afterward.
responses.push(reply(approved));review.observe({verification_status:'pending',probation_override_expires_at:null});assert.equal(review.state.fresh,false);await new Promise(r=>setImmediate(r));
assert.equal(review.state.fresh,true);assert.equal(button(),revoke);assert.equal(document.activeElement,revoke);assert.match(feedback.textContent,/Approval #11 saved through/);
assert.equal(requests.filter(r=>r.options.method==='POST').length,1);assert.equal(requests.at(-1).options.method,'GET');
// A real remote change is read independently; a failed reconciliation pauses.
responses.push(new Error('remote status offline'));review.observe({verification_status:'pending',probation_override_expires_at:null});await new Promise(r=>setImmediate(r));assert.equal(review.state.fresh,false);assert.equal(button(),revoke);assert.equal(button().disabled,true);assert.match(feedback.textContent,/saved through/);assert.match(ids['override-read-note'].textContent,/remote status offline/);
''')
