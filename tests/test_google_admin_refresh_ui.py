"""Execute the deployed Google Admin UI's public load and event callbacks."""
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).parents[1]


@unittest.skipUnless(shutil.which('node'), 'Node.js required')
class GoogleAdminRefreshUITests(unittest.TestCase):
    def run_node(self, code):
        fixture = (ROOT / 'tests/cis_workspace_dom_fixture.js').read_text().split('const ids=new Map();', 1)[0]
        fixture = fixture.replace(" if(selector===\"[type='submit']\")", " if(selector==='summary')return n.tag==='summary';\n if(selector==='details[open]')return n.tag==='details'&&n.open;\n if(selector===\"[type='submit']\")")
        script = "const assert=require('node:assert/strict');\n" + fixture + r'''
const ids=new Map(),handlers={};
const document={activeElement:null,createElement:tag=>new Node(tag),createTextNode:value=>{const n=new Node('#text');n.textContent=value;return n;},
 getElementById(id){return ids.get(id)||null;},querySelector:()=>({dataset:{organizationId:'1'}}),addEventListener:(name,fn)=>{handlers[name]=fn;}};
const names=['summary','refresh-status','observation','refresh','connection','checklist','pending-evidence','customer-consent','connect','collect','disconnect','schedule','schedule-review','save-schedule','feedback','review-form','review-check','review-save','review-feedback'];
for(const name of names)ids.set('google-admin-'+name,new Node(['schedule','review-check'].includes(name)?'select':'div'));
const n=name=>document.getElementById('google-admin-'+name);
const actions=new Node();actions.append(n('connect'),n('collect'),n('disconnect'));
const originalAppend=Node.prototype.append;
Node.prototype.append=function(...nodes){originalAppend.call(this,...nodes);if(this.tag==='select'&&!this.value&&this.children[0])this.value=this.children[0].value;};
Object.defineProperty(Node.prototype,'options',{get(){return this.children.filter(n=>n.tag==='option');}});
n('review-form').record={check_id:'GA-01',evidence_collected_at:'2026-10-09T02:00',policy_scope:'Typed staff OU',observed:'Typed evidence',expected:'Typed target',rationale:'Typed rationale',source_reference:'Private fixture capture',owner:'Fixture administrator',validation:'Fixture validation'};
class FormData {constructor(form){this.rows=Object.entries(form.record);}[Symbol.iterator](){return this.rows[Symbol.iterator]();}}
class CustomEvent {constructor(type){this.type=type;}}
const timers=new Map();let timerId=0,events=[];
const window={location:{hash:'#google-admin',assign:url=>{window.assigned=url;}},setTimeout(fn,ms){timers.set(++timerId,{fn,ms});return timerId;},clearTimeout:id=>timers.delete(id),dispatchEvent:event=>events.push(event.type)};
function check(id,status='manual_review'){return {id,title:'Fixture '+id,cis_controls:'CIS Controls v8.1',expected:'Fixture expected',status,observed:'Literal fixture observation',source:'https://support.google.com/a/fixture'};}
function fixture(){return {organization_id:1,observed_at:'2026-10-09T02:00:00Z',configured:true,connected:true,is_admin:true,verified:true,
 customer_id:'C123',binding:{customer_id:'C123',domains:['fixture.example']},connected_at:'2026-10-08T12:00:00Z',connection_reference:'a'.repeat(64),last_verified_at:'2026-10-09T01:00:00Z',last_error:null,
 latest_matches_connection:true,pending_manual_evidence:{},schedule_days:0,next_run_at:null,checklist:[check('GA-01'),check('GA-02')],latest_attempt:{id:7,status:'completed',stage:'Completed'},
 latest:{report_id:7,completed_at:'2026-10-09T01:00:00Z',assessment:{checks:[check('GA-01','fail'),check('GA-02','manual_review')],summary:{pass:0,fail:1,manual_review:1,unavailable:0,not_applicable:0,error:0,applicable:2,definitive:1,coverage_percent:50,observed_pass_rate:0},manual_evidence:{}},comparison:{baseline:true,configuration_changes:[],coverage_changes:[],baseline_changes:[]}}};}
let data=fixture(),failure=false,calls=[];
function response(body,ok=true){return {ok,json:async()=>structuredClone(body)};}
const normalFetch=async(path,options)=>{calls.push({path,options});if(options.method==='GET'){if(failure)throw new Error('Read connection unavailable');return response(data);}return response({message:'Evidence saved for next assessment',revocation_confirmed:true,authorization_url:options.method==='POST'&&path.endsWith('/connect')?'https://accounts.google.com/fixture':undefined});};
global.fetch=normalFetch;
''' + (ROOT / 'src/daedalus/static/js/google-admin.js').read_text()
        script += "\nhandlers.DOMContentLoaded();\nconst load=window.daedalusGoogleAdmin.load;\n(async()=>{\n" + code + "\n})().catch(e=>{console.error(e);process.exitCode=1;});"
        result = subprocess.run(['node', '-'], input=script, text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_failed_read_retains_summary_checklist_selection_notes_and_dirty_schedule(self):
        self.run_node(r'''
await load();const summary=n('summary').textContent,card=n('checklist').children[0];card.open=true;card.querySelector('summary').focus();
n('schedule').value='7';await n('schedule').emit('change');n('schedule-review').checked=true;n('review-check').value='GA-02';
failure=true;assert.equal(await load(),false);assert.equal(n('summary').textContent,summary);assert.equal(n('checklist').children[0],card);assert.equal(card.open,true);
assert.equal(document.activeElement,card.querySelector('summary'));assert.equal(n('schedule').value,'7');assert.equal(n('review-check').value,'GA-02');assert.equal(n('review-form').record.observed,'Typed evidence');
assert.match(n('refresh-status').textContent,/Previously loaded.*may be out of date/);assert.equal(n('collect').getAttribute('aria-disabled'),'true');
const count=calls.length;await n('collect').emit('click');await n('connect').emit('click');await n('save-schedule').emit('click');await n('review-form').emit('submit',{preventDefault(){}});assert.equal(calls.length,count);
failure=false;await n('refresh').emit('click');assert.equal(n('refresh-status').textContent,'');assert.equal(n('collect').getAttribute('aria-disabled'),'false');assert.equal(n('schedule').value,'7');
assert.equal(n('schedule-review').checked,true);assert.ok(calls.every(c=>c.options.cache==='no-store'&&c.options.credentials==='same-origin'));
''')

    def test_initial_failure_is_unavailable_and_retry_restores_saved_assessment(self):
        self.run_node(r'''
failure=true;await load();assert.match(n('summary').textContent,/unavailable/);assert.match(n('connection').textContent,/unavailable/);assert.equal(n('collect').getAttribute('aria-disabled'),'true');
failure=false;await load();assert.match(n('summary').textContent,/1 failed/);assert.equal(n('refresh-status').textContent,'');assert.equal(n('checklist').children.length,2);
''')

    def test_malformed_or_foreign_response_retains_saved_view(self):
        self.run_node(r'''
await load();const original=n('summary').textContent,card=n('checklist').children[0];
for(const mutate of [d=>d.organization_id=2,d=>d.latest.assessment.summary=null,d=>d.latest.assessment.summary.fail=99,
 d=>d.binding.domains=null,d=>d.binding.customer_id='different',d=>d.connected_at='invalid',d=>d.latest.comparison={},d=>d.latest.assessment.checks[0].source='javascript:alert(1)',
 d=>d.checklist=null,d=>d.latest_matches_connection='true',d=>d.latest_attempt.id=0,d=>d.latest.assessment.manual_evidence={bad:null},d=>d.latest.assessment.manual_evidence={bad:{captured_at:'invalid'}},d=>d.checklist=[]]){
 data=fixture();mutate(data);assert.equal(await load(),false);assert.equal(n('summary').textContent,original);assert.equal(n('checklist').children[0],card);assert.match(n('refresh-status').textContent,/Could not refresh/);
}
''')

    def test_superseded_success_and_failure_are_ignored(self):
        self.run_node(r'''
await load();let pending=[];global.fetch=(path,options)=>new Promise((resolve,reject)=>pending.push({options,resolve,reject}));
const old=load();global.fetch=normalFetch;data.latest.report_id=8;data.latest_attempt.id=8;await load();assert.equal(pending[0].options.signal.aborted,true);
pending[0].resolve(response(fixture()));await old;assert.equal(n('summary').textContent.includes('Latest attempt'),false);
const saved=n('summary').textContent;pending=[];global.fetch=(path,options)=>new Promise((resolve,reject)=>pending.push({reject}));const failed=load();
global.fetch=normalFetch;await load();pending[0].reject(new Error('Late error'));await failed;assert.equal(n('summary').textContent,saved);assert.equal(n('refresh-status').textContent,'');
assert.equal([...timers.values()].filter(t=>t.ms===20000).length,0);assert.equal([...timers.values()].filter(t=>t.ms===30000).length,1);
''')

    def test_background_read_does_not_interrupt_retry_and_warning_is_quiet(self):
        self.run_node(r'''
await load();failure=true;await load();const warning=n('refresh-status').textContent,writes=n('refresh-status').textWrites;
await load(true);assert.equal(n('refresh-status').textWrites,writes);
let release;global.fetch=()=>new Promise(resolve=>{release=resolve;});const retry=load();assert.equal(await load(true),false);assert.equal(n('refresh-status').textContent,warning);
release(response(fixture()));await retry;assert.equal(n('refresh-status').textContent,'');
''')

    def test_deadline_retains_summary_and_retry_recovers(self):
        self.run_node(r'''
await load();const summary=n('summary').textContent;global.fetch=(path,options)=>new Promise((resolve,reject)=>options.signal.addEventListener('abort',()=>reject(new Error('aborted'))));
const hung=load();[...timers.values()].find(t=>t.ms===20000).fn();await hung;assert.equal(n('summary').textContent,summary);assert.match(n('refresh-status').textContent,/timed out/);
global.fetch=normalFetch;await load();assert.equal(n('refresh-status').textContent,'');
''')

    def test_new_report_resets_recurrence_ack_but_retains_dirty_schedule_and_open_checks(self):
        self.run_node(r'''
await load();n('schedule').value='7';await n('schedule').emit('change');n('schedule-review').checked=true;await n('schedule-review').emit('change');assert.equal(n('save-schedule').getAttribute('aria-disabled'),'false');
const card=n('checklist').children[0];card.open=true;card.children.at(-1).focus();const focused=document.activeElement;
data.latest.report_id=8;data.latest_attempt.id=8;await load();assert.equal(n('schedule-review').checked,false);assert.equal(n('schedule').value,'7');assert.equal(n('save-schedule').getAttribute('aria-disabled'),'true');
assert.equal(n('checklist').children[0],card);assert.equal(card.open,true);assert.equal(document.activeElement,focused);
''')

    def test_changed_check_restores_open_state_and_moves_focus_to_its_summary(self):
        self.run_node(r'''
await load();const card=n('checklist').children[0];card.open=true;card.children.at(-1).focus();
data.latest.assessment.checks[0].observed='Changed saved evidence';await load();const replacement=n('checklist').children[0];assert.notEqual(replacement,card);assert.equal(replacement.open,true);assert.equal(document.activeElement,replacement.querySelector('summary'));
''')

    def test_retired_review_choice_preserves_notes_and_requires_explicit_current_selection(self):
        self.run_node(r'''
await load();n('review-check').value='GA-02';data.checklist=[check('GA-01')];await load();assert.equal(n('review-check').value,'GA-02');assert.equal(n('review-save').getAttribute('aria-disabled'),'true');assert.equal(n('review-form').record.observed,'Typed evidence');
n('review-check').value='GA-01';await n('review-check').emit('change');assert.equal(n('review-save').getAttribute('aria-disabled'),'false');
''')

    def test_prior_connection_report_cannot_approve_recurrence_and_disconnect_can_cancel(self):
        self.run_node(r'''
await load();n('schedule').value='7';await n('schedule').emit('change');n('schedule-review').checked=true;data.latest_matches_connection=false;await load();
assert.equal(n('schedule-review').checked,false);assert.equal(n('save-schedule').getAttribute('aria-disabled'),'true');assert.match(n('summary').textContent,/previous audit connection/);
await n('disconnect').emit('click');const cancel=actions.children.at(-1);await cancel.emit('click');assert.equal(document.activeElement,n('disconnect'));assert.equal(calls.filter(c=>c.options.method!=='GET').length,0);
''')

    def test_failed_read_prevents_pending_disconnect_and_changed_connection_requires_new_confirmation(self):
        self.run_node(r'''
await load();await n('disconnect').emit('click');const confirm=actions.children.at(-2);failure=true;await load();await confirm.emit('click');assert.equal(calls.filter(c=>c.options.method==='DELETE').length,0);assert.match(n('feedback').textContent,/Refresh/);
failure=false;data.connected_at='2026-10-09T02:01:00Z';data.connection_reference='b'.repeat(64);await load();await confirm.emit('click');assert.equal(calls.filter(c=>c.options.method==='DELETE').length,0);assert.match(n('feedback').textContent,/connection changed/);assert.equal(document.activeElement,n('disconnect'));
''')

    def test_action_outcome_survives_failed_reconciliation_and_cannot_repeat(self):
        self.run_node(r'''
await load();failure=true;await n('collect').emit('click');assert.equal(calls.filter(c=>c.options.method==='POST').length,1);assert.equal(calls.find(c=>c.options.method==='POST').options.headers['X-Daedalus-Audit-Connection'],'a'.repeat(64));assert.match(n('feedback').textContent,/Saved/);assert.match(n('refresh-status').textContent,/making another/);
await n('collect').emit('click');assert.equal(calls.filter(c=>c.options.method==='POST').length,1);failure=false;await load();assert.match(n('feedback').textContent,/Saved/);
''')

    def test_manual_notes_and_success_feedback_survive_failed_read_and_invalid_date_stays_local(self):
        self.run_node(r'''
await load();n('review-form').record.evidence_collected_at='invalid';await n('review-form').emit('submit',{preventDefault(){}});assert.match(n('review-feedback').textContent,/valid source evidence date/);assert.equal(calls.filter(c=>c.options.method==='POST').length,0);
n('review-form').record.evidence_collected_at='2026-10-09T02:00';failure=true;await n('review-form').emit('submit',{preventDefault(){}});
assert.equal(calls.filter(c=>c.options.method==='POST').length,1);assert.match(n('review-feedback').textContent,/next assessment/);assert.equal(n('review-form').record.observed,'Typed evidence');assert.equal(n('review-save').getAttribute('aria-disabled'),'true');
''')

    def test_permissions_allow_stopping_recurrence_when_verification_or_configuration_is_unavailable(self):
        self.run_node(r'''
await load();data.verified=false;data.configured=false;await load();n('schedule').value='0';await n('schedule').emit('change');assert.equal(n('save-schedule').getAttribute('aria-disabled'),'false');assert.equal(n('collect').getAttribute('aria-disabled'),'true');
data.is_admin=false;await load();await n('save-schedule').emit('click');await n('disconnect').emit('click');assert.equal(calls.filter(c=>c.options.method!=='GET').length,0);
''')

    def test_pending_manual_evidence_survives_failure_and_clears_only_after_inclusion_read(self):
        self.run_node(r'''
data.pending_manual_evidence={'GA-01':{review_id:12,captured_at:'2026-10-09T01:00:00Z',recorded_at:'2026-10-09T02:00:00Z',policy_scope:'Staff OU',observed:'<script>literal notes</script>',expected:'Reviewed target',rationale:'Reviewed reason',source_reference:'Private capture',owner:'Administrator',validation:'Review procedure'}};
await load();const card=n('pending-evidence').children[0];card.open=true;card.querySelector('summary').focus();assert.match(card.textContent,/<script>literal notes<\/script>/);
failure=true;await load();assert.equal(n('pending-evidence').children[0],card);failure=false;await load();assert.equal(n('pending-evidence').children[0],card);assert.equal(card.open,true);
data.pending_manual_evidence={};await load();assert.match(n('pending-evidence').textContent,/No recorded manual evidence/);assert.equal(document.activeElement,n('refresh'));
''')

    def test_pending_action_serializes_requests_and_defers_background_reads(self):
        self.run_node(r'''
await load();let release;global.fetch=(path,options)=>{calls.push({path,options});return new Promise(resolve=>{release=resolve;});};
const collect=n('collect').emit('click'),count=calls.length;await n('collect').emit('click');assert.equal(calls.length,count);assert.equal(await load(true),false);assert.equal(calls.length,count);
global.fetch=normalFetch;release(response({}));await collect;assert.equal(n('collect').getAttribute('aria-disabled'),'false');assert.equal(events.length,1);
''')

    def test_pending_read_schema_failure_preserves_recorded_notes(self):
        self.run_node(r'''
await load();const summary=n('summary').textContent;data.pending_manual_evidence={'GA-01':null};assert.equal(await load(),false);assert.equal(n('summary').textContent,summary);assert.match(n('refresh-status').textContent,/Pending manual evidence/);
''')

    def test_active_attempt_polls_quickly_but_idle_and_hidden_views_do_not(self):
        self.run_node(r'''
await load();assert.equal([...timers.values()].filter(t=>t.ms===30000).length,1);
data.latest_attempt={id:8,status:'running',stage:'Collecting'};await load();assert.equal([...timers.values()].filter(t=>t.ms===5000).length,1);assert.equal(n('collect').getAttribute('aria-disabled'),'true');
window.location.hash='#dns';await load();assert.equal(timers.size,0);
''')

    def test_inconsistent_coverage_or_status_counts_cannot_replace_saved_assessment(self):
        self.run_node(r'''
await load();const saved=n('summary').textContent;
for(const mutate of [d=>d.latest.assessment.summary.coverage_percent=99,d=>d.latest.assessment.summary.observed_pass_rate=50,d=>d.latest.assessment.checks[0].status='unavailable',d=>d.latest.assessment.checks[0].status='unrecognized']){
 data=fixture();mutate(data);assert.equal(await load(),false);assert.equal(n('summary').textContent,saved);
}
''')
