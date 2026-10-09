"""Execute shipped TXT instructions, explicit replacement and DNS recovery."""
import shutil
import subprocess
import unittest
from pathlib import Path
import test_workspace_requests_ui as workspace_ui

SOURCE = Path(__file__).parents[1] / 'src/daedalus/static/js/domain-verification.js'
FIXTURE = r'''
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
''' + workspace_ui.NODE + r'''
Node.prototype.removeAttribute=function(k){delete this.attributes[k];};
const ids={};for(const id of ['domain-verification-details','domain-instructions-refresh','domain-instructions-observed','domain-instructions-read-note','verification-instructions','verification-feedback','domain-last-check','issue-domain-challenge','verify-domain','replace-domain-challenge','challenge-replacement','dns-challenge','challenge-record-name','challenge-record-value','challenge-expires','domain-verification-summary'])ids[id]=new Node();
for(const node of Object.values(ids)){node.classList.names=new Set();node.classList.toggle=(name,on)=>on?node.classList.names.add(name):node.classList.names.delete(name);}
const details=ids['domain-verification-details'];details.append(...Object.entries(ids).filter(([id])=>!['domain-verification-details','replace-domain-challenge','challenge-record-name','challenge-record-value','challenge-expires'].includes(id)).map(([,node])=>node));
ids['challenge-replacement'].append(ids['replace-domain-challenge']);ids['dns-challenge'].append(ids['challenge-record-name'],ids['challenge-record-value'],ids['challenge-expires']);
const document={getElementById:id=>ids[id]||null,createElement:tag=>new Node(tag),activeElement:null,body:new Node('body')};
const window={setTimeout,clearTimeout};let requests=[],responses=[],verified=0,checked=0;
let transport=async(path,options)=>{requests.push({path,options});const r=responses.shift();if(r instanceof Error)throw r;if(!r)throw new Error('No fixture response');return r;};
// Keep active/expired proof and future-date checks independent of the CI date.
class ReviewDate extends Date{static now(){return Date.parse('2026-10-09T12:00:00Z');}}
const context=vm.createContext({window,document,AbortController,Headers,Date:ReviewDate,Number,Map,Set,JSON,Error,Array,Promise});vm.runInContext(fs.readFileSync(SOURCE,'utf8'),context);
const review=window.DaedalusDomainVerification.create({organizationId:'9',userId:'2',domain:'example.org',fetch:(...args)=>transport(...args),onVerified:async()=>{verified++;},onChecked:async()=>{checked++;}});
const record={challenge_id:21,record_name:'_daedalus-verification.example.org',record_value:'daedalus-verification='+'A'.repeat(32),value_available:true,created_at:'2026-10-09T00:00:00Z',expires_at:'2026-11-08T00:00:00Z'};
const body=(extra={})=>({organization_id:9,user_id:2,domain:'example.org',observed_at:'2026-10-09T00:00:02Z',verified:false,verified_at:null,state:'active',state_reference:'a'.repeat(64),last_check:null,txt:record,...extra});
const check=(outcome='not_found',extra={})=>({outcome,checked_at:'2026-10-09T00:00:01Z',challenge_id:21,record_name:record.record_name,...extra});
const proof={...record,challenge_id:22,record_value:'daedalus-verification='+'B'.repeat(32)};
const replacement=()=>body({txt:proof,state_reference:'b'.repeat(64),created:true});
const owned=()=>body({verified:true,state:'verified',verified_at:'2026-10-09T00:00:01Z',last_check:check('verified'),txt:null,state_reference:'c'.repeat(64)});
const reply=(data,status=200)=>({ok:status>=200&&status<300,status,json:async()=>data});
const refresh=ids['domain-instructions-refresh'],ensure=ids['issue-domain-challenge'],verify=ids['verify-domain'],replace=ids['replace-domain-challenge'],feedback=ids['verification-feedback'];
const panel=()=>ids['challenge-replacement'].children.find(n=>n.className==='inline-confirmation');
const confirm=()=>panel().children[1].children[0],cancel=()=>panel().children[1].children[1];
const click=button=>button.events.click();
'''


@unittest.skipUnless(shutil.which('node'), 'Node.js required')
class DomainVerificationReviewUITests(unittest.TestCase):
    def run_node(self, code):
        script = 'const SOURCE=' + repr(str(SOURCE)) + ';\n' + FIXTURE + '\n(async()=>{' + code + r'''})().catch(e=>{console.error(e);process.exitCode=1;});'''
        result = subprocess.run(['node', '-e', script], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_dated_domain_audit_summaries_describe_outcomes_without_exposing_proof(self):
        self.run_node(r'''
const source=fs.readFileSync(SOURCE.replace('domain-verification.js','dashboard.js'),'utf8');
const start=source.indexOf('  function auditEventSummary('),end=source.indexOf('  async function loadAuditLog()',start);
const dateLabel=value=>value||'Date unavailable';eval(source.slice(start,end));
assert.match(auditEventSummary({action:'domain_challenge.issued',details:{record_name:record.record_name,record_value:record.record_value}}),/TXT ownership instructions prepared/);
assert.ok(!auditEventSummary({action:'domain_challenge.issued',details:{record_name:record.record_name,record_value:record.record_value}}).includes(record.record_value));
assert.match(auditEventSummary({action:'domain.verification_checked',details:check()}),/2026-10-09T00:00:01Z: record not found; ownership remains pending/);
assert.match(auditEventSummary({action:'domain.verification_checked',details:check('lookup_failed')}),/lookup failed; ownership was not verified/);
assert.match(auditEventSummary({action:'domain.verification_checked',details:check('verified')}),/ownership verified/);
assert.equal(auditEventSummary({action:'domain.verified',details:{domain:'example.org'}}),'Domain ownership verified for example.org.');
''')

    def test_read_and_ensure_reuse_proof_without_automatic_issue_or_replacement(self):
        self.run_node(r'''
assert.equal(ensure.disabled,true);responses.push(reply(body()));await review.load();assert.equal(requests.length,1);assert.equal(requests[0].options.method,'GET');assert.equal(requests[0].options.cache,'no-store');assert.equal(requests[0].options.credentials,'same-origin');assert.equal(ensure.disabled,false);
assert.equal(ids['challenge-record-value'].textContent,record.record_value);assert.match(ids['challenge-expires'].textContent,/Prepared/);
assert.equal(ensure.hidden,true);assert.equal(verify.hidden,false);
responses.push(reply(body({created:false})),reply(body({created:false})));await click(ensure);await click(ensure);
assert.ok(requests.slice(1).every(r=>r.path.endsWith('/ensure')));assert.equal(requests.at(-1).options.headers.get('X-Daedalus-Domain-State'),'a'.repeat(64));assert.equal(ids['challenge-record-value'].textContent,record.record_value);assert.match(feedback.textContent,/same active record is retained/);assert.equal(verified,0);
''')

    def test_failed_read_retains_instructions_dates_focus_and_fixed_refresh_only_reads(self):
        self.run_node(r'''
responses.push(reply(body()));await review.load();replace.focus();const when=ids['domain-instructions-observed'].textContent;
responses.push(new Error('offline'));await review.load();assert.equal(document.activeElement,refresh);assert.equal(ids['challenge-record-value'].textContent,record.record_value);assert.match(ids['domain-instructions-observed'].textContent,/Last observed/);assert.equal(ensure.disabled,true);assert.equal(verify.disabled,true);assert.equal(replace.disabled,true);
assert.match(ids['domain-instructions-read-note'].textContent,/before publishing or changing/);const count=requests.length;await click(ensure);await click(verify);await click(replace);assert.equal(requests.length,count);
responses.push(reply(body()));await click(refresh);assert.equal(requests.at(-1).options.method,'GET');assert.equal(replace.disabled,false);assert.equal(document.activeElement,refresh);assert.equal(ids['challenge-record-value'].textContent,record.record_value);
''')

    def test_explicit_inline_replacement_cancel_stale_confirmation_and_saved_proof(self):
        self.run_node(r'''
responses.push(reply(body()));await review.load();await click(replace);assert.ok(panel());assert.equal(requests.length,1);assert.match(panel().textContent,/previous value will stop/);await click(cancel());assert.equal(panel(),undefined);assert.equal(document.activeElement,replace);
await click(replace);const oldConfirm=confirm();responses.push(reply(replacement()));await review.load();assert.equal(panel(),undefined);const count=requests.length;await click(oldConfirm);assert.equal(requests.length,count);
await click(replace);responses.push(reply(body({txt:{...proof,challenge_id:23},state_reference:'d'.repeat(64),created:true})));await click(confirm());assert.equal(requests.at(-1).path,'/api/workspaces/9/domain-challenge');assert.equal(requests.at(-1).options.headers.get('X-Daedalus-Domain-State'),'b'.repeat(64));assert.match(feedback.textContent,/Replacement TXT record saved/);assert.match(feedback.textContent,/previous value no longer verifies/);assert.equal(panel(),undefined);assert.equal(document.activeElement,refresh);
''')

    def test_duplicate_confirmation_is_guarded_and_lost_response_requires_read_recovery(self):
        self.run_node(r'''
responses.push(reply(body()));await review.load();await click(replace);const control=confirm();let finish;
transport=(path,options)=>{requests.push({path,options});return new Promise(r=>finish=r);};const pending=click(control);const count=requests.length;await click(control);await click(ensure);await review.load();assert.equal(requests.length,count);assert.equal(refresh.disabled,true);
finish(reply(null));await pending;assert.equal(panel(),undefined);assert.equal(review.state.fresh,false);assert.equal(ensure.disabled,true);assert.equal(ids['challenge-record-value'].textContent,record.record_value);assert.match(feedback.textContent,/check what was saved/);
transport=async(path,options)=>{requests.push({path,options});return reply(replacement());};await click(refresh);assert.equal(requests.at(-1).options.method,'GET');assert.equal(ids['challenge-record-value'].textContent,proof.record_value);assert.match(feedback.textContent,/saved current TXT record/);assert.equal(requests.filter(r=>r.options.method==='POST').length,1);
''')

    def test_legacy_expired_missing_and_verified_states_do_not_rotate_on_read(self):
        self.run_node(r'''
responses.push(reply(body({txt:{...record,record_value:null,value_available:false}})));await review.load();assert.match(ids['verification-instructions'].textContent,/remains valid/);assert.match(ids['challenge-record-value'].textContent,/cannot be redisplayed/);assert.equal(verify.disabled,false);assert.equal(replace.hidden,false);
responses.push(reply(body({state:'expired',txt:{...record,created_at:'2026-09-01T00:00:00Z',expires_at:'2026-10-08T00:00:00Z'}})));await review.load();assert.ok(ids['dns-challenge'].classList.names.has('hidden'));assert.match(ids['verification-instructions'].textContent,/expired/);assert.equal(verify.disabled,true);assert.equal(ids['challenge-replacement'].hidden,true);assert.equal(ensure.disabled,false);
responses.push(reply(body({state:'none',txt:null})));await review.load();assert.match(ids['verification-instructions'].textContent,/prepares the ownership instructions/);assert.equal(ensure.disabled,false);
assert.equal(ensure.hidden,false);assert.equal(verify.hidden,true);
responses.push(reply(body({verified:true,state:'verified',txt:null,verified_at:null})));await review.load();assert.equal(verified,1);assert.match(ids['verification-instructions'].textContent,/verification date is unavailable/);assert.equal(details.hidden,false);assert.equal(ensure.hidden,true);assert.equal(verify.hidden,true);assert.equal(requests.filter(r=>r.options.method==='POST').length,0);
''')

    def test_pending_read_does_not_steal_new_focus_and_hidden_verify_returns_to_refresh(self):
        self.run_node(r'''
responses.push(reply(body()));await review.load();replace.focus();let finish;
transport=()=>new Promise(resolve=>finish=resolve);const reading=review.load();document.body.focus();
const newControl=new Node('input');newControl.focus();finish(reply(body()));await reading;assert.equal(document.activeElement,newControl);
transport=async()=>reply(owned());verify.focus();await click(verify);assert.equal(document.activeElement,refresh);assert.equal(verify.hidden,true);
''')

    def test_negative_and_failed_dns_results_are_dated_unknown_and_keep_proof(self):
        self.run_node(r'''
responses.push(reply(body()));await review.load();responses.push(reply(body({last_check:check(),detail:'Not found'})));await click(verify);assert.match(feedback.textContent,/not found yet/);assert.match(feedback.textContent,/Checked/);assert.match(feedback.textContent,/Ownership remains pending/);assert.equal(checked,1);assert.equal(verified,0);assert.equal(review.state.fresh,true);
responses.push(reply(body({last_check:check('lookup_failed'),detail:'Resolver <script>literal</script> unavailable'}),503));await click(verify);assert.match(feedback.textContent,/DNS lookup failed/);assert.match(feedback.textContent,/Resolver <script>literal<\/script> unavailable/);assert.equal(checked,2);assert.equal(verified,0);assert.equal(ids['challenge-record-value'].textContent,record.record_value);assert.equal(verify.disabled,false);
responses.push(reply(body({txt:proof,state_reference:'b'.repeat(64),last_check:check()})));await review.load();assert.match(ids['domain-last-check'].textContent,/earlier record/);
''')

    def test_verification_updates_in_place_and_saved_feedback_survives_later_failed_read(self):
        self.run_node(r'''
responses.push(reply(body()));await review.load();responses.push(reply(owned()));await click(verify);assert.equal(verified,1);assert.match(feedback.textContent,/Domain ownership verified/);assert.match(feedback.textContent,/Recorded/);assert.equal(details.hidden,false);assert.equal(verify.hidden,true);assert.equal(ids['domain-verification-summary'].textContent,'Domain ownership verified');
responses.push(new Error('following read offline'));await review.load();assert.match(feedback.textContent,/Domain ownership verified/);assert.equal(review.state.fresh,false);assert.match(ids['domain-instructions-read-note'].textContent,/following read offline/);assert.equal(verified,1);
responses.push(reply(owned()));await review.load();assert.equal(verified,1);assert.match(feedback.textContent,/Domain ownership verified/);
''')
        self.assertNotIn('location.reload', SOURCE.read_text())
        self.assertNotIn('window.confirm', SOURCE.read_text())

    def test_lost_verification_response_recovers_verified_state_without_another_dns_query(self):
        self.run_node(r'''
responses.push(reply(body()));await review.load();responses.push(new Error('committed response lost'));await click(verify);assert.equal(review.state.fresh,false);assert.equal(verified,0);assert.equal(ids['challenge-record-value'].textContent,record.record_value);
responses.push(reply(owned()));await click(refresh);assert.equal(requests.at(-1).options.method,'GET');assert.equal(verified,1);assert.match(feedback.textContent,/Ownership status refreshed/);assert.match(feedback.textContent,/Domain ownership is verified/);assert.equal(requests.filter(r=>r.path.endsWith('/verify-domain')).length,1);
''')

    def test_account_domain_scope_and_malformed_fields_retain_the_last_record(self):
        self.run_node(r'''
responses.push(reply(body()));await review.load();
for(const extra of [{organization_id:10},{user_id:3},{domain:'other.example'},{state_reference:'bad'},{observed_at:'bad'},{observed_at:'2099-01-01T00:00:00Z'},{verified_at:'2026-10-09T00:00:00Z'},{txt:{...record,record_value:'<script>literal</script>'}},{txt:{...record,record_name:'_daedalus-verification.other.example'}},{txt:{...record,created_at:'bad'}},{last_check:check('unknown')},{last_check:check('not_found',{checked_at:'2099-01-01T00:00:00Z'})},{state:'none'}]){
 responses.push(reply(body(extra)));await review.load();assert.equal(review.state.fresh,false);assert.equal(ids['challenge-record-value'].textContent,record.record_value);assert.equal(replace.disabled,true);
}
responses.push(reply(body()));await review.load();responses.push(reply(body({created:false,txt:proof})));await click(ensure);assert.equal(review.state.fresh,false);assert.match(feedback.textContent,/response is incomplete/);assert.equal(ids['challenge-record-value'].textContent,record.record_value);
''')

    def test_request_and_body_deadlines_ignore_late_results_and_release_read_refresh(self):
        self.run_node(r'''
let expire;window.setTimeout=(fn,ms)=>{assert.equal(ms,20000);expire=fn;return 1;};window.clearTimeout=()=>{};
let finish;transport=(path,options)=>{requests.push({path,options});return new Promise(r=>finish=r);};const loading=review.load();expire();await loading;assert.equal(review.state.loading,false);assert.match(ids['domain-instructions-read-note'].textContent,/timed out/);
transport=async()=>reply(body());await review.load();finish(reply(body({domain:'wrong.example'})));await new Promise(r=>setImmediate(r));assert.equal(review.state.fresh,true);
let finishBody;transport=async()=>({ok:true,status:200,json:()=>new Promise(r=>finishBody=r)});const pending=click(verify);await new Promise(r=>setImmediate(r));expire();await pending;assert.equal(review.state.busy,false);assert.equal(review.state.fresh,false);assert.equal(refresh.disabled,false);assert.equal(verified,0);assert.equal(ids['challenge-record-value'].textContent,record.record_value);
finishBody(owned());await new Promise(r=>setImmediate(r));assert.equal(verified,0);assert.equal(review.state.fresh,false);
''')

    def test_expiry_and_remote_ownership_reconcile_by_get_preserving_existing_focus(self):
        self.run_node(r'''
responses.push(reply(body()));await review.load();replace.focus();responses.push(reply(owned()));review.observe({verification_status:'verified'});await new Promise(r=>setImmediate(r));assert.equal(requests.at(-1).options.method,'GET');assert.equal(verified,1);assert.equal(details.hidden,false);
responses.push(reply(body()));await review.load();review.state.body={...review.state.body,txt:{...record,created_at:'2026-09-01T00:00:00Z',expires_at:'2026-10-08T00:00:00Z'}};responses.push(reply(body({state:'expired',txt:review.state.body.txt})));review.observe({verification_status:'pending'});await new Promise(r=>setImmediate(r));assert.equal(review.state.body.state,'expired');assert.equal(verify.disabled,true);assert.equal(ensure.disabled,false);assert.equal(requests.at(-1).options.method,'GET');
''')
