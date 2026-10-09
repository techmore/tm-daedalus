"""Execute the shipped monitoring controller and actual presentation helper."""
import shutil
import subprocess
import unittest
from pathlib import Path
import test_workspace_requests_ui as workspace_ui

ROOT=Path(__file__).parents[1]
FIXTURE=r'''
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
'''+workspace_ui.NODE+r'''
const ids={};for(const id of ['dns-monitoring-details','dns-schedule-refresh','dns-schedule-observed','dns-schedule-read-note','dns-schedule-feedback','dns-schedule-status','dns-schedule-next-run','dns-action-schedule'])ids[id]=new Node();
const checkbox=new Node('input'),interval=new Node('select'),button=new Node('button');button.textContent='Save schedule';checkbox.checked=false;interval.value='24';
const selectors={'[data-schedule-enabled="dns"]':checkbox,'[data-schedule-interval="dns"]':interval,'[data-save-schedule="dns"]':button};
ids['dns-monitoring-details'].append(...Object.values(ids).filter(n=>n!==ids['dns-monitoring-details']),checkbox,interval,button);
const document={getElementById:id=>ids[id]||null,querySelector:s=>selectors[s]||null,activeElement:null,body:new Node('body')};
const window={setTimeout,clearTimeout};let requests=[],responses=[],saved=0;
let transport=async(path,options)=>{requests.push({path,options});const response=responses.shift();if(response instanceof Error)throw response;if(!response)throw new Error('No fixture response');return response;};
class ReviewDate extends Date{static now(){return Date.parse('2026-10-09T12:00:00Z');}}
const context=vm.createContext({window,document,Headers,AbortController,Date:ReviewDate,Number,JSON,Error,Array,Promise,dateLabel:v=>v,text:(node,value)=>{if(node)node.textContent=value;}});
const source=fs.readFileSync(ROOT+'/src/daedalus/static/js/dashboard.js','utf8');vm.runInContext(source.slice(source.indexOf('  function externalSchedulePresentation('),source.indexOf('  function renderExternalCheckSchedule(')),context);
vm.runInContext(fs.readFileSync(ROOT+'/src/daedalus/static/js/monitoring-schedule.js','utf8'),context);
const options={type:'dns',organizationId:'9',userId:'2',domain:'example.org',present:context.externalSchedulePresentation,fetch:(...args)=>transport(...args),onSaved:async()=>{saved++;}};
const review=window.DaedalusMonitoringSchedule.create(options);
const body=(extra={})=>({organization_id:9,user_id:2,domain:'example.org',check_type:'dns',can_manage:true,enabled:false,interval_hours:24,next_run_at:null,last_started_at:null,last_completed_at:null,last_run_status:null,updated_at:'2026-10-09T00:00:00Z',updated_by:'Admin',observed_at:'2026-10-09T00:00:02Z',state_reference:'a'.repeat(64),...extra});
const changed=(extra={})=>body({enabled:true,interval_hours:168,next_run_at:'2026-10-16T00:00:01Z',updated_at:'2026-10-09T00:00:01Z',state_reference:'b'.repeat(64),changed:true,...extra});
const reply=data=>({ok:true,status:200,json:async()=>data});
const refresh=ids['dns-schedule-refresh'],feedback=ids['dns-schedule-feedback'],status=ids['dns-schedule-status'],note=ids['dns-schedule-read-note'];
const choose=(enabled=true,cadence='168')=>{checkbox.checked=enabled;interval.value=cadence;checkbox.events.change();interval.events.change();};
const click=node=>node.events.click();
'''


@unittest.skipUnless(shutil.which('node'),'Node.js required')
class MonitoringScheduleReviewUITests(unittest.TestCase):
    def run_node(self,code):
        script='const ROOT='+repr(str(ROOT))+';\n'+FIXTURE+'\n(async()=>{'+code+r'''})().catch(e=>{console.error(e);process.exitCode=1;});'''
        r=subprocess.run(['node','-e',script],capture_output=True,text=True,timeout=30)
        self.assertEqual(r.returncode,0,r.stderr)

    def test_audit_summaries_describe_saved_configuration_and_expected_collection(self):
        self.run_node(r'''
const source=fs.readFileSync(ROOT+'/src/daedalus/static/js/dashboard.js','utf8');const dateLabel=v=>v;
eval(source.slice(source.indexOf('  function auditEventSummary('),source.indexOf('  async function loadAuditLog()')));
assert.equal(auditEventSummary({action:'external_check.schedule_updated',details:{check_type:'dns',enabled:false,interval_hours:168}}),'DNS & email monitoring configuration saved: automatic checks off.');
assert.match(auditEventSummary({action:'external_check.schedule_updated',details:{check_type:'web',enabled:true,interval_hours:168,next_run_at:'2026-10-16T00:00:00Z'}}),/Website monitoring configuration saved: weekly.*Next expected collection 2026-10-16/);
assert.match(auditEventSummary({action:'external_check.schedule_defaulted',details:{check_type:'dns',enabled:true,interval_hours:24}}),/daily/);
''')

    def test_reads_are_scoped_dated_and_do_not_save_or_start_collection(self):
        self.run_node(r'''
assert.equal(button.disabled,true);responses.push(reply(body()));await review.load();assert.equal(requests.length,1);assert.equal(requests[0].options.method,'GET');assert.equal(requests[0].options.cache,'no-store');assert.equal(requests[0].options.credentials,'same-origin');assert.match(status.textContent,/Automatic checks off/);assert.match(ids['dns-schedule-next-run'].textContent,/Configuration saved.*Admin/);assert.equal(checkbox.disabled,false);assert.equal(interval.disabled,true);assert.equal(saved,0);
responses.push(reply(body()));await click(refresh);assert.equal(requests.filter(r=>r.options.method==='PUT').length,0);assert.match(ids['dns-schedule-observed'].textContent,/Schedule read/);
''')

    def test_refresh_preserves_unsaved_choices_and_shows_actual_saved_configuration(self):
        self.run_node(r'''
responses.push(reply(body()));await review.load();choose();interval.focus();responses.push(reply(body()));await review.load();assert.equal(checkbox.checked,true);assert.equal(interval.value,'168');assert.equal(document.activeElement,interval);assert.match(note.textContent,/have not been saved/);assert.equal(status.textContent,'Automatic checks off');
responses.push(reply(body({interval_hours:168,state_reference:'c'.repeat(64)})));await review.load();assert.equal(checkbox.checked,true);assert.equal(interval.value,'168');assert.equal(status.textContent,'Automatic checks off');assert.equal(review.state.dirty,true);
''')

    def test_failed_read_retains_status_dates_choices_and_keyboard_retry(self):
        self.run_node(r'''
responses.push(reply(body()));await review.load();choose();interval.focus();responses.push(new Error('Offline'));await review.load();assert.equal(status.textContent,'Automatic checks off');assert.match(ids['dns-schedule-observed'].textContent,/Last observed/);assert.equal(interval.value,'168');assert.equal(checkbox.checked,true);assert.equal(button.disabled,true);assert.equal(document.activeElement,refresh);assert.match(note.textContent,/choices remain visible/);
const count=requests.length;await click(button);assert.equal(requests.length,count);responses.push(reply(body()));await click(refresh);assert.equal(interval.value,'168');assert.equal(checkbox.checked,true);assert.equal(button.disabled,false);assert.equal(document.activeElement,refresh);
''')

    def test_duplicate_save_and_newer_choices_survive_a_confirmed_save(self):
        self.run_node(r'''
responses.push(reply(body()));await review.load();choose();button.focus();let finish;transport=(path,options)=>{requests.push({path,options});return new Promise(resolve=>finish=resolve);};const pending=click(button);const count=requests.length;await click(button);await review.load();assert.equal(requests.length,count);assert.equal(refresh.disabled,true);assert.equal(requests.at(-1).options.headers.get('X-Daedalus-Schedule-State'),'a'.repeat(64));assert.deepEqual(JSON.parse(requests.at(-1).options.body),{enabled:true,interval_hours:168});
choose(false,'24');finish(reply(changed()));await pending;assert.equal(saved,1);assert.equal(checkbox.checked,false);assert.equal(interval.value,'24');assert.equal(review.state.dirty,true);assert.match(feedback.textContent,/newer choices remain unsaved/);assert.equal(document.activeElement,button);assert.equal(status.textContent,'Weekly schedule saved');
''')

    def test_lost_save_requires_get_and_recovers_matching_saved_choices_without_another_write(self):
        self.run_node(r'''
responses.push(reply(body()));await review.load();choose();responses.push(new Error('Committed response lost'));await click(button);assert.equal(review.state.fresh,false);assert.equal(review.state.dirty,true);assert.match(feedback.textContent,/check what was saved/);assert.equal(interval.value,'168');assert.equal(saved,0);
responses.push(reply(changed()));await click(refresh);assert.equal(requests.at(-1).options.method,'GET');assert.equal(requests.filter(r=>r.options.method==='PUT').length,1);assert.equal(review.state.dirty,false);assert.match(feedback.textContent,/saved configuration matches/);assert.equal(status.textContent,'Weekly schedule saved');assert.equal(saved,0);
''')

    def test_confirmed_feedback_survives_failed_read_and_actor_is_literal_text(self):
        self.run_node(r'''
responses.push(reply(body()));await review.load();choose();responses.push(reply(changed({updated_by:'Admin <script>literal</script>'})));await click(button);assert.match(ids['dns-schedule-next-run'].textContent,/Admin <script>literal<\/script>/);assert.match(feedback.textContent,/Schedule saved/);assert.equal(saved,1);
responses.push(new Error('Read failed after save'));await review.load();assert.match(feedback.textContent,/Schedule saved/);assert.match(note.textContent,/Read failed after save/);assert.equal(review.state.fresh,false);assert.equal(checkbox.checked,true);
''')

    def test_noop_retains_configuration_date_and_collection_time(self):
        self.run_node(r'''
responses.push(reply(body()));await review.load();responses.push(reply(body({changed:false})));await click(button);assert.match(feedback.textContent,/Existing schedule retained/);assert.match(feedback.textContent,/collection time was not reset/);assert.equal(saved,1);assert.equal(review.state.body.updated_at,'2026-10-09T00:00:00Z');
''')

    def test_wrong_account_topic_dates_or_malformed_response_cannot_replace_saved_view(self):
        self.run_node(r'''
responses.push(reply(body()));await review.load();choose();for(const extra of [{organization_id:10},{user_id:3},{domain:'other.example'},{check_type:'web'},{can_manage:'true'},{enabled:'true'},{interval_hours:72},{observed_at:'bad'},{observed_at:'2099-01-01T00:00:00Z'},{updated_at:'2099-01-01T00:00:00Z'},{next_run_at:'2026-10-10T00:00:00Z'},{state_reference:'bad'}]){responses.push(reply(body(extra)));await review.load();assert.equal(review.state.fresh,false);assert.equal(status.textContent,'Automatic checks off');assert.equal(interval.value,'168');assert.equal(button.disabled,true);}
responses.push(reply(body()));await review.load();responses.push(reply(changed({interval_hours:24})));await click(button);assert.equal(review.state.fresh,false);assert.match(feedback.textContent,/response is incomplete/);assert.equal(status.textContent,'Automatic checks off');
''')

    def test_request_and_body_deadline_ignore_abort_resistant_late_results(self):
        self.run_node(r'''
let expire,finish;window.setTimeout=fn=>{expire=fn;return 1;};window.clearTimeout=()=>{};transport=()=>new Promise(resolve=>finish=resolve);const pending=review.load();expire();await pending;assert.equal(review.state.loading,false);assert.match(note.textContent,/timed out/);
transport=async()=>reply(body());await review.load();finish(reply(body({domain:'other.example'})));await new Promise(r=>setImmediate(r));assert.equal(review.state.fresh,true);choose();let finishBody;transport=async()=>({ok:true,json:()=>new Promise(resolve=>finishBody=resolve)});const saving=click(button);await new Promise(r=>setImmediate(r));expire();await saving;assert.equal(review.state.saving,false);assert.equal(refresh.disabled,false);assert.equal(review.state.fresh,false);finishBody(changed());await new Promise(r=>setImmediate(r));assert.equal(saved,0);assert.equal(status.textContent,'Automatic checks off');
''')

    def test_member_read_only_controls_and_first_load_failure(self):
        self.run_node(r'''
responses.push(new Error('Unavailable'));await review.load();assert.equal(button.disabled,true);assert.match(ids['dns-schedule-observed'].textContent,/No saved schedule read/);responses.push(reply(body({can_manage:false})));await review.load();assert.equal(button.disabled,true);assert.equal(checkbox.disabled,true);const count=requests.length;await click(button);assert.equal(requests.length,count);
document.querySelector=()=>null;const member=window.DaedalusMonitoringSchedule.create(options);responses.push(reply(body({can_manage:false})));await member.load();assert.equal(member.state.fresh,true);assert.equal(await member.save(),false);
''')

    def test_worker_progress_reconciliation_is_get_only_and_retains_edits(self):
        self.run_node(r'''
responses.push(reply(body()));await review.load();choose();const count=requests.length;review.observe(body());assert.equal(requests.length,count);
const progress=body({last_completed_at:'2026-10-09T00:00:01Z',last_run_status:'deferred'});responses.push(reply(progress));review.observe(progress);await new Promise(r=>setImmediate(r));assert.equal(requests.at(-1).options.method,'GET');assert.equal(interval.value,'168');assert.equal(checkbox.checked,true);assert.match(ids['dns-schedule-next-run'].textContent,/Last attempt.*deferred/);assert.equal(requests.filter(r=>r.options.method==='PUT').length,0);
''')

    def test_overview_enable_reads_current_configuration_and_protects_unsaved_or_changed_choices(self):
        self.run_node(r'''
responses.push(reply(body()));await review.load();choose();const before=requests.length;await assert.rejects(review.enable(168,body()),/unsaved/);assert.equal(requests.length,before);
checkbox.checked=false;interval.value='24';responses.push(reply(body()));await review.load();responses.push(reply(body({interval_hours:168,state_reference:'c'.repeat(64)})));await assert.rejects(review.enable(24,body()),/configuration changed/);assert.equal(requests.filter(r=>r.options.method==='PUT').length,0);
responses.push(reply(body()),reply(changed({interval_hours:24})));assert.equal(await review.enable(24,body()),true);assert.equal(requests.at(-1).options.method,'PUT');assert.equal(saved,1);
responses.push(reply(changed({interval_hours:24})));assert.equal(await review.enable(24,body()),true);assert.equal(requests.filter(r=>r.options.method==='PUT').length,1);
''')
