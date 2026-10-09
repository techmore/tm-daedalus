"""Exercise the actual DNS/website action callbacks, not a separate UI model."""
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).parents[1]
SOURCE = ROOT / "src/daedalus/static/js/dashboard.js"


@unittest.skipUnless(shutil.which("node"), "Node.js required")
class ExternalTopicActionTests(unittest.TestCase):
    def run_node(self, helper, assertions, setup=""):
        prelude = r'''
const assert=require('node:assert/strict');
class Node {
 constructor(tag='div') {this.tag=tag;this.children=[];this.dataset={};this.textContent='';this.disabled=false;this.events={};this.attrs={};this.open=false;this.className='';}
 append(...nodes){this.children.push(...nodes);}
 after(...nodes){this.afterNodes=nodes;}
 setAttribute(name,value){this.attrs[name]=value;}
 addEventListener(name,callback){this.events[name]=callback;}
 focus(){document.activeElement=this;}
 scrollIntoView(options){this.scrolled=options;}
 querySelector(selector){return selector==='summary'?this.summary:null;}
}
const nodes=new Map(), selectors=new Map();
const document={activeElement:null,createElement:tag=>new Node(tag),getElementById:id=>nodes.get(id)||null,
 querySelector:selector=>selectors.get(selector)||null,querySelectorAll:selector=>selectors.get(selector)||[],addEventListener(){}};
function text(node,value){if(node)node.textContent=String(value);}
const dateLabel=String;
function flat(node){return node.textContent+' '+node.children.map(flat).join(' ');}
let calls=[], readCalls=0, navigation=[], responses=[], readError=null, pendingPost=null;
async function postJson(path){calls.push(path);if(pendingPost)return await pendingPost;const value=responses.shift();if(value instanceof Error)throw value;return value;}
async function loadReports(){readCalls++;if(readError)throw readError;}
function activateTab(tab,history){navigation.push({tab,history});}
'''
        result = subprocess.run(["node", "-e", prelude + setup + helper + "\n" + assertions], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def source_part(self, start, end):
        source = SOURCE.read_text()
        return source[source.index(start):source.index(end)]

    def test_schedule_labels_distinguish_saved_cadence_and_overdue_collection(self):
        helper = self.source_part("  function externalSchedulePresentation(", "  function renderWebsiteAuditOutcome(")
        self.run_node(helper, r'''
const now=Date.parse('2026-10-09T05:00:00Z');
const weekly={enabled:true,interval_hours:168,next_run_at:'2026-10-16T05:00:00Z'};
const original=JSON.stringify(weekly);
assert.equal(externalSchedulePresentation(weekly,now).label,'Weekly schedule saved');
assert.match(externalSchedulePresentation(weekly,now).detail,/Next scheduled collection/);
assert.doesNotMatch(externalSchedulePresentation(weekly,now).label,/Daily|active|running/);
assert.match(externalSchedulePresentation({...weekly,next_run_at:'2026-10-08T05:00:00Z'},now).detail,/Expected collection.*no later schedule update/);
assert.doesNotMatch(externalSchedulePresentation({...weekly,next_run_at:'2026-10-08T05:00:00Z'},now).detail,/Next scheduled/);
assert.equal(externalSchedulePresentation({...weekly,interval_hours:24},now).label,'Daily schedule saved');
assert.equal(externalSchedulePresentation({...weekly,enabled:false},now).label,'Automatic checks off');
for(const value of [null,{}, {...weekly,enabled:'true'},{...weekly,interval_hours:72}])assert.equal(externalSchedulePresentation(value,now).state,'unknown');
for(const next of [null,true,'invalid'])assert.match(externalSchedulePresentation({...weekly,next_run_at:next},now).detail,/not recorded/);
assert.equal(JSON.stringify(weekly),original);
const status=new Node(), detail=new Node(), note=new Node(), checkbox=new Node(), interval=new Node();
nodes.set('dns-schedule-status',status);nodes.set('dns-schedule-next-run',detail);nodes.set('dns-action-schedule',note);
selectors.set('[data-schedule-enabled="dns"]',checkbox);selectors.set('[data-schedule-interval="dns"]',interval);
renderExternalCheckSchedule('dns',weekly);
assert.match(note.textContent,/Weekly schedule saved/);assert.equal(checkbox.checked,true);assert.equal(interval.value,'168');
assert.equal(status.className,'check-status');assert.equal(interval.disabled,false);
renderExternalCheckSchedule('dns',null);
assert.equal(status.textContent,'Monitoring schedule unknown');assert.equal(checkbox.checked,true);assert.equal(interval.value,'168');
''')

    def test_action_bar_opens_existing_schedule_without_writes_or_duplicate_reads(self):
        helper = self.source_part("  function buildCheckActionBar(", '  ["dns", "web"].forEach(buildCheckActionBar);')
        for role in ("admin", "user"):
            with self.subTest(role=role):
                self.run_node(helper, r'''
const intro=new Node(), panel=new Node(), details=new Node();details.summary=new Node('summary');
panel.querySelector=selector=>selector==='.page-intro'?intro:null;
nodes.set('tab-dns',panel);nodes.set('dns-monitoring-details',details);
buildCheckActionBar('dns');const bar=intro.afterNodes[0];
const buttons=bar.children;
assert.equal(buttons.filter(b=>b.dataset.generateReport==='').length,1);
assert.equal(buttons.find(b=>b.dataset.generateReport==='').textContent,'Create PDF report');
assert.equal(bar.afterNodes[0].id,'dns-action-schedule');assert.match(bar.afterNodes[0].textContent,/Loading saved/);
assert.equal(bar.afterNodes[1].attrs.role,'status');
if(role==='admin'){
 assert.equal(buttons.length,3);assert.equal(buttons[0].dataset.runExternalCheck,'dns');
 assert.equal(buttons[1].attrs['aria-controls'],'dns-monitoring-details');
 buttons[1].events.click();assert.equal(details.open,true);assert.equal(document.activeElement,details.summary);assert.deepEqual(details.summary.scrolled,{block:'center'});
}else{assert.equal(buttons.length,1);}
assert.equal(calls.length,0);assert.equal(readCalls,0);
''', setup="const role=" + repr(role) + ";\n")

    def test_failed_saved_read_labels_cached_schedule_and_retry_restores_it(self):
        helper = self.source_part("  function externalSchedulePresentation(", "  function renderWebsiteAuditOutcome(")
        helper += self.source_part("  function updateSavedCheckStatus(", "  function savedCheckHistory(")
        self.run_node(helper, r'''
const schedule={enabled:true,interval_hours:168,next_run_at:'2026-10-16T05:00:00Z'};
const note=new Node(),warning=new Node(),button=new Node('button');
nodes.set('dns-action-schedule',note);nodes.set('dns-history-status',warning);selectors.set('[data-refresh-check="dns"]',button);
renderExternalCheckSchedule('dns',schedule);assert.match(note.textContent,/^Weekly schedule saved/);
const state={loaded:true,loading:false,error:'Offline',body:{schedule}};
document.activeElement=button;updateSavedCheckStatus('dns',state,button);
assert.match(note.textContent,/^Last observed: Weekly schedule saved/);assert.match(warning.textContent,/Previously loaded evidence/);
assert.equal(button.textContent,'Retry saved evidence');assert.equal(document.activeElement,button);
state.loading=true;updateSavedCheckStatus('dns',state,button);assert.match(note.textContent,/^Last observed/);
renderExternalCheckSchedule('dns',schedule);state.error=null;state.loading=false;updateSavedCheckStatus('dns',state,button);
assert.match(note.textContent,/^Weekly schedule saved/);assert.equal(warning.textContent,'');assert.equal(button.textContent,'Refresh saved evidence');
updateSavedCheckStatus('dns',{loaded:false,loading:false,error:'Offline',body:null},button);
assert.match(note.textContent,/Monitoring schedule unavailable/);
''')

    def report_helper(self):
        return self.source_part("  var externalReportCreationBusy = false;", "  function buildCheckActionBar(")

    def test_schedule_save_preserves_focus_and_guards_repeat_requests_and_failure(self):
        helper = self.source_part('  document.querySelectorAll("[data-save-schedule]")', '  var workspaceDialog =')
        self.run_node(helper, r'''
(async()=>{
document.activeElement=button;let resolve;pendingSave=new Promise(done=>resolve=done);
const first=button.events.click();assert.equal(button.disabled,false);assert.equal(button.attrs['aria-disabled'],'true');
assert.equal(document.activeElement,button);await button.events.click();assert.equal(saves.length,1);
resolve({enabled:true,interval_hours:168});await first;
assert.equal(document.activeElement,button);assert.equal(button.attrs['aria-disabled'],'false');assert.equal(button.attrs['aria-busy'],'false');
assert.equal(button.textContent,'Save schedule');assert.equal(rendered.interval_hours,168);assert.deepEqual(saves[0].payload,{enabled:true,interval_hours:168});
pendingSave=Promise.reject(new Error('Save unavailable'));await button.events.click();
assert.equal(document.activeElement,button);assert.equal(button.attrs['aria-disabled'],'false');assert.equal(interval.value,'168');
assert.equal(nodes.get('dns-schedule-status').textContent,'Save unavailable');assert.equal(saves.length,2);
button.disabled=true;await button.events.click();assert.equal(saves.length,2);
})().catch(error=>{console.error(error);process.exitCode=1;});
''', setup=r'''
const button=new Node('button');button.textContent='Save schedule';button.dataset.saveSchedule='dns';
const checkbox=new Node('input');checkbox.checked=true;const interval=new Node('select');interval.value='168';
selectors.set('[data-save-schedule]',[button]);selectors.set('[data-schedule-enabled="dns"]',checkbox);selectors.set('[data-schedule-interval="dns"]',interval);
nodes.set('dns-schedule-status',new Node());let saves=[],pendingSave=null,rendered=null;
async function requestJson(path,method,payload){saves.push({path,method,payload});return await pendingSave;}
function renderExternalCheckSchedule(type,saved){rendered=saved;}async function loadAuditLog(){}
''')

    def test_report_creation_has_one_request_then_library_progress_without_download_polling(self):
        self.run_node(self.report_helper(), r'''
(async()=>{
const button=new Node('button');button.textContent='Create PDF report';button.dataset.reportFeedback='dns-action-feedback';
const other=new Node('button'), source=new Node(), library=new Node();
nodes.set('dns-action-feedback',source);nodes.set('domain-report-feedback',library);selectors.set('[data-generate-report]',[button,other]);
let resolve;pendingPost=new Promise(done=>resolve=done);
const first=queueExternalPostureReport(button);assert.equal(button.disabled,true);assert.equal(other.disabled,true);
await queueExternalPostureReport(other);assert.equal(calls.length,1);assert.equal(readCalls,0);
resolve({id:72});await first;
assert.deepEqual(calls,['/api/reports/external-posture']);assert.equal(readCalls,1);assert.deepEqual(navigation,[{tab:'reports',history:true}]);
assert.match(library.textContent,/Report #72 queued/);assert.match(library.textContent,/progress.*finished download/);
assert.equal(source.textContent,library.textContent);assert.equal(button.textContent,'Create PDF report');assert.equal(button.disabled,false);assert.equal(other.disabled,false);assert.equal(externalReportCreationBusy,false);
})().catch(error=>{console.error(error);process.exitCode=1;});
''')

    def test_report_request_failure_stays_on_topic_and_releases_controls_for_retry(self):
        self.run_node(self.report_helper(), r'''
(async()=>{
const button=new Node('button');button.textContent='Create PDF report';button.dataset.reportFeedback='web-action-feedback';
const source=new Node();nodes.set('web-action-feedback',source);selectors.set('[data-generate-report]',[button]);
responses.push(new Error('Could not queue report'));await queueExternalPostureReport(button);
assert.equal(source.textContent,'Could not queue report');assert.equal(navigation.length,0);assert.equal(readCalls,0);assert.equal(button.disabled,false);
responses.push({id:73});await queueExternalPostureReport(button);assert.equal(calls.length,2);assert.match(source.textContent,/Report #73 queued/);
})().catch(error=>{console.error(error);process.exitCode=1;});
''')

    def test_report_history_failure_preserves_successful_creation_receipt(self):
        self.run_node(self.report_helper(), r'''
(async()=>{
const button=new Node('button');button.dataset.reportFeedback='dns-action-feedback';const source=new Node(),library=new Node();
nodes.set('dns-action-feedback',source);nodes.set('domain-report-feedback',library);selectors.set('[data-generate-report]',[button]);
responses.push({id:74});readError=new Error('Read failed');await queueExternalPostureReport(button);
assert.equal(calls.length,1);assert.match(library.textContent,/Report #74 queued/);assert.match(library.textContent,/Refresh reports to retry/);
assert.doesNotMatch(library.textContent,/generation failed|could not be generated/);assert.equal(source.textContent,library.textContent);assert.equal(button.disabled,false);
})().catch(error=>{console.error(error);process.exitCode=1;});
''')

    def test_check_action_uses_shared_collector_and_separate_feedback(self):
        helper = self.source_part('  document.querySelectorAll("[data-run-external-check]")', '  document.querySelectorAll("[data-schedule-enabled]")')
        self.run_node(helper, r'''
(async()=>{
const last=nodes.get('dns-check-last-run');last.textContent='Last checked yesterday';
responses.push(new Error('Collection unavailable'));await button.events.click();
assert.equal(last.textContent,'Last checked yesterday');assert.equal(nodes.get('dns-action-feedback').textContent,'Collection unavailable');
assert.equal(button.disabled,false);assert.equal(button.textContent,'Check now');assert.equal(refreshCount,0);
responses.push({id:48,status:'completed_with_warnings'});await button.events.click();
assert.deepEqual(calls,['/api/external-checks/dns/run','/api/external-checks/dns/run']);assert.equal(refreshCount,1);assert.equal(notices.length,1);
assert.match(nodes.get('dns-action-feedback').textContent,/Check #48 recorded: completed with warnings/);
button.disabled=true;await button.events.click();assert.equal(calls.length,2);
})().catch(error=>{console.error(error);process.exitCode=1;});
''', setup=r'''
const button=new Node('button');button.dataset.runExternalCheck='dns';button.textContent='Check now';
selectors.set('[data-run-external-check]',[button]);nodes.set('dns-check-last-run',new Node());nodes.set('dns-action-feedback',new Node());
let refreshCount=0,notices=[];async function loadExternalCheck(){refreshCount++;}function notifyExternalCheck(body){notices.push(body);}async function loadAuditLog(){}
''')

    def test_template_retains_one_editor_and_collection_attempt_without_duplicate_action(self):
        source = SOURCE.read_text()
        template = (ROOT / "src/daedalus/templates/dashboard.html").read_text()
        external = template.split('data-external-check="{{ key }}">', 1)[1].split("{% elif key == 'google-admin' %}", 1)[0]
        self.assertNotIn("data-run-external-check", external)
        self.assertIn('id="{{ key }}-monitoring-details"', external)
        self.assertIn('<summary>Latest collection attempt</summary>', external)
        self.assertIn('id="domain-report-feedback"', template)
        bar = self.source_part("  function buildCheckActionBar(", '  ["dns", "web"].forEach(buildCheckActionBar);')
        self.assertNotIn("fetch(", bar)
        self.assertNotIn("postJson(", bar)
        self.assertNotIn("setTimeout", bar)
        self.assertNotIn("Daily check: on", source)


if __name__ == "__main__":
    unittest.main()
