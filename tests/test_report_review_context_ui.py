from pathlib import Path
import shutil
import subprocess
import unittest

ROOT=Path(__file__).parents[1]


@unittest.skipUnless(shutil.which('node'), 'Node.js required')
class ReportReviewContextUITests(unittest.TestCase):
    def run_ui(self, scenario):
        source=(ROOT/'src/daedalus/static/js/dashboard.js').read_text()
        renderer=source[source.index('  function reportJobStatusSummary('):source.index('  var driveState =',source.index('  function reportJobStatusSummary('))]
        matching=source[source.index('  function matchingReportJobs('):source.index('  function addMerakiDetailList(')]
        fixture=(ROOT/'tests/cis_workspace_dom_fixture.js').read_text().split("const form=document.getElementById('cis-profile-form')")[0]
        fixture=fixture.replace('function matches(n,selector){','function matches(n,selector){\n if(selector.includes(","))return selector.split(",").some(s=>matches(n,s.trim()));\n if(/^[a-z]+$/.test(selector))return n.tag===selector;')
        script="const assert=require('node:assert/strict');\n"+fixture+r'''
Node.prototype.closest=function(selector){return matches(this,selector)?this:this.parentElement?.closest(selector)||null;};
Node.prototype.insertBefore=function(node,reference){if(node.parentElement){const rows=node.parentElement.children;rows.splice(rows.indexOf(node),1);}node.parentElement=this;this.children.splice(reference?this.children.indexOf(reference):this.children.length,0,node);};
// Model native focus loss when a node is moved or removed, so restoration is exercised.
const nativeAppend=Node.prototype.append,nativeRemove=Node.prototype.remove,nativeInsert=Node.prototype.insertBefore;
Node.prototype.append=function(...nodes){for(const node of nodes)if(node.parentElement&&node.contains(document.activeElement))document.activeElement=document.body;nativeAppend.apply(this,nodes);};
Node.prototype.remove=function(){if(this.contains(document.activeElement))document.activeElement=document.body;nativeRemove.call(this);};
Node.prototype.insertBefore=function(node,reference){if(node.contains(document.activeElement))document.activeElement=document.body;nativeInsert.call(this,node,reference);};
let driveState=null,detailReads=[],summaryReads=[],writes=[];
const openMerakiDashboardDetails=new Set();
const dateLabel=String,text=(node,value)=>node.textContent=value;
const appendEmpty=(container,value)=>{const node=new Node('p');node.textContent=value;container.append(node);};
const makeAuditMetric=(label,value)=>{const node=new Node('div');node.textContent=label+' '+value;return node;};
async function loadMerakiSummaryObservations(id,container){summaryReads.push({id,container});container.textContent='Saved network observations';}
async function loadMerakiDashboardDetails(id,container){detailReads.push({id,container});container.dataset.loaded='true';const nested=new Node('details'),summary=new Node('summary'),link=new Node('a');nested.className='saved-subsection';summary.textContent='Saved topology';link.textContent='Official purchase link';link.href='https://store.ui.com/fixture';nested.append(summary,link);container.append(nested);}
let postJson=async(path)=>{writes.push(path);return {id:"saved-fixture"};};const loadReports=async()=>{};
for(const id of ['meraki-report-job-list','meraki-report-library-status','meraki-current-summary','scanner-report-job-list','scanner-report-library-status']){const node=document.getElementById(id);node.id=id;document.body.append(node);}
const list=document.getElementById('meraki-report-job-list'),overview=document.getElementById('meraki-current-summary');
const controls=document.getElementById(list.id+'-history-controls'),refresh=new Node('button');refresh.dataset.historyRefresh='true';controls.append(refresh);document.body.append(controls);
function job(id=64,type='meraki_security'){return {id,report_type:type,status:'completed',domain:'fixture.example',actor:'Owner',created_at:'2026-10-09T01:00:00Z',completed_at:'2026-10-09T02:00:00Z',stage:'PDF ready',size_bytes:1234,download_url:'/api/reports/'+id+'/download',meraki_snapshot_url:type==='meraki_security'?'/api/meraki/reports/'+id+'/snapshot':null,meraki_summary:{review_observation_count:3,security_controls_unavailable:1,device_count:264,network_count:6}};}
const render=(rows,latest)=>renderReportJobs(rows,list.id,'meraki-report-library-status','meraki_security',latest);
async function openReport(){const card=list.children[0],details=card.querySelector('.meraki-report-details');details.open=true;await details.emit('toggle');const nested=details.querySelector('.saved-subsection');nested.open=true;const link=nested.querySelector('a');link.focus();return {card,details,nested,link};}
'''+matching+renderer+'\n(async()=>{\n'+scenario+'\n})().catch(e=>{console.error(e);process.exit(1);});'
        result=subprocess.run(['node','-'],input=script,text=True,capture_output=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_unchanged_refresh_keeps_actual_report_nodes_nested_review_and_focus(self):
        self.run_ui(r'''
render([job()]);const saved=await openReport(),observation=summaryReads[0].container,status=document.getElementById('meraki-report-library-status');const statusWrites=status.textWrites;
render([job()]);assert.equal(list.children[0],saved.card);assert.equal(saved.details.open,true);assert.equal(saved.nested.open,true);
assert.equal(document.activeElement,saved.link);assert.equal(summaryReads.length,1);assert.equal(detailReads.length,1);
assert.equal(overview.children.at(-1),observation);assert.equal(status.textWrites,statusWrites);assert.equal(writes.length,0);
''')

    def test_new_report_preserves_older_open_review_and_updates_current_assessment(self):
        self.run_ui(r'''
render([job()]);const saved=await openReport();render([job(65),job()]);
assert.equal(list.children[1],saved.card);assert.equal(saved.nested.open,true);assert.equal(document.activeElement,saved.link);
assert.deepEqual(summaryReads.map(x=>x.id),[64,65]);assert.equal(detailReads.length,1);
assert.ok(overview.textContent.includes('Latest completed report'));assert.equal(writes.length,0);
''')

    def test_changed_metadata_reuses_saved_disclosure_and_inflight_evidence_container(self):
        self.run_ui(r'''
render([job()]);const saved=await openReport();const changed={...job(),stage:'Saved in Drive',drive_link:'https://drive.google.com/fixture'};
render([changed]);assert.notEqual(list.children[0],saved.card);assert.equal(list.children[0].querySelector('.meraki-report-details'),saved.details);
assert.equal(saved.nested.open,true);assert.equal(document.activeElement,saved.link);assert.equal(detailReads.length,1);
assert.equal(summaryReads.length,1);assert.ok(list.children[0].textContent.includes('Saved in Drive'));
''')

    def test_focused_download_is_restored_to_same_action_on_replaced_card(self):
        self.run_ui(r'''
render([job()]);const download=list.children[0].querySelector('[data-report-action="download"]');download.focus();
render([{...job(),size_bytes:4321}]);const replacement=list.children[0].querySelector('[data-report-action="download"]');
assert.notEqual(replacement,download);assert.equal(document.activeElement,replacement);assert.equal(replacement.href,download.href);
''')

    def test_removed_focused_report_moves_to_fixed_refresh_control_including_empty_history(self):
        self.run_ui(r'''
render([job()]);await openReport();render([job(65)]);assert.equal(document.activeElement,refresh);
await openReport();render([]);assert.equal(document.activeElement,refresh);assert.ok(list.textContent.includes('No Meraki reports'));
''')

    def test_changed_current_summary_moves_its_removed_control_focus_to_new_evidence(self):
        self.run_ui(r'''
render([job()]);const control=new Node('button');summaryReads[0].container.append(control);control.focus();
render([job(65),job()]);assert.equal(document.activeElement,overview);assert.equal(overview.tabIndex,-1);assert.equal(summaryReads.at(-1).id,65);
''')

    def test_drive_presentation_changes_controls_without_losing_open_meraki_details(self):
        self.run_ui(r'''
render([job()]);const saved=await openReport();driveState={connected:true,is_admin:true};render([job()]);
assert.equal(list.children[0].querySelector('.meraki-report-details'),saved.details);assert.equal(saved.nested.open,true);
assert.ok(list.children[0].querySelector('[data-report-action="save-drive"]'));assert.equal(document.activeElement,saved.link);
driveState={connected:true,is_admin:false};render([job()]);assert.equal(list.children[0].querySelector('[data-report-action="save-drive"]'),null);
assert.equal(detailReads.length,1);assert.equal(writes.length,0);
''')

    def test_drive_save_outcome_survives_unchanged_read_without_a_provider_link(self):
        self.run_ui(r'''
driveState={connected:true,is_admin:true};render([job()]);const button=list.children[0].querySelector('[data-report-action="save-drive"]');button.focus();
await button.click();assert.equal(button.textContent,'Saved to Drive');assert.equal(button.disabled,true);
render([job()]);assert.equal(list.children[0].querySelector('[data-report-action="save-drive"]'),button);
assert.equal(button.textContent,'Saved to Drive');assert.equal(document.activeElement,button);assert.equal(writes.length,1);
''')

    def test_failed_drive_save_retains_retry_feedback_through_a_history_refresh(self):
        self.run_ui(r'''
driveState={connected:true,is_admin:true};render([job()]);const button=list.children[0].querySelector('[data-report-action="save-drive"]');button.focus();
postJson=async()=>{throw new Error('Provider unavailable');};await button.click();render([job()]);
assert.equal(button.textContent,'Retry');assert.equal(button.disabled,false);assert.equal(document.activeElement,button);
postJson=async()=>({id:'saved-fixture'});await button.click();assert.equal(button.textContent,'Saved to Drive');
''')

    def test_all_report_topics_reuse_unchanged_cards_and_running_progress_updates(self):
        self.run_ui(r'''
for(const type of ['external_posture','scanner_results','cis_endpoint','google_admin_security']){
 const row=job(70,type);renderReportJobs([row],list.id,'meraki-report-library-status',type);
 const card=list.children[0],download=card.querySelector('[data-report-action="download"]');download.focus();
 renderReportJobs([row],list.id,'meraki-report-library-status',type);assert.equal(list.children[0],card);assert.equal(document.activeElement,download);
}
const waiting={...job(80,'scanner_results'),status:'running',progress:20,download_url:null,stage:'Rendering'};
renderReportJobs([waiting],list.id,'meraki-report-library-status','scanner_results');const before=list.children[0];
assert.equal(before.querySelector('.report-progress-track').getAttribute('aria-valuenow'),'20');
renderReportJobs([{...waiting,progress:60}],list.id,'meraki-report-library-status','scanner_results');
assert.notEqual(list.children[0],before);assert.equal(list.children[0].querySelector('.report-progress-track').getAttribute('aria-valuenow'),'60');
renderReportJobs([job(80,'scanner_results')],list.id,'meraki-report-library-status','scanner_results');
assert.equal(list.children[0].querySelector('.report-progress-track'),null);assert.ok(list.children[0].querySelector('[data-report-action="download"]'));
''')

    def test_latest_completed_outside_history_page_remains_stable_across_failed_attempts(self):
        self.run_ui(r'''
const failed={...job(90),status:'failed',download_url:null,meraki_snapshot_url:null,stage:'Collection unavailable'};
render([failed],job());const observation=summaryReads[0].container;observation.focus();
render([{...failed,error_summary:'Attempt failed'}],job());assert.equal(summaryReads.length,1);
assert.equal(overview.children.at(-1),observation);assert.equal(document.activeElement,observation);
''')
