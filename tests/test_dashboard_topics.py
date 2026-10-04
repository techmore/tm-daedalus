import json
from pathlib import Path
import shutil
import subprocess
import unittest


class DashboardTopicTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'), 'Node.js required')
    def test_report_status_counts_only_ready_downloads_as_available(self):
        source = (Path(__file__).parents[1] / 'src/daedalus/static/js/dashboard.js').read_text()
        helper = source[source.index('  function reportJobStatusSummary('):source.index('  function renderReportJobs(')]
        script = "const assert=require('node:assert/strict');" + helper + """
assert.equal(reportJobStatusSummary([]), '0 PDF(s) ready.');
assert.equal(reportJobStatusSummary([{status:'completed',download_url:'/pdf'},{status:'queued'},{status:'running'},{status:'failed'},{status:'completed'},{status:'unknown'}]), '1 PDF(s) ready · 2 in progress · 1 failed · 2 without a ready download.');
assert.equal(reportJobStatusSummary([{status:'failed'}]), '0 PDF(s) ready · 1 failed.');
"""
        result = subprocess.run(['node','-e',script],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_report_library_includes_all_topics_before_creation(self):
        root = Path(__file__).parents[1]
        template = (root / 'src/daedalus/templates/dashboard.html').read_text()
        self.assertLess(template.index('id="posture-report-job-list"'), template.index('data-generate-report'))
        source = (root / 'src/daedalus/static/js/dashboard.js').read_text()
        self.assertIn('renderReportJobs(reports, "posture-report-job-list", "posture-report-library-status", ["meraki_security", "cis_endpoint"])', source)
        self.assertIn('"posture-report-job-list", "meraki-report-job-list"', source)

    def test_endpoint_topic_groups_results_and_changes_before_setup(self):
        template = (Path(__file__).parents[1] / 'src/daedalus/templates/dashboard.html').read_text()
        section = template.split('<section class="cis-workspace">', 1)[1].split("{% elif key in ['dns', 'web'] %}", 1)[0]
        self.assertLess(section.index('id="cis-report-list"'), section.index('id="cis-change-list"'))
        self.assertLess(section.index('id="cis-change-list"'), section.index('id="cis-device-list"'))
        self.assertLess(section.index('id="cis-device-list"'), section.index('<summary>How endpoint check-ins work'))
        self.assertLess(section.index('id="cis-device-list"'), section.index('<summary>Profiles &amp; device setup'))

    def test_external_topics_lead_with_assessment_and_changes(self):
        template = (Path(__file__).parents[1] / 'src/daedalus/templates/dashboard.html').read_text()
        section = template.split('data-external-check="{{ key }}">', 1)[1].split("{% elif key == 'reports' %}", 1)[0]
        self.assertLess(section.index('id="{{ key }}-priorities"'), section.index('data-run-external-check'))
        self.assertLess(section.index('id="{{ key }}-check-changes"'), section.index('id="dns-record-grid"'))
        self.assertIn('<details class="topic-secondary"><summary>Assessment scope &amp; limitations</summary>', section)

    @unittest.skipUnless(shutil.which('node'), 'Node.js required')
    def test_scanner_card_controls_preserve_open_state_and_scope_guard(self):
        source = (Path(__file__).parents[1] / 'src/daedalus/static/js/dashboard.js').read_text()
        renderer = source[source.index('  function makeAgentCard('):source.index('  function makeEventRow(')]
        script = """const assert=require('node:assert/strict');
class Node {constructor(tag){this.tag=tag;this.children=[];this.dataset={};this.style={};this.events={};this.open=false;}
get childNodes(){return this.children;}
append(...nodes){for(const n of nodes){if(n.parent)n.parent.children=n.parent.children.filter(x=>x!==n);n.parent=this;this.children.push(n);}}
setAttribute(){} addEventListener(name,callback){this.events[name]=callback;}}
const document={createElement:tag=>new Node(tag)};
const role='admin',controlsEnabled=true;
const openScannerControls=new Set(),openCommandHistories=new Set(),openScanHistories=new Set(),openComparisonHistories=new Set();
const scannerNetworkInputs=new Map(),scannerScopeFeedback=new Map(),scannerTargets=new Map(),scannerSkipDiscovery=new Map();
function canViewScannerCommandHistory(){return true;} function supportsMacOSUpdateCheck(){return false;}
function flatten(n){return [n,...n.children.flatMap(flatten)];}
""" + renderer + """
const agent={id:2,name:'<script>literal</script>',status:'online',enabled:true,authorized_networks:[],command_protocol_version:3,nmapui_ready:true};
let card=makeAgentCard(agent,'example.test');
let controls=card.children.find(n=>n.className==='topic-secondary scanner-controls');
assert.equal(controls.open,false);
assert.equal(flatten(controls).find(n=>n.dataset.command==='start_scan').disabled,true);
assert.ok(card.children.indexOf(card.children.find(n=>n.className==='agent-command-history agent-run-history'))<card.children.indexOf(controls));
assert.equal(card.children.find(n=>n.tag==='h3').textContent,'<script>literal</script>');
controls.open=true;controls.events.toggle();
card=makeAgentCard({...agent,authorized_networks:['10.0.0.0/24']},'example.test');
controls=card.children.find(n=>n.className==='topic-secondary scanner-controls');
assert.equal(controls.open,true);
assert.equal(flatten(controls).find(n=>n.dataset.command==='start_scan').disabled,false);
controls.open=false;controls.events.toggle();assert.equal(openScannerControls.has(2),false);
"""
        result = subprocess.run(['node', '-e', script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_scanner_structure_keeps_evidence_before_controls(self):
        root = Path(__file__).parents[1]
        template = (root / 'src/daedalus/templates/dashboard.html').read_text()
        self.assertLess(template.index('id="scanner-assessment"'), template.index('id="agent-list"'))
        source = (root / 'src/daedalus/static/js/dashboard.js').read_text()
        self.assertIn('controlDetails.open = openScannerControls.has(agent.id)', source)
        self.assertIn('card.append(scanHistory, comparisonHistory);', source)
        self.assertIn('if (controlDetails.childNodes.length > 1) card.append(controlDetails);\n    if (history) card.append(history);', source)

    @unittest.skipUnless(shutil.which('node'), 'Node.js required')
    def test_scanner_coverage_excludes_revoked_nodes_and_requires_ready_evidence(self):
        source = (Path(__file__).parents[1] / 'src/daedalus/static/js/dashboard.js').read_text()
        helper = source[source.index('  function scannerCoverageMetrics('):source.index('  function renderScannerAssessment(')]
        script = "const assert=require('node:assert/strict');" + helper + """
assert.deepEqual(scannerCoverageMetrics([]),{enabled:0,online:0,ready:0,scoped:0});
assert.deepEqual(scannerCoverageMetrics([
 {status:'online',enabled:true,nmapui_ready:true,authorized_networks:[]},
 {status:'offline',enabled:true,nmapui_ready:true,authorized_networks:['10.0.0.0/24']},
 {status:'online',enabled:false,nmapui_ready:true,authorized_networks:['10.1.0.0/24']},
 {status:'online',enabled:true,nmapui_ready:null,authorized_networks:[]}
]),{enabled:3,online:2,ready:1,scoped:1});
"""
        result = subprocess.run(['node', '-e', script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which('node'), 'Node.js required')
    def test_endpoint_priority_metrics_keep_unknown_counts(self):
        source = (Path(__file__).parents[1] / 'src/daedalus/static/js/dashboard.js').read_text()
        helper = source[source.index('  function cisPriorityMetrics('):source.index('  function renderCISReports(')]
        script = "const assert=require('node:assert/strict');" + helper + """
const metrics=cisPriorityMetrics({summary:{fail:82,manual:19,error:17,score:23.38}},1);
assert.deepEqual(metrics.slice(0,3),[['82','Failed checks'],['19','Need manual review'],['17','Collection errors']]);
assert.equal(cisPriorityMetrics({summary:{score:'100'}},1)[0][0],'Unknown');
assert.equal(cisPriorityMetrics({summary:{score:'100'}},1)[3][0],'—');
assert.equal(cisPriorityMetrics(null,0)[0][0],'—');
"""
        result = subprocess.run(['node', '-e', script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_external_topics_put_assessment_before_records_and_controls(self):
        root = Path(__file__).parents[1]
        template = (root / 'src/daedalus/templates/dashboard.html').read_text()
        self.assertLess(template.index('id="{{ key }}-priority-title"'), template.index('id="dns-record-grid"'))
        self.assertLess(template.index('id="{{ key }}-priority-title"'), template.index('id="web-summary-grid"'))
        self.assertLess(template.index('id="{{ key }}-priority-title"'), template.index('<summary>Exposure findings'))
        source = (root / 'src/daedalus/static/js/dashboard.js').read_text()
        self.assertIn('grid.append(networkHeading, networkMetrics, mailHeading, summary)', source)
        self.assertIn('A lookup failed; review the saved evidence', source)

    @unittest.skipUnless(shutil.which('node'), 'Node.js required')
    def test_assessment_summaries_preserve_unknown_and_partial_coverage(self):
        source=(Path(__file__).parents[1]/'src/daedalus/static/js/dashboard.js').read_text()
        priority=source[source.index('  function renderTopicPriorities('):source.index('  function renderDnsSnapshot(')]
        outcome=source[source.index('  function renderWebsiteAuditOutcome('):source.index('  function renderActiveExposure(')]
        script='''const assert=require('node:assert/strict');
class Node { constructor(){this.children=[];this.textContent='';} replaceChildren(){this.children=[];} append(...items){this.children.push(...items);} }
const nodes={}; const document={getElementById:id=>nodes[id]||(nodes[id]=new Node()),createElement:()=>new Node()};
function appendEmpty(node,message){node.textContent=message;}
function text(node,message){node.textContent=message;}
function dateLabel(value){return value;}
function emailAuthenticationMetrics(){return [{label:'SPF',value:'Unknown',detail:'Lookup unavailable',state:'neutral'}];}
function flatten(node){return node.textContent+' '+node.children.map(flatten).join(' ');}
'''+priority+outcome+'''
renderTopicPriorities('dns',{resolver_errors:{MX:'timeout'}});
assert.match(flatten(nodes['dns-priorities']),/remain unknown/);
renderTopicPriorities('web',{http_status:200,tls:{valid_until:'2100-01-01'},security_headers:{}});
assert.match(flatten(nodes['web-priorities']),/evidence is unavailable/);
assert.doesNotMatch(flatten(nodes['web-priorities']),/No response, certificate/);
renderWebsiteAuditOutcome('audit','Audit',{status:'completed_with_warnings',snapshot:{findings:[],coverage_complete:false}});
assert.match(nodes.audit.textContent,/absence does not establish resolution/);
renderWebsiteAuditOutcome('audit','Audit',{status:'failed'});
assert.match(nodes.audit.textContent,/latest attempt failed/);
assert.doesNotMatch(nodes.audit.textContent,/0 observation/);
'''
        result=subprocess.run(['node','-e',script],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)

    @unittest.skipUnless(shutil.which('node'), 'Node.js required')
    def test_audit_review_keeps_previous_completed_evidence_and_groups_metadata(self):
        source=(Path(__file__).parents[1]/'src/daedalus/static/js/dashboard.js').read_text()
        renderer=source[source.index('  function niktoObservationGroup('):source.index('  async function loadNikto(')]
        script='''const assert=require('node:assert/strict');
class Node { constructor(tag){this.tag=tag;this.children=[];this.textContent='';} replaceChildren(){this.children=[];} append(...items){this.children.push(...items);} }
const host=new Node('div'); const document={getElementById:()=>host,createElement:tag=>new Node(tag)};
function appendEmpty(node,message){node.textContent=message;}
function dateLabel(value){return value;}
function flatten(node){return node.textContent+' '+node.children.map(flatten).join(' ');}
'''+renderer+'''
const completed={id:43,status:'completed_with_warnings',completed_at:'saved-time',snapshot:{findings:[
{test_id:'013587',method:'GET',path:'/',description:'Missing header'},
{test_id:'000287',method:'GET',path:'/',description:'Wildcard CORS'},
{test_id:'999100',method:'GET',path:'/',description:'Cache metadata'}]}};
const frozen=JSON.stringify(completed);
renderNiktoReview([{id:46,status:'running'},completed]);
assert.match(flatten(host),/run #43/);
assert.match(flatten(host),/Policy review/);
assert.match(flatten(host),/Needs application context/);
assert.match(flatten(host),/not vulnerability severity ratings/);
assert.equal(host.children.find(n=>n.tag==='details').children[0].textContent,'Infrastructure information · 1');
assert.equal(JSON.stringify(completed),frozen);
assert.equal(niktoObservationGroup({test_id:'unknown'}),'Needs application context');
renderNiktoReview([{id:46,status:'failed'}]);
assert.match(flatten(host),/No completed deeper audit/);
'''
        result=subprocess.run(['node','-e',script],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)

    @unittest.skipUnless(shutil.which('node'), 'Node.js required')
    def test_overview_rejects_stale_responses_and_preserves_keyboard_focus(self):
        source=(Path(__file__).parents[1]/'src/daedalus/static/js/dashboard.js').read_text()
        renderer=source[source.index('  async function loadWorkspacePosture('):source.index('  function refresh(force)')]
        script='''const assert=require('node:assert/strict');
let focused=null;
class Node { constructor(){this.children=[];this.textContent='';this.dataset={};this.events={};}
replaceChildren(){this.children=[];} append(...items){this.children.push(...items);}
contains(node){return this.children.includes(node);} addEventListener(name,cb){this.events[name]=cb;}
querySelector(){return this.children.find(n=>n.dataset.postureKey==='dns');}
focus(){focused=this.dataset.postureKey;document.activeElement=this;}}
const host=new Node(); const document={activeElement:null,getElementById:()=>host,createElement:()=>new Node()};
let postureRequestSequence=0; const orgId='1'; const requests=[];
const fetch=()=>new Promise(resolve=>requests.push(resolve));
function dateLabel(value){return value;} function appendEmpty(node,value){node.textContent=value;}
let opened=null; function activateTab(key){opened=key;}
const response=(summary)=>({ok:true,json:async()=>({areas:[{key:'dns',title:'DNS',state:'not_assessed',summary,updated_at:null}]})});
'''+renderer+'''
(async()=>{
const first=loadWorkspacePosture();requests.shift()(response('Initial'));await first;
document.activeElement=host.children[0];
const old=loadWorkspacePosture();const current=loadWorkspacePosture();
requests[1](response('<script>new evidence</script>'));await current;
requests[0](response('Stale evidence'));await old;
assert.equal(host.children[0].children[2].textContent,'<script>new evidence</script>');
assert.equal(host.children[0].children[1].textContent,'Not assessed');
assert.equal(focused,'dns');
host.children[0].events.click();assert.equal(opened,'dns');
})().catch(error=>{console.error(error);process.exitCode=1;});
'''
        result=subprocess.run(['node','-e',script],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)

    @unittest.skipUnless(shutil.which('node'), 'Node.js required')
    def test_meraki_summary_observations_are_literal_bounded_and_shared(self):
        source=(Path(__file__).parents[1]/'src/daedalus/static/js/dashboard.js').read_text()
        code=source[source.index('  function fetchMerakiDashboardDetails('):source.index('  async function loadMerakiDashboardDetails(')]
        script="""const assert=require('node:assert/strict');
class Node {constructor(){this.children=[];this.textContent='';this.isConnected=true;} replaceChildren(){this.children=[];this.textContent='';} append(...items){this.children.push(...items);}}
const document={createElement:()=>new Node()};
const merakiDashboardDetailCache=new Map(); let calls=0;
let findings=[{status:'Review',title:'<script>literal</script>',detail:'Saved review detail'},{status:'Coverage warning',title:'Not a review item'}];
async function fetch(){calls++;return {ok:true,json:async()=>({findings})};}
function appendEmpty(node,message){const child=new Node();child.textContent=message;node.append(child);}
function flatten(node){return node.textContent+' '+node.children.map(flatten).join(' ');}
"""+code+"""
(async()=>{
const host=new Node();await loadMerakiSummaryObservations(31,host);
assert.ok(flatten(host).includes("<script>literal</script>"));assert.doesNotMatch(flatten(host),/Not a review item/);
const second=new Node();await loadMerakiSummaryObservations(31,second);assert.equal(calls,1);
findings=Array.from({length:9},()=>({status:'Review',title:'Review row'}));await loadMerakiSummaryObservations(32,host);
assert.equal(host.children.filter(x=>x.className==='audit-policy-card').length,5);
assert.match(flatten(host),/Additional review observations/);
findings=undefined;await loadMerakiSummaryObservations(33,host);assert.match(flatten(host),/evidence is unavailable/);
findings=[];await loadMerakiSummaryObservations(34,host);assert.match(flatten(host),/No saved observations/);
const detached=new Node();detached.isConnected=false;await loadMerakiSummaryObservations(34,detached);assert.equal(detached.children.length,0);
})().catch(error=>{console.error(error);process.exitCode=1;});
"""
        result=subprocess.run(['node','-e',script],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
