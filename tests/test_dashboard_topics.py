import json
from pathlib import Path
import shutil
import subprocess
import unittest


class DashboardTopicTests(unittest.TestCase):
    def test_audit_tables_expose_named_keyboard_scroll_regions(self):
        source = (Path(__file__).parents[1] / 'src/daedalus/static/js/dashboard.js').read_text()
        helper = source[source.index('  function makeAuditTable('):source.index('  function rowsForRecord(')]
        self.assertIn('scroller.tabIndex = 0;', helper)
        self.assertIn('scroller.setAttribute("role", "region");', helper)
        self.assertIn('title + "; scroll horizontally to view all columns"', helper)

    def test_empty_change_history_does_not_imply_only_one_assessment(self):
        source = (Path(__file__).parents[1] / 'src/daedalus/static/js/dashboard.js').read_text()
        self.assertIn('No confirmed changes are recorded in the saved assessment history.', source)
        self.assertIn('unavailable checks cannot establish changes.', source)
        self.assertNotIn('No changes have been detected yet; the first successful run is the baseline.', source)

    @unittest.skipUnless(shutil.which('node'), 'Node.js required')
    def test_mail_route_summary_distinguishes_unknown_and_null_mx(self):
        source = (Path(__file__).parents[1] / 'src/daedalus/static/js/dashboard.js').read_text()
        helper = source[source.index('  function mailRouteMetric('):source.index('  function renderTopicPriorities(')]
        script = "const assert=require('node:assert/strict');" + helper + """
assert.equal(mailRouteMetric({},{}).value,'Unknown');
assert.equal(mailRouteMetric({MX:null},{}).value,'Unknown');
for (const MX of [[null], [''], ['  '], [false], [1], [{}], ['10 mx.example.', null]]) {
  assert.equal(mailRouteMetric({MX},{}).value,'Unknown');
  assert.equal(mailRouteMetric({MX},{}).state,'neutral');
}
assert.equal(mailRouteMetric({MX:['0 .']},{MX:'Timeout'}).value,'Lookup failed');
assert.equal(mailRouteMetric({MX:[]},{}).value,'0');
assert.match(mailRouteMetric({MX:[]},{}).detail,/fallback was not evaluated/);
assert.equal(mailRouteMetric({MX:['0 .']},{}).value,'No mail');
assert.equal(mailRouteMetric({MX:['0 .','10 mx.example.']},{}).value,'Review');
assert.equal(mailRouteMetric({MX:['10 mx.example.']},{}).value,'1');
assert.match(mailRouteMetric({MX:['10 mx.example.']},{}).detail,/delivery was not tested/);
"""
        result = subprocess.run(['node', '-e', script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which('node'), 'Node.js required')
    def test_dns_lookup_recovery_copy_distinguishes_availability_from_empty_records(self):
        source = (Path(__file__).parents[1] / 'src/daedalus/static/js/dashboard.js').read_text()
        helper = source[source.index('  function displayCheckValue('):source.index('  function appendEmpty(')]
        script = "const assert=require('node:assert/strict');" + helper + """
assert.equal(displayCheckValue(null, 'resolver_errors.DS'), 'Lookup available');
assert.equal(displayCheckValue('unavailable', 'resolver_errors.DS'), 'Lookup unavailable');
assert.equal(displayCheckValue(undefined, 'resolver_errors.DS'), 'Not captured');
assert.equal(displayCheckValue([], 'records.DS'), 'No values returned');
assert.equal(displayCheckValue(null, 'tls.subject'), 'No value returned');
"""
        result = subprocess.run(['node', '-e', script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('displayCheckValue(pair[1], change.field_path)', source)

    def test_enrollment_copy_controls_require_successful_code(self):
        root = Path(__file__).parents[1]
        template = (root / 'src/daedalus/templates/dashboard.html').read_text()
        source = (root / 'src/daedalus/static/js/dashboard.js').read_text()
        self.assertIn('id="copy-code" disabled', template)
        self.assertIn('id="copy-enrollment" disabled', template)
        self.assertIn('delete codeOutput.dataset.code;', source)
        self.assertIn('delete commandOutput.dataset.scannerName;', source)
        self.assertIn('codeOutput.dataset.code = body.code;', source)
        self.assertNotIn('.textContent.split("  (expires")', source)
        self.assertIn('if (!command.dataset.scannerName) return;', source)


    @unittest.skipUnless(shutil.which('node'), 'Node.js required')
    def test_scanner_platform_choice_selects_target_installer(self):
        source = (Path(__file__).parents[1] / 'src/daedalus/static/js/dashboard.js').read_text()
        helper = source[source.index('  function scannerInstaller('):source.index('  var enrollmentPlatform =')]
        script = "const assert=require('node:assert/strict');" + helper + """
assert.equal(scannerInstaller('linux'),'install-service-linux.sh');
assert.equal(scannerInstaller('macos'),'install-service-macos.sh');
assert.equal(scannerInstaller('foreground'),'install.sh');
assert.throws(()=>scannerInstaller('windows'),/Choose the scanner/);
"""
        result = subprocess.run(['node', '-e', script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('scannerInstaller(enrollmentPlatform.value)', source)
        self.assertIn('scannerInstaller(selectedPlatform)', source)


    def test_website_audit_evidence_is_visible_and_separate_from_summary(self):
        template = (Path(__file__).parents[1] / 'src/daedalus/templates/dashboard.html').read_text()
        priority = template[template.index('id="{{ key }}-priority-title"'):template.index('id="{{ key }}-changes-title"')]
        self.assertNotIn('id="web-audit-review"', priority)
        self.assertEqual(template.count('id="web-audit-review"'), 1)
        self.assertLess(template.index('id="web-summary-grid"'), template.index('id="web-audit-review"'))
        self.assertLess(template.index('id="web-audit-review"'), template.index('<summary>Linked vendors'))
        self.assertLess(template.index('id="web-audit-review"'), template.index('<summary>Refresh assessment'))
        start = template.index('<section class="website-audit-evidence"')
        evidence = template[start:template.index('</section>', start)]
        self.assertNotIn('<details', evidence)

    @unittest.skipUnless(shutil.which('node'), 'Node.js required')
    def test_assessment_refreshes_ignore_outdated_successes_and_failures(self):
        source = (Path(__file__).parents[1] / 'src/daedalus/static/js/dashboard.js').read_text()
        cases = [
            ('loadActiveExposure', '', '  document.querySelectorAll("[data-load-older-active]"'),
            ('loadExternalCheck', "'dns'", '  document.querySelectorAll("[data-load-older-checks]"'),
        ]
        for name, args, end in cases:
            with self.subTest(loader=name):
                helper = source[source.index('  async function ' + name + '('):source.index(end)]
                script = """const assert=require('node:assert/strict');
const orgId=1,externalCheckHistory=Object.create(null);
let activeExposureHistory={},rendered=[];
const nodes=new Map(),document={querySelector:()=>null,getElementById(id){if(!nodes.has(id))nodes.set(id,{textContent:'',replaceChildren(){this.textContent='';}});return nodes.get(id);}};
function appendEmpty(node,value){node.textContent=value;}function text(node,value){node.textContent=value;}
function renderActiveExposure(body){rendered.push(body.marker);}function renderCheckHistory(type,body){rendered.push(body.marker);}
let requests=[];function fetch(){return new Promise((resolve,reject)=>requests.push({resolve,reject}));}
function result(marker){return {ok:true,json:async()=>({marker,runs:[],changes:[]})};}
""" + helper + """
(async()=>{
const old=CALL,newer=CALL;requests[1].resolve(result('new'));await newer;
requests[0].resolve(result('old'));await old;assert.deepEqual(rendered,['new']);
requests=[];const failedOld=CALL,newest=CALL;requests[1].resolve(result('newest'));await newest;
requests[0].reject(new Error('stale error'));await failedOld;assert.deepEqual(rendered,['new','newest']);
assert.equal(nodes.size,0);
requests=[];const current=CALL;requests[0].reject(new Error('current error'));await current;
assert.ok([...nodes.values()].some(node=>node.textContent.includes('unavailable')));
})().catch(error=>{console.error(error);process.exitCode=1;});
"""
                script = script.replace('CALL', name + '(' + args + ')')
                result = subprocess.run(['node', '-e', script], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which('node'), 'Node.js required')
    def test_deeper_audit_refresh_failure_is_visible_and_stale_errors_ignored(self):
        source = (Path(__file__).parents[1] / 'src/daedalus/static/js/dashboard.js').read_text()
        helper = source[source.index('  async function loadNikto('):source.index('  var niktoButton =')]
        script = """const assert=require('node:assert/strict');
class Node {constructor(){this.children=['old'];this.textContent='';}replaceChildren(){this.children=[];this.textContent='';}}
const ids=new Map(),document={getElementById(id){if(!ids.has(id))ids.set(id,new Node());return ids.get(id);}};
const orgId=1,niktoHistory={hasMore:true,cursor:1,sequence:0};
function text(node,value){node.textContent=value;}function appendEmpty(node,value){node.textContent=value;}
let rejectRequest;let fetch=async()=>{throw new Error('Unavailable');};
"""+helper+"""
(async()=>{
await loadNikto();assert.match(document.getElementById('web-nikto-outcome').textContent,/unavailable/);
assert.equal(document.getElementById('web-audit-review').children.length,0);
assert.match(document.getElementById('web-audit-review').textContent,/could not be refreshed/);
document.getElementById('web-audit-review').textContent='Current saved review';
await loadNikto(true);assert.equal(document.getElementById('web-audit-review').textContent,'Current saved review');
fetch=()=>new Promise((resolve,reject)=>{rejectRequest=reject;});
const pending=loadNikto();niktoHistory.sequence++;
document.getElementById('web-nikto-outcome').textContent='Newer evidence';
rejectRequest(new Error('Old request failed'));await pending;
assert.equal(document.getElementById('web-nikto-outcome').textContent,'Newer evidence');
})().catch(error=>{console.error(error);process.exitCode=1;});
"""
        result = subprocess.run(['node', '-e', script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which('node'), 'Node.js required')
    def test_exposure_review_preserves_latest_attempt_and_literal_evidence(self):
        source = (Path(__file__).parents[1] / 'src/daedalus/static/js/dashboard.js').read_text()
        helper = source[source.index('  function renderExposureReview('):source.index('  function renderActiveExposure(')]
        script = """const assert=require('node:assert/strict');
class Node {constructor(){this.children=[];this.textContent='';}replaceChildren(){this.children=[];this.textContent='';}append(...items){this.children.push(...items);}}
const host=new Node(),document={getElementById:()=>host,createElement:()=>new Node()};
function appendEmpty(node,message){node.textContent=message;}function dateLabel(value){return value;}
function flatten(node){return node.textContent+' '+node.children.map(flatten).join(' ');}
""" + helper + """
renderExposureReview({id:3,status:'completed_with_warnings',snapshot:{coverage_complete:false,findings:[{signature_id:'<script>literal</script>',path:'/probe',http_status:200}]}});
assert.match(flatten(host),/Coverage incomplete/);assert.equal(host.children[1].children[0].textContent,'<script>literal</script>');
renderExposureReview({status:'failed',snapshot:{findings:[{signature_id:'stale'}]}});
assert.match(flatten(host),/Latest exposure attempt failed/);assert.doesNotMatch(flatten(host),/stale/);assert.equal(host.children.length,0);
renderExposureReview({status:'completed',snapshot:{coverage_complete:true,findings:[]}});
assert.match(flatten(host),/does not establish/);assert.match(flatten(host),/No configured signature/);
renderExposureReview(null);assert.match(flatten(host),/No saved exposure assessment/);
"""
        result = subprocess.run(['node', '-e', script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Current exposure evidence could not be refreshed.', source)
        self.assertIn('Public exposure paths: current evidence unavailable.', source)


    @unittest.skipUnless(shutil.which('node'), 'Node.js required')
    def test_vendor_review_drafts_retries_and_literal_history(self):
        source = (Path(__file__).parents[1] / 'src/daedalus/static/js/dashboard.js').read_text()
        helper = source[source.index('  var vendorReviewContext ='):source.index('  function groupExternalDependencies(')]
        script = """const assert=require('node:assert/strict');
class Node {constructor(){this.children=[];this.value='';this.events={};this.classList={toggle(){}};}
replaceChildren(){this.children=[];}append(...nodes){this.children.push(...nodes);}addEventListener(name,fn){this.events[name]=fn;}}
const ids=new Map();const document={getElementById(id){if(!ids.has(id))ids.set(id,new Node());return ids.get(id);},createElement(){return new Node();}};
function text(n,v){n.textContent=v;}function appendEmpty(n,v){n.textContent=v;}function dateLabel(v){return v;}
let uuidCalls=0;const crypto={randomUUID(){uuidCalls++;return '00000000-0000-0000-0000-000000000001';}};
let fail=true;const posts=[];
const fetch=async(url,options)=>{if(options.method==='POST'){posts.push(JSON.parse(options.body));return {ok:!fail,json:async()=>fail?{detail:'Temporary failure'}:{review:{id:1}}};}
return {ok:true,json:async()=>({reviews:[{id:1,origin:{host:'cdn.test'},status:'monitor',note:'<script>literal</script>',actor_user_id:1,created_at:'date'}],history:[],history_has_more:false})};};
""" + helper + """
(async()=>{
loadVendorReviewContext(10,[{host:'cdn.test',scheme:'https'}]);
const note=document.getElementById('vendor-review-note'),origin=document.getElementById('vendor-review-origin'),status=document.getElementById('vendor-review-status');
note.value='Review this dependency';origin.value='0';status.value='monitor';
loadVendorReviewContext(11,[{host:'new.test',scheme:'https'}]);assert.equal(vendorReviewContext.runId,10);
await vendorReviewForm.events.submit({preventDefault(){}});assert.equal(note.value,'Review this dependency');
fail=false;await vendorReviewForm.events.submit({preventDefault(){}});
assert.equal(posts[0].request_id,posts[1].request_id);assert.equal(uuidCalls,1);assert.equal(posts[1].run_id,10);assert.equal(note.value,'');
assert.equal(document.getElementById('vendor-review-decisions').children[0].children[1].textContent,'<script>literal</script>');
loadVendorReviewContext(11,[{host:'new.test',scheme:'https'}]);assert.equal(vendorReviewContext.runId,11);
loadVendorReviewContext(null,null);assert.equal(vendorReviewContext,null);assert.equal(document.getElementById('vendor-review-decisions').children.length,0);
})().catch(e=>{console.error(e);process.exitCode=1;});
"""
        result = subprocess.run(['node','-e',script],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)

    @unittest.skipUnless(shutil.which('node'), 'Node.js required')
    def test_vendor_groups_preserve_observations_and_avoid_object_key_collisions(self):
        source = (Path(__file__).parents[1] / 'src/daedalus/static/js/dashboard.js').read_text()
        helper = source[source.index('  function groupExternalDependencies('):source.index('  function renderWebsiteSnapshot(')]
        script = "const assert=require('node:assert/strict');" + helper + """
const resources=[{host:'a.test',category:'Analytics'},{host:'b.test',category:'Fonts and CDN'},{host:'c.test',category:'Analytics'},{host:'literal.test',category:'__proto__'},{host:'unknown.test'}];
const original=JSON.stringify(resources), groups=groupExternalDependencies(resources);
assert.deepEqual(groups.map(g=>g.category),['Analytics','Fonts and CDN','__proto__','Unclassified']);
assert.deepEqual(groups[0].resources.map(r=>r.host),['a.test','c.test']);
const resource={host:'cdn.test',scheme:'https',port:443};
const origin={...resource,http_reference_count:0,script_reference_count:2,stylesheet_reference_count:1,integrity_declared_reference_count:1,integrity_missing_reference_count:2};
const snapshot={dependency_origin_observations:{schema_version:1,origins:[origin]}};
assert.equal(dependencyOriginEvidence(snapshot,resource),'0 HTTP · 2 script(s) · 1 stylesheet(s) · integrity: 1 declared, 2 not declared');
assert.equal(dependencyOriginEvidence({},resource),'Origin attributes not recorded');
assert.equal(dependencyOriginEvidence(snapshot,{...resource,port:8443}),'Origin attributes unavailable');
snapshot.dependency_origin_observations.origins.push({...origin});
assert.equal(dependencyOriginEvidence(snapshot,resource),'Origin attributes unavailable');
snapshot.dependency_origin_observations.origins=[{...origin,script_reference_count:-1}];
assert.equal(dependencyOriginEvidence(snapshot,resource),'Origin attributes unavailable');

assert.equal(JSON.stringify(resources),original);assert.deepEqual(groupExternalDependencies(null),[]);
"""
        result = subprocess.run(['node','-e',script],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('statusTone: insecure ? "is-absent" : "is-neutral"', source)
        self.assertIn('Categories are hostname observations, not vendor security assessments.', source)

    @unittest.skipUnless(shutil.which('node'), 'Node.js required')
    def test_overview_prioritizes_review_and_keeps_unknown_unassessed(self):
        source = (Path(__file__).parents[1] / 'src/daedalus/static/js/dashboard.js').read_text()
        helper = source[source.index('  function workspaceAssessmentSummary('):source.index('  async function loadWorkspacePosture(')]
        script = "const assert=require('node:assert/strict');" + helper + """
const areas=[{key:'saved',state:'recorded'},{key:'review1',state:'attention'},{key:'missing',state:'not_assessed'},{key:'failed',state:'unavailable'},{key:'review2',state:'attention'},{key:'future',state:'unexpected'}];
const original=JSON.stringify(areas), result=workspaceAssessmentSummary(areas);
assert.deepEqual(result.areas.map(a=>a.key),['failed','review1','review2','future','missing','saved']);
assert.equal(result.counts.attention,2);assert.equal(result.counts.unavailable,1);
assert.equal(result.counts.not_assessed,1);assert.equal(result.counts.unknown,1);
assert.equal(JSON.stringify(areas),original);
"""
        result = subprocess.run(['node','-e',script],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('!Array.isArray(body.areas) || !body.areas.length', source)
        self.assertIn('Current assessment coverage is unavailable.', source)

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
        self.assertLess(section.index('id="cis-change-list"'), section.index('id="cis-report-list"'))
        self.assertLess(section.index('id="cis-change-list"'), section.index('id="cis-device-list"'))
        self.assertLess(section.index('id="cis-device-list"'), section.index('<summary>How endpoint check-ins work'))
        self.assertLess(section.index('id="cis-device-list"'), section.index('<summary>Profiles &amp; device setup'))
        self.assertIn('class="topic-priority" aria-labelledby="cis-assessment-title"', section)
        self.assertIn('class="topic-changes" aria-labelledby="cis-changes-title"', section)
        self.assertLess(section.index('id="cis-assessment-scope"'), section.index('id="cis-results-title"'))

    def test_external_topics_lead_with_assessment_and_changes(self):
        template = (Path(__file__).parents[1] / 'src/daedalus/templates/dashboard.html').read_text()
        section = template.split('data-external-check="{{ key }}">', 1)[1].split("{% elif key == 'reports' %}", 1)[0]
        self.assertLess(section.index('id="{{ key }}-priorities"'), section.index('data-run-external-check'))
        self.assertLess(section.index('id="{{ key }}-check-changes"'), section.index('id="dns-record-grid"'))
        self.assertLess(section.index('id="dns-record-grid"'), section.index('<summary>Refresh assessment</summary>'))
        self.assertLess(section.index('<summary>Refresh assessment</summary>'), section.index('data-run-external-check'))
        self.assertIn('<details class="topic-secondary"><summary>Assessment scope &amp; limitations</summary>', section)
        self.assertIn('class="topic-changes" aria-labelledby="{{ key }}-changes-title"', section)
        self.assertLess(section.index('id="{{ key }}-changes-title"'), section.index('class="topic-evidence"'))
        self.assertLess(section.index('id="dns-record-grid"'), section.index('<summary>Assessment scope'))

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
function loadSavedScannerAssessment(){}
function canViewScannerCommandHistory(){return true;} function supportsOSUpdateCheck(){return false;}
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

    @unittest.skipUnless(shutil.which('node'), 'Node.js required')
    def test_endpoint_history_groups_keep_every_entry_in_order(self):
        source = (Path(__file__).parents[1] / 'src/daedalus/static/js/dashboard.js').read_text()
        helper = source[source.index('  function groupEarlierCISHistory('):source.index('  function renderCISReports(')]
        script = """const assert=require('node:assert/strict');
class Node {
 constructor(tag){this.tag=tag;this.children=[];this.parent=null;}
 append(...items){for(const item of items){if(item.parent){item.parent.children.splice(item.parent.children.indexOf(item),1);}item.parent=this;this.children.push(item);}}
}
const document={createElement:tag=>new Node(tag)};
""" + helper + """
for(const size of [0,10,11,100]) {
 const list=new Node('div');const original=Array.from({length:size},(_,id)=>{const n=new Node('article');n.id=id;return n;});list.append(...original);
 groupEarlierCISHistory(list,'changes',false);
 if(size<=10){assert.deepEqual(list.children,original);continue;}
 assert.equal(list.children.length,11);const group=list.children[10];assert.equal(group.tag,'details');assert.equal(group.open,false);
 assert.equal(group.children[0].textContent,(size-10)+' earlier changes');
 assert.deepEqual([...list.children.slice(0,10),...group.children[1].children],original);
}
const reopened=new Node('div');reopened.append(...Array.from({length:23},()=>new Node('details')));
groupEarlierCISHistory(reopened,'reports',true);assert.equal(reopened.children[10].open,true);
"""
        result = subprocess.run(['node', '-e', script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which('node'), 'Node.js required')
    def test_endpoint_evidence_groups_prioritize_failures_and_keep_unknown_unassessed(self):
        source = (Path(__file__).parents[1] / 'src/daedalus/static/js/dashboard.js').read_text()
        helper = source[source.index('  function renderCISResultGroups('):source.index('  function renderCISProfiles(')]
        script = """const assert=require('node:assert/strict');
class Node {constructor(tag){this.tag=tag;this.children=[];this.textContent='';} append(...items){this.children.push(...items);}}
const document={createElement:tag=>new Node(tag)};
function makeCISResultRow(result){const row=new Node('article');row.result=result;return row;}
function appendEmpty(host,message){host.textContent=message;}
""" + helper + """
const results=[{status:'pass',category:'macos',id:1},{status:'manual',category:'chrome',id:2},{status:'fail',category:'macos',id:3},{status:'error',category:'chrome',id:4},{status:'unknown',category:'<script>',id:5}];
const original=JSON.stringify(results);const host=new Node('div');renderCISResultGroups(host,results);
assert.deepEqual(host.children.map(section=>section.children[0].textContent),['Checks requiring attention · 1','Unassessed checks · 3','Passing checks · 1']);
const unassessed=host.children[1];assert.equal(unassessed.children[1].children[0].textContent,'Chrome · 2 checks');
assert.equal(unassessed.children[2].children[0].textContent,'<script> · 1 checks');
assert.ok(host.children.every(section=>section.children.slice(1).every(details=>details.tag==='details'&&!details.open)));
assert.equal(JSON.stringify(results),original);
const empty=new Node('div');renderCISResultGroups(empty,[]);assert.match(empty.textContent,/No individual check evidence/);
"""
        result = subprocess.run(['node', '-e', script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which('node'), 'Node.js required')
    def test_endpoint_headline_scope_identifies_its_report_and_profile(self):
        source = (Path(__file__).parents[1] / 'src/daedalus/static/js/dashboard.js').read_text()
        helper = source[source.index('  function cisAssessmentScope('):source.index('  function cisPriorityMetrics(')]
        script = "const assert=require('node:assert/strict');function dateLabel(value){return value;}" + helper + """
assert.match(cisAssessmentScope(null),/first saved endpoint assessment/);
assert.equal(cisAssessmentScope({device_name:'<script>device</script>',profile_slug:'baseline',profile_version:'1.0',collected_at:'saved-time'}),'Latest saved assessment: <script>device</script> · baseline v1.0 · collected saved-time. Check counts and pass rate below describe this report.');
assert.match(cisAssessmentScope({}),/Profile not identified/);
"""
        result = subprocess.run(['node', '-e', script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('text(document.getElementById("cis-assessment-scope"), cisAssessmentScope(reports[0]))', source)

    @unittest.skipUnless(shutil.which('node'), 'Node.js required')
    def test_device_assessment_labels_preserve_coverage_and_unknown_results(self):
        source = (Path(__file__).parents[1] / 'src/daedalus/static/js/dashboard.js').read_text()
        helper = source[source.index('  function cisDeviceAssessmentLabel('):source.index('  function renderCISDevices(')]
        script = "const assert=require('node:assert/strict');" + helper + """
assert.equal(cisDeviceAssessmentLabel({}), 'Assessment results unavailable');
const summary={total:4,pass:1,fail:1,manual:2,error:0,score:25};
assert.equal(cisDeviceAssessmentLabel({latest_assessment_summary:summary}), 'Latest assessment: 25.0% pass rate · 2 of 4 checks assessed · 1 failed · 2 manual · 0 errors');
for (const invalid of [{...summary,total:5},{...summary,pass:'1'},{...summary,score:NaN},{...summary,error:-1},{...summary,score:101}]) {
  assert.equal(cisDeviceAssessmentLabel({latest_assessment_summary:invalid}), 'Assessment results need review');
}
"""
        result = subprocess.run(['node', '-e', script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which('node'), 'Node.js required')
    def test_endpoint_coverage_keeps_incomplete_counts_unknown(self):
        source = (Path(__file__).parents[1] / 'src/daedalus/static/js/dashboard.js').read_text()
        helper = source[source.index('  function renderCISCoverage('):source.index('  function renderCISDevices(')]
        script = """const assert=require('node:assert/strict');
const host={children:[],replaceChildren(){this.children=[];},append(item){this.children.push(item);}};
const document={getElementById:()=>host};
function makeAuditMetric(label,value,detail,tone){return {label,value,tone};}
"""+helper+"""
renderCISCoverage({device_count:3,assessment_counts:{current:1,stale:1,unknown:1,missing:0}});
assert.deepEqual(host.children.map(x=>x.value),['1','1','1','0']);assert.equal(host.children[3].tone,'neutral');
renderCISCoverage({device_count:4,assessment_counts:{current:1,stale:1,unknown:1,missing:0}});
assert.ok(host.children.every(x=>x.value==='Unknown'));
renderCISCoverage({device_count:1,assessment_counts:{current:'1',stale:0,unknown:0,missing:0}});
assert.ok(host.children.every(x=>x.value==='Unknown'));
"""
        result = subprocess.run(['node', '-e', script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which('node'), 'Node.js required')
    def test_repeated_scheduled_notices_are_quiet_while_manual_feedback_remains(self):
        source = (Path(__file__).parents[1] / 'src/daedalus/static/js/dashboard.js').read_text()
        helper = source[source.index('  function notifyExternalCheck('):source.index('  function notifyScannerUpdate(')]
        script = """const assert=require('node:assert/strict');let shown=0;
const notifiedCheckRuns={};const toast={classList:{remove(){shown++;}},hideTimer:null};
const document={getElementById:()=>toast};const window={clearTimeout(){},setTimeout(){return 1;}};
function text(node,value){node.textContent=value;}
"""+helper+"""
notifyExternalCheck({run_id:1,status:'failed',check_type:'dns',source:'schedule',notice_suppressed:true});assert.equal(shown,0);
notifyExternalCheck({run_id:1,status:'failed',check_type:'dns',source:'manual',notice_suppressed:true});assert.equal(shown,1);assert.match(toast.textContent,/failed/);
notifyExternalCheck({run_id:2,status:'completed_with_warnings',check_type:'dns',source:'schedule',notice_suppressed:true});assert.equal(shown,1);
notifyExternalCheck({run_id:3,status:'failed',check_type:'dns',source:'schedule',notice_suppressed:false});assert.equal(shown,2);
"""
        result = subprocess.run(['node', '-e', script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_external_evidence_groups_keep_key_metrics_visible(self):
        template = (Path(__file__).parents[1] / 'src/daedalus/templates/dashboard.html').read_text()
        evidence = template[template.index('<section class="topic-evidence" aria-labelledby="{{ key }}-evidence-title"'):template.index('<summary>Exposure findings')]
        self.assertIn('aria-labelledby="{{ key }}-evidence-title"', evidence)
        self.assertLess(evidence.index('id="dns-record-grid"'), evidence.index('<details'))
        self.assertLess(evidence.index('id="web-summary-grid"'), evidence.index('<details'))
        self.assertLess(evidence.index('<summary>Browser security policy evidence</summary>'), evidence.index('id="web-header-grid"'))
        self.assertNotIn('<details open', evidence)

    @unittest.skipUnless(shutil.which('node'), 'Node.js required')
    def test_dns_renderer_keeps_record_drawers_with_their_topic(self):
        source = (Path(__file__).parents[1] / 'src/daedalus/static/js/dashboard.js').read_text()
        helper = source[source.index('  function renderDnsSnapshot('):source.index('  var vendorReviewContext =')]
        helper = source[source.index('  function mailRouteMetric('):source.index('  function renderTopicPriorities(')] + helper
        script = """const assert=require('node:assert/strict');
class Node {constructor(tag='div'){this.tag=tag;this.children=[];this.attributes={};}append(...n){this.children.push(...n);}replaceChildren(){this.children=[];}setAttribute(k,v){this.attributes[k]=v;}}
const grid=new Node();const document={getElementById:()=>grid,createElement:tag=>new Node(tag)};
function appendEmpty(n,v){n.append(v);}function uncheckedRecordRow(t,n){return {type:t,name:n};}
function rowsForRecord(t,n,v,e){return [{type:t,name:n,value:v,error:e}];}
function makeAuditMetric(label,value,detail,state){return {label,value,detail,state};}
function emailAuthenticationMetrics(){return [{label:'SPF',value:'Unknown',detail:'fixture',state:'attention'},{label:'DMARC',value:'Unknown',detail:'fixture',state:'attention'}];}
function makeAuditTable(title,note,rows){return {title,note,rows};}
""" + helper + """
renderDnsSnapshot({domain:'example.org',records:{A:['192.0.2.1'],AAAA:[],CNAME:[],MX:['mail.example.org'],SPF:[],DMARC:[],DKIM:{}},resolver_errors:{'www A':'SERVFAIL'},dnssec_observations:{assessment:'lookup_incomplete'}});
assert.equal(grid.children.length,4);
const [resolution,email,registration,diagnostics]=grid.children;
assert.equal(registration.attributes['aria-labelledby'],'dns-registration-group');
assert.equal(registration.children[1].children[0].value,'Not assessed');
assert.equal(registration.children[2].children[0].textContent,'Registration evidence');
assert.equal(resolution.attributes['aria-labelledby'],'dns-resolution-group');
assert.equal(email.attributes['aria-labelledby'],'dns-email-group');
assert.equal(resolution.children[2].tag,'details');assert.equal(email.children[2].tag,'details');
assert.equal(resolution.children[2].children[0].textContent,'Domain record evidence');
assert.equal(email.children[2].children[0].textContent,'Email record evidence');
assert.ok(resolution.children[2].children[1].rows.every(r=>r.type!=='MX'));
assert.ok(email.children[2].children[1].rows.some(r=>r.type==='MX'));
assert.equal(diagnostics.tag,'details');
assert.match(diagnostics.children.at(-1).textContent,/unknown, not missing/);
assert.equal(resolution.children[1].children[1].value,'Unknown');
function dateLabel(value){return value;}
renderDnsSnapshot({domain:'example.org',records:{},registration_observations:{state:'observed',collection_partial:false,registrars:['Fixture registrar'],nameservers:['ns.example.org'],events:[{action:'expiration',date:'2027-01-01T00:00:00Z'}]}});
const observedRegistration=grid.children[2];
assert.equal(observedRegistration.children[1].children.length,4);
assert.equal(observedRegistration.children[1].children[1].value,'Fixture registrar');
assert.equal(observedRegistration.children[1].children[2].value,'2027-01-01T00:00:00Z');
assert.equal(observedRegistration.children[2].children[1].rows.length,3);
renderDnsSnapshot({domain:'example.org',records:{},registration_observations:{state:'unavailable'}});
assert.equal(grid.children[2].children[1].children[0].value,'Unavailable');
renderDnsSnapshot(null);assert.equal(grid.children.length,1);
"""
        result = subprocess.run(['node', '-e', script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which('node'), 'Node.js required')
    def test_scanner_saved_summary_keeps_unknowns_and_scope_limits(self):
        source = (Path(__file__).parents[1] / 'src/daedalus/static/js/dashboard.js').read_text()
        helper = source[source.index('  function renderSavedScannerAssessment('):source.index('  function loadSavedScannerAssessment(')]
        script = """const assert=require('node:assert/strict');
class Node {constructor(){this.children=[];}append(...n){this.children.push(...n);}replaceChildren(){this.children=[];}}
const document={createElement:()=>new Node()};function appendEmpty(n,v){n.append(v);}function dateLabel(v){return v||'Unknown';}
function makeAuditMetric(label,value,detail,state){return {label,value,detail,state};}
""" + helper + """
const host=new Node();renderSavedScannerAssessment(host,{run:{status:'failed'},observations:null,reason:'Latest result malformed'});
assert.equal(host.children.at(-1),'Latest result malformed');
renderSavedScannerAssessment(host,{run:{status:'completed',last_occurred_at:'saved'},observations:{host_count:1,open_port_count:0,unknown_port_state_count:2,collected_at:'collected',covered_targets:null}});
assert.equal(host.children[2].children[1].state,'neutral');assert.equal(host.children[2].children[2].state,'attention');
assert.match(host.children[3].textContent,/coverage was not explicitly reported/);assert.match(host.children[3].textContent,/do not establish coverage/);
renderSavedScannerAssessment(host,{run:null});assert.equal(host.children.length,2);
"""
        result = subprocess.run(['node', '-e', script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which('node'), 'Node.js required')
    def test_certificate_expiry_requires_timezone_and_uses_exact_boundaries(self):
        source = (Path(__file__).parents[1] / 'src/daedalus/static/js/dashboard.js').read_text()
        helper = source[source.index('  function websiteCertificateAssessment('):source.index('  function renderTopicPriorities(')]
        script = "const assert=require('node:assert/strict');" + helper + """
const now=Date.parse('2026-10-04T12:00:00Z');
const assess=value=>websiteCertificateAssessment({valid_until:value},now);
for(const value of [null,'2100-01-01','2026-10-04T12:00:00','2026-02-30T12:00:00Z','2026-10-04T24:00:00Z','2026-10-04T12:00:00+24:00']) assert.equal(assess(value).state,'unknown');
assert.equal(assess('2026-10-04T11:59:59Z').state,'expired');
assert.equal(assess('2026-10-04T12:00:00Z').state,'expired');
assert.equal(assess('2026-10-04T12:00:01Z').state,'expiring');
assert.equal(assess('2026-11-03T11:59:59Z').state,'expiring');
assert.equal(assess('2026-11-03T12:00:00Z').state,'recorded');
assert.deepEqual(assess('2026-10-04T08:00:00-04:00'),assess('2026-10-04T12:00:00Z'));
assert.equal(assess('2028-02-29T12:00:00.123456+00:00').state,'recorded');
"""
        result = subprocess.run(['node', '-e', script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('var certificateAssessment = websiteCertificateAssessment(snapshot.tls)', source)
        self.assertIn('var certificateAssessment = websiteCertificateAssessment(certificate)', source)

    def test_external_topics_put_assessment_before_records_and_controls(self):
        root = Path(__file__).parents[1]
        template = (root / 'src/daedalus/templates/dashboard.html').read_text()
        self.assertLess(template.index('id="{{ key }}-priority-title"'), template.index('id="dns-record-grid"'))
        self.assertLess(template.index('id="{{ key }}-priority-title"'), template.index('id="web-summary-grid"'))
        self.assertLess(template.index('id="{{ key }}-priority-title"'), template.index('<summary>Exposure findings'))
        source = (root / 'src/daedalus/static/js/dashboard.js').read_text()
        self.assertIn('evidenceGroup("dns-resolution-group", networkHeading, networkMetrics', source)
        self.assertIn('evidenceGroup("dns-email-group", mailHeading, summary', source)
        self.assertIn('A lookup failed; review the saved evidence', source)

    @unittest.skipUnless(shutil.which('node'), 'Node.js required')
    def test_assessment_summaries_preserve_unknown_and_partial_coverage(self):
        source=(Path(__file__).parents[1]/'src/daedalus/static/js/dashboard.js').read_text()
        priority=source[source.index('  function websiteCertificateAssessment('):source.index('  function renderDnsSnapshot(')]
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
assert.equal(nodes['dns-priorities'].children[0].className,'assessment-findings');
assert.equal(nodes['dns-priorities'].children[0].children[0].children[0].textContent,'SPF: Unknown');
assert.equal(nodes['dns-priorities'].children[1].className,'check-scope-note');
assert.doesNotMatch(flatten(nodes['dns-priorities'].children[0]),/missing selector/);
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
        renderer=source[source.index('  function workspaceAssessmentSummary('):source.index('  function refresh(force)')]
        script='''const assert=require('node:assert/strict');
let focused=null;
class Node { constructor(){this.children=[];this.textContent='';this.dataset={};this.events={};}
replaceChildren(){this.children=[];} append(...items){this.children.push(...items);}
contains(node){return this.children.includes(node);} addEventListener(name,cb){this.events[name]=cb;}
querySelector(){return this.children.find(n=>n.dataset.postureKey==='dns');}
focus(){focused=this.dataset.postureKey;document.activeElement=this;}}
const host=new Node(), priorities=new Node(); const document={activeElement:null,getElementById:id=>id==='workspace-posture'?host:priorities,createElement:()=>new Node()};
function makeAuditMetric(label,value,detail,tone){const n=new Node();n.textContent=label+':'+value;n.tone=tone;return n;}
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
assert.equal(priorities.children[0].children[2].textContent,'Unassessed areas:1');
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
