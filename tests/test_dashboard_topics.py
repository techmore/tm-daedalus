import json
from pathlib import Path
import shutil
import subprocess
import unittest


class DashboardTopicTests(unittest.TestCase):
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

    def test_external_topics_put_results_before_review_and_controls(self):
        root = Path(__file__).parents[1]
        template = (root / 'src/daedalus/templates/dashboard.html').read_text()
        self.assertLess(template.index('id="dns-record-grid"'), template.index('id="{{ key }}-priority-title"'))
        self.assertLess(template.index('id="web-summary-grid"'), template.index('id="{{ key }}-priority-title"'))
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
