import json
from pathlib import Path
import shutil
import subprocess
import unittest


class DashboardTopicTests(unittest.TestCase):
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
