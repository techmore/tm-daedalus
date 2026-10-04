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
