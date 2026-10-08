from pathlib import Path
import shutil
import subprocess
import pytest


@pytest.mark.skipif(not shutil.which('node'),reason='Node required')
def test_action_timeline_literals_empty_windows_and_open_saved_evidence():
    source=(Path(__file__).parents[1]/'src/daedalus/static/js/dashboard.js').read_text()
    helper=source[source.index('  function renderMerakiActionPlan('):source.index('  function renderMerakiClientDistributions(')]
    helper+=source[source.index('  function renderMerakiActionOverview('):source.index('  function renderMerakiClientOverview(')]
    script='''const assert=require('node:assert/strict');class Node{constructor(tag){this.tag=tag;this.children=[];this.textContent='';this.events={}}append(...n){this.children.push(...n)}addEventListener(k,v){this.events[k]=v}}
let focused=false;const saved={open:false,querySelector(){return{focus(){focused=true},scrollIntoView(){}}}};const document={createElement:tag=>new Node(tag),querySelector:()=>saved};function all(n){return[n,...n.children.flatMap(all)]}
'''+helper+'''
const plan={schema_version:1,scope:'No automatic changes',phases:['Immediate','Short','Medium','Long'],rows:[{phase:0,title:'<script>literal</script>',status:'review',observation:'Saved finding',action:'Review policy',verification:'Repeat audit',suggested_owner:'Network administrator',evidence_references:['meraki.findings']}]};
const host=new Node('div');renderMerakiActionPlan(host,plan);const nodes=all(host),text=nodes.map(n=>n.textContent).join(' ');assert.ok(text.includes('<script>literal</script>'));assert.ok(text.includes('No actions derived'));assert.ok(text.includes('Validation: Repeat audit'));assert.ok(text.includes('Saved evidence: meraki.findings'));assert.equal(nodes.filter(n=>n.tag==='details').length,4);assert.ok(!nodes.some(n=>n.tag==='script'));
const overview=new Node('div');renderMerakiActionOverview(overview,{report_id:55,action_plan:plan});all(overview).find(n=>n.tag==='button').events.click();assert.ok(saved.open&&focused);assert.ok(all(overview).some(n=>n.textContent.includes('No automatic remediation')));
const legacy=new Node('div');renderMerakiActionPlan(legacy,null);renderMerakiActionOverview(legacy,{});assert.equal(legacy.children.length,0);
'''
    result=subprocess.run(['node','-e',script],capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    assert 'innerHTML' not in helper
