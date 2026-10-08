from pathlib import Path
import json,shutil,subprocess
import pytest
from daedalus.meraki_paths import build_path_analysis,project_path_analysis
from test_meraki_paths import snapshot

@pytest.mark.skipif(not shutil.which('node'),reason='Node required')
def test_grouped_review_literal_text_zero_unknown_and_keyboard_tables():
    source=(Path(__file__).parents[1]/'src/daedalus/static/js/dashboard.js').read_text()
    helper=source[source.index('  function renderMerakiPaths('):source.index('  function renderMerakiNeighbors(')]
    s=snapshot();evidence=project_path_analysis(build_path_analysis(s),s)
    evidence['additional_networks']=2;evidence['networks'][0]['switches'][0]['additional_aps']=3;evidence['networks'][0]['additional_switches']=4
    script='''const assert=require('node:assert/strict');class Node{constructor(tag){this.tag=tag;this.children=[];this.textContent='';this.attrs={}}append(...n){this.children.push(...n)}setAttribute(k,v){this.attrs[k]=v}}
const document={createElement:t=>new Node(t)};function all(n){return[n,...n.children.flatMap(all)]}
'''+helper+'''
const evidence=JSON.parse(require('node:fs').readFileSync(0,'utf8'));const box=new Node('div');renderMerakiPaths(box,evidence,false);const nodes=all(box);
assert.ok(nodes.some(n=>n.tag==='caption'));assert.ok(nodes.some(n=>n.tabIndex===0&&n.attrs.role==='region'));assert.ok(!nodes.some(n=>n.tag==='script'));
for(const text of ['<script>AP</script>','1/2 APs uniquely mapped','Success: 0','1 Gbps','coverage partial','WiFi 0%','86,400 seconds','Unavailable','No assigned WAN appliance','3 more APs','4 more switches','2 more networks','measured-window averages'])assert.ok(nodes.some(n=>n.textContent.includes(text)),text);
const overview=new Node('div');renderMerakiPaths(overview,evidence,true);assert.ok(all(overview).some(n=>n.textContent.includes('1/2 APs uniquely mapped')));assert.ok(!all(overview).some(n=>n.tag==='table'));
const invalid=new Node('div');renderMerakiPaths(invalid,{status:'invalid_evidence',scope:'Saved evidence'},false);assert.ok(all(invalid).some(n=>n.textContent.includes('invalid or unavailable')));
const absent=new Node('div');renderMerakiPaths(absent,null,false);assert.equal(absent.children.length,0);
'''
    result=subprocess.run(['node','-e',script],input=json.dumps(evidence),capture_output=True,text=True);assert result.returncode==0,result.stderr
    assert 'innerHTML' not in helper


def test_layer_review_precedes_purchase_details_and_all_overview_branches():
    source=(Path(__file__).parents[1]/'src/daedalus/static/js/dashboard.js').read_text()
    renderer=source[source.index('  function renderMerakiDashboardDetails('):source.index('  function fetchMerakiDashboardDetails(')]
    assert renderer.index('renderMerakiPaths(')<renderer.index('var plan = details.unifi_plan')
    assert source.count('renderMerakiPaths(container, details.path_analysis, true)')==3
