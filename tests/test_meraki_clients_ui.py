from pathlib import Path
import shutil
import subprocess
import pytest


@pytest.mark.skipif(not shutil.which('node'),reason='Node required')
def test_grouped_distributions_use_literal_text_and_keyboard_regions():
    source=(Path(__file__).parents[1]/'src/daedalus/static/js/dashboard.js').read_text()
    helper=source[source.index('  function renderMerakiClientDistributions('):source.index('  function renderMerakiCis8(')]
    helper+=source[source.index('  function renderMerakiClientOverview('):source.index('  function renderMerakiCis8Overview(')]
    script='''const assert=require('node:assert/strict');
class Node {constructor(tag){this.tag=tag;this.children=[];this.textContent='';this.events={};this.attrs={};}append(...items){this.children.push(...items)}setAttribute(k,v){this.attrs[k]=v}addEventListener(k,v){this.events[k]=v}}
let focused=false;const saved={open:false,querySelector(){return{focus(){focused=true},scrollIntoView(){}}}};
const document={createElement:tag=>new Node(tag),querySelector:()=>saved};function all(n){return[n,...n.children.flatMap(all)]}
'''+helper+'''
const host=new Node('div');const observations=[{network_name:'<b>HQ</b>',status:'complete',data:{wireless_client_count:0,excluded_connection_count:0,scope:'No concurrency claim',distributions:{ssid:{status:'complete',rows:[{label:'<script>literal</script>',count:0}],unknown_count:1,additional_group_count:2,additional_client_count:3}}}},{network_name:'Failed',status:'unavailable',data:null}];
renderMerakiClientDistributions(host,observations,2);const nodes=all(host);const text=nodes.map(x=>x.textContent).join(' ');assert.ok(text.includes('<script>literal</script>'));assert.ok(text.includes('0 wireless records'));assert.ok(text.includes('2 additional groups (3 records)'));assert.ok(text.includes('Distribution evidence unavailable or invalid'));assert.ok(text.includes('RSSI: not provided'));assert.ok(!nodes.some(x=>x.tag==='script'));assert.ok(nodes.some(x=>x.attrs.role==='region'&&x.tabIndex===0));
const overview=new Node('div');renderMerakiClientOverview(overview,{report_id:54,wireless_clients:observations});all(overview).find(x=>x.tag==='button').events.click();assert.ok(saved.open&&focused);assert.ok(all(overview).some(x=>x.textContent.includes('distinct people')));
const legacy=new Node('div');renderMerakiClientDistributions(legacy,null);renderMerakiClientOverview(legacy,{});assert.equal(legacy.children.length,0);
'''
    result=subprocess.run(['node','-e',script],capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    assert 'innerHTML' not in helper
