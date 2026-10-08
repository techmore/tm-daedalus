from pathlib import Path
import shutil, subprocess
import pytest

@pytest.mark.skipif(not shutil.which('node'),reason='Node required')
def test_literal_neighbors_and_keyboard_table_unknown_and_empty():
    source=(Path(__file__).parents[1]/'src/daedalus/static/js/dashboard.js').read_text()
    helper=source[source.index('  function renderMerakiNeighbors('):source.index('  function renderMerakiSwitchPorts(')]
    script='''const assert=require('node:assert/strict');class Node{constructor(tag){this.tag=tag;this.children=[];this.textContent='';this.attrs={}}append(...n){this.children.push(...n)}setAttribute(k,v){this.attrs[k]=v}}
const document={createElement:t=>new Node(t)};function all(n){return[n,...n.children.flatMap(all)]}
'''+helper+'''
const box=new Node('div');renderMerakiNeighbors(box,{scope:'Saved evidence',switches:[{device_name:'Switch',network_name:'HQ',status:'complete',data:{matched_port_count:1,reported_port_count:3,unmatched_port_count:1,ambiguous_port_count:1,additional_rows:4,rows:[{local_port:'1',status:'matched',neighbor_name:'<script>literal</script>',neighbor_model:'MR',neighbor_port:'eth0',protocols:['lldp'],remote_port_conflict:true},{local_port:'2',status:'unmatched',protocols:[]},{local_port:'3',status:'ambiguous',protocols:[]}]}},{status:'unsupported',data:null},{status:'complete',data:{matched_port_count:0,reported_port_count:0,unmatched_port_count:0,ambiguous_port_count:0,rows:[]}}],additional_switches:2});
const nodes=all(box);assert.ok(nodes.some(n=>n.tag==='caption'));assert.ok(nodes.some(n=>n.tabIndex===0&&n.attrs.role==='region'));assert.ok(nodes.some(n=>n.textContent==='<script>literal</script>'));assert.ok(!nodes.some(n=>n.tag==='script'));for(const text of ['Conflicting port IDs','Not matched to assigned inventory','Ambiguous discovery','relationships unavailable','No discovery ports returned','4 more ports','2 more switches'])assert.ok(nodes.some(n=>n.textContent.includes(text)),text);
const empty=new Node('div');renderMerakiNeighbors(empty,null);assert.equal(empty.children.length,0);
'''
    result=subprocess.run(['node','-e',script],capture_output=True,text=True);assert result.returncode==0,result.stderr
    assert 'innerHTML' not in helper
