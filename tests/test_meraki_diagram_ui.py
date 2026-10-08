from pathlib import Path
import shutil
import subprocess
import pytest


@pytest.mark.skipif(not shutil.which('node'),reason='Node required')
def test_svg_literal_names_scrolling_and_undirected_edges():
    source=(Path(__file__).parents[1]/'src/daedalus/static/js/dashboard.js').read_text()
    helper=source[source.index('  function renderMerakiNetworkDiagram('):source.index('  function renderMerakiTopology(')]
    script='''const assert=require('node:assert/strict');class Node{constructor(tag){this.tag=tag;this.children=[];this.textContent='';this.attrs={}}append(...n){this.children.push(...n)}setAttribute(k,v){this.attrs[k]=v}}
const document={createElement:t=>new Node(t),createElementNS:(ns,t)=>new Node(t)};function all(n){return[n,...n.children.flatMap(all)]}
'''+helper+'''
const box=new Node('div');renderMerakiNetworkDiagram(box,{network_name:'HQ',diagram:{status:'available',width:1000,height:300,scope:'Undirected relationships',nodes:[{device_serial:'__proto__',name:'<script>literal</script>',model:'MS',number:1,x:10,y:10,width:180,height:70,reported_root:true},{device_serial:'B',name:'AP',model:'MR',number:2,x:10,y:150,width:180,height:70}],links:[{device_serials:['__proto__','B']}],additional_nodes:2,additional_links:3}});
const nodes=all(box);assert.equal(nodes.filter(n=>n.tag==='line').length,1);assert.equal(nodes.filter(n=>n.tag==='rect').length,2);assert.ok(nodes.some(n=>n.tabIndex===0&&n.attrs.role==='region'));assert.ok(nodes.some(n=>n.tag==='svg'&&n.attrs.role==='img'));assert.ok(nodes.some(n=>n.tag==='title'&&n.textContent.includes('<script>literal</script>')));assert.ok(!nodes.some(n=>n.tag==='script'));assert.ok(!nodes.some(n=>n.attrs['marker-end']));assert.ok(nodes.some(n=>n.textContent.includes('2 additional devices')));
const empty=new Node('div');renderMerakiNetworkDiagram(empty,{diagram:{status:'empty'}});assert.equal(empty.children.length,0);
'''
    result=subprocess.run(['node','-e',script],capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    assert 'innerHTML' not in helper
