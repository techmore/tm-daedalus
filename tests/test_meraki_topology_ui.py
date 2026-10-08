from pathlib import Path
import shutil,subprocess,unittest

@unittest.skipUnless(shutil.which('node'),'Node required')
class TopologyUITests(unittest.TestCase):
    def test_named_relationships_unknowns_literals_keyboard_and_empty_states(self):
        source=(Path(__file__).parents[1]/'src/daedalus/static/js/dashboard.js').read_text()
        helper=source[source.index('  function renderMerakiTopology('):source.index('  function renderMerakiRefreshPlan(')]
        helper+=source[source.index('  function renderMerakiTopologyOverview('):source.index('  function renderMerakiWanOverview(')]
        script='''const assert=require('node:assert/strict');
class Node{constructor(tag){this.tag=tag;this.children=[];this.attrs={};this.textContent='';this.events={};}append(...items){this.children.push(...items);}setAttribute(k,v){this.attrs[k]=v;}addEventListener(k,v){this.events[k]=v;}}
let focused=false;const saved={open:false,querySelector(){return{focus(){focused=true},scrollIntoView(){}}}};
const document={createElement:tag=>new Node(tag),querySelector:s=>saved};function all(n){return[n,...n.children.flatMap(all)];}
'''+helper+'''
const evidence={networks:[{network_name:'<script>literal</script>',status:'complete',node_count:2,link_count:1,isolated_node_count:0,root_node_count:1,omitted_node_count:0,omitted_link_count:1,reported_error_count:null,nodes:[{name:'Core',model:'MS',reported_root:true},{name:'AP',model:'MR'}],links:[{endpoint_names:['Core','AP'],link_count:2}],additional_nodes:1,additional_links:2},{network_name:'Empty',status:'complete',nodes:[],links:[]},{network_name:'Missing',status:'unsupported'}],scope:'Observed only'};
const box=new Node('div');renderMerakiTopology(box,evidence);const nodes=all(box),text=nodes.map(n=>n.textContent).join(' ');
assert.ok(text.includes('<script>literal</script>'));assert.ok(text.includes('Unavailable'));assert.ok(text.includes('No relationships shown'));assert.ok(text.includes('Missing links do not establish disconnection'));
assert.equal(nodes.filter(n=>n.tag==='th'&&n.attrs.scope==='col').length,3);assert.ok(nodes.some(n=>n.tag==='caption'));assert.ok(nodes.some(n=>n.tabIndex===0));assert.ok(text.includes('1 more assigned devices'));assert.ok(!nodes.some(n=>n.tag==='script'));
const overview=new Node('div');renderMerakiTopologyOverview(overview,{report_id:52,topology_graph:evidence});all(overview).find(n=>n.tag==='button').events.click();assert.ok(saved.open&&focused);
const legacy=new Node('div');renderMerakiTopology(legacy,null);renderMerakiTopologyOverview(legacy,{});assert.equal(legacy.children.length,0);
'''
        result=subprocess.run(['node','-e',script],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertNotIn('innerHTML',helper)
