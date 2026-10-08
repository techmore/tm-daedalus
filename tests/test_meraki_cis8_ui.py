from pathlib import Path
import shutil,subprocess,unittest

@unittest.skipUnless(shutil.which('node'),'Node required')
class Cis8UITests(unittest.TestCase):
    def test_evidence_status_unknowns_and_literal_details(self):
        source=(Path(__file__).parents[1]/'src/daedalus/static/js/dashboard.js').read_text()
        helper=source[source.index('  function renderMerakiCis8('):source.index('  function renderMerakiTopology(')]
        helper+=source[source.index('  function renderMerakiCis8Overview('):source.index('  function renderMerakiTopologyOverview(')]
        script='''const assert=require('node:assert/strict');
class Node{constructor(tag){this.tag=tag;this.children=[];this.textContent='';this.events={};}append(...items){this.children.push(...items);}addEventListener(k,v){this.events[k]=v;}}
let focused=false;const saved={open:false,querySelector(){return{focus(){focused=true},scrollIntoView(){}}}};
const document={createElement:tag=>new Node(tag),querySelector:s=>saved};function all(n){return[n,...n.children.flatMap(all)];}
'''+helper+'''
const box=new Node('div'),evidence={schema_version:1,scope:'No compliance score',rows:[{control_id:1,title:'<script>literal</script>',status:'partial',observation:'Assigned inventory',next_action:'Review',evidence_references:['meraki.devices']},{control_id:2,title:'Software',status:'unknown'}],summary:{partial:1,review:0,not_assessed:1}};
renderMerakiCis8(box,evidence);const text=all(box).map(n=>n.textContent).join(' ');assert.ok(text.includes('<script>literal</script>'));assert.ok(text.includes('Partial evidence'));assert.ok(text.includes('Not assessed'));assert.ok(text.includes('meraki.devices'));assert.ok(!all(box).some(n=>n.tag==='script'));
const overview=new Node('div');renderMerakiCis8Overview(overview,{report_id:53,cis8_assessment:evidence});all(overview).find(n=>n.tag==='button').events.click();assert.ok(saved.open&&focused);assert.ok(all(overview).some(n=>n.textContent.includes('no safeguard compliance')));
const legacy=new Node('div');renderMerakiCis8(legacy,null);renderMerakiCis8Overview(legacy,{});assert.equal(legacy.children.length,0);
'''
        result=subprocess.run(['node','-e',script],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertNotIn('innerHTML',helper)
