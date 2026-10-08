from pathlib import Path
import shutil
import subprocess
import unittest


@unittest.skipUnless(shutil.which('node'), 'Node.js required')
class MerakiPlanningUITests(unittest.TestCase):
    def test_top_level_budgets_are_dated_literal_and_open_matching_evidence(self):
        source=(Path(__file__).parents[1]/'src/daedalus/static/js/dashboard.js').read_text()
        helper=source[source.index('  function renderMerakiPlanningOverview('):source.index('  async function loadMerakiSummaryObservations(')]
        script='''const assert=require('node:assert/strict');
class Node {constructor(tag){this.tag=tag;this.children=[];this.textContent='';this.events={};} append(...items){this.children.push(...items);} addEventListener(k,v){this.events[k]=v;}}
let focused=false,scrolled=false,selector;
const summary={focus(){focused=true;},scrollIntoView(){scrolled=true;}};
const saved={open:false,querySelector(){return summary;}};
const document={createElement:tag=>new Node(tag),querySelector:s=>{selector=s;return saved;}};
function all(n){return [n,...n.children.flatMap(all)];}
''' + helper + '''
const box=new Node('div');
renderMerakiPlanningOverview(box,{report_id:45,unifi_plan:{schema_version:1,currency:'USD',price_observed_on:'2026-10-07',refresh_plan:{schema_version:1,currency:'USD',scenarios:[{name:'<script>literal</script>',annual_reserve_cents:141950,replacement_cycle_years:8,complete_inventory_pricing:true}]},scenarios:[{name:'<script>literal</script>',hardware_subtotal_cents:1135600,complete_inventory_pricing:true},{name:'Higher capacity',hardware_subtotal_cents:1294000,complete_inventory_pricing:false},{name:'Hidden third',hardware_subtotal_cents:1}]}});
const text=all(box).map(n=>n.textContent).join('\\n');
assert.ok(text.includes('$11,356'));assert.ok(text.includes('$1,419.50/year'));assert.ok(text.includes('assumed 8-year cycle'));
assert.ok(text.includes('$12,940'));
assert.ok(text.includes('2026-10-07'));
assert.ok(text.includes('<script>literal</script>'));
assert.ok(text.includes('Partial inventory pricing'));
assert.ok(!text.includes('Hidden third'));
all(box).find(n=>n.tag==='button').events.click();
assert.equal(saved.open,true);assert.ok(focused&&scrolled);assert.ok(selector.includes('45'));
const empty=new Node('div');renderMerakiPlanningOverview(empty,{unifi_plan:{schema_version:1,currency:'USD',scenarios:[{hardware_subtotal_cents:NaN}]}});assert.equal(empty.children.length,0);
'''
        result=subprocess.run(['node','-e',script],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_refresh_details_keep_partial_unknown_and_literal_text(self):
        source=(Path(__file__).parents[1]/'src/daedalus/static/js/dashboard.js').read_text()
        helper=source[source.index('  function renderMerakiRefreshPlan('):source.index('  function renderMerakiSwitchPorts(')]
        script='''const assert=require('node:assert/strict');
class Node{constructor(tag){this.tag=tag;this.children=[];this.textContent='';}append(...items){this.children.push(...items);}}
const document={createElement:tag=>new Node(tag)};function all(n){return[n,...n.children.flatMap(all)];}
'''+helper+'''
const box=new Node('div');renderMerakiRefreshPlan(box,{schema_version:1,currency:'USD',scope:'<script>literal</script>',scenarios:[{name:'Partial',annual_reserve_cents:0,replacement_cycle_years:8,complete_inventory_pricing:false,unpriced_device_count:2},{name:'Missing',annual_reserve_cents:null,replacement_cycle_years:8}]});
const text=all(box).map(n=>n.textContent).join(' ');assert.ok(text.includes('$0.00'));assert.ok(text.includes('Unavailable'));assert.ok(text.includes('2 unpriced devices'));assert.ok(text.includes('Partial pricing'));assert.ok(text.includes('<script>literal</script>'));
const legacy=new Node('div');renderMerakiRefreshPlan(legacy,null);assert.equal(legacy.children.length,0);
'''
        result=subprocess.run(['node','-e',script],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
