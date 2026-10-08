from pathlib import Path
import shutil
import subprocess
import unittest


@unittest.skipUnless(shutil.which('node'), 'Node.js required')
class MerakiWanOverviewUITests(unittest.TestCase):
    def test_summary_is_bounded_literal_and_keyboard_opens_matching_report(self):
        source=(Path(__file__).parents[1]/'src/daedalus/static/js/dashboard.js').read_text()
        helper=source[source.index('  function renderMerakiWanOverview('):source.index('  function renderMerakiPlanningOverview(')]
        script="""const assert=require('node:assert/strict');
class Node{constructor(tag){this.tag=tag;this.children=[];this.textContent='';this.events={};}append(...items){this.children.push(...items);}addEventListener(k,v){this.events[k]=v;}}
let focused=false;const summary={focus(){focused=true;},scrollIntoView(){}};const saved={open:false,querySelector(){return summary;}};
const document={createElement:tag=>new Node(tag),querySelector:selector=>{assert.ok(selector.includes('48'));return saved;}};function all(n){return[n,...n.children.flatMap(all)];}
"""+helper+"""
const box=new Node('div');renderMerakiWanOverview(box,{report_id:48,wan_uplinks:{status:'complete',data:{reported_device_count:1,expected_device_count:1,state_counts:{active:1},missing_device_count:0}},wan_usage:[{network_name:'<script>literal</script>',status:'complete',data:{interfaces:Array.from({length:5},()=>({interface:'wan1',directions:{received:{average_mbps:0,peak_interval_average_mbps:2,observed_seconds:3600}}}))}}]});
const nodes=all(box),text=nodes.map(n=>n.textContent).join(' ');assert.ok(text.includes('<script>literal</script>'));assert.ok(text.includes('Download average: 0 Mbps'));assert.ok(text.includes('Upload average: Unavailable'));assert.ok(text.includes('1 active interfaces'));assert.ok(text.includes('Additional WAN evidence'));
assert.equal(nodes.filter(n=>n.tag==='article').length,3);const button=nodes.find(n=>n.tag==='button');assert.equal(button.type,'button');button.events.click();assert.ok(saved.open);assert.ok(focused);
const legacy=new Node('div');renderMerakiWanOverview(legacy,{});assert.equal(legacy.children.length,0);
"""
        result=subprocess.run(['node','-e',script],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
