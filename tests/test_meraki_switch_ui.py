from pathlib import Path
import shutil
import subprocess
import unittest

@unittest.skipUnless(shutil.which('node'), 'Node.js required')
class SwitchPortUITests(unittest.TestCase):
    def test_grouped_port_evidence_unknowns_zero_literal_text_keyboard_and_overview(self):
        source=(Path(__file__).parents[1]/'src/daedalus/static/js/dashboard.js').read_text()
        helper=source[source.index('  function renderMerakiSwitchPorts('):source.index('  function renderMerakiWanUsage(')]
        script="""const assert=require('node:assert/strict');
class Node{constructor(tag){this.tag=tag;this.children=[];this.attrs={};this.textContent='';this.listeners={};}append(...items){this.children.push(...items);}setAttribute(k,v){this.attrs[k]=v;}addEventListener(k,f){this.listeners[k]=f;}}
let focused=false;const summary={focus(){focused=true},scrollIntoView(){}};const saved={open:false,querySelector(){return summary;}};
const document={createElement:tag=>new Node(tag),querySelector(selector){assert.ok(selector.includes('49'));return saved;}};
function all(n){return[n,...n.children.flatMap(all)];}
"""+helper+"""
const box=new Node('div'),evidence={switches:[{device_name:'<script>literal</script>',network_name:'HQ',status:'complete',configuration_status:'unavailable',data:{reported_port_count:1,connected_port_count:1,review_port_count:0,rows:[{port_id:'1',state:'connected',speed:'1 Gbps',is_uplink:false,traffic_kbps:{total:0},usage_kb:{total:NaN},review_prompts:[]}],additional_rows:1}}],additional_switches:2};
renderMerakiSwitchPorts(box,evidence);const nodes=all(box),text=nodes.map(n=>n.textContent).join(' ');
assert.ok(text.includes('<script>literal</script>'));assert.ok(text.includes('Unavailable'));assert.ok(!text.includes('NaN'));
assert.ok(nodes.some(n=>n.tag==='details'));assert.equal(nodes.filter(n=>n.tag==='th'&&n.attrs.scope==='col').length,8);
assert.ok(nodes.some(n=>n.tabIndex===0));assert.ok(nodes.some(n=>n.tag==='caption'));
assert.equal(nodes.find(n=>n.tag==='tbody').children[0].children[4].textContent,'0');
assert.ok(text.includes('1 more ports'));assert.ok(text.includes('2 more switches'));assert.ok(!nodes.some(n=>n.tag==='script'));
const overview=new Node('div');renderMerakiSwitchOverview(overview,{report_id:49,switch_ports:evidence});
const button=all(overview).find(n=>n.tag==='button');assert.equal(button.type,'button');button.listeners.click();assert.ok(saved.open&&focused);
const legacy=new Node('div');renderMerakiSwitchPorts(legacy,undefined);renderMerakiSwitchOverview(legacy,{});assert.equal(legacy.children.length,0);
"""
        result=subprocess.run(['node','-e',script],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertNotIn('innerHTML',helper)
