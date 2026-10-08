from pathlib import Path
import shutil
import subprocess
import unittest


@unittest.skipUnless(shutil.which('node'), 'Node.js required')
class MerakiWanUsageUITests(unittest.TestCase):
    def test_units_unknowns_literal_text_keyboard_and_empty_evidence(self):
        source=(Path(__file__).parents[1]/'src/daedalus/static/js/dashboard.js').read_text()
        helper=source[source.index('  function renderMerakiWanUsage('):source.index('  function renderMerakiWanuplinks(')]
        script="""const assert=require('node:assert/strict');
class Node{constructor(tag){this.tag=tag;this.children=[];this.attrs={};this.textContent='';}append(...items){this.children.push(...items);}setAttribute(k,v){this.attrs[k]=v;}}
const document={createElement:tag=>new Node(tag)};function all(n){return[n,...n.children.flatMap(all)];}
"""+helper+"""
const box=new Node('div');renderMerakiWanUsage(box,[{network_name:'<script>literal</script>',status:'complete',data:{interval_count:2,interfaces:[{interface:'wan1',reported_interval_count:2,directions:{sent:{observed_bytes:1073741824,observed_seconds:3600,measured_interval_count:1,average_mbps:0,peak_interval_average_mbps:NaN}}}],additional_interfaces:2}}]);
const nodes=all(box),text=nodes.map(n=>n.textContent).join(' ');
assert.ok(text.includes('<script>literal</script>'));assert.ok(text.includes('Unavailable'));assert.ok(!text.includes('NaN'));
assert.ok(text.includes('Upload'));assert.ok(text.includes('Download'));assert.ok(text.includes('1/2'));assert.ok(text.includes('2 more interfaces'));
assert.equal(nodes.filter(n=>n.tag==='th'&&n.attrs.scope==='col').length,7);assert.ok(nodes.some(n=>n.tag==='caption'));assert.ok(nodes.some(n=>n.tabIndex===0));
const body=nodes.find(n=>n.tag==='tbody');assert.equal(body.children[0].children[2].textContent,'1');assert.equal(body.children[0].children[3].textContent,'1');assert.equal(body.children[0].children[5].textContent,'0');
const empty=new Node('div');renderMerakiWanUsage(empty,[{status:'complete',data:{interval_count:0,interfaces:[]}}]);assert.ok(all(empty).some(n=>n.textContent.includes('Usage remains unavailable')));assert.ok(!all(empty).some(n=>n.tag==='table'));
const legacy=new Node('div');renderMerakiWanUsage(legacy,[]);assert.equal(legacy.children.length,0);
"""
        result=subprocess.run(['node','-e',script],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
