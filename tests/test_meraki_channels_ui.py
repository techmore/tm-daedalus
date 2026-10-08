from pathlib import Path
import shutil
import subprocess
import unittest


@unittest.skipUnless(shutil.which('node'), 'Node.js required')
class MerakiChannelUITests(unittest.TestCase):
    def test_channel_table_units_unknown_values_literal_text_and_semantics(self):
        source = (Path(__file__).parents[1] / 'src/daedalus/static/js/dashboard.js').read_text()
        helper = source[source.index('  function renderMerakiChannelUtilization('):source.index('  function renderMerakiWirelessConnections(')]
        script = '''const assert=require('node:assert/strict');
class Node {constructor(tag){this.tag=tag;this.children=[];this.attrs={};this.textContent='';} append(...items){this.children.push(...items);} setAttribute(k,v){this.attrs[k]=v;}}
const document={createElement:tag=>new Node(tag)};
function all(node){return [node,...node.children.flatMap(all)];}
''' + helper + '''
const box=new Node('div');
renderMerakiChannelUtilization(box,{status:'complete',data:{reported_device_count:1,expected_device_count:2,measured_band_count:1,review_band_count:1},rows:[{device_serial:'<script>literal</script>',band:'5',percentages:{wifi:0,nonWifi:NaN,total:101},review_threshold_met:true}],additional_rows:4});
const nodes=all(box),text=nodes.map(n=>n.textContent).join('\\n');
assert.ok(text.includes('<script>literal</script'));
assert.ok(text.includes('0%'));
assert.ok(text.includes('Unavailable'));
assert.ok(!text.includes('NaN'));
assert.ok(!text.includes('101%'));
assert.ok(text.includes('4 more rows'));
assert.ok(text.includes('1/2 assigned APs measured'));
assert.equal(nodes.filter(n=>n.tag==='th'&&n.attrs.scope==='col').length,6);
assert.ok(nodes.some(n=>n.tag==='caption'));
assert.ok(nodes.some(n=>n.tabIndex===0));
'''
        result = subprocess.run(['node', '-e', script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
