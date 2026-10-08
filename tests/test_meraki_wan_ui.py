from pathlib import Path
import shutil
import subprocess
import unittest


@unittest.skipUnless(shutil.which('node'), 'Node.js required')
class MerakiWanUITests(unittest.TestCase):
    def test_literal_text_keyboard_table_and_unknown_state(self):
        source = (Path(__file__).parents[1] / 'src/daedalus/static/js/dashboard.js').read_text()
        helper = source[source.index('  function renderMerakiWanuplinks('):source.index('  function renderMerakiChannelUtilization(')]
        script = """const assert=require('node:assert/strict');
class Node {constructor(tag){this.tag=tag;this.children=[];this.attrs={};this.textContent='';} append(...items){this.children.push(...items);} setAttribute(k,v){this.attrs[k]=v;}}
const document={createElement:tag=>new Node(tag)};
function all(node){return [node,...node.children.flatMap(all)];}
""" + helper + """
const box=new Node('div');
renderMerakiWanuplinks(box,{status:'complete',data:{reported_device_count:1,expected_device_count:2,interface_count:1,missing_device_count:1},rows:[{device_serial:'<script>literal</script>',network_id:'N_1',interface:'wan1',state:null}],additional_rows:4});
const nodes=all(box),text=nodes.map(n=>n.textContent).join('\\n');
assert.ok(text.includes('<script>literal</script'));
assert.ok(text.includes('unknown'));
assert.ok(text.includes('4 more interfaces'));
assert.ok(text.includes('1/2 assigned appliances reported'));
assert.equal(nodes.filter(n=>n.tag==='th'&&n.attrs.scope==='col').length,5);
assert.ok(nodes.some(n=>n.tag==='caption'));
assert.ok(nodes.some(n=>n.tabIndex===0));
const legacy=new Node('div');renderMerakiWanuplinks(legacy,{});assert.equal(legacy.children.length,0);
"""
        result = subprocess.run(['node', '-e', script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
