from pathlib import Path
import shutil
import subprocess
import unittest


@unittest.skipUnless(shutil.which('node'), 'Node.js required')
class MerakiPowerUITests(unittest.TestCase):
    def test_power_summary_and_table_keep_coverage_units_and_keyboard_semantics(self):
        source = (Path(__file__).parents[1] / 'src/daedalus/static/js/dashboard.js').read_text()
        helper = source[source.index('  function renderMerakiPowerUsage('):source.index('  function renderMerakiDashboardDetails(')]
        script = '''const assert=require('node:assert/strict');
class Node {constructor(tag){this.tag=tag;this.children=[];this.dataset={};this.attrs={};this.textContent='';} append(...items){this.children.push(...items);} setAttribute(k,v){this.attrs[k]=v;}}
const document={createElement:tag=>new Node(tag)};
function all(node){return [node,...node.children.flatMap(all)];}
''' + helper + r'''
const box=new Node('div');
renderMerakiPowerUsage(box,[
 {device_serial:'<script>literal</script>',network_name:'HQ',status:'complete',data:{energy_coverage:'partial',requested_timespan_seconds:86400,measured_energy_wh:240,measured_average_watts:10,measured_port_count:1,port_count:2}},
 {device_serial:'SW-2',status:'complete',data:{energy_coverage:'complete',requested_timespan_seconds:86400,measured_energy_wh:0,measured_average_watts:0,measured_port_count:2,port_count:2}},
 {device_serial:'SW-3',status:'unavailable',data:null},
 {device_serial:'SW-4',status:'complete',data:{energy_coverage:'complete',requested_timespan_seconds:null,measured_energy_wh:1000,measured_average_watts:42}},
],7);
const nodes=all(box), text=nodes.map(n=>n.textContent).join('\n');
assert.ok(text.includes('240 Wh'));
assert.ok(text.includes('1/4'));
assert.ok(text.includes('0 Wh'));assert.ok(text.includes('0 W'));
assert.ok(!text.includes('1,240 Wh'));assert.ok(!text.includes('1,000 Wh'));
assert.ok(text.includes('7 more switches'));
assert.ok(text.includes('Summary covers shown switches'));
assert.ok(text.includes('not establish peak demand'));
assert.ok(nodes.some(n=>n.tag==='th'&&n.scope==='row'&&n.textContent.includes('<script>literal</script>')));
assert.equal(nodes.filter(n=>n.tag==='th'&&n.scope==='col').length,5);
assert.equal(nodes.filter(n=>n.tag==='tr').length,5);
const region=nodes.find(n=>n.attrs.role==='region');
assert.equal(region.tabIndex,0);assert.equal(region.attrs['aria-label'],'Switch PoE usage table');
assert.ok(nodes.some(n=>n.tag==='caption'));
assert.ok(nodes.filter(n=>n.tag==='td').every(n=>n.dataset.label));
assert.ok(!nodes.some(n=>n.tag==='script'));
const empty=new Node('div');renderMerakiPowerUsage(empty,undefined,0);assert.equal(empty.children.length,0);
const unknown=new Node('div');renderMerakiPowerUsage(unknown,[{status:'complete',data:{requested_timespan_seconds:86400,measured_energy_wh:NaN}}],0);
assert.ok(!all(unknown).some(n=>n.textContent.includes('NaN')));
assert.ok(all(unknown).some(n=>n.tag==='dd'&&n.textContent==='Unavailable'));
'''
        result = subprocess.run(['node', '-e', script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('innerHTML', helper)

    def test_table_keeps_theme_and_scoped_scroll_rules(self):
        root = Path(__file__).parents[1] / 'src/daedalus'
        style = (root / 'static/css/app.css').read_text()
        self.assertIn('.meraki-power-scroll:focus-visible', style)
        self.assertIn('.meraki-detail-section .table-scroll { max-width: 100%; overflow-x: auto;', style)
        self.assertIn('.meraki-detail-section .table-scroll:focus-visible', style)
        self.assertIn('.meraki-power-table { min-width: 640px; }', style)
        self.assertIn('background: var(--card-surface)', style)
        template = (root / 'templates/dashboard.html').read_text()
        self.assertIn('app.css?v=daedalus-20261008-162', template)
        self.assertIn('dashboard.js?v=daedalus-20261008-162', template)
