from pathlib import Path
import shutil
import subprocess
import unittest


@unittest.skipUnless(shutil.which("node"), "Node.js required")
class MerakiWirelessUITests(unittest.TestCase):
    def test_outcomes_keep_literal_names_zero_counts_and_partial_coverage(self):
        source = (Path(__file__).parents[1] / "src/daedalus/static/js/dashboard.js").read_text()
        helper = source[source.index("  function renderMerakiWirelessConnections("):source.index("  function renderMerakiDashboardDetails(")]
        script = '''const assert = require('node:assert/strict');
let lines=[];
function addMerakiDetailList(container,title,rows,render){lines=rows.map(render);}
''' + helper + '''
renderMerakiWirelessConnections({},[
 {network_name:'<script>literal</script>',status:'complete',data:{requested_timespan_seconds:86400,reported_device_count:1,expected_device_count:19,counter_coverage:'partial',observed_counter_totals:{success:0,assoc:2,auth:NaN,dhcp:'3'}}},
 {network_name:'Other',status:'unavailable',data:null}
]);
assert.ok(lines[0].includes('<script>literal</script'));
assert.ok(lines[0].includes('Successful connections: 0'));
assert.ok(lines[0].includes('1/19 assigned APs reported'));
assert.ok(lines[0].includes('partial counter coverage'));
assert.ok(lines[0].includes('Prior 24 hours'));
assert.ok(!lines[0].includes('NaN'));
assert.ok(!lines[0].includes('DHCP failures: 3'));
assert.ok(lines[0].includes('not a combined failure rate or security score'));
assert.equal(lines[1],'Other · Collection: unavailable');
'''
        result = subprocess.run(["node", "-e", script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
