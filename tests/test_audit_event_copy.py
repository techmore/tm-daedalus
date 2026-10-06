import subprocess
import shutil
from pathlib import Path
import unittest


class AuditEventCopyTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'), 'Node.js required')
    def test_expiry_summary_distinguishes_deadline_and_observation(self):
        source = (Path(__file__).parents[1] / 'src/daedalus/static/js/dashboard.js').read_text()
        function = source[source.index('  function auditEventSummary('):source.index('  async function loadAuditLog(')]
        script = "const assert=require('node:assert/strict');const dateLabel=value=>value;" + function + """
const text=auditEventSummary({action:'probation_override.expired',details:{override_id:3,expires_at:'deadline',observed_at:'later observation'}});
assert.equal(text,'Temporary override #3 expired at deadline. Recorded when observed: later observation.');
assert.equal(auditEventSummary({action:'unrecognized',details:{}}),'');
const grant=auditEventSummary({action:'probation_override.granted',details:{override_id:4,expires_at:'new deadline',reason:'Owner approval'}});
assert.ok(grant.includes('Owner approval'));assert.ok(grant.includes('new deadline'));
"""
        result = subprocess.run(['node', '-e', script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
