import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import zipfile


class ScannerBannerCalendarTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'), 'Node required')
    def test_distributed_banner_uses_local_calendar_days(self):
        bundle = Path(__file__).parents[1] / 'src/daedalus/agent_bundle/nmapui-source.zip'
        with zipfile.ZipFile(bundle) as archive:
            source = archive.read('daedalus-nmapui-source/static/js/scan_banners.js')
        script = r"""
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const ctx={window:{},Date};vm.createContext(ctx);vm.runInContext(fs.readFileSync(process.argv[1],'utf8'),ctx);
const age=ctx.historicalScanAgeDays,now=new Date('2026-10-06T14:40:00Z');
assert.equal(age('2026-10-05T17:45:03Z',now),1);
assert.equal(age('2026-10-06T04:01:00Z',now),0);
assert.equal(age('2026-03-08T04:59:00Z',new Date('2026-03-08T07:01:00Z')),1);
for(const value of [null,'','bad','2026-10-07T14:40:00Z'])assert.equal(age(value,now),null);
"""
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'banner.js';path.write_bytes(source)
            result=subprocess.run(['node','-e',script,str(path)],env={**os.environ,'TZ':'America/New_York'},capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
