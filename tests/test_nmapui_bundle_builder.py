import subprocess
import tempfile
from pathlib import Path
import unittest
import shutil
import zipfile

from scripts.build_nmapui_source_bundle import _source_worktree_paths


class NmapUISourceProvenanceTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'), 'Node.js required')
    def test_packaged_partial_initial_message_preserves_discovered_network(self):
        archive = Path(__file__).parents[1] / 'src/daedalus/agent_bundle/nmapui-source.zip'
        with zipfile.ZipFile(archive) as bundle:
            source = bundle.read('daedalus-nmapui-source/static/js/scan_runtime.js').decode()
        start = source.index("    socket.on('initial_data', (data) => {")
        branch = source[start:source.index("    socket.emit('get_initial_data');", start)]
        script = """const assert=require('node:assert/strict');let handler;
const fields={'local-ip-value':{textContent:'10.20.0.107'},'subnet-mask-value':{textContent:'255.255.255.0'},'cidr-value':{textContent:'10.20.0.0/24'},'public-ip-value':{textContent:'observed'},'scan-target':{value:''}};
const document={getElementById:id=>fields[id]};function setText(id,value){fields[id].textContent=value;}
const socket={on:(name,callback)=>handler=callback};
""" + branch + """
handler({autoScan:{enabled:false}});
assert.equal(fields['local-ip-value'].textContent,'10.20.0.107');
assert.equal(fields['cidr-value'].textContent,'10.20.0.0/24');
assert.equal(fields['scan-target'].value,'');
handler({localIP:'10.20.0.108',mask:'255.255.255.0',cidr:'10.20.0.0/24',publicIP:''});
assert.equal(fields['local-ip-value'].textContent,'10.20.0.108');
assert.equal(fields['scan-target'].value,'10.20.0.0/24');
fields['scan-target'].value='operator-selection';handler({cidr:'10.21.0.0/24'});
assert.equal(fields['scan-target'].value,'operator-selection');
"""
        result = subprocess.run(['node', '-e', script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which('node'), 'Node.js required')
    def test_packaged_route_status_distinguishes_disabled_and_unavailable(self):
        archive = Path(__file__).parents[1] / 'src/daedalus/agent_bundle/nmapui-source.zip'
        with zipfile.ZipFile(archive) as bundle:
            source = bundle.read('daedalus-nmapui-source/static/js/discovery_ui.js').decode()
        function = source[source.index('function renderRoutePath(data)'):source.index('function updateHistoryBadge')]
        script = """const assert=require('node:assert/strict');
const route={children:[],replaceChildren(){this.children=[];},appendChild(child){this.children.push(child);}};
const document={getElementById:()=>route,createElement:()=>({})};
""" + function + """
renderRoutePath({fingerprinting_enabled:false});
assert.equal(route.children[0].textContent,'External route discovery is disabled for this scanner.');
renderRoutePath({fingerprinting_enabled:true});
assert.equal(route.children[0].textContent,'No route data available');
renderRoutePath({error:'Lookup failed'});
assert.equal(route.children[0].textContent,'Lookup failed');
"""
        result = subprocess.run(['node', '-e', script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_manifest_can_identify_uncommitted_runtime_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            subprocess.run(["git", "init", "-q", str(repository)], check=True)
            subprocess.run(["git", "-C", str(repository), "config", "user.name", "Test"], check=True)
            subprocess.run(["git", "-C", str(repository), "config", "user.email", "test@example.invalid"], check=True)
            (repository / "app.py").write_text("committed\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repository), "add", "app.py"], check=True)
            subprocess.run(["git", "-C", str(repository), "commit", "-qm", "fixture"], check=True)

            (repository / "app.py").write_text("changed\n", encoding="utf-8")
            (repository / "new.py").write_text("untracked\n", encoding="utf-8")
            (repository / "notes.txt").write_text("not packaged\n", encoding="utf-8")

            paths = _source_worktree_paths(repository, {"app.py", "new.py"})
            self.assertEqual(paths, ["app.py", "new.py"])


if __name__ == "__main__":
    unittest.main()
