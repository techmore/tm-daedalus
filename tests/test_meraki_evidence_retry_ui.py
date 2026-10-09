from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).parents[1]


@unittest.skipUnless(shutil.which('node'), 'Node.js required')
class MerakiEvidenceRetryUITests(unittest.TestCase):
    def run_ui(self, scenario):
        source = (ROOT / 'src/daedalus/static/js/dashboard.js').read_text()
        loader = source[source.index('  function fetchMerakiDashboardDetails('):source.index('  function renderMerakiActionOverview(')]
        wrappers = source[source.index('  async function loadMerakiSummaryObservations('):source.index('  function reportJobStatusSummary(')]
        dom = (ROOT / 'tests/cis_workspace_dom_fixture.js').read_text().split("const form=document.getElementById('cis-profile-form')")[0]
        dom = dom.replace("if(selector===\"[type='submit']\")", "if(selector==='summary')return n.tag==='summary';\n if(selector===\"[type='submit']\")")
        script = "const assert=require('node:assert/strict');\n" + dom + r'''
let orgId='1',calls=[],timers=new Map(),timerId=0,mode='good';
const window={setTimeout(fn){timers.set(++timerId,fn);return timerId;},clearTimeout(id){timers.delete(id);}};
const merakiDashboardDetailCache=new Map();
const body=()=>({report_id:64,organization_id:1,summary:{device_count:264},findings:[]});
function normalFetch(path,options){calls.push({path,options});
 if(mode==='failure')return Promise.reject(new Error('secret-looking transport detail'));
 if(mode==='deadline')return new Promise((resolve,reject)=>options.signal.addEventListener('abort',()=>reject(new Error('aborted'))));
 return Promise.resolve({ok:mode!=='http',json:async()=>mode==='invalid'?[]:mode==='foreign'?{...body(),organization_id:9}:mode==='wrong-report'?{...body(),report_id:60}:body()});
}
global.fetch=normalFetch;
function renderMerakiDashboardDetails(container,data){container.textContent='Saved inventory '+data.summary.device_count;}
function renderMerakiSummaryObservations(container,data){container.textContent='Saved review '+data.report_id;}
const host=new Node('details'),summary=new Node('summary'),box=new Node();host.append(summary,box);host.open=true;
const buttons=()=>box.children.filter(n=>n.tag==='button');
''' + loader + wrappers + '\n(async()=>{\n' + scenario + '\n})().catch(e=>{console.error(e);process.exit(1);});'
        result = subprocess.run(['node', '-e', script], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_failed_read_inline_retry_loads_evidence_and_restores_focus(self):
        self.run_ui(r'''
mode='failure';assert.equal(await loadMerakiDashboardDetails(64,box),false);
assert.equal(box.dataset.loaded,undefined);assert.equal(box.dataset.loading,undefined);
assert.equal(box.getAttribute('aria-busy'),'false');assert.equal(merakiDashboardDetailCache.size,0);
assert.ok(!box.textContent.includes('secret-looking'));assert.equal(buttons().length,1);
const retry=buttons()[0];retry.focus();mode='good';assert.equal(await retry.click(),true);
assert.equal(box.textContent,'Saved inventory 264');assert.equal(box.dataset.loaded,'true');
assert.equal(document.activeElement,summary);assert.equal(host.open,true);assert.equal(calls.length,2);
assert.ok(calls.every(c=>c.options.credentials==='same-origin'&&c.options.cache==='no-store'&&!c.options.method));
assert.equal(timers.size,0);
''')

    def test_reopening_failed_details_retries_without_another_loaded_marker(self):
        self.run_ui(r'''
mode='failure';await loadMerakiDashboardDetails(64,box);mode='good';
assert.equal(await loadMerakiDashboardDetails(64,box),true);assert.equal(calls.length,2);
assert.equal(await loadMerakiDashboardDetails(64,box),false);assert.equal(calls.length,2);
''')
        source = (ROOT / 'src/daedalus/static/js/dashboard.js').read_text()
        disclosure = source[source.index('        details.addEventListener("toggle"'):source.index('  function formatBytes(')]
        self.assertNotIn('detailContent.dataset.loaded = "true"', disclosure)

    def test_summary_and_open_details_share_one_pending_saved_read(self):
        self.run_ui(r'''
let resolve;fetch=(path,options)=>{calls.push({path,options});return new Promise(r=>{resolve=r;});};
const overview=new Node();const first=loadMerakiDashboardDetails(64,box),second=loadMerakiSummaryObservations(64,overview);
assert.equal(await loadMerakiDashboardDetails(64,box),false);assert.equal(calls.length,1);
resolve({ok:true,json:async()=>body()});assert.deepEqual(await Promise.all([first,second]),[true,true]);
assert.equal(overview.textContent,'Saved review 64');assert.equal(timers.size,0);
''')

    def test_bad_envelopes_and_http_errors_are_not_cached(self):
        for mode in ['invalid', 'foreign', 'wrong-report', 'http']:
            with self.subTest(mode=mode):
                self.run_ui(f"mode='{mode}';" + r'''
assert.equal(await loadMerakiSummaryObservations(64,box),false);assert.equal(merakiDashboardDetailCache.size,0);
assert.equal(box.dataset.loaded,undefined);mode='good';assert.equal(await buttons()[0].click(),true);
assert.equal(calls.length,2);assert.equal(box.textContent,'Saved review 64');
''')

    def test_deadline_recovers_and_repeat_failure_keeps_retry_focus(self):
        self.run_ui(r'''
mode='deadline';let pending=loadMerakiDashboardDetails(64,box);
for(const fn of [...timers.values()])fn();assert.equal(await pending,false);
const retry=buttons()[0];retry.focus();mode='failure';assert.equal(await retry.click(),false);
assert.equal(document.activeElement,buttons()[0]);assert.equal(box.getAttribute('aria-busy'),'false');
mode='good';assert.equal(await buttons()[0].click(),true);assert.equal(calls.length,3);
''')

    def test_retry_keeps_its_control_during_wait_and_does_not_steal_moved_focus(self):
        self.run_ui(r'''
mode='failure';await loadMerakiDashboardDetails(64,box);const retry=buttons()[0];retry.focus();
let resolve;fetch=()=>new Promise(r=>{resolve=r;});const pending=retry.click();
assert.equal(buttons()[0],retry);assert.equal(document.activeElement,retry);
assert.equal(retry.getAttribute('aria-disabled'),'true');assert.equal(await retry.click(),false);
const elsewhere=new Node('button');elsewhere.focus();resolve({ok:true,json:async()=>body()});
assert.equal(await pending,true);assert.equal(document.activeElement,elsewhere);
''')

    def test_detached_view_does_not_render_late_success_or_failure(self):
        self.run_ui(r'''
let resolve;fetch=()=>new Promise(r=>{resolve=r;});
const pending=loadMerakiDashboardDetails(64,box);box.isConnected=false;
resolve({ok:true,json:async()=>body()});assert.equal(await pending,false);
assert.equal(box.dataset.loaded,undefined);assert.equal(box.getAttribute('aria-busy'),'false');
assert.ok(!box.textContent.includes('264'));
merakiDashboardDetailCache.clear();mode='failure';fetch=normalFetch;
await loadMerakiDashboardDetails(64,box);assert.equal(buttons().length,0);
''')

    def test_invalid_ids_never_make_a_request(self):
        self.run_ui(r'''
for(const id of [0,-1,'64',NaN,1.5])await assert.rejects(fetchMerakiDashboardDetails(id));
assert.equal(calls.length,0);assert.equal(timers.size,0);
''')

    def test_shared_summary_keeps_lifecycle_and_paths_with_or_without_review_findings(self):
        source = (ROOT / 'src/daedalus/static/js/dashboard.js').read_text()
        renderer = source[source.index('  function renderMerakiSummaryObservations('):source.index('  async function loadMerakiSummaryObservations(')]
        self.run_ui(renderer + r'''
const called=[];
const names=['renderMerakiActionOverview','renderMerakiClientOverview','renderMerakiCis8Overview','renderMerakiTopologyOverview','renderMerakiProviderLifecycle','renderMerakiLifecycle','renderMerakiPaths','renderMerakiSwitchOverview','renderMerakiWanOverview','renderMerakiPlanningOverview'];
for(const name of names)globalThis[name]=()=>called.push(name);
function appendEmpty(container,text){const item=new Node();item.textContent=text;container.append(item);}
for(const findings of [[],[{status:'Review',title:'<script>literal</script>',detail:'Saved review'}]]){
 called.length=0;renderMerakiSummaryObservations(box,{findings,unifi_plan:{provider_lifecycle:{},lifecycle:{}},path_analysis:{}});
 assert.deepEqual(called,names);assert.equal(box.querySelectorAll('.audit-policy-card').length,findings.length);
 assert.ok(!box.children.some(n=>n.tag==='script'));
}
''')

    def test_retry_does_not_trigger_a_provider_audit(self):
        source = (ROOT / 'src/daedalus/static/js/dashboard.js').read_text()
        helper = source[source.index('  function fetchMerakiDashboardDetails('):source.index('  function renderMerakiActionOverview(')]
        self.assertNotIn('postJson', helper)
        self.assertNotIn('innerHTML', helper)
        self.assertIn('20000', helper)
