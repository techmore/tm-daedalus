"""Actual saved-check pager and dashboard integration, without network audits."""
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).parents[1]
JS = ROOT / 'src/daedalus/static/js'


@unittest.skipUnless(shutil.which('node'), 'Node.js required')
class SavedCheckHistoryUITests(unittest.TestCase):
    def run_node(self, code, dashboard=False):
        setup = "const assert=require('node:assert/strict');\nconst window={location:{origin:'https://portal.example'}};\n"
        setup += (JS / 'check-history.js').read_text() + '\n'
        if dashboard:
            source = (JS / 'dashboard.js').read_text()
            setup += (ROOT / 'tests/saved_check_dom_fixture.js').read_text() + '\n'
            setup += source[source.index('  function savedSuccessfulCheck('):source.index('  function renderExposureReview(')]
            setup += source[source.index('  function niktoObservationGroup('):source.index('  var niktoButton =')]
            for start, end in (
                ('  async function loadActiveExposure(', '  document.querySelectorAll("[data-load-older-active]"'),
                ('  async function loadExternalCheck(', '  document.querySelectorAll("[data-load-older-checks]"'),
            ):
                setup += source[source.index(start):source.index(end)]
        script = setup + '\n(async()=>{\n' + code + '\n})().catch(error=>{console.error(error);process.exitCode=1;});'
        result = subprocess.run(['node', '-'], input=script, text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_independent_loaded_boundaries_survive_refresh_with_new_runs_and_changes(self):
        self.run_node(r"""
let runs=[9,8,7,6,5,4],changes=[19,18,17,16,15,14],calls=[];
function response(path){const url=new URL(path,window.location.origin);calls.push(url);
 const data={check_type:'dns',domain:'example.org',latest_snapshot:null,latest_snapshot_run:null,latest_snapshot_run_id:null};
 for(const [name,ids] of [['runs',runs],['changes',changes]]){
 const before=Number(url.searchParams.get(name+'_before'))||Infinity;
 const remaining=ids.filter(id=>id<before),selected=remaining.slice(0,2);
 data[name]=selected.map(id=>({id}));data[name+'_has_more']=remaining.length>2;
 data[name+'_next_before']=remaining.length>2?selected.at(-1):null;
 }return {ok:true,json:async()=>data};
}
global.fetch=async(path,options)=>{assert.equal(options.credentials,'same-origin');assert.equal(options.cache,'no-store');assert.equal(options.method,undefined);return response(path);};
const p=window.daedalusCheckHistory.create({url:'/api/external-checks/dns',type:'dns',changed:()=>{}});
await p.refresh();await p.older('runs');await p.older('changes');
assert.deepEqual(p.state.runs.map(r=>r.id),[9,8,7,6]);assert.deepEqual(p.state.changes.map(r=>r.id),[19,18,17,16]);
runs.unshift(11,10);changes.unshift(21,20);await p.refresh();
assert.deepEqual(p.state.runs.map(r=>r.id),[11,10,9,8,7,6]);assert.deepEqual(p.state.changes.map(r=>r.id),[21,20,19,18,17,16]);
assert.equal(p.state.runsCursor,6);assert.equal(p.state.changesCursor,16);
await p.older('runs');assert.deepEqual(p.state.runs.map(r=>r.id),[11,10,9,8,7,6,5,4]);assert.equal(p.state.runsHasMore,false);
const count=calls.length;await p.older('runs');assert.equal(calls.length,count);
""")

    def test_partial_refresh_failure_retains_both_histories_and_original_metadata(self):
        self.run_node(r"""
let version=0,failure=false;
global.fetch=async(path)=>{const url=new URL(path,window.location.origin),older=url.searchParams.has('runs_before');
 if(failure&&older)throw new Error('Older request unavailable');
 const ids=older?[3,2]:version?[7,6]:[5,4];
 return {ok:true,json:async()=>({check_type:'web',domain:'example.org',latest_snapshot:null,latest_snapshot_run:null,latest_snapshot_run_id:null,
 marker:version,runs:ids.map(id=>({id})),changes:[],runs_has_more:!older,runs_next_before:older?null:ids.at(-1),changes_has_more:false,changes_next_before:null})};};
const p=window.daedalusCheckHistory.create({url:'/api/external-checks/web',type:'web',changed:()=>{}});
await p.refresh();await p.older('runs');const original=p.state.body;
version=1;failure=true;assert.equal(await p.refresh(),false);assert.equal(p.state.body,original);assert.equal(p.state.body.marker,0);
assert.deepEqual(p.state.runs.map(r=>r.id),[5,4,3,2]);assert.equal(p.state.loading,null);assert.match(p.state.error,/unavailable/);
failure=false;await p.refresh();assert.equal(p.state.error,null);assert.equal(p.state.body.marker,1);
""")

    def test_malformed_or_foreign_responses_do_not_replace_saved_evidence(self):
        self.run_node(r"""
const valid={check_type:'dns',domain:'example.org',latest_snapshot:{records:{}},latest_snapshot_run:{id:8,status:'completed'},latest_snapshot_run_id:8,
 runs:[{id:8},{id:7}],changes:[{id:12}],runs_has_more:true,runs_next_before:7,changes_has_more:false,changes_next_before:null};
let body=valid;global.fetch=async()=>({ok:true,json:async()=>body});
const p=window.daedalusCheckHistory.create({url:'/api/external-checks/dns',type:'dns',changed:()=>{}});
await p.refresh();const original=p.state.body;
for(const invalid of [{runs:[{id:8},{id:8}]},{runs:[{id:7},{id:8}]},{runs_next_before:99},{runs_has_more:'true'},
 {changes_has_more:true,changes_next_before:99},{changes:[{id:true}]},{check_type:'web'},{domain:'foreign.example'},
 {latest_snapshot_run_id:99},{latest_snapshot:[]},{latest_snapshot_run:undefined},{runs:Array.from({length:101},(_,i)=>({id:200-i}))}]){
 body={...valid,...invalid};await p.refresh();assert.equal(p.state.body,original);assert.ok(p.state.error);
}
body={...valid,runs:[{id:7}],runs_next_before:null,runs_has_more:false};await p.older('runs');
assert.equal(p.state.body,original,'cursor row cannot repeat in an older page');
""")

    def test_slow_older_success_or_failure_cannot_overwrite_a_new_refresh(self):
        self.run_node(r"""
function body(ids,more=false){return {check_type:'dns',domain:'example.org',latest_snapshot:null,latest_snapshot_run:null,latest_snapshot_run_id:null,
 runs:ids.map(id=>({id})),changes:[],runs_has_more:more,runs_next_before:more?ids.at(-1):null,changes_has_more:false,changes_next_before:null};}
let pending=[],slow=false,ids=[3,2];global.fetch=path=>{
 if(slow&&path.includes('runs_before'))return new Promise((resolve,reject)=>pending.push({resolve,reject}));
 return Promise.resolve({ok:true,json:async()=>body(ids,ids[0]===3)});};
const p=window.daedalusCheckHistory.create({url:'/api/external-checks/dns',type:'dns',changed:()=>{}});
await p.refresh();slow=true;const old=p.older('runs');ids=[5,4,3,2];await p.refresh();
pending[0].resolve({ok:true,json:async()=>body([1])});await old;assert.deepEqual(p.state.runs.map(r=>r.id),ids);
// Force another retained boundary with an older page for the stale failure case.
p.state.body.runs_has_more=true;p.state.body.runs_next_before=2;
const failed=p.older('runs');await p.refresh();pending[1].reject(new Error('Old failure'));await failed;
assert.equal(p.state.error,null);assert.deepEqual(p.state.runs.map(r=>r.id),ids);
""")

    def test_deleted_boundary_stops_after_crossing_its_id(self):
        self.run_node(r"""
let rows=[6,5,4,3,2,1],calls=0;
global.fetch=async path=>{calls++;const before=Number(new URL(path,window.location.origin).searchParams.get('runs_before'))||Infinity;
 const remaining=rows.filter(id=>id<before),page=remaining.slice(0,2);
 return {ok:true,json:async()=>({check_type:'dns',domain:'example.org',latest_snapshot:null,latest_snapshot_run:null,latest_snapshot_run_id:null,
 runs:page.map(id=>({id})),changes:[],runs_has_more:remaining.length>2,runs_next_before:remaining.length>2?page.at(-1):null,changes_has_more:false,changes_next_before:null})};};
const p=window.daedalusCheckHistory.create({url:'/api/external-checks/dns',type:'dns',changed:()=>{}});
await p.refresh();await p.older('runs');rows=[8,7,6,5,4,2,1];await p.refresh();
assert.deepEqual(p.state.runs.map(r=>r.id),[8,7,6,5,4,2]);assert.equal(p.state.runsCursor,2);assert.ok(calls<10);
""")

    def test_dashboard_failures_retain_review_history_dates_and_focus_for_all_check_types(self):
        self.run_node(r"""
for(const type of ['dns','web','web-active','web-nikto']){
 let failed=false,body=makeBody(type,[8,7],[18,17]);
 global.fetch=async(path,options)=>{assert.equal(options.method,undefined);assert.match(path,/^\/api\/external-checks\//);if(failed)throw new Error('Offline');return {ok:true,json:async()=>body};};
 const pager=savedCheckHistory(type);await pager.refresh();
 const review=document.getElementById(type==='web-active'?'web-exposure-review':type==='web-nikto'?'web-audit-review':type+'-priorities');
 const original=review.children, saved=pager.state.body;
 const button=document.querySelector('[data-refresh-check="'+type+'"]');button.focus();
 failed=true;await pager.refresh();assert.equal(pager.state.body,saved);assert.equal(review.children,original);
 assert.match(document.getElementById(type+'-history-status').textContent,/Previously loaded evidence/);
 assert.equal(document.activeElement,button);assert.equal(button.textContent,'Retry saved evidence');assert.equal(button.attributes['aria-disabled'],'false');
 failed=false;await pager.refresh();assert.equal(document.getElementById(type+'-history-status').textContent,'');
 assert.equal(button.textContent,'Refresh saved evidence');assert.equal(document.activeElement,button);
}
""", dashboard=True)

    def test_first_load_and_current_failures_are_visible_but_stale_requests_are_quiet(self):
        self.run_node(r"""
let pending=[];global.fetch=()=>new Promise((resolve,reject)=>pending.push({resolve,reject}));
const old=loadExternalCheck('dns'),newer=loadExternalCheck('dns');pending[1].resolve({ok:true,json:async()=>makeBody('dns',[9],[])});await newer;
const original=document.getElementById('dns-priorities').children;pending[0].reject(new Error('Stale failure'));await old;
assert.equal(document.getElementById('dns-priorities').children,original);assert.equal(document.getElementById('dns-history-status').textContent,'');
const first=loadActiveExposure();pending[2].reject(new Error('First request failed'));await first;
assert.match(document.getElementById('web-active-history-status').textContent,/Saved evidence is unavailable/);
assert.equal(document.querySelector('[data-refresh-check="web-active"]').textContent,'Retry saved evidence');
""", dashboard=True)

    def test_latest_success_outside_page_and_open_nikto_details_survive_refresh(self):
        self.run_node(r"""
let body=makeBody('web-nikto',[12,11],[]);body.runs[0].status='queued';body.runs[1].status='failed';
body.latest_snapshot_run={id:1,status:'completed',completed_at:'2026-10-01T00:00:00Z'};body.latest_snapshot_run_id=1;
body.latest_snapshot={findings:[{test_id:'013587',method:'GET',path:'/',description:'<script>saved observation</script>'}]};
global.fetch=async()=>({ok:true,json:async()=>body});await loadNikto();
assert.match(flatten(document.getElementById('web-audit-review')),/run #1/);assert.match(flatten(document.getElementById('web-audit-review')),/<script>saved observation/);
const host=document.getElementById('web-nikto-runs');const detail=host.querySelectorAll('[data-saved-run-id]')[1];detail.open=true;
const action=host.querySelectorAll('[data-nikto-cancel]')[0];action.focus();await loadNikto();
assert.equal(host.querySelectorAll('[data-saved-run-id]')[1].open,true);assert.equal(document.activeElement.dataset.niktoCancel,'12');
body.runs[0].status='running';await loadNikto();assert.equal(document.activeElement,document.querySelector('[data-refresh-check="web-nikto"]'));
""", dashboard=True)

    def test_busy_and_last_page_history_controls_keep_keyboard_focus(self):
        self.run_node(r"""
const pager=savedCheckHistory('dns');let body=makeBody('dns',[3,2],[]);body.runs_has_more=true;body.runs_next_before=2;
global.fetch=async()=>({ok:true,json:async()=>body});await pager.refresh();
const older=document.querySelector('[data-load-older-checks="dns"][data-page-kind="runs"]');older.focus();
let resolve;global.fetch=()=>new Promise(r=>{resolve=r;});const pending=pager.older('runs');
assert.equal(document.activeElement,older);assert.equal(older.disabled,false);assert.equal(older.attributes['aria-disabled'],'true');
resolve({ok:true,json:async()=>makeBody('dns',[1],[])});await pending;
assert.equal(older.classList.contains('hidden'),true);assert.equal(document.activeElement,document.querySelector('[data-refresh-check="dns"]'));
""", dashboard=True)

    def test_background_poll_does_not_abort_an_in_progress_review_refresh(self):
        self.run_node(r"""
let requests=[];global.fetch=()=>new Promise(resolve=>requests.push(resolve));
const exposure=loadActiveExposure();const nikto=loadNikto();
await loadActiveExposure(undefined,true);await loadNikto(undefined,true);
assert.equal(requests.length,2,'periodic polls must let retained-depth reads finish');
requests[0]({ok:true,json:async()=>makeBody('web-active',[8],[])});
requests[1]({ok:true,json:async()=>makeBody('web-nikto',[9],[])});
await Promise.all([exposure,nikto]);
assert.equal(activeExposureHistory.loading,null);assert.equal(niktoHistory.loading,null);
""", dashboard=True)

    def test_refresh_warning_remains_until_success_without_poll_announcements(self):
        self.run_node(r"""
let fail=false,resolve;global.fetch=async()=>{if(fail)throw new Error('Offline');return {ok:true,json:async()=>makeBody('dns',[4],[])};};
const pager=savedCheckHistory('dns');await pager.refresh();fail=true;await pager.refresh();
const note=document.getElementById('dns-history-status');const warning=note.textContent;
global.fetch=()=>new Promise(r=>{resolve=r;});const retry=pager.refresh();
assert.equal(note.textContent,warning);assert.match(note.textContent,/out of date/);
resolve({ok:true,json:async()=>makeBody('dns',[4],[])});await retry;assert.equal(note.textContent,'');
const poll=pager.refresh();assert.equal(note.textContent,'','healthy polls stay quiet');
resolve({ok:true,json:async()=>makeBody('dns',[4],[])});await poll;
""", dashboard=True)

    def test_template_loads_pager_before_dashboard_and_retry_controls_do_not_run_checks(self):
        template = (ROOT / 'src/daedalus/templates/dashboard.html').read_text()
        self.assertLess(template.index('/static/js/check-history.js'), template.index('/static/js/dashboard.js'))
        self.assertIn('data-refresh-check="{{ key }}"', template)
        for kind in ('web-active', 'web-nikto'):
            self.assertIn(f'data-refresh-check="{kind}"', template)
            self.assertIn(f'id="{kind}-history-status" role="status"', template)
        self.assertIn('SAVED ASSESSMENT', template)
        source = (JS / 'dashboard.js').read_text()
        binding = source[source.index('  document.querySelectorAll("[data-refresh-check]"'):source.index('  function renderExposureReview(')]
        self.assertNotIn('postJson', binding)
        self.assertIn('pager.refresh()', binding)
