"""Endpoint saved evidence, setup authority, and review-context refresh behavior."""
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).parents[1]
SOURCE = ROOT / 'src/daedalus/static/js/dashboard.js'


@unittest.skipUnless(shutil.which('node'), 'Node.js required')
class CISWorkspaceRefreshUITests(unittest.TestCase):
    def run_node(self, code, actions=False):
        source = SOURCE.read_text()
        script = "const assert=require('node:assert/strict');\n" + (ROOT / 'tests/cis_workspace_dom_fixture.js').read_text()
        script += source[source.index('  function makeCISResultRow('):source.index('  var cisInstallMacOS26 =')]
        if actions:
            script += source[source.index('  var cisInstallMacOS26 ='):source.index('  document.addEventListener("click", function (event) {', source.index('  var cisInstallMacOS26 ='))]
            script += source[source.index('  function buildCISClientConfig('):source.index('  var shell =')]
            script += source[source.index('  var cisProfileForm ='):source.index('  var generateReport =')]
        script += '\n(async()=>{\n' + code + '\n})().catch(e=>{console.error(e);process.exitCode=1;});'
        result = subprocess.run(['node', '-'], input=script, text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_failed_refresh_retains_evidence_selection_focus_and_typed_form(self):
        self.run_node("""
assert.equal(await loadCIS(),true);
const picker=document.getElementById('cis-client-profile');picker.value='level-2';picker.focus();
const saved=cisWorkspaceRead.bodies,ids=['cis-summary-metrics','cis-assessment-coverage','cis-device-list','cis-profile-list','cis-report-list','cis-change-list'];
const original=ids.map(id=>document.getElementById(id).children[0]);
readFailure=true;assert.equal(await loadCIS(),false);
assert.equal(cisWorkspaceRead.bodies,saved);assert.deepEqual(ids.map(id=>document.getElementById(id).children[0]),original);
assert.equal(picker.value,'level-2');assert.equal(document.activeElement,picker);assert.equal(form.elements.description.value,'Typed notes');
assert.match(document.getElementById('cis-refresh-status').textContent,/Previously loaded.*may be out of date.*2026-10-09/);
assert.match(document.getElementById('cis-assessment-scope').textContent,/collected 2026-10-09/);
const badge=document.getElementById('cis-device-list').querySelector('[data-cis-client-state]');
assert.match(badge.textContent,/Last observed: Client checking in/);assert.equal(badge.className,'cis-device-state is-unknown');
assert.equal(document.getElementById('cis-issue-key').getAttribute('aria-disabled'),'true');assert.equal(beginCISMutation(),false);
readFailure=false;assert.equal(await loadCIS(),true);assert.equal(document.getElementById('cis-refresh-status').textContent,'');
assert.equal(badge.textContent,'Client checking in');assert.equal(badge.className,'cis-device-state is-online');assert.equal(picker.value,'level-2');
assert.equal(document.getElementById('cis-issue-key').getAttribute('aria-disabled'),'false');assert.equal(timers.size,0);
assert.ok(calls.every(c=>c.options.credentials==='same-origin'&&c.options.cache==='no-store'&&c.options.method===undefined));
""")

    def test_initial_failure_is_unavailable_and_retry_restores_saved_baseline(self):
        self.run_node("""
readFailure=true;await loadCIS();assert.equal(cisWorkspaceRead.bodies,null);
for(const id of ['cis-report-list','cis-device-list','cis-profile-list'])assert.match(document.getElementById(id).textContent,/Saved data unavailable/);
assert.match(document.getElementById('cis-key-status').textContent,/unavailable/);assert.equal(beginCISMutation(),false);
readFailure=false;await loadCIS();assert.match(document.getElementById('cis-assessment-scope').textContent,/Latest saved assessment/);
assert.equal(document.getElementById('cis-refresh-status').textContent,'');
""")

    def test_partial_http_failure_or_malformed_metadata_does_not_commit_other_lists(self):
        self.run_node("""
await loadCIS();const saved=cisWorkspaceRead.bodies;const original=structuredClone(bodies);
for(const mutate of [b=>b[1].organization_id=2,b=>b[0].observed_at='bad',b=>b[2].reports=null,b=>b[2].reports[0].summary=null,
 b=>b[2].reports[0].summary.score=101,b=>b[2].reports[0].summary.total=99,b=>b[0].assessment_counts.current=7,
 b=>b[0].devices_truncated=true,b=>b[1].profiles[0]=null,b=>b[3].changes.push(b[3].changes[0])]){
 bodies=structuredClone(original);mutate(bodies);await loadCIS();assert.equal(cisWorkspaceRead.bodies,saved);assert.ok(cisWorkspaceRead.error);
}
bodies=structuredClone(original);bodies[2].reports.unshift(report(3));
global.fetch=async(path,options)=>path.endsWith('/changes')?{ok:false,json:async()=>({detail:[{msg:'structured API validation'}]})}:normalFetch(path,options);
await loadCIS();assert.equal(cisWorkspaceRead.bodies,saved);assert.match(cisWorkspaceRead.error,/Could not load endpoint/);
""")

    def test_superseded_success_and_failure_cannot_replace_current_view(self):
        self.run_node("""
await loadCIS();let pending=[];
global.fetch=(path,options)=>new Promise((resolve,reject)=>pending.push({path,options,resolve,reject}));
const older=loadCIS();const first=pending.slice();global.fetch=normalFetch;bodies[2].reports.unshift(report(3));await loadCIS();
assert.ok(first.every(p=>p.options.signal.aborted));for(const p of first)p.resolve({ok:true,json:async()=>fixtures()[endpoints.indexOf(p.path.split('/').at(-1))]});
await older;assert.equal(cisWorkspaceRead.bodies[2].reports[0].id,3);
pending=[];global.fetch=(path,options)=>new Promise((resolve,reject)=>pending.push({resolve,reject}));const lateFailure=loadCIS();
global.fetch=normalFetch;bodies[2].reports.unshift(report(4));await loadCIS();pending.forEach(p=>p.reject(new Error('Late error')));await lateFailure;
assert.equal(cisWorkspaceRead.bodies[2].reports[0].id,4);assert.equal(cisWorkspaceRead.error,null);assert.equal(cisWorkspaceRead.loading,false);assert.equal(timers.size,0);
""")

    def test_deadline_failure_retains_evidence_and_allows_retry(self):
        self.run_node("""
await loadCIS();const saved=cisWorkspaceRead.bodies;
global.fetch=(path,options)=>new Promise((resolve,reject)=>options.signal.addEventListener('abort',()=>reject(new Error('Aborted'))));
const hung=loadCIS();assert.equal(timers.size,1);[...timers.values()][0]();await hung;
assert.equal(cisWorkspaceRead.bodies,saved);assert.match(cisWorkspaceRead.error,/timed out/);assert.equal(cisWorkspaceRead.loading,false);
global.fetch=normalFetch;await loadCIS();assert.equal(cisWorkspaceRead.error,null);assert.equal(timers.size,0);
""")

    def test_background_refresh_does_not_interrupt_review_request_or_clear_failure_early(self):
        self.run_node("""
await loadCIS();readFailure=true;await loadCIS();const warning=document.getElementById('cis-refresh-status').textContent;
let release;global.fetch=(path,options)=>new Promise(resolve=>{if(path.endsWith('/status'))release=resolve;else resolve({ok:true,json:async()=>bodies[endpoints.indexOf(path.split('/').at(-1))]});});
const retry=loadCIS();const sequence=cisWorkspaceRead.sequence;assert.equal(await loadCIS(true),false);assert.equal(cisWorkspaceRead.sequence,sequence);
assert.equal(document.getElementById('cis-refresh-status').textContent,warning);release({ok:true,json:async()=>bodies[0]});await retry;
assert.equal(document.getElementById('cis-refresh-status').textContent,'');
""")

    def test_open_report_keeps_loaded_evidence_nested_details_and_focus_when_new_report_arrives(self):
        self.run_node("""
await loadCIS();const list=document.getElementById('cis-report-list'),card=list.children[0];card.open=true;await card.emit('toggle');
const results=card.querySelector('.cis-result-list'),category=results.querySelector('.topic-secondary');category.open=true;
const button=results.querySelector('.cis-pdf-toolbar').children[0];button.focus();const detailCalls=calls.filter(c=>c.path==='/api/cis/reports/2').length;
bodies[2].reports.unshift(report(3));await loadCIS();assert.equal(list.children[1],card);assert.equal(card.open,true);assert.equal(category.open,true);
assert.equal(document.activeElement,button);assert.equal(card.querySelector('.cis-result-list'),results);assert.match(results.textContent,/Saved literal evidence/);
await card.emit('toggle');assert.equal(calls.filter(c=>c.path==='/api/cis/reports/2').length,detailCalls);
const unchanged=list.children[0];await loadCIS(true);assert.equal(list.children[0],unchanged);
""")

    def test_report_remains_visible_when_new_reports_push_it_into_earlier_group(self):
        self.run_node("""
bodies[2].reports=Array.from({length:10},(_,i)=>report(20-i));await loadCIS();const list=document.getElementById('cis-report-list');const card=list.children[9];
card.open=true;await card.emit('toggle');const button=card.querySelector('.cis-pdf-toolbar').children[0];button.focus();
bodies[2].reports.unshift(report(21));await loadCIS();const group=list.querySelector('.cis-history-group');assert.equal(group.open,true);assert.equal(group.contains(card),true);assert.equal(document.activeElement,button);
bodies[2].reports=[];await loadCIS();assert.equal(document.activeElement,document.getElementById('cis-refresh'));
""")

    def test_profile_selection_and_focused_setup_controls_survive_refresh(self):
        self.run_node("""
await loadCIS();const picker=document.getElementById('cis-client-profile');picker.value='level-2';
const issue=document.getElementById('cis-issue-key');issue.focus();const pending=loadCIS();assert.equal(issue.disabled,false);assert.equal(issue.getAttribute('aria-disabled'),'true');await pending;
assert.equal(document.activeElement,issue);assert.equal(picker.value,'level-2');
bodies[1].profiles.push({...bodies[1].profiles[0],id:3,slug:'new-profile'});await loadCIS();assert.equal(picker.value,'level-2');
bodies[1].profiles=bodies[1].profiles.filter(p=>p.slug!=='level-2');await loadCIS();assert.equal(picker.value,'level-1');
""")

    def test_device_truncation_is_explicit_and_presence_expires_on_fresh_read(self):
        self.run_node("""
bodies[0].device_count=251;bodies[0].devices=Array.from({length:250},(_,i)=>({...bodies[0].devices[0],id:i+1}));bodies[0].devices_truncated=true;bodies[0].assessment_counts={current:1,stale:0,unknown:0,missing:250};
await loadCIS();assert.match(document.getElementById('cis-device-list-scope').textContent,/250.*251.*includes all/);
bodies[0].devices[0].client_state='offline';await loadCIS(true);assert.equal(document.getElementById('cis-device-list').querySelector('[data-cis-client-state]').textContent,'Client check-in overdue');
role='user';updateCISReadControls();assert.equal(beginCISMutation(),false);
""")

    def test_successful_mutation_with_failed_read_keeps_feedback_and_prevents_repeat(self):
        self.run_node("""
const starter=document.getElementById('cis-install-starter');await starter.emit('click');assert.equal(mutations.length,0);
await loadCIS();readFailure=true;await starter.emit('click');assert.equal(mutations.length,1);
assert.match(document.getElementById('cis-profile-feedback').textContent,/published/);assert.equal(cisWorkspaceRead.invalidated,true);
assert.equal(starter.getAttribute('aria-disabled'),'true');await starter.emit('click');assert.equal(mutations.length,1);
readFailure=false;await loadCIS();assert.equal(cisWorkspaceRead.invalidated,false);assert.match(document.getElementById('cis-profile-feedback').textContent,/published/);
""", actions=True)

    def test_read_refresh_and_published_profile_guards_do_not_write_or_duplicate_installs(self):
        self.run_node("""
bodies[1].profiles.push(...['cis-macos-26-tahoe-level-1','cis-macos-26-tahoe-level-2','csp-macos-browser-baseline'].map((slug,i)=>({...bodies[1].profiles[0],id:i+3,slug,version:slug.startsWith('csp')?'1.0.0':'1.1.0'})));
await loadCIS();await document.getElementById('cis-install-macos26').emit('click');await document.getElementById('cis-install-starter').emit('click');
assert.equal(mutations.length,0);await loadCIS();assert.equal(mutations.length,0);
const template=require('node:fs').readFileSync('src/daedalus/templates/dashboard.html','utf8');assert.match(template,/id="cis-refresh"/);assert.match(template,/id="cis-client-feedback" aria-live="polite"/);
""", actions=True)

    def test_pending_setup_write_blocks_duplicate_actions_and_refresh_until_reconciled(self):
        self.run_node("""
await loadCIS();let release;postJson=(path,body)=>{mutations.push({path,body});return new Promise(resolve=>{release=resolve;});};
const starter=document.getElementById('cis-install-starter'),first=starter.emit('click');
assert.equal(cisWorkspaceRead.mutationBusy,true);await starter.emit('click');assert.equal(mutations.length,1);
const readCount=calls.length;assert.equal(await loadCIS(true),false);assert.equal(calls.length,readCount);
release({});await first;assert.equal(cisWorkspaceRead.mutationBusy,false);assert.equal(cisWorkspaceRead.invalidated,false);
""", actions=True)

    def test_key_rotation_preserves_selected_profile_and_keeps_delivery_feedback(self):
        self.run_node("""
await loadCIS();document.getElementById('cis-client-profile').value='level-2';
let config;URL.createObjectURL=blob=>{config=blob;return 'blob:fixture';};URL.revokeObjectURL=()=>{};
readFailure=true;await document.getElementById('cis-issue-key').emit('click');
assert.equal(mutations.length,1);assert.match(await config.text(),/profile_slug: \"level-2\"/);
assert.match(document.getElementById('cis-client-feedback').textContent,/Upload key rotated/);
assert.match(document.getElementById('cis-key-status').textContent,/Last observed/);
await document.getElementById('cis-issue-key').emit('click');assert.equal(mutations.length,1);
readFailure=false;await loadCIS();assert.match(document.getElementById('cis-client-feedback').textContent,/Upload key rotated/);
""", actions=True)

    def test_current_server_permissions_override_cached_admin_controls(self):
        self.run_node("""
await loadCIS();assert.equal(canManageCIS(),true);bodies[0].can_manage=false;await loadCIS();
assert.equal(canManageCIS(),false);assert.equal(document.getElementById('cis-issue-key').getAttribute('aria-disabled'),'true');
await document.getElementById('cis-issue-key').emit('click');assert.equal(mutations.length,0);
""", actions=True)

    def test_repeated_background_failure_does_not_repeat_identical_live_warning(self):
        self.run_node("""
await loadCIS();readFailure=true;await loadCIS();const note=document.getElementById('cis-refresh-status'),writes=note.textWrites;
await loadCIS(true);assert.equal(note.textWrites,writes);assert.match(note.textContent,/Could not refresh/);
readFailure=false;await loadCIS();assert.equal(note.textContent,'');const cleared=note.textWrites;
await loadCIS(true);assert.equal(note.textWrites,cleared);
""")
