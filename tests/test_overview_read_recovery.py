"""Exercise the actual Overview loader and action callbacks, including failed reads."""
import shutil
import unittest

import test_dashboard_status_board as fixtures


@unittest.skipUnless(shutil.which("node"), "Node.js required")
class OverviewReadRecoveryTests(unittest.TestCase):
    run_node = fixtures.DashboardStatusBoardTests.run_node

    def test_failed_read_retains_nodes_focus_and_reviews_then_retry_restores_controls(self):
        self.run_node(r'''
(async()=>{
workspacePostureRead.body=null;
const rows=[area('dns','recorded',{schedule:{enabled:false,interval_hours:168}}),area('scanners','attention')];
responses.push({ok:true,json:async()=>postureBody(rows)}); await loadWorkspacePosture();
const card=evidence.children[0], list=overview.children[1], run=find(overview,node=>node.dataset.statusKey==='public-refresh');
const schedule=find(overview,node=>node.dataset.statusKey==='dns-schedule');
refreshButton.focus(); responses.push(new Error('offline')); await refreshButton.events.click();
assert.equal(evidence.children[0],card); assert.equal(overview.children[1],list); assert.equal(document.activeElement,refreshButton);
assert.equal(board.dataset.readStale,'true'); assert.equal(evidence.dataset.readStale,'true');
assert.match(observed.textContent,/Last observed 2026-10-08T21:00:00Z/); assert.match(readNote.textContent,/scanner availability and schedules are last observed/);
assert.equal(refreshButton.textContent,'Retry workspace status'); assert.equal(run.attributes['aria-disabled'],'true');
const before=requests.length; await run.events.click(); await schedule.events.click(); assert.equal(requests.length,before);
find(overview,node=>node.dataset.statusKey==='dns-review').events.click(); assert.equal(opened.key,'dns');
responses.push({ok:true,json:async()=>postureBody(rows,{assessed_at:'2026-10-08T21:01:00Z'})}); await refreshButton.events.click();
assert.equal(evidence.children[0],card); assert.equal(overview.children[1],list); assert.equal(document.activeElement,refreshButton);
assert.equal(readNote.hidden,true); assert.equal(board.dataset.readStale,'false'); assert.equal(run.attributes['aria-disabled'],'false');
assert.match(observed.textContent,/Status read 2026-10-08T21:01:00Z/);
assert.equal(requests[0].options.cache,'no-store'); assert.ok(requests[0].options.signal);
})().catch(error=>{console.error(error);process.exitCode=1;});
''', role="admin", include_loader=True)

    def test_first_failure_has_fixed_retry_and_no_false_assessment(self):
        self.run_node(r'''
(async()=>{
workspacePostureRead.body=null; responses.push({ok:false,json:async()=>({detail:'Unauthorized'})}); await loadWorkspacePosture();
assert.equal(workspacePostureRead.body,null); assert.match(flatten(overview),/unavailable/); assert.match(flatten(evidence),/has not been loaded/);
assert.equal(refreshButton.textContent,'Retry workspace status'); assert.equal(readNote.hidden,false); assert.equal(observed.textContent,'No workspace status read yet.');
responses.push({ok:true,json:async()=>postureBody([area('cis','not_assessed')])}); await refreshButton.events.click();
assert.match(flatten(overview),/Not assessed/); assert.doesNotMatch(flatten(overview),/Evidence saved/);
assert.equal(find(overview,node=>node.dataset.statusKey==='public-refresh'),null);
})().catch(error=>{console.error(error);process.exitCode=1;});
''', include_loader=True)

    def test_wrong_workspace_or_malformed_payload_cannot_replace_saved_evidence(self):
        self.run_node(r'''
(async()=>{
workspacePostureRead.body=null;
const rows=[area('dns','recorded')]; responses.push({ok:true,json:async()=>postureBody(rows)}); await loadWorkspacePosture();
const card=evidence.children[0];
for(const extra of [{organization_id:2},{can_manage:'true'},{domain:null},{assessed_at:'invalid'},
 {assessed_at:'2026-10-10T21:00:00Z'},{areas:[]},{areas:[null]},{areas:[rows[0],rows[0]]},
 {areas:[{...rows[0],key:'unapproved-route'}]},{areas:[{...rows[0],summary:null}]}]) {
 responses.push({ok:true,json:async()=>postureBody(rows,extra)}); await loadWorkspacePosture();
 assert.equal(evidence.children[0],card); assert.equal(workspacePostureRead.body.organization_id,1); assert.ok(workspacePostureRead.error);
}
})().catch(error=>{console.error(error);process.exitCode=1;});
''', role="admin", include_loader=True)

    def test_background_read_leaves_active_request_alone_and_superseded_failure_is_ignored(self):
        self.run_node(r'''
(async()=>{
workspacePostureRead.body=null; const pending=[];
fetch=(path,options)=>new Promise((resolve,reject)=>{requests.push({path,options});pending.push({resolve,reject});});
const first=loadWorkspacePosture(); const initialController=workspacePostureRead.controller;
await loadWorkspacePosture(true); assert.equal(requests.length,1);
const second=loadWorkspacePosture(); assert.equal(initialController.signal.aborted,true); assert.equal(requests.length,2);
pending[1].resolve({ok:true,json:async()=>postureBody([area('dns','recorded',{summary:'New saved evidence'})])}); await second;
const card=evidence.children[0]; pending[0].reject(new Error('Old request failed')); await first;
assert.equal(evidence.children[0],card); assert.equal(workspacePostureRead.error,null); assert.equal(workspacePostureRead.loading,false);
assert.match(flatten(evidence),/New saved evidence/); assert.equal(refreshButton.attributes['aria-busy'],'false');
})().catch(error=>{console.error(error);process.exitCode=1;});
''', include_loader=True)

    def test_deadline_aborts_pending_read_and_allows_a_retry(self):
        self.run_node(r'''
(async()=>{
workspacePostureRead.body=null; let expire=null,cleared=false;
window.setTimeout=(callback,delay)=>{assert.equal(delay,20000);expire=callback;return 42;}; window.clearTimeout=id=>{assert.equal(id,42);cleared=true;};
fetch=(path,options)=>new Promise((resolve,reject)=>options.signal.addEventListener('abort',()=>reject(new Error('aborted'))));
const read=loadWorkspacePosture(); expire(); await read;
assert.equal(cleared,true); assert.match(readNote.textContent,/timed out/); assert.equal(workspacePostureRead.loading,false); assert.equal(workspacePostureRead.controller,null);
fetch=async()=>({ok:true,json:async()=>postureBody([area('dns','recorded')])}); await refreshButton.events.click();
assert.equal(workspacePostureRead.error,null); assert.equal(readNote.hidden,true);
})().catch(error=>{console.error(error);process.exitCode=1;});
''', include_loader=True)

    def test_partial_run_retry_survives_changed_poll_and_next_full_run_resets_both_types(self):
        self.run_node(r'''
(async()=>{
workspacePostureRead.body=null; const rows=[area('dns','recorded')];
responses.push({ok:true,json:async()=>postureBody(rows)}); await loadWorkspacePosture();
const run=find(overview,node=>node.dataset.statusKey==='public-refresh');
responses.push({ok:true},{ok:false}); await run.events.click(); assert.equal(run.textContent,'Retry website');
responses.push({ok:true,json:async()=>postureBody(rows)}); await loadWorkspacePosture(true);
assert.equal(find(overview,node=>node.dataset.statusKey==='public-refresh'),run); assert.equal(run.textContent,'Retry website');
responses.push({ok:true,json:async()=>postureBody([area('dns','running')])}); await loadWorkspacePosture(true);
const changed=find(overview,node=>node.dataset.statusKey==='public-refresh'); assert.notEqual(changed,run); assert.equal(changed.textContent,'Retry website'); assert.match(flatten(overview),/DNS & email check requested/);
responses.push({ok:true},{ok:true,json:async()=>postureBody(rows)}); await changed.events.click();
assert.equal(requests.filter(r=>r.options.method==='POST').length,3);
const next=find(overview,node=>node.dataset.statusKey==='public-refresh');
responses.push({ok:true},{ok:true},{ok:true,json:async()=>postureBody(rows)}); await next.events.click();
assert.deepEqual(requests.filter(r=>r.options.method==='POST').map(r=>r.path),['/api/external-checks/dns/run','/api/external-checks/web/run','/api/external-checks/web/run','/api/external-checks/dns/run','/api/external-checks/web/run']);
})().catch(error=>{console.error(error);process.exitCode=1;});
''', role="admin", include_loader=True)

    def test_pending_mutation_blocks_duplicate_writes_and_reads_then_failure_allows_retry(self):
        self.run_node(r'''
(async()=>{
workspacePostureRead.body=null; const rows=[area('dns','recorded',{schedule:{enabled:false,interval_hours:168}})];
responses.push({ok:true,json:async()=>postureBody(rows)}); await loadWorkspacePosture();
const enable=find(overview,node=>node.dataset.statusKey==='dns-schedule'), run=find(overview,node=>node.dataset.statusKey==='public-refresh'); let rejectWrite;
fetch=(path,options)=>{requests.push({path,options});return new Promise((resolve,reject)=>{rejectWrite=reject;});};
const write=enable.events.click(); const before=requests.length;
await enable.events.click(); await run.events.click(); await loadWorkspacePosture(true); await refreshButton.events.click();
assert.equal(requests.length,before); assert.equal(workspacePostureRead.mutationBusy,true); assert.equal(refreshButton.attributes['aria-disabled'],'true');
rejectWrite(new Error('write failed')); await write;
assert.equal(workspacePostureRead.mutationBusy,false); assert.equal(enable.textContent,'Retry automatic checks'); assert.equal(enable.attributes['aria-disabled'],'false');
assert.deepEqual(JSON.parse(requests.at(-1).options.body),{enabled:true,interval_hours:168});
})().catch(error=>{console.error(error);process.exitCode=1;});
''', role="admin", include_loader=True)

    def test_new_role_removes_actions_and_old_callback_cannot_write(self):
        self.run_node(r'''
(async()=>{
workspacePostureRead.body=null; const rows=[area('dns','recorded',{schedule:{enabled:false,interval_hours:24}})];
responses.push({ok:true,json:async()=>postureBody(rows)}); await loadWorkspacePosture();
const old=find(overview,node=>node.dataset.statusKey==='public-refresh');
responses.push({ok:true,json:async()=>postureBody(rows,{can_manage:false})}); await loadWorkspacePosture();
assert.equal(find(overview,node=>node.dataset.statusKey==='public-refresh'),null); assert.equal(find(overview,node=>node.dataset.statusKey==='dns-schedule'),null);
const before=requests.length; await old.events.click(); assert.equal(requests.length,before);
assert.ok(find(overview,node=>node.dataset.statusKey==='dns-review'));
})().catch(error=>{console.error(error);process.exitCode=1;});
''', role="admin", include_loader=True)
