"""Actual customer read and workspace-selection callbacks with scoped API fixtures."""
import shutil
import subprocess
import unittest
from sqlalchemy import select

from daedalus import server
from daedalus.models import ExternalCheckSchedule, Membership
import test_active_website_flows as api_fixtures
import test_dashboard_status_board as ui_fixtures


class PortfolioMembershipFlowTests(unittest.TestCase):
    setUp = api_fixtures.ActiveWebsiteFlowsTests.setUp
    tearDown = api_fixtures.ActiveWebsiteFlowsTests.tearDown
    context = api_fixtures.ActiveWebsiteFlowsTests.context

    def test_old_tab_context_is_rejected_before_schedule_write_after_switch(self):
        original, _ = self.context()
        created = self.client.post('/api/workspaces', json={'name': 'Other tab', 'domain': 'other-tab.example'})
        other = created.json()['organization_id']
        def saved_schedules():
            with self.session_factory() as db:
                return [(row.id, row.organization_id, row.enabled, row.interval_hours, row.next_run_at)
                        for row in db.scalars(select(ExternalCheckSchedule).order_by(ExternalCheckSchedule.id))]
        before = saved_schedules()
        stale = {'X-Daedalus-Workspace': str(original)}
        self.assertEqual(self.client.get('/api/workspace-posture', headers=stale).status_code, 409)
        response = self.client.put('/api/external-checks/web/schedule', headers=stale,
                                   json={'enabled': True, 'interval_hours': 168})
        self.assertEqual(response.status_code, 409, response.text)
        self.assertIn('Workspace selection changed', response.text)
        self.assertEqual(saved_schedules(), before)
        self.assertEqual(self.client.get('/api/dashboard').json()['organization']['id'], other)
        current = {'X-Daedalus-Workspace': str(other)}
        self.assertEqual(self.client.put('/api/external-checks/web/schedule', headers=current,
                         json={'enabled': True, 'interval_hours': 168}).status_code, 200)
        self.assertEqual(self.client.get('/api/workspace-posture', headers=current).json()['organization_id'], other)

    def test_review_selects_only_approved_workspace_and_rejects_revoked_access(self):
        original, user = self.context()
        created = self.client.post('/api/workspaces', json={'name': 'Penn fixture', 'domain': 'penn-fixture.example'})
        self.assertEqual(created.status_code, 200, created.text)
        other = created.json()['organization_id']
        selected = self.client.post('/api/workspaces/select', json={'organization_id': original})
        self.assertEqual(selected.json(), {'ok': True, 'organization_id': original})
        before = self.client.get('/api/portfolio')
        self.assertEqual(before.json()['organization_id'], original)
        self.assertIs(before.json()['can_switch_workspaces'], True)
        self.assertIn(other, [row['id'] for row in before.json()['workspaces']])
        self.assertEqual(self.client.post('/api/workspaces/select', json={'organization_id': other}).json()['organization_id'], other)
        self.assertEqual(self.client.get('/api/workspace-posture').json()['organization_id'], other)
        self.client.post('/api/workspaces/select', json={'organization_id': original})
        with self.session_factory() as db:
            membership = db.scalar(select(Membership).where(Membership.organization_id == other, Membership.user_id == user))
            membership.status = 'denied'
            db.commit()
        self.assertNotIn(other, [row['id'] for row in self.client.get('/api/portfolio').json()['workspaces']])
        self.assertEqual(self.client.post('/api/workspaces/select', json={'organization_id': other}).status_code, 403)
        self.assertEqual(self.client.get('/api/workspace-posture').json()['organization_id'], original)
        self.client.post('/logout')
        self.assertEqual(self.client.get('/api/portfolio').status_code, 401)


@unittest.skipUnless(shutil.which('node'), 'Node.js required')
class PortfolioReviewUITests(unittest.TestCase):
    run_node = ui_fixtures.DashboardStatusBoardTests.run_node

    def test_dashboard_fetch_binds_workspace_without_mutating_options_or_external_requests(self):
        source = ui_fixtures.SOURCE.read_text()
        helper = source[source.index('  function fetch(url, options)'):source.index('  var postureRequestSequence')]
        script = r'''
const assert=require('node:assert/strict');const orgId='7';let recorded;
const window={fetch:async(url,options)=>{recorded={url,options};return {ok:true};}};
''' + helper + r'''
(async()=>{
const original={method:'PUT',headers:{'Content-Type':'application/json','X-Daedalus-Workspace':'99'},body:'{}',signal:new AbortController().signal};
const response=await fetch('/api/external-checks/web/schedule',original);
assert.equal(response.ok,true);assert.equal(recorded.options.headers.get('X-Daedalus-Workspace'),'7');
assert.equal(recorded.options.headers.get('Content-Type'),'application/json');assert.equal(recorded.options.signal,original.signal);
assert.equal(original.headers['X-Daedalus-Workspace'],'99');assert.notEqual(recorded.options,original);
await fetch('https://external.example/api/resource',original);assert.equal(recorded.options,original);
await fetch('/static/file.css',original);assert.equal(recorded.options,original);
})().catch(e=>{console.error(e);process.exitCode=1;});
'''
        result = subprocess.run(['node', '-e', script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_read_failure_retains_customer_nodes_focus_and_pauses_switch_until_retry(self):
        self.run_node(r'''
(async()=>{
const rows=[{id:2,name:'BFS',domain:'bfs.org',role:'admin',verification_status:'pending',areas:[area('meraki','attention')]}];
responses.push({ok:true,json:async()=>customerBody(rows)});await loadPortfolio();
const list=portfolio.children[1],button=find(portfolio,n=>n.dataset.selectWorkspace===2);customerRefresh.focus();
assert.equal(button.dataset.workspaceReviewTab,'overview');assert.match(flatten(portfolio),/TXT verification pending/);
responses.push(new Error('offline'));await customerRefresh.events.click();
assert.equal(portfolio.children[1],list);assert.equal(document.activeElement,customerRefresh);assert.equal(customerBoard.dataset.readStale,'true');
assert.equal(button.attributes['aria-disabled'],'true');assert.match(customerNote.textContent,/access are last observed/);assert.match(customerObserved.textContent,/Last observed/);
const before=requests.length;await selectWorkspace(2,'overview',button);assert.equal(requests.length,before);assert.equal(reloads,0);
responses.push({ok:true,json:async()=>customerBody(rows,{assessed_at:'2026-10-08T21:01:00Z'})});await customerRefresh.events.click();
assert.equal(portfolio.children[1],list);assert.equal(button.attributes['aria-disabled'],'false');assert.equal(customerNote.hidden,true);assert.equal(document.activeElement,customerRefresh);
responses.push({ok:true,json:async()=>({ok:true,organization_id:2})});await selectWorkspace('2','overview',button);
assert.equal(reloads,1);assert.deepEqual(locationChanges,['/dashboard#overview']);assert.equal(JSON.parse(requests.at(-1).options.body).organization_id,2);
assert.equal(requests[0].options.cache,'no-store');assert.ok(requests[0].options.signal);
})().catch(e=>{console.error(e);process.exitCode=1;});
''', include_loader=True, include_selection=True)

    def test_switch_failure_visible_retry_and_overlapping_switch_guard(self):
        self.run_node(r'''
(async()=>{
const rows=[{id:2,name:'BFS',domain:'bfs.org',role:'member',verification_status:'pending',areas:[area('dns','not_assessed')]}];
responses.push({ok:true,json:async()=>customerBody(rows)});await loadPortfolio();const button=find(portfolio,n=>n.dataset.selectWorkspace===2);button.focus();let reject;
fetch=(path,options)=>{requests.push({path,options});return new Promise((resolve,fail)=>{reject=fail;});};
const pending=selectWorkspace(2,'overview',button);const before=requests.length;
await selectWorkspace(3);await selectWorkspace(2,'overview',button);await loadPortfolio(true);assert.equal(requests.length,before);
assert.equal(selectControl.disabled,true);assert.equal(button.attributes['aria-busy'],'true');assert.equal(selectionNote.hidden,false);
reject(new Error('transport interrupted'));await pending;
assert.equal(workspaceSelectionBusy,false);assert.equal(selectControl.disabled,false);assert.equal(selectControl.value,orgId);assert.equal(button.attributes['aria-busy'],'false');
assert.match(selectionNote.textContent,/previous workspace/);assert.equal(document.activeElement,button);assert.equal(reloads,0);assert.deepEqual(locationChanges,[]);
fetch=async()=>({ok:true,json:async()=>({ok:true,organization_id:2})});await selectWorkspace(2,null,button);
assert.equal(reloads,1);assert.deepEqual(locationChanges,[]);
})().catch(e=>{console.error(e);process.exitCode=1;});
''', include_loader=True, include_selection=True)

    def test_current_workspace_review_needs_no_post_and_mismatched_reply_does_not_navigate(self):
        self.run_node(r'''
(async()=>{
await selectWorkspace(1,'overview');assert.equal(opened.key,'overview');assert.equal(requests.length,0);assert.equal(reloads,0);
responses.push({ok:true,json:async()=>({ok:true,organization_id:3})});await selectWorkspace(2,'overview');
assert.equal(reloads,0);assert.deepEqual(locationChanges,[]);assert.match(selectionNote.textContent,/could not be confirmed/);assert.equal(workspaceSelectionBusy,false);
for(const id of [true,null,undefined,'',-1,'1.5','not-an-id']) await selectWorkspace(id);
assert.equal(requests.length,1);
})().catch(e=>{console.error(e);process.exitCode=1;});
''', include_loader=True, include_selection=True)

    def test_wrong_session_or_malformed_customer_response_retains_saved_view(self):
        self.run_node(r'''
(async()=>{
const row={id:2,name:'BFS',domain:'bfs.org',role:'admin',verification_status:'verified',areas:[area('meraki','attention')]};
responses.push({ok:true,json:async()=>customerBody([row])});await loadPortfolio();const list=portfolio.children[1];
for(const extra of [{organization_id:3},{can_switch_workspaces:'true'},{assessed_at:'invalid'},{workspaces:[row,row]},
 {workspaces:[null]},{workspaces:[{...row,id:'2'}]},{workspaces:[{...row,role:'unknown'}]},{workspaces:[{...row,areas:null}]}]) {
 responses.push({ok:true,json:async()=>customerBody([row],extra)});await loadPortfolio();assert.equal(portfolio.children[1],list);assert.ok(portfolioRead.error);
}
})().catch(e=>{console.error(e);process.exitCode=1;});
''', include_loader=True)

    def test_deadline_supersession_first_load_retry_and_removed_customer_focus(self):
        self.run_node(r'''
(async()=>{
let expire=null;window.setTimeout=(fn,ms)=>{assert.equal(ms,20000);expire=fn;return 42;};window.clearTimeout=()=>{};
fetch=(path,options)=>new Promise((resolve,reject)=>options.signal.addEventListener('abort',()=>reject(new Error('aborted'))));
const timeout=loadPortfolio();expire();await timeout;assert.equal(portfolioRead.body,null);assert.match(customerNote.textContent,/timed out/);assert.match(flatten(portfolio),/unavailable/);
const pending=[];fetch=(path,options)=>new Promise((resolve,reject)=>pending.push({resolve,reject,options}));
const old=loadPortfolio();await loadPortfolio(true);assert.equal(pending.length,1);const current=loadPortfolio();assert.equal(pending[0].options.signal.aborted,true);
const row={id:2,name:'BFS',domain:'bfs.org',role:'admin',verification_status:'verified',areas:[area('dns','recorded')]};
pending[1].resolve({ok:true,json:async()=>customerBody([row])});await current;pending[0].reject(new Error('old failure'));await old;
assert.equal(portfolioRead.error,null);assert.equal(customerNote.hidden,true);const button=find(portfolio,n=>n.dataset.selectWorkspace===2);button.focus();
fetch=async()=>({ok:true,json:async()=>customerBody([])});await customerRefresh.events.click();
assert.equal(document.activeElement,customerRefresh);assert.equal(portfolio.children[0].children[0].textContent,'No customers available');
})().catch(e=>{console.error(e);process.exitCode=1;});
''', include_loader=True)
