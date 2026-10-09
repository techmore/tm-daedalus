"""Execute the shipped account request-review controller and DOM reconciliation."""
import shutil
import subprocess
import unittest
from pathlib import Path
import test_membership_review_ui as member_ui

SOURCE=Path(__file__).parents[1]/'src/daedalus/static/js/workspace-requests.js'
NODE=member_ui.FIXTURE[member_ui.FIXTURE.index('class Node{'):member_ui.FIXTURE.index('const ids={};')]
FIXTURE=r'''
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
'''+NODE.replace("s==='[data-member-action]'&&c.dataset.memberAction", "s==='[data-workspace-review-open]'&&c.dataset.workspaceReviewOpen")+r'''
const ids={};for(const prefix of ['dialog-workspace','account-workspace'])for(const suffix of ['list','refresh','observed','read-note'])ids[prefix+'-'+suffix]=new Node();
ids['workspace-select']=new Node('select');
const document={getElementById:id=>ids[id]||null,createElement:tag=>new Node(tag),activeElement:null};
const window={setTimeout,clearTimeout};let requests=[],responses=[],selections=[],reads=0,busy=false;
let transport=async(path,options)=>{requests.push({path,options});const r=responses.shift();if(r instanceof Error)throw r;if(!r)throw new Error('No fixture response');return r;};
const context=vm.createContext({window,document,AbortController,Date,Number,Map,Set,JSON,Error,Array});vm.runInContext(fs.readFileSync(SOURCE,'utf8'),context);
const review=window.DaedalusWorkspaceRequests.create({userId:'1',organizationId:'2',fetch:(...args)=>transport(...args),selectionBusy:()=>busy,select:(id,button)=>selections.push({id,button}),onRead:()=>reads++});
const approved={id:2,name:'CSP',domain:'cybersecuritypilot.org',role:'admin',status:'approved',membership_created_at:'2026-10-01T00:00:00Z',requested_at:null};
const pending={id:3,name:'School <img onerror=bad()>',domain:'school.example',role:'user',status:'pending',membership_created_at:'2026-10-02T00:00:00Z',requested_at:'2026-10-09T00:00:00Z'};
const body=(extra={})=>({user_id:1,observed_at:'2026-10-09T00:00:00Z',workspaces:[approved,pending],...extra});
const reply=(data,status=200)=>({ok:status===200,status,json:async()=>data});
const list=ids['dialog-workspace-list'],refresh=ids['dialog-workspace-refresh'],select=ids['workspace-select'];
const open=()=>list.querySelector('[data-workspace-review-open]');
'''


@unittest.skipUnless(shutil.which('node'),'Node.js required')
class WorkspaceRequestUITests(unittest.TestCase):
    def run_node(self,code):
        script='const SOURCE='+repr(str(SOURCE))+';\n'+FIXTURE+'\n(async()=>{'+code+r'''})().catch(e=>{console.error(e);process.exitCode=1;});'''
        result=subprocess.run(['node','-e',script],capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_saved_rows_dates_focus_literal_content_and_failed_read_retry(self):
        self.run_node(r'''
responses.push(reply(body()));assert.equal(await review.load(),true);const row=list.children[0],button=open(),option=select.children[0];button.focus();
assert.match(list.textContent,/School <img onerror=bad\(\)>/);assert.match(list.textContent,/Request recorded/);assert.match(list.textContent,/Awaiting admin approval/);
assert.equal(requests[0].options.cache,'no-store');assert.equal(requests[0].options.credentials,'same-origin');assert.ok(requests[0].options.signal);
assert.equal(select.value,'2');assert.equal(select.disabled,false);
responses.push(new Error('offline'));assert.equal(await review.load(),false);assert.equal(list.children[0],row);assert.equal(document.activeElement,button);assert.equal(select.disabled,true);
assert.match(ids['dialog-workspace-read-note'].textContent,/access is last observed/);assert.match(ids['account-workspace-observed'].textContent,/Last checked/);
await button.events.click({stopPropagation(){}});assert.equal(selections.length,0);
responses.push(reply(body({observed_at:'2026-10-09T00:01:00Z'})));await review.load();assert.equal(list.children[0],row);assert.equal(select.children[0],option);assert.equal(document.activeElement,button);assert.equal(select.disabled,false);
await button.events.click({stopPropagation(){}});assert.equal(selections[0].id,2);busy=true;review.updateControls();await button.events.click({stopPropagation(){}});assert.equal(selections.length,1);assert.equal(select.disabled,true);
''')

    def test_first_failure_disables_rendered_sidebar_and_retry_can_show_empty_account(self):
        self.run_node(r'''
responses.push(new Error('offline'));await review.load();assert.equal(select.disabled,true);assert.equal(review.canSelect(2),false);assert.match(ids['account-workspace-read-note'].textContent,/unavailable/);
responses.push(reply(body({workspaces:[]})));await review.load();assert.equal(review.state.fresh,true);assert.equal(select.children.length,0);assert.match(list.textContent,/no workspace memberships/);assert.match(ids['account-workspace-observed'].textContent,/0 approved workspaces/);
''')

    def test_wrong_account_duplicate_ids_malformed_and_future_dates_retain_view(self):
        self.run_node(r'''
responses.push(reply(body()));await review.load();const row=list.children[0];
for(const extra of [{user_id:2},{observed_at:'2099-01-01T00:00:00Z'},{observed_at:'invalid'}, {workspaces:[approved,approved]},
{workspaces:[{...approved,id:'2'}]}, {workspaces:[{...pending,status:'unknown'}]}, {workspaces:[{...pending,requested_at:undefined}]},
{workspaces:[{...pending,membership_created_at:'bad'}]}, {workspaces:[null]}, {workspaces:null}]){
responses.push(reply(body(extra)));assert.equal(await review.load(),false);assert.equal(list.children[0],row);assert.equal(select.disabled,true);assert.ok(review.state.error);
}
''')

    def test_deadline_covers_transport_and_response_body_and_older_reads_cannot_restore_access(self):
        self.run_node(r'''
let expire;window.setTimeout=(fn,ms)=>{assert.equal(ms,20000);expire=fn;return 1;};window.clearTimeout=()=>{};
transport=(path,options)=>new Promise((resolve,reject)=>options.signal.addEventListener('abort',()=>reject(new Error('aborted'))));
const timed=review.load();expire();await timed;assert.match(review.state.error,/timed out/);
let finishBody;transport=async()=>({ok:true,json:()=>new Promise(resolve=>finishBody=resolve)});
const slowBody=review.load();await new Promise(resolve=>setImmediate(resolve));expire();finishBody(body());await slowBody;assert.equal(review.state.body,null);assert.match(review.state.error,/timed out/);
const pendingReads=[];transport=(path,options)=>new Promise((resolve,reject)=>pendingReads.push({resolve,reject,options}));
const old=review.load(),current=review.load();assert.equal(pendingReads[0].options.signal.aborted,true);
pendingReads[1].resolve(reply(body({workspaces:[pending]})));await current;
pendingReads[0].resolve(reply(body()));await old;assert.equal(review.canSelect(2),false);assert.equal(review.state.body.workspaces.length,1);assert.equal(review.state.error,null);
''')

    def test_changed_or_removed_focused_row_moves_focus_and_distinguishes_unknown_request_date(self):
        self.run_node(r'''
responses.push(reply(body()));await review.load();open().focus();responses.push(reply(body({workspaces:[{...approved,status:'revoked'}, {...pending,requested_at:null}]})));await review.load();
assert.equal(document.activeElement,refresh);assert.equal(open(),null);assert.match(list.textContent,/Access removed/);assert.match(list.textContent,/Request date unavailable/);assert.equal(select.children.length,0);
responses.push(reply(body({workspaces:[{...pending,status:'denied'}]})));await review.load();assert.match(list.textContent,/Request declined/);
''')

    def test_repeated_read_keeps_review_nodes_and_pending_read_pauses_selection(self):
        self.run_node(r'''
responses.push(reply(body()));await review.load();const row=list.children[0],button=open();button.focus();
let finish;transport=()=>new Promise(resolve=>finish=resolve);const reading=review.load();assert.equal(review.canSelect(2),false);assert.equal(button.attributes['aria-disabled'],'true');assert.equal(select.disabled,true);
finish(reply(body()));await reading;assert.equal(list.children[0],row);assert.equal(document.activeElement,button);assert.equal(button.attributes['aria-disabled'],'false');
''')
