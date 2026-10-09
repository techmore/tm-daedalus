"""Execute the shipped customer form and its per-domain result actions."""
import shutil
import subprocess
import unittest
from pathlib import Path
import test_workspace_requests_ui as workspace_ui

SOURCE=Path(__file__).parents[1]/'src/daedalus/static/js/customer-create.js'
FIXTURE=r'''
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
'''+workspace_ui.NODE+r'''
Node.prototype.replaceChildren=function(){this.children.forEach(n=>n.parentElement=null);this.children=[];this._text='';};
const ids={};for(const id of ['create-workspace-form','customer-create-feedback','customer-create-result','customer-create-rows','customer-create-result-title','customer-create-observed','dialog-workspace-refresh'])ids[id]=new Node();
const submit=new Node('button'),input=new Node('input');ids['create-workspace-form'].querySelector=()=>submit;
let values={name:'Customer',domains:'one.example',onboarding:null,onboarding_reason:null},resets=0;
ids['create-workspace-form'].reset=()=>{resets++;values={name:'',domains:'',onboarding:null,onboarding_reason:null};};
class FormData{constructor(){this.data={...values};}get(key){return this.data[key];}}
const document={getElementById:id=>ids[id]||null,createElement:tag=>new Node(tag),querySelector:()=>input,activeElement:null};
const window={setTimeout,clearTimeout};let requests=[],responses=[],selections=[],savedReads=0,busy=false,readFailure=false;
let transport=async(path,options)=>{requests.push({path,options});const r=responses.shift();if(r instanceof Error)throw r;if(!r)throw new Error('No fixture response');return r;};
const account={state:{body:{workspaces:[]},fresh:false},canSelect:id=>account.state.fresh&&account.state.body.workspaces.some(w=>w.id===id&&w.status==='approved')};
const context=vm.createContext({window,document,FormData,AbortController,Date,Number,Map,Set,JSON,Error,Array});vm.runInContext(fs.readFileSync(SOURCE,'utf8'),context);
const creation=window.DaedalusCustomerCreation.create({userId:'1',fetch:(...args)=>transport(...args),workspaceReview:()=>account,selectionBusy:()=>busy,select:(id,button)=>selections.push({id,button}),afterSave:async()=>{savedReads++;if(readFailure)throw new Error('independent read offline');}});
const created={domain:'one.example',status:'created',organization_id:2,name:'Customer',created_at:'2026-10-09T00:00:00Z',probation_expires_at:'2026-11-08T00:00:00Z'};
const body=(extra={})=>({user_id:1,observed_at:'2026-10-09T00:00:00Z',customer:'Customer',created:1,results:[created],...extra});
const reply=(data,status=200)=>({ok:status===200,status,json:async()=>data});
const form=ids['create-workspace-form'],feedback=ids['customer-create-feedback'],rows=ids['customer-create-rows'];
const send=()=>form.events.submit({preventDefault(){}}),click=button=>button.events.click({stopPropagation(){}});
'''


@unittest.skipUnless(shutil.which('node'),'Node.js required')
class CustomerCreationUITests(unittest.TestCase):
    def test_mobile_status_columns_are_scoped_to_status_rows(self):
        css=(SOURCE.parent.parent/'css/app.css').read_text()
        self.assertIn('.status-row .status-when, .status-row .status-action-slot',css)
        self.assertNotIn('.status-verdict, .status-when, .status-action-slot',css)

    def run_node(self,code):
        script='const SOURCE='+repr(str(SOURCE))+';\n'+FIXTURE+'\n(async()=>{'+code+r'''})().catch(e=>{console.error(e);process.exitCode=1;});'''
        result=subprocess.run(['node','-e',script],capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_duplicate_submit_guard_no_implicit_selection_and_saved_feedback_survives_read_failure(self):
        self.run_node(r'''
let finish;transport=(path,options)=>{requests.push({path,options});return new Promise(resolve=>finish=resolve);};
const sending=send();assert.equal(submit.disabled,true);await send();assert.equal(requests.length,1);
assert.equal(JSON.parse(requests[0].options.body).select_created_workspace,false);assert.equal(requests[0].options.credentials,'same-origin');
readFailure=true;finish(reply(body()));await sending;assert.equal(selections.length,0);assert.equal(savedReads,1);assert.equal(submit.disabled,false);
assert.match(feedback.textContent,/workspaces saved/);assert.equal(resets,1);assert.match(rows.textContent,/awaiting verification/);assert.match(ids['customer-create-observed'].textContent,/Recorded/);
''')

    def test_partial_results_retain_draft_and_existing_domain_action_only_prefills_access(self):
        self.run_node(r'''
values.domains='one.example existing.example bad';responses.push(reply(body({results:[created,{domain:'existing.example',status:'exists'},{input:'<bad>',status:'invalid',detail:'Invalid <script>literal</script>'}]})));await send();
assert.equal(resets,0);assert.equal(values.domains,'one.example existing.example bad');assert.equal(rows.children.length,3);assert.match(rows.textContent,/Invalid <script>literal<\/script>/);
const action=rows.children[1].children[1];assert.equal(action.textContent,'Request access');await click(action);assert.equal(input.value,'existing.example');assert.equal(document.activeElement,input);assert.equal(requests.length,1);
account.state.body.workspaces=[{id:3,domain:'existing.example',status:'approved'}];account.state.fresh=true;creation.updateControls();assert.equal(action.textContent,'Open workspace');await click(action);assert.equal(selections[0].id,3);
''')

    def test_success_keeps_changed_draft_and_created_open_requires_fresh_account_access(self):
        self.run_node(r'''
let finish;transport=()=>new Promise(resolve=>finish=resolve);const sending=send();values.name='Another draft';finish(reply(body()));await sending;
assert.equal(values.name,'Another draft');assert.equal(resets,0);const button=rows.children[0].children[1];await click(button);assert.equal(selections.length,0);assert.equal(button.attributes['aria-disabled'],'true');
account.state.body.workspaces=[{id:2,domain:'one.example',status:'approved'}];account.state.fresh=true;creation.updateControls();button.focus();await click(button);assert.equal(selections[0].id,2);
account.state.fresh=false;creation.updateControls();assert.equal(document.activeElement,button);await click(button);assert.equal(selections.length,1);assert.equal(button.attributes['aria-disabled'],'true');
account.state.fresh=true;busy=true;creation.updateControls();await click(button);assert.equal(selections.length,1);
''')

    def test_unconfirmed_reply_retains_form_and_previous_confirmed_results(self):
        self.run_node(r'''
responses.push(reply(body()));await send();const row=rows.children[0];values={name:'Customer',domains:'two.example'};
for(const data of [null,body({user_id:2}),body({created:2}),body({observed_at:'2099-01-01T00:00:00Z'}),body({results:[{...created,created_at:'bad'}]}),body({results:[{...created,status:'unknown'}]})]) {
responses.push(reply(data));await send();assert.equal(rows.children[0],row);assert.equal(values.domains,'two.example');assert.match(feedback.textContent,/Refresh workspaces/);assert.equal(savedReads,1);
}
''')

    def test_timeout_covers_request_and_body_and_retains_details_without_retry(self):
        self.run_node(r'''
let expire;window.setTimeout=(fn,ms)=>{assert.equal(ms,20000);expire=fn;return 1;};window.clearTimeout=()=>{};
transport=(path,options)=>{requests.push({path,options});return new Promise((resolve,reject)=>options.signal.addEventListener('abort',()=>reject(new Error('aborted'))));};
const timed=send();expire();await timed;assert.match(feedback.textContent,/timed out/);assert.equal(values.domains,'one.example');assert.equal(resets,0);assert.equal(requests.length,1);
let finishBody;transport=async()=>({ok:true,json:()=>new Promise(resolve=>finishBody=resolve)});const slow=send();await new Promise(resolve=>setImmediate(resolve));expire();finishBody(body());await slow;
assert.equal(creation.state.body,null);assert.equal(savedReads,0);assert.match(feedback.textContent,/Refresh workspaces/);assert.equal(submit.disabled,false);
''')

    def test_validation_and_denial_do_not_clear_form_or_create_rows(self):
        self.run_node(r'''
values.name=' ';await send();assert.equal(requests.length,0);values.name='Customer';values.domains=Array(21).fill('one.example').join(' ');await send();assert.equal(requests.length,0);
values.domains='one.example';responses.push(reply({detail:'Onboarding requires platform approval'},403));await send();assert.match(feedback.textContent,/platform approval/);assert.equal(values.domains,'one.example');assert.equal(rows.children.length,0);assert.equal(resets,0);
responses.push(reply(body({created:0,results:[{domain:'one.example',status:'exists'}]})));await send();assert.equal(resets,0);assert.match(feedback.textContent,/No new workspaces/);
''')
