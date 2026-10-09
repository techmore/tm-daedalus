"""Execute the shipped shared member/Overview controller and actual callbacks."""
import shutil
import subprocess
import unittest
from pathlib import Path

SOURCE=Path(__file__).parents[1]/'src/daedalus/static/js/memberships.js'
FIXTURE=r'''
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
class Node{
 constructor(tag='div'){this.tagName=tag;this.children=[];this.dataset={};this.events={};this.attributes={};this.parentElement=null;this._text='';this.hidden=false;this.disabled=false;this.className='';this.classList={remove:()=>{},add:()=>{}};}
 get textContent(){return this._text+this.children.map(c=>c.textContent).join(' ');}set textContent(v){this._text=v;this.children.forEach(c=>c.parentElement=null);this.children=[];}
 get childElementCount(){return this.children.length;}get firstElementChild(){return this.children[0]||null;}get nextElementSibling(){return this.parentElement?.children[this.parentElement.children.indexOf(this)+1]||null;}
 append(...nodes){nodes.forEach(n=>{n.remove();n.parentElement=this;this.children.push(n);});}
 insertBefore(n,before){if(n===before)return;n.remove();n.parentElement=this;const i=this.children.indexOf(before);if(i<0)this.children.push(n);else this.children.splice(i,0,n);}
 remove(){if(this.parentElement)this.parentElement.children=this.parentElement.children.filter(c=>c!==this);this.parentElement=null;}
 setAttribute(k,v){this.attributes[k]=v;}addEventListener(k,f){this.events[k]=f;}
 contains(n){return n===this||this.children.some(c=>c.contains(n));}focus(){document.activeElement=this;}
 querySelectorAll(s){return this.children.flatMap(c=>[(s==='[data-member-action]'&&c.dataset.memberAction||s==='.inline-confirmation'&&c.className==='inline-confirmation')?c:null,...c.querySelectorAll(s)]).filter(Boolean);}
 querySelector(s){return this.querySelectorAll(s)[0]||null;}
}
const ids={};for(const id of ['membership-list','membership-refresh','membership-read-note','membership-observed','membership-summary','member-access-note','pending-approvals'])ids[id]=new Node();
const document={getElementById:id=>ids[id]||null,createElement:tag=>new Node(tag),activeElement:null};
const window={setTimeout,clearTimeout};let requests=[],responses=[],confirmations=[],saved=0,reloads=0,stops=0;
let transport=async(path,options)=>{requests.push({path,options});const r=responses.shift();if(r instanceof Error)throw r;if(!r)throw new Error('No fixture response');return r;};
const context=vm.createContext({window,document,AbortController,Headers,Date,Number,Map,Set,JSON,Error,Array});vm.runInContext(fs.readFileSync(SOURCE,'utf8'),context);
const review=window.DaedalusMembershipReview.create({organizationId:'1',fetch:(...args)=>transport(...args),confirm:(button,message,label,run)=>confirmations.push({button,message,label,run}),onSaved:async()=>{saved++;},onSelfRoleChange:()=>{reloads++;}});
const owner={id:1,name:'Owner',email:'owner@example.org',role:'admin',status:'approved',is_self:true,state_reference:'a'.repeat(64)};
const guest={id:2,name:'Guest',email:'guest@example.net',role:'user',status:'pending',is_self:false,state_reference:'b'.repeat(64)};
const body=(extra={})=>({organization_id:1,observed_at:'2026-10-09T00:00:00Z',can_manage:true,controls_enabled:true,approved_admin_count:1,members:[owner,guest],...extra});
const reply=(data,status=200)=>({ok:status===200,status,json:async()=>data});
const all=n=>[n,...n.children.flatMap(all)];
const action=(host,id,kind,value)=>all(host).find(n=>n.dataset.memberId===String(id)&&n.dataset.memberAction===kind&&(value===undefined||n.dataset.memberValue===value));
const click=button=>button.events.click({stopPropagation(){stops++;}});
const memberList=ids['membership-list'],pendingHost=ids['pending-approvals'],refresh=ids['membership-refresh'];
'''

@unittest.skipUnless(shutil.which('node'),'Node.js required')
class MembershipReviewUITests(unittest.TestCase):
    def run_node(self,code):
        script='const SOURCE='+repr(str(SOURCE))+';\n'+FIXTURE+'\n(async()=>{'+code+r'''})().catch(e=>{console.error(e);process.exitCode=1;});'''
        result=subprocess.run(['node','-e',script],capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_saved_read_retains_members_pending_rows_focus_and_blocks_writes(self):
        self.run_node(r'''
responses.push(reply(body()));await review.load();const row=memberList.children[1],button=action(memberList,2,'decision','true'),pending=action(pendingHost,2,'decision','true');button.focus();
assert.equal(requests[0].options.headers.get('X-Daedalus-Workspace'),'1');assert.equal(requests[0].options.cache,'no-store');
responses.push(new Error('offline'));await review.load();assert.equal(memberList.children[1],row);assert.equal(action(pendingHost,2,'decision','true'),pending);assert.equal(document.activeElement,button);
assert.match(ids['membership-read-note'].textContent,/last observed/);assert.equal(button.attributes['aria-disabled'],'true');const count=requests.length;
await click(button);await click(pending);await review.load(true);assert.equal(requests.length,count);
responses.push(reply(body({observed_at:'2026-10-09T00:01:00Z'})));await review.load();assert.equal(memberList.children[1],row);assert.equal(document.activeElement,button);assert.equal(button.attributes['aria-disabled'],'false');assert.equal(ids['membership-read-note'].hidden,true);
''')

    def test_shared_decision_posts_once_and_success_survives_failed_reconciliation(self):
        self.run_node(r'''
responses.push(reply(body()));await review.load();const pending=action(pendingHost,2,'decision','true'),member=action(memberList,2,'decision','false');pending.focus();let resolve;
transport=(path,options)=>{requests.push({path,options});return new Promise(r=>resolve=r);};const saving=click(pending),count=requests.length;
await click(pending);await click(member);await review.load(true);assert.equal(requests.length,count);assert.equal(review.state.busy,true);assert.ok(stops>=3);
assert.equal(requests.at(-1).options.headers.get('X-Daedalus-Membership-State'),guest.state_reference);assert.equal(JSON.parse(requests.at(-1).options.body).approve,true);
transport=async()=>{throw new Error('follow-up offline');};resolve(reply({organization_id:1,id:2,status:'approved',role:'user'}));await saving;
assert.match(ids['member-access-note'].textContent,/was approved/);assert.match(ids['membership-read-note'].textContent,/follow-up offline/);assert.equal(saved,1);assert.equal(review.state.fresh,false);
transport=async()=>reply(body({members:[owner,{...guest,status:'approved',state_reference:'c'.repeat(64)}]}));await review.load();assert.equal(action(pendingHost,2,'decision','true'),undefined);assert.ok(document.activeElement!==pending);
assert.ok(action(memberList,2,'role','admin'));assert.match(ids['member-access-note'].textContent,/was approved/);const before=requests.length;await click(pending);assert.equal(requests.length,before);
''')

    def test_confirmation_rechecks_saved_target_and_self_transfer_requires_another_admin(self):
        self.run_node(r'''
const approved={...guest,status:'approved'};responses.push(reply(body({members:[owner,approved]})));await review.load();assert.equal(action(memberList,1,'role','user'),undefined);
await click(action(memberList,2,'role','admin'));const old=confirmations.at(-1);assert.match(old.message,/administrator access/);
responses.push(reply(body({members:[owner,{...approved,state_reference:'c'.repeat(64)}]})));await review.load();const count=requests.length;await assert.rejects(old.run(),/no longer current/);assert.equal(requests.length,count);
responses.push(reply(body({members:[owner,{...approved,role:'admin',state_reference:'d'.repeat(64)}],approved_admin_count:2})));await review.load();
await click(action(memberList,1,'role','user'));const handoff=confirmations.at(-1);assert.match(handoff.message,/other approved admins/);
responses.push(reply({organization_id:1,id:1,role:'user',changed:true}));await handoff.run();assert.equal(reloads,1);assert.equal(saved,0);
''')

    def test_malformed_cross_workspace_or_inconsistent_role_body_retains_saved_view(self):
        self.run_node(r'''
responses.push(reply(body()));await review.load();const row=memberList.children[0];
for(const extra of [{organization_id:2},{observed_at:'bad'},{approved_admin_count:2},{can_manage:'true'},{members:[owner,owner]},{members:[owner,{...guest,state_reference:'bad'}]},{can_manage:false,members:[{...owner,role:'user'},guest]}]){
 responses.push(reply(body(extra)));await review.load();assert.equal(memberList.children[0],row);assert.equal(review.state.fresh,false);assert.equal(ids['membership-read-note'].hidden,false);
}
responses.push(reply(body({can_manage:false,members:[{...owner,role:'user'}]})));await review.load();assert.equal(memberList.children.length,1);assert.equal(memberList.querySelectorAll('[data-member-action]').length,0);assert.match(ids['membership-summary'].textContent,/user membership/);
''')

    def test_first_load_deadline_supersession_and_background_preserves_confirmation(self):
        self.run_node(r'''
let expire;window.setTimeout=fn=>{expire=fn;return 1;};window.clearTimeout=()=>{};
transport=(path,options)=>new Promise((resolve,reject)=>options.signal.addEventListener('abort',()=>reject(new Error('aborted'))));const timeout=review.load();expire();await timeout;
assert.match(ids['membership-read-note'].textContent,/timed out/);assert.match(memberList.textContent,/Refresh members/);
const reads=[];transport=(path,options)=>new Promise(resolve=>reads.push({resolve,options}));const old=review.load(),current=review.load();assert.equal(reads[0].options.signal.aborted,true);
reads[1].resolve(reply(body()));await current;reads[0].resolve(reply(body({organization_id:2})));await old;assert.equal(review.state.fresh,true);
const panel=new Node();panel.className='inline-confirmation';memberList.children[0].append(panel);const count=reads.length;await review.load(true);assert.equal(reads.length,count);
''')

    def test_closed_approval_keeps_deny_remove_and_refuses_uncertain_writes(self):
        self.run_node(r'''
const approved={...guest,id:3,email:'approved@example.net',status:'approved'};responses.push(reply(body({members:[owner,guest,approved]})));await review.load();review.pauseApproval();
assert.equal(action(memberList,2,'decision','true').disabled,true);assert.equal(action(memberList,2,'decision','false').disabled,false);assert.equal(action(memberList,3,'revoke').disabled,false);
await click(action(memberList,2,'decision','true'));assert.equal(requests.length,1);await click(action(memberList,3,'revoke'));const removal=confirmations.at(-1);
responses.push(reply({organization_id:2,id:3,status:'revoked',role:'user'}));await assert.rejects(removal.run(),/could not be confirmed/);assert.equal(review.state.fresh,false);assert.equal(saved,0);
const count=requests.length;await click(action(memberList,2,'decision','false'));assert.equal(requests.length,count);
''')

    def test_background_read_keeps_actions_usable_and_cannot_overwrite_a_decision(self):
        self.run_node(r'''
responses.push(reply(body()));await review.load();const button=action(memberList,2,'decision','true');let resolveRead;
transport=(path,options)=>{requests.push({path,options});return new Promise(r=>resolveRead=r);};
const reading=review.load(true),readRequest=requests.at(-1);
assert.equal(review.state.loading,true);assert.equal(review.state.fresh,true);assert.equal(button.attributes['aria-disabled'],'false');
transport=async(path,options)=>{requests.push({path,options});return options.method==='POST'
 ?reply({organization_id:1,id:2,status:'approved',role:'user'})
 :reply(body({members:[owner,{...guest,status:'approved',state_reference:'c'.repeat(64)}]}));};
await click(button);assert.equal(readRequest.options.signal.aborted,true);
resolveRead(reply(body()));await reading;
assert.equal(review.state.body.members[1].status,'approved');assert.equal(review.state.fresh,true);assert.equal(review.state.loading,false);
assert.match(ids['member-access-note'].textContent,/was approved/);
// A failed background observation must still pause changes and retain rows.
transport=async()=>{throw new Error('offline');};await review.load(true);assert.equal(review.state.fresh,false);
assert.equal(memberList.children.length,2);assert.equal(action(memberList,2,'role','admin').attributes['aria-disabled'],'true');
''')


@unittest.skipUnless(shutil.which('node'),'Node.js required')
class MembershipRequestUITests(unittest.TestCase):
    def test_real_request_callback_bounds_transport_and_blocks_duplicate_submits(self):
        source=(SOURCE.parent/'dashboard.js').read_text()
        callback=source[source.index('  async function requestMembership('):source.index('  function setWorkspaceSelectionBusy(')]
        script=r'''
const assert=require('node:assert/strict');let handler,expire,cleared=0,posts=0,resets=0,reads=0,resolve;
const submit={disabled:false},feedback={textContent:''},form={addEventListener:(_,fn)=>handler=fn,querySelector:()=>submit,reset:()=>resets++};
const document={getElementById:id=>id==='request-access-form'?form:feedback};
const window={setTimeout:fn=>{expire=fn;return 1;},clearTimeout:()=>cleared++};
const FormData=class {get(){return 'example.org';}};
const text=(node,value)=>node.textContent=value,showError=text,clearMembershipNotice=()=>{};
async function loadWorkspaces(){reads++;}
let fetch=(path,options)=>{posts++;assert.equal(path,'/api/membership-requests');assert.equal(options.method,'POST');assert.equal(options.credentials,'same-origin');return new Promise(r=>resolve=r);};
const reply=(body,ok=true)=>({ok,json:async()=>body}),event={preventDefault(){}};
'''+callback+r'''
(async()=>{
 const sending=handler(event);assert.equal(submit.disabled,true);await handler(event);assert.equal(posts,1);
 resolve(reply({status:'pending',organization:'Example'}));await sending;
 assert.match(feedback.textContent,/Request sent to Example admin/);assert.equal(submit.disabled,false);assert.equal(resets,1);assert.equal(reads,1);assert.equal(cleared,1);
 fetch=async()=>reply({status:'revoked',organization:'Example'});await handler(event);
 assert.match(feedback.textContent,/could not be confirmed/);assert.equal(resets,1);assert.equal(submit.disabled,false);
 fetch=async()=>({ok:false,json:async()=>({detail:'Domain unavailable'})});await handler(event);assert.equal(feedback.textContent,'Domain unavailable');
 fetch=async()=>reply(null,false);await handler(event);assert.equal(feedback.textContent,'The access request could not be confirmed.');
 fetch=(path,options)=>new Promise((r,reject)=>options.signal.addEventListener('abort',()=>reject(new Error('aborted'))));
 const timeout=handler(event);expire();await timeout;
 assert.match(feedback.textContent,/whether your access request was saved before trying again/);assert.equal(submit.disabled,false);assert.equal(resets,1);
 fetch=async()=>({ok:true,json:async()=>{throw new Error('bad JSON');}});await handler(event);assert.match(feedback.textContent,/could not be confirmed/);
})().catch(e=>{console.error(e);process.exitCode=1;});
'''
        result=subprocess.run(['node','-e',script],capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr)
