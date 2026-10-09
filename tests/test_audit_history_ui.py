"""Run the shipped action-history controller and real read-only callbacks."""
import json
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT=Path(__file__).parents[1]
FIXTURE=r'''
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
class Node {
 constructor(tag='div'){this.tagName=tag;this.children=[];this.dataset={};this.events={};this.attributes={};this.parentElement=null;this._text='';this.hidden=false;this.open=false;}
 get textContent(){return this._text+this.children.map(c=>c.textContent).join(' ');}set textContent(v){this._text=v;this.children.forEach(c=>c.parentElement=null);this.children=[];}
 get firstElementChild(){return this.children[0]||null;}get nextElementSibling(){return this.parentElement?.children[this.parentElement.children.indexOf(this)+1]||null;}
 append(...nodes){nodes.forEach(n=>{n.remove();n.parentElement=this;this.children.push(n);});}
 insertBefore(n,b){if(n===b)return;n.remove();n.parentElement=this;const i=this.children.indexOf(b);if(i<0)this.children.push(n);else this.children.splice(i,0,n);}
 remove(){if(this.parentElement)this.parentElement.children=this.parentElement.children.filter(c=>c!==this);this.parentElement=null;}
 setAttribute(k,v){this.attributes[k]=v;}addEventListener(k,f){this.events[k]=f;}
 contains(n){return n===this||this.children.some(c=>c.contains(n));}focus(){document.activeElement=this;}
}
const ids={};for(const id of ['audit-log-list','audit-log-refresh','audit-log-older','audit-log-observed','audit-log-read-note'])ids[id]=new Node();
const document={getElementById:id=>ids[id]||null,createElement:tag=>new Node(tag),activeElement:null};
const window={location:{origin:'https://portal.example'},setTimeout,clearTimeout};let calls=[],responses=[];
let transport=async(path,options)=>{calls.push({path,options});const r=responses.shift();if(r instanceof Error)throw r;if(!r)throw new Error('Missing response');return r;};
const context=vm.createContext({window,document,AbortController,Headers,Date,Number,Map,Set,JSON,Error,Array,URL});
vm.runInContext(fs.readFileSync(ROOT+'/src/daedalus/static/js/history.js','utf8'),context);
vm.runInContext(fs.readFileSync(ROOT+'/src/daedalus/static/js/audit-history.js','utf8'),context);
const review=window.DaedalusAuditReview.create({organizationId:1,fetch:(...args)=>transport(...args),summary:entry=>'Saved '+entry.action});
const event=id=>({id,actor:'<script>literal</script>',action:'membership.approved',details:{email:'member@example.net'},created_at:'2026-10-09T00:00:00Z'});
const body=(rows=[3,2],extra={})=>({organization_id:1,observed_at:'2026-10-09T00:00:00Z',events:rows.map(event),total_count:3,has_more:true,next_before:rows.at(-1),...extra});
const reply=data=>({ok:true,status:200,json:async()=>data});
const list=ids['audit-log-list'],refresh=ids['audit-log-refresh'],older=ids['audit-log-older'];
'''


@unittest.skipUnless(shutil.which('node'),'Node.js required')
class AuditHistoryUITests(unittest.TestCase):
    def run_node(self,code):
        script='const ROOT='+json.dumps(str(ROOT))+';\n'+FIXTURE+'\n(async()=>{'+code+r'''})().catch(e=>{console.error(e);process.exitCode=1;});'''
        r=subprocess.run(['node','-e',script],capture_output=True,text=True,timeout=30);self.assertEqual(r.returncode,0,r.stderr)

    def test_reads_bind_workspace_and_failure_retains_open_evidence_and_focus(self):
        self.run_node(r'''
responses.push(reply(body()));await review.load();assert.equal(calls[0].options.headers.get('X-Daedalus-Workspace'),'1');assert.equal(calls[0].options.cache,'no-store');assert.equal(calls[0].options.method,undefined);
const row=list.children[0],details=row.children.at(-1),label=details.children[0];details.open=true;label.focus();assert.equal(row.children[0].children[1].textContent,'by <script>literal</script>');
responses.push(new Error('Offline'));await review.load();assert.equal(list.children[0],row);assert.equal(details.open,true);assert.equal(document.activeElement,label);assert.match(ids['audit-log-read-note'].textContent,/retained/);assert.match(ids['audit-log-observed'].textContent,/Last checked/);
responses.push(reply(body()));await review.load();assert.equal(list.children[0],row);assert.equal(details.open,true);assert.equal(document.activeElement,label);assert.equal(ids['audit-log-read-note'].hidden,true);
''')

    def test_older_callback_refresh_depth_and_final_page_focus(self):
        self.run_node(r'''
responses.push(reply(body()));await review.load();older.focus();responses.push(reply(body([1],{has_more:false,next_before:null})));await older.events.click();
await new Promise(r=>setImmediate(r));assert.deepEqual(Array.from(review.state.rows,r=>r.id),[3,2,1]);assert.equal(older.hidden,true);assert.equal(document.activeElement,refresh);
const row=list.children[1];responses.push(reply(body([4,3],{total_count:4})),reply(body([2,1],{total_count:4,has_more:false,next_before:null})));await refresh.events.click();await new Promise(r=>setImmediate(r));
assert.deepEqual(Array.from(review.state.rows,r=>r.id),[4,3,2,1]);assert.equal(list.children[2],row);assert.match(ids['audit-log-observed'].textContent,/Showing 4 of 4/);
''')

    def test_malformed_foreign_or_nonadvancing_page_does_not_replace_saved_rows(self):
        self.run_node(r'''
responses.push(reply(body()));await review.load();const row=list.children[0];
for(const invalid of [body([3,2],{organization_id:2}),body([3,2],{observed_at:'bad'}),body([3,2],{total_count:1}),body([2,3]),body([3,2],{events:[{...event(3),details:[]},event(2)]})]){
 responses.push(reply(invalid));await review.load();assert.equal(list.children[0],row);assert.ok(review.state.error);
}
responses.push(reply(body([4],{next_before:4})));await review.older();assert.equal(list.children[0],row);assert.ok(review.state.error);
''')

    def test_deadline_on_response_body_retains_first_load_retry_and_ignores_late_response(self):
        self.run_node(r'''
let expire,release;window.setTimeout=fn=>{expire=fn;return 1;};window.clearTimeout=()=>{};
transport=async(path,options)=>({ok:true,json:()=>new Promise((resolve,reject)=>{release=resolve;options.signal.addEventListener('abort',()=>reject(new Error('aborted')));})});
const pending=review.load();await new Promise(r=>setImmediate(r));expire();await pending;assert.match(review.state.error,/timed out/);assert.equal(review.state.busy,false);assert.match(ids['audit-log-read-note'].textContent,/unavailable/);
transport=async()=>reply(body());await review.load();assert.equal(review.state.error,null);assert.equal(review.state.loaded,true);
''')

    def test_superseded_read_cannot_restore_old_workspace_and_duplicate_older_is_ignored(self):
        self.run_node(r'''
const reads=[];transport=(path,options)=>new Promise(resolve=>reads.push({resolve,options}));const old=review.load(),current=review.load();assert.equal(reads[0].options.signal.aborted,true);
reads[1].resolve(reply(body()));await current;reads[0].resolve(reply(body([3,2],{organization_id:2})));await old;assert.equal(review.state.error,null);
const pending=review.older();const count=reads.length;await older.events.click();assert.equal(reads.length,count);reads.at(-1).resolve(reply(body([1],{has_more:false,next_before:null})));await pending;assert.equal(review.state.rows.length,3);
''')

    def test_empty_and_http_denial_do_not_claim_successful_read(self):
        self.run_node(r'''
responses.push({ok:false,status:403,json:async()=>({detail:'Workspace admin role required'})});await review.load();assert.equal(review.state.loaded,false);assert.match(review.state.error,/admin role/);
responses.push(reply(body([],{total_count:0,has_more:false,next_before:null})));await review.load();assert.match(list.textContent,/No workspace admin actions/);assert.equal(older.hidden,true);assert.match(ids['audit-log-observed'].textContent,/Showing 0 of 0/);
''')

    def test_direct_members_startup_and_final_boot_read_share_one_controller(self):
        self.run_node(r'''
const source=fs.readFileSync(ROOT+'/src/daedalus/static/js/dashboard.js','utf8');
const start=source.indexOf('  async function loadAuditLog() {'),end=source.indexOf('  function notificationReviewLabel(',start);
const init=source.indexOf('  var auditReview = null;'),activation=source.indexOf('  activateTab(tabFromLocation(), false);');
let creates=0,loads=0;window.DaedalusAuditReview={create:()=>{creates++;return{load:()=>{loads++;return Promise.resolve(true);}};}};
const timeline=[{position:init,code:'var auditReview = null;'},{position:activation,code:'activateTab(tabFromLocation(), false);'}].sort((a,b)=>a.position-b.position).map(item=>item.code).join('\n');
eval('var orgId=1,role="admin";function auditEventSummary(){}function tabFromLocation(){return"members";}function activateTab(){loadAuditLog();}'+source.slice(start,end)+timeline+'\nloadAuditLog();');
assert.equal(creates,1);assert.equal(loads,2);
''')
