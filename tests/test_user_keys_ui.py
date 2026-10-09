"""Exercise the complete shipped access-key script and its real event callbacks."""
import shutil
import subprocess
import unittest
from pathlib import Path

SOURCE = Path(__file__).parents[1] / 'src/daedalus/static/js/user_keys.js'
FIXTURE = r'''
const assert=require('node:assert/strict'),vm=require('node:vm'),fs=require('node:fs');
class Element {
 constructor(tag='div'){this.tagName=tag;this.children=[];this.events={};this.dataset={};this.attributes={};this.hidden=false;this.disabled=false;this.value='';this._text='';}
 set textContent(v){this._text=v;this.children=[];}get textContent(){return this._text+this.children.map(c=>c.textContent).join(' ');}
 append(...nodes){this.children.push(...nodes);}replaceChildren(...nodes){this.children=nodes;this._text='';}
 setAttribute(k,v){this.attributes[k]=v;}
 addEventListener(k,f){this.events[k]=f;}focus(){document.activeElement=this;}select(){this.selected=true;}
 contains(n){return n===this||this.children.some(c=>c.contains(n));}
 querySelectorAll(s){return this.children.flatMap(c=>[(s==='button'&&c.tagName==='button'||s==='.key-status'&&c.className==='key-status')?c:null,...c.querySelectorAll(s)]).filter(Boolean);}
 querySelector(s){return this.querySelectorAll(s)[0]||null;}
 reset(){for(const e of Object.values(this.elements||{}))e.value='';}
}
const ids={};for(const id of ['key-feedback','access-key-account','key-list','refresh-keys','key-read-feedback','key-observed','new-key-panel','new-key','new-key-detail','hide-new-key','key-create-note'])ids[id]=new Element();
ids['access-key-account'].dataset.organizationId='7';ids['new-key-panel'].hidden=true;
const form=ids['create-key']=new Element('form');form.elements={name:new Element('input'),expires_days:new Element('input')};form.elements.name.value='Mac client';form.elements.expires_days.value='30';form.append(new Element('button'));
const document={getElementById:id=>ids[id]||null,createElement:tag=>new Element(tag),activeElement:null};
let requests=[],responses=[],redirects=[];const location={assign:path=>redirects.push(path)};
const window={setTimeout,clearTimeout};let transport=async(path,options)=>{requests.push({path,options});const item=responses.shift();if(item instanceof Error)throw item;if(!item)throw new Error('No fixture response');return item;};
const fetch=(...args)=>transport(...args);
const key={id:1,name:'Mac client',created_at:'2026-10-08T00:00:00Z',expires_at:'2027-10-08T00:00:00Z',revoked_at:null};
const body=(extra={})=>({organization_id:7,observed_at:'2026-10-08T01:00:00Z',can_create:true,current_key_id:null,keys:[{...key}],...extra});
const reply=(data,status=200)=>({ok:status===200,status,json:async()=>data});
const tick=()=>new Promise(resolve=>setImmediate(resolve));
const submit=()=>form.events.submit({preventDefault(){}});
const refresh=()=>ids['refresh-keys'].events.click();
const buttons=()=>ids['key-list'].querySelectorAll('button');
responses.push(reply(body()));
const context=vm.createContext({document,window,location,fetch,Headers,AbortController,Date,Set,Number,JSON,Error,console});
vm.runInContext(fs.readFileSync(SOURCE,'utf8'),context);
'''

@unittest.skipUnless(shutil.which('node'), 'Node.js required')
class UserKeyUITests(unittest.TestCase):
    def run_node(self, code, setup=''):
        fixture = FIXTURE.replace("responses.push(reply(body()));", setup+"\nresponses.push(reply(body()));")
        script = 'const SOURCE='+repr(str(SOURCE))+';\n'+fixture+'\n(async()=>{await tick();'+code+r'''})().catch(e=>{console.error(e);process.exitCode=1;});'''
        result = subprocess.run(['node', '-e', script], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_failed_read_keeps_nodes_focus_and_blocks_writes_until_retry(self):
        self.run_node(r'''
const row=ids['key-list'].children[0],button=buttons()[0];button.focus();
assert.equal(requests[0].options.headers.get('X-Daedalus-Workspace'),'7');assert.equal(requests[0].options.cache,'no-store');
responses.push(new Error('offline'));await refresh();assert.equal(ids['key-list'].children[0],row);assert.equal(document.activeElement,button);
assert.match(row.textContent,/Last observed/);assert.equal(button.attributes['aria-disabled'],'true');assert.equal(form.querySelector('button').disabled,true);
const count=requests.length;await button.events.click();await submit();assert.equal(requests.length,count);
responses.push(reply(body({observed_at:'2026-10-08T02:00:00Z'})));await refresh();assert.equal(ids['key-list'].children[0],row);
assert.equal(document.activeElement,button);assert.equal(button.attributes['aria-disabled'],'false');assert.equal(ids['key-read-feedback'].hidden,true);
''')

    def test_create_once_retains_secret_after_failed_reconciliation_and_requires_save(self):
        self.run_node(r'''
let resolve;transport=(path,options)=>{requests.push({path,options});return new Promise(r=>resolve=r);};
const pending=submit(),count=requests.length;await submit();assert.equal(requests.length,count);assert.equal(form.querySelector('button').disabled,true);
transport=async(path,options)=>{requests.push({path,options});throw new Error('read interrupted');};
const token='dd_user_'+'A'.repeat(64);resolve(reply({id:2,organization_id:7,token,expires_at:key.expires_at}));await pending;
assert.equal(ids['new-key'].value,token);assert.equal(ids['new-key-panel'].hidden,false);assert.equal(ids['new-key'].selected,true);
assert.match(ids['key-feedback'].textContent,/was created/);assert.match(ids['key-read-feedback'].textContent,/read interrupted/);
await submit();assert.equal(requests.length,count+1);assert.equal(form.querySelector('button').disabled,true);
transport=async(path,options)=>{requests.push({path,options});return reply(body({keys:[{...key,id:2},key]}));};await refresh();
assert.equal(ids['new-key'].value,token);assert.equal(form.querySelector('button').disabled,true);
ids['hide-new-key'].events.click();assert.equal(ids['new-key'].value,'');assert.equal(ids['new-key-panel'].hidden,true);assert.equal(form.querySelector('button').disabled,false);
''')

    def test_revoke_once_feedback_survives_read_failure_and_focus_recovers(self):
        self.run_node(r'''
const button=buttons()[0];button.focus();let resolve;
transport=(path,options)=>{requests.push({path,options});return new Promise(r=>resolve=r);};const pending=button.events.click(),count=requests.length;
await button.events.click();await submit();await refresh();assert.equal(requests.length,count);
transport=async()=>{throw new Error('offline');};resolve(reply({status:'revoked',id:1,organization_id:7,revoked_at:'2026-10-08T02:00:00Z',ends_current_session:false}));await pending;
assert.match(ids['key-feedback'].textContent,/was revoked/);assert.match(ids['key-read-feedback'].textContent,/offline/);assert.equal(document.activeElement,button);
responses.push(reply(body({keys:[{...key,revoked_at:'2026-10-08T02:00:00Z'}]})));transport=async()=>responses.shift();await refresh();
assert.equal(buttons().length,0);assert.equal(document.activeElement,ids['refresh-keys']);assert.match(ids['key-list'].textContent,/Revoked/);
assert.match(ids['key-feedback'].textContent,/was revoked/);
''')

    def test_malformed_or_other_workspace_reply_cannot_replace_saved_keys(self):
        self.run_node(r'''
const row=ids['key-list'].children[0];
for(const extra of [{organization_id:8},{observed_at:'bad'},{can_create:'true'},{keys:[key,key]},{keys:[{...key,id:'1'}]},{keys:[{...key,expires_at:'bad'}]},{current_key_id:9}]){
 responses.push(reply(body(extra)));await refresh();assert.equal(ids['key-list'].children[0],row);assert.equal(form.querySelector('button').disabled,true);assert.equal(ids['key-read-feedback'].hidden,false);
}
''')

    def test_expired_keys_current_session_revocation_and_expired_login(self):
        self.run_node(r'''
responses.push(reply(body({keys:[{...key,expires_at:'2026-10-07T00:00:00Z'}]})));await refresh();assert.equal(buttons().length,0);assert.match(ids['key-list'].textContent,/Expired/);
responses.push(reply(body({current_key_id:1,can_create:false})));await refresh();assert.equal(form.querySelector('button').disabled,true);assert.match(ids['key-list'].textContent,/current sign-in key/);
responses.push(reply({status:'revoked',id:1,organization_id:7,revoked_at:'2026-10-08T02:00:00Z',ends_current_session:true}));await buttons()[0].events.click();assert.deepEqual(redirects,['/']);
responses.push(reply({detail:'Invalid or expired access key'},401));await refresh();assert.deepEqual(redirects,['/','/']);
''')

    def test_read_deadline_and_superseded_response_do_not_replace_current_state(self):
        self.run_node(r'''
let expire;window.setTimeout=fn=>{expire=fn;return 1;};window.clearTimeout=()=>{};
transport=(path,options)=>new Promise((resolve,reject)=>options.signal.addEventListener('abort',()=>reject(new Error('aborted'))));
const timed=refresh();expire();await timed;assert.match(ids['key-read-feedback'].textContent,/timed out/);
const pending=[];transport=(path,options)=>new Promise(resolve=>pending.push(resolve));const old=refresh(),current=refresh();
pending[1](reply(body({keys:[{...key,id:2,name:'Current'}]})));await current;pending[0](reply(body({keys:[{...key,name:'Old'}]})));await old;
assert.match(ids['key-list'].textContent,/Current/);assert.doesNotMatch(ids['key-list'].textContent,/Old/);assert.equal(ids['key-read-feedback'].hidden,true);
''')

    def test_login_pending_invalid_reply_error_and_retry(self):
        self.run_node(r'''
responses.length=0;const login=ids['token-login'];let resolve;
transport=(path,options)=>{requests.push({path,options});return new Promise(r=>resolve=r);};
const pending=login.events.submit({preventDefault(){}}),count=requests.length;
await login.events.submit({preventDefault(){}});assert.equal(requests.length,count);assert.equal(login.querySelector('button').disabled,true);
resolve(reply({detail:'Invalid or expired access key'},401));await pending;
assert.match(ids['key-feedback'].textContent,/Invalid or expired/);assert.equal(login.elements.token.value,'private-fixture');assert.deepEqual(redirects,[]);
transport=async()=>reply({});await login.events.submit({preventDefault(){}});assert.deepEqual(redirects,[]);assert.match(ids['key-feedback'].textContent,/could not be confirmed/);
transport=async()=>reply({redirect:'/dashboard'});await login.events.submit({preventDefault(){}});assert.deepEqual(redirects,['/dashboard']);assert.equal(login.elements.token.value,'');
assert.equal(requests[0].options.headers.has('X-Daedalus-Workspace'),false);
''', setup=r'''
delete ids['access-key-account'];const login=ids['token-login']=new Element('form');login.elements={token:new Element('input')};login.elements.token.value='private-fixture';login.append(new Element('button'));
''')

    def test_first_load_failure_retains_form_and_can_retry(self):
        self.run_node(r'''
assert.equal(form.elements.name.value,'Mac client');assert.equal(form.querySelector('button').disabled,true);
assert.match(ids['key-read-feedback'].textContent,/unavailable/);assert.equal(ids['key-list'].textContent,'Refresh keys to try again.');
responses.length=0;transport=async()=>responses.shift();responses.push(reply(body()));await refresh();assert.equal(form.elements.name.value,'Mac client');assert.equal(form.querySelector('button').disabled,false);
''', setup="transport=async()=>{throw new Error('initial offline');};")
