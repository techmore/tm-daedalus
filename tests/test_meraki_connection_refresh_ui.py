from pathlib import Path
import shutil
import subprocess
import unittest

ROOT=Path(__file__).parents[1]


@unittest.skipUnless(shutil.which('node'),'Node.js required')
class MerakiConnectionRefreshUITests(unittest.TestCase):
    def run_ui(self, scenario):
        source=(ROOT/'src/daedalus/static/js/dashboard.js').read_text()
        helpers=source[source.index('  var merakiOrgOptions = []'):source.index('  function makeCISResultRow(')]
        fixture=(ROOT/'tests/cis_workspace_dom_fixture.js').read_text().split("const form=document.getElementById('cis-profile-form')")[0]
        script="const assert=require('node:assert/strict');\n"+fixture+r'''
Object.defineProperty(Node.prototype,'classList',{get(){const owner=this;owner.classes??=new Set();return {toggle(name,on){if(on)owner.classes.add(name);else owner.classes.delete(name);},contains:name=>owner.classes.has(name)};}});
let orgId='1',role='admin',readFailure=false,calls=[],reportReads=0;
const text=(node,value)=>{if(node)node.textContent=value;},dateLabel=String;
const loadReports=async()=>{reportReads++;};
const timers=new Map();let timerId=0;
const window={setTimeout(fn){timers.set(++timerId,fn);return timerId;},clearTimeout(id){timers.delete(id);}};
const form=document.getElementById('meraki-key-form'),submit=new Node('button');submit.type='submit';form.append(submit);
const select=document.getElementById('meraki-org-select'),input=document.getElementById('meraki-api-key');input.value='Typed fixture key';
const approved=id=>({id,name:id+' tenant',authorized:true,granted_at:'2026-10-09T03:00:00Z'});
const initial=()=>({organization_id:1,configured:true,key_hint:'1234',last_verified_at:'2026-10-09T03:00:00Z',can_manage:true,observed_at:'2026-10-09T03:10:00Z',credential_reference:'a'.repeat(64),state_reference:'b'.repeat(64),organizations:[approved('org-one')],active_report:null});
let state=initial(),providerChoices=[{id:'org-one',name:'One tenant'},{id:'org-two',name:'Two tenant'}],referenceCounter=0;
const bump=()=>state.state_reference=require('node:crypto').createHash('sha256').update('fixture'+ ++referenceCounter).digest('hex');
let mutation=async(path,options)=>{
 if(options.headers['X-Daedalus-Meraki-State']!==state.state_reference)return {ok:false,json:async()=>({detail:'Saved Meraki connection or approvals changed.'})};
 const payload=options.body?JSON.parse(options.body):{};
 if(path==='/api/meraki/organizations')return {ok:true,json:async()=>({organization_id:1,credential_reference:state.credential_reference,state_reference:state.state_reference,organizations:providerChoices})};
 if(path==='/api/meraki/credential'&&options.method==='PUT'){
  state={...state,configured:true,key_hint:'5678',credential_reference:'c'.repeat(64),organizations:[]};bump();
  return {ok:true,json:async()=>({organization_id:1,credential_reference:state.credential_reference,state_reference:state.state_reference,organizations:providerChoices})};
 }
 if(path==='/api/meraki/credential'){state={...state,configured:false,key_hint:null,last_verified_at:null,credential_reference:null,organizations:[]};bump();}
 if(path==='/api/meraki/organization-scope'){
  if(options.method==='POST')state.organizations.push(approved(payload.meraki_organization_id));
  else state.organizations=state.organizations.filter(item=>item.id!==payload.meraki_organization_id);
  bump();
 }
 if(path==='/api/meraki/reports')state.active_report={id:70,status:'queued',stage:'Queued',progress:0};
 return {ok:true,json:async()=>({id:70,authorized:options.method==='POST'})};
};
function normalFetch(path,options={}){calls.push({path,options});
 if(path==='/api/meraki/status'){
  if(readFailure)return Promise.reject(new Error('Fixture read failure'));
  return Promise.resolve({ok:true,json:async()=>structuredClone(state)});
 }
 return mutation(path,options);
}
global.fetch=normalFetch;
const button=id=>document.getElementById(id);
const writes=()=>calls.filter(call=>call.options.method);
'''+helpers+'\n(async()=>{\n'+scenario+'\n})().catch(e=>{console.error(e);process.exit(1);});'
        result=subprocess.run(['node','-'],input=script,text=True,capture_output=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_initial_saved_read_restores_approved_choices_without_contacting_cisco(self):
        self.run_ui(r'''
assert.equal(await loadMerakiStatus(),true);assert.equal(select.value,'org-one');assert.equal(writes().length,0);
assert.equal(button('meraki-generate-report').getAttribute('aria-disabled'),'false');
assert.ok(button('meraki-connection-state').textContent.startsWith('Saved key'));
assert.ok(button('meraki-connection-observation').textContent.includes('does not query Cisco'));
assert.equal(calls[0].options.cache,'no-store');assert.equal(calls[0].options.credentials,'same-origin');
''')

    def test_failed_refresh_preserves_options_focus_and_typed_key_but_blocks_actions(self):
        self.run_ui(r'''
await loadMerakiStatus();const saved=merakiWorkspaceRead.body,option=select.children[0];select.focus();
readFailure=true;assert.equal(await loadMerakiStatus(),false);assert.equal(merakiWorkspaceRead.body,saved);
assert.equal(select.children[0],option);assert.equal(document.activeElement,select);assert.equal(input.value,'Typed fixture key');
assert.match(button('meraki-connection-state').textContent,/Last observed/);assert.match(button('meraki-connection-refresh-status').textContent,/Last successful/);
assert.equal(button('meraki-generate-report').getAttribute('aria-disabled'),'true');
await button('meraki-generate-report').click();await button('meraki-remove-key').click();await form.emit('submit',{preventDefault(){}});
assert.equal(writes().length,0);readFailure=false;await button('meraki-refresh-connection').click();
assert.equal(merakiWorkspaceRead.error,null);assert.equal(select.children[0],option);assert.equal(button('meraki-generate-report').getAttribute('aria-disabled'),'false');
''')

    def test_initial_failure_is_unknown_and_repeat_failure_is_quiet(self):
        self.run_ui(r'''
readFailure=true;await loadMerakiStatus();assert.equal(merakiWorkspaceRead.body,null);
assert.equal(button('meraki-connection-state').textContent,'Saved connection unavailable');
const status=button('meraki-connection-refresh-status'),count=status.textWrites;
await loadMerakiStatus(true);assert.equal(status.textWrites,count);assert.equal(merakiActionAllowed('save'),false);
''')

    def test_malformed_or_foreign_read_keeps_previous_saved_context(self):
        self.run_ui(r'''
await loadMerakiStatus();const saved=merakiWorkspaceRead.body,base=structuredClone(state);
for(const corrupt of [body=>body.organization_id=2,body=>body.observed_at='invalid',body=>body.state_reference='short',body=>body.configured='yes',body=>body.organizations.push(body.organizations[0]),body=>body.organizations[0].granted_at=null,body=>body.active_report={id:1,status:'completed',stage:'Done',progress:100}]){
 state=structuredClone(base);corrupt(state);assert.equal(await loadMerakiStatus(),false);assert.equal(merakiWorkspaceRead.body,saved);
}
state=base;await loadMerakiStatus();assert.equal(merakiWorkspaceRead.error,null);
''')

    def test_newer_read_wins_over_superseded_success_or_failure(self):
        self.run_ui(r'''
await loadMerakiStatus();let pending=[];fetch=(path,options)=>new Promise((resolve,reject)=>pending.push({resolve,reject,options}));
const old=loadMerakiStatus(),first=pending[0];fetch=normalFetch;state.organizations=[approved('org-two')];bump();await loadMerakiStatus();
assert.equal(first.options.signal.aborted,true);first.resolve({ok:true,json:async()=>initial()});await old;
assert.equal(merakiWorkspaceRead.body.organizations[0].id,'org-two');
fetch=(path,options)=>new Promise((resolve,reject)=>pending.push({resolve,reject,options}));const late=loadMerakiStatus();fetch=normalFetch;await loadMerakiStatus();pending.at(-1).reject(new Error('late'));
await late;assert.equal(merakiWorkspaceRead.error,null);assert.equal(timers.size,0);
''')

    def test_deadline_recovers_and_background_read_does_not_interrupt_retry(self):
        self.run_ui(r'''
await loadMerakiStatus();const saved=merakiWorkspaceRead.body;
fetch=(path,options)=>new Promise((resolve,reject)=>options.signal.addEventListener('abort',()=>reject(new Error('aborted'))));
const pending=loadMerakiStatus(),sequence=merakiWorkspaceRead.sequence;
assert.equal(await loadMerakiStatus(true),false);assert.equal(merakiWorkspaceRead.sequence,sequence);
[...timers.values()][0]();await pending;assert.match(merakiWorkspaceRead.error,/timed out/);assert.equal(merakiWorkspaceRead.body,saved);
fetch=normalFetch;await loadMerakiStatus();assert.equal(merakiWorkspaceRead.error,null);assert.equal(timers.size,0);
''')

    def test_explicit_provider_refresh_preserves_choices_and_updates_approval_flags(self):
        self.run_ui(r'''
await loadMerakiStatus();await button('meraki-load-organizations').click();assert.equal(writes().length,1);
select.value='org-two';select.focus();await loadMerakiStatus(true);assert.equal(select.value,'org-two');
assert.equal(merakiActionAllowed('authorize'),true);assert.equal(merakiActionAllowed('collect'),false);
await button('meraki-authorize-org').click();assert.equal(select.value,'org-two');assert.equal(document.activeElement,select);
assert.equal(merakiActionAllowed('authorize'),false);assert.equal(merakiActionAllowed('collect'),true);
assert.equal(merakiOrgOptions.length,2);assert.ok(writes().every(call=>call.options.headers['X-Daedalus-Meraki-State']));
''')

    def test_replaced_key_discards_old_provider_catalog_and_requires_explicit_new_selection(self):
        self.run_ui(r'''
await loadMerakiStatus();await loadMerakiOrganizations();select.value='org-two';
state={...state,credential_reference:'d'.repeat(64),organizations:[]};bump();await loadMerakiStatus();
assert.equal(merakiWorkspaceRead.providerOptions,null);assert.equal(select.value,'org-two');
assert.ok(select.children.some(option=>option.disabled&&option.value==='org-two'));assert.equal(merakiActionAllowed('authorize'),false);
providerChoices=[{id:'new-org',name:'New tenant'}];await loadMerakiOrganizations();assert.equal(merakiActionAllowed('authorize'),false);
select.value='new-org';assert.equal(merakiActionAllowed('authorize'),true);
''')

    def test_missing_provider_choice_blocks_collection_but_allows_revocation(self):
        self.run_ui(r'''
await loadMerakiStatus();providerChoices=[{id:'org-two',name:'Two tenant'}];await loadMerakiOrganizations();
assert.equal(select.value,'org-one');assert.equal(merakiActionAllowed('collect'),false);assert.equal(merakiActionAllowed('revoke'),true);
assert.match(button('meraki-org-scope-state').textContent,/Not returned/);await button('meraki-revoke-org').click();
assert.equal(state.organizations.length,0);assert.equal(merakiActionAllowed('collect'),false);
''')

    def test_action_serialization_and_failed_reconciliation_keep_outcome_and_block_duplicate_writes(self):
        self.run_ui(r'''
await loadMerakiStatus();let finish;mutation=(path,options)=>new Promise(resolve=>{finish=resolve;});
const pending=button('meraki-generate-report').click();assert.equal(merakiWorkspaceRead.busy,true);
assert.equal(await button('meraki-generate-report').click(),false);assert.equal(await loadMerakiStatus(),false);assert.equal(writes().length,1);
readFailure=true;finish({ok:true,json:async()=>({id:70})});await pending;
assert.match(button('meraki-feedback').textContent,/Assessment queued for org-one/);assert.ok(merakiWorkspaceRead.error);
assert.equal(merakiActionAllowed('collect'),false);assert.equal(reportReads,1);
''')

    def test_changed_server_state_refuses_the_reviewed_action_then_recovers_with_get(self):
        self.run_ui(r'''
await loadMerakiStatus();state.organizations=[];bump();const before=state.state_reference;
assert.equal(await button('meraki-generate-report').click(),false);assert.match(button('meraki-feedback').textContent,/changed/);
assert.equal(merakiWorkspaceRead.body.state_reference,before);assert.equal(merakiActionAllowed('collect'),false);
assert.equal(writes()[0].options.headers['X-Daedalus-Meraki-State'],'b'.repeat(64));
''')

    def test_active_report_and_role_changes_guard_setup_actions(self):
        self.run_ui(r'''
await loadMerakiStatus();state.active_report={id:70,status:'running',stage:'Collecting',progress:60};await loadMerakiStatus();
for(const action of ['save','remove','revoke','collect'])assert.equal(merakiActionAllowed(action),false);
assert.equal(merakiActionAllowed('load'),true);assert.match(button('meraki-org-scope-state').textContent,/Report 70 running/);
state.active_report=null;state.can_manage=false;state.key_hint=null;await loadMerakiStatus();
for(const action of ['save','load','remove','revoke','collect','authorize'])assert.equal(merakiActionAllowed(action),false);
''')

    def test_key_save_preserves_a_newly_typed_draft_and_stages_new_provider_choices(self):
        self.run_ui(r'''
state={...state,configured:false,key_hint:null,last_verified_at:null,credential_reference:null,organizations:[]};await loadMerakiStatus();
const originalMutation=mutation;let release;mutation=async(path,options)=>{await new Promise(resolve=>{release=resolve;});return originalMutation(path,options);};
const pending=form.emit('submit',{preventDefault(){}});input.value='Newly typed fixture key';release();await pending;
assert.equal(input.value,'Newly typed fixture key');assert.equal(merakiOrgOptions.length,2);
assert.equal(select.value,'org-one');assert.equal(merakiActionAllowed('authorize'),true);
assert.match(button('meraki-feedback').textContent,/Key verified and saved/);
''')

    def test_failed_action_keeps_feedback_and_selection_after_a_failed_then_successful_read(self):
        self.run_ui(r'''
await loadMerakiStatus();select.focus();mutation=async()=>({ok:false,json:async()=>({detail:'Cisco request unavailable'})});readFailure=true;
assert.equal(await button('meraki-generate-report').click(),false);assert.equal(select.value,'org-one');assert.equal(document.activeElement,select);
assert.equal(button('meraki-feedback').textContent,'Cisco request unavailable');assert.equal(merakiActionAllowed('collect'),false);
readFailure=false;await loadMerakiStatus();assert.equal(button('meraki-feedback').textContent,'Cisco request unavailable');assert.equal(merakiActionAllowed('collect'),true);
''')

    def test_invalid_provider_choices_do_not_replace_saved_catalog(self):
        self.run_ui(r'''
await loadMerakiStatus();await loadMerakiOrganizations();const saved=merakiWorkspaceRead.providerOptions;
mutation=async()=>({ok:true,json:async()=>({organization_id:2,credential_reference:'a'.repeat(64),organizations:[{id:'foreign-org',name:'Foreign'}]})});
assert.equal(await loadMerakiOrganizations(),false);assert.equal(merakiWorkspaceRead.providerOptions,saved);
assert.equal(merakiOrgOptions.some(item=>item.id==='foreign-org'),false);assert.match(button('meraki-feedback').textContent,/could not be validated/);
''')
