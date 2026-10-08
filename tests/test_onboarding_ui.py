"""Nonmodal customer review fixtures; no browser, credentials or live requests."""
import subprocess
import unittest
from pathlib import Path


HARNESS = r'''
const fs = require('fs');
const vm = require('vm');
const assert = require('assert');
const source = fs.readFileSync(process.argv[1], 'utf8');
const dueCustomer = (id = 7) => ({id, name:'Fixture Customer', domain:'fixture.example.org', onboarding:{version:1, status:'onboarding', review_required:true, review_due_at:'2026-10-01T00:00:00Z', reason:'Vendor transition'}});
function createUI(customers = [dueCustomer()], initialFailure = false) {
  const env = {rows:JSON.parse(JSON.stringify(customers)), decisions:[], events:[], getFailure:initialFailure, postFailure:null, modalCount:0, otherDialog:null};
  class Element {
    constructor(tag = 'div') {
      this.tag = tag; this.children=[]; this.handlers={}; this.dataset={}; this.open=false; this.disabled=false;
      this._text=''; this.textUpdates=0;
      const classes = new Set();
      this.classList = {toggle(name, value) { value ? classes.add(name) : classes.delete(name); }, contains:name=>classes.has(name)};
    }
    set textContent(value) { this._text=value; this.textUpdates++; }
    get textContent() { return this._text; }
    replaceChildren() { this.children=[]; }
    append(...items) { this.children.push(...items); }
    setAttribute() {}
    addEventListener(name, callback) { this.handlers[name]=callback; }
    contains(element) { return this===element || this.children.some(item=>item.contains(element)); }
    showModal() { this.open=true; env.modalCount++; env.document.activeElement=env.ids['onboarding-review-later']; }
    close() { if (!this.open) return; this.open=false; if (this.handlers.close) this.handlers.close(); }
    focus() { env.document.activeElement=this; }
    querySelectorAll(selector) {
      const names=selector.split(',').map(name=>name.trim());
      return this.children.flatMap(item=>[...(names.includes(item.tag) ? [item] : []), ...item.querySelectorAll(selector)]);
    }
  }
  env.ids=Object.fromEntries(['onboarding-review-dialog','onboarding-review-later','onboarding-review-reminder','onboarding-review-status','onboarding-review-open','onboarding-customers','onboarding-due-customers','onboarding-feedback','onboarding-review-feedback'].map(id=>[id,new Element()]));
  env.ids['onboarding-review-reminder'].classList.toggle('hidden',true);
  env.opener=new Element('button');
  env.document={hidden:false, activeElement:null, getElementById:id=>env.ids[id], createElement:tag=>new Element(tag), querySelectorAll:()=>[env.opener], querySelector:selector=>selector==='dialog[open]' ? (env.otherDialog || (env.ids['onboarding-review-dialog'].open ? env.ids['onboarding-review-dialog'] : null)) : selector==='[data-open-workspace-dialog]' ? env.opener : null};
  env.window={setInterval:(callback, interval)=>{assert.equal(interval,60000); env.poll=callback;}, dispatchEvent:event=>env.events.push(event.type)};
  env.fetch=async (url, options)=> {
    if (options.method==='POST') {
      const decision=JSON.parse(options.body); env.decisions.push(decision);
      if (env.postFailure) return {ok:false, status:409, json:async()=>({detail:env.postFailure})};
      const row=env.rows.find(row=>row.id===Number(url.split('/').pop()));
      row.onboarding.review_required=false; row.onboarding.version++; row.onboarding.reason=decision.reason;
      if (decision.action==='end') row.onboarding.status='ended';
      return {ok:true, json:async()=>({})};
    }
    if (env.getFailure) return {ok:false, status:503, json:async()=>({})};
    const snapshot=JSON.parse(JSON.stringify(env.rows));
    const gate=env.holdNextGet; env.holdNextGet=null;
    if (gate) await gate;
    return {ok:true, json:async()=>({customers:snapshot})};
  };
  vm.runInNewContext(source,{document:env.document, window:env.window, fetch:env.fetch, Event:class {constructor(type){this.type=type;}}, console});
  return env;
}
const settle = () => new Promise(resolve=>setImmediate(resolve));
const reminderVisible = env => !env.ids['onboarding-review-reminder'].classList.contains('hidden');
const formControls = form => form.querySelectorAll('input, button');
const reasonControl = form => formControls(form).find(item=>item.tag==='input');
const control = (form, action) => formControls(form).find(item=>item.value===action);
'''


class OnboardingUITests(unittest.TestCase):
    def run_ui(self, scenario):
        script = HARNESS + "\n(async()=>{\n" + scenario + "\n})().catch(error=>{console.error(error);process.exitCode=1});\n"
        path = Path(__file__).parents[1] / 'src/daedalus/static/js/onboarding.js'
        result = subprocess.run(['node', '-e', script, str(path)], capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_initial_load_reload_new_due_customer_and_minute_polls_are_nonmodal(self):
        self.run_ui(r'''
const env=createUI(); await settle();
assert(reminderVisible(env));
assert.equal(env.ids['onboarding-review-status'].textContent,'1 customer approval needs review.');
assert.equal(env.modalCount,0,'Initial load must not open a review dialog');
const statusUpdates=env.ids['onboarding-review-status'].textUpdates;
env.poll(); await settle(); await env.window.daedalusOnboarding.load(true);
assert.equal(env.modalCount,0,'Forced list reload and minute poll must remain nonmodal');
assert.equal(env.ids['onboarding-review-status'].textUpdates,statusUpdates,'Unchanged count must not repeatedly announce');
env.rows.push(dueCustomer(8)); env.poll(); await settle();
assert.equal(env.ids['onboarding-review-status'].textContent,'2 customer approvals need review.');
assert.equal(env.modalCount,0,'A newly due customer updates the reminder only');
const reloaded=createUI(env.rows); await settle();
assert(reminderVisible(reloaded)); assert.equal(reloaded.modalCount,0,'A page reload must remain nonmodal');
const empty=createUI([]); await settle(); assert(!reminderVisible(empty)); assert.equal(empty.modalCount,0);
''')

    def test_only_explicit_review_opens_and_closing_never_reprompts(self):
        self.run_ui(r'''
const env=createUI(); await settle();
env.ids['onboarding-review-open'].focus(); env.ids['onboarding-review-open'].handlers.click(); await settle();
assert(env.ids['onboarding-review-dialog'].open); assert.equal(env.modalCount,1);
env.ids['onboarding-review-later'].handlers.click();
assert(!env.ids['onboarding-review-dialog'].open); assert.equal(env.document.activeElement,env.ids['onboarding-review-open']);
env.poll(); await settle(); assert.equal(env.modalCount,1);
env.rows.push(dueCustomer(8)); await env.window.daedalusOnboarding.load(); assert.equal(env.modalCount,1);
env.otherDialog={open:true}; env.ids['onboarding-review-open'].handlers.click(); await settle();
assert.equal(env.modalCount,1,'Do not stack a review dialog over an already open dialog');
env.otherDialog=null; env.ids['onboarding-review-open'].handlers.click(); await settle();
env.ids['onboarding-review-dialog'].close(); env.poll(); await settle();
assert.equal(env.modalCount,2,'Escape/close must not arrange another automatic prompt');
''')

    def test_focused_drafts_and_observed_versions_survive_background_changes(self):
        self.run_ui(r'''
const env=createUI(); await settle(); env.ids['onboarding-review-open'].handlers.click(); await settle();
const form=env.ids['onboarding-due-customers'].children[0], reason=reasonControl(form);
reason.value='Unsaved human decision'; reason.focus();
env.rows[0].onboarding.version=2; env.rows[0].onboarding.reason='Another administrator changed this';
env.rows.push(dueCustomer(8)); env.poll(); await settle();
assert.equal(env.document.activeElement,reason); assert.equal(env.ids['onboarding-due-customers'].children[0],form);
assert.equal(reason.value,'Unsaved human decision'); assert.equal(env.ids['onboarding-review-status'].textContent,'2 customer approvals need review.');
env.postFailure='Another review changed this customer. Refresh before reviewing';
await form.handlers.submit({preventDefault(){},submitter:control(form,'approve')});
assert.equal(env.decisions[0].version,1,'A poll must not silently update the version attached to an edited form');
assert.equal(env.decisions[0].reason,'Unsaved human decision');
assert(form.children[form.children.length-1].textContent.includes('Another review changed'));
assert(form.querySelectorAll('button').every(button=>!button.disabled)); assert.equal(env.document.activeElement,reason);
env.postFailure=null; env.document.activeElement=env.ids['onboarding-review-later'];
await env.window.daedalusOnboarding.load();
assert.equal(reasonControl(env.ids['onboarding-due-customers'].children[0]).value,'Another administrator changed this');
''')

    def test_unchanged_poll_preserves_unfocused_draft_and_failed_refresh_keeps_last_count(self):
        self.run_ui(r'''
const env=createUI(); await settle(); const form=env.ids['onboarding-customers'].children[0], reason=reasonControl(form);
reason.value='Draft after leaving the field'; env.document.activeElement=env.opener;
env.poll(); await settle(); assert.equal(env.ids['onboarding-customers'].children[0],form); assert.equal(reason.value,'Draft after leaving the field');
env.getFailure=true; env.poll(); await settle();
assert(reminderVisible(env)); assert.equal(env.modalCount,0);
assert.equal(env.ids['onboarding-review-status'].textContent,'1 customer approval needs review. Could not refresh; this is the last loaded count.');
assert(env.ids['onboarding-feedback'].textContent.includes('could not be loaded'));
env.getFailure=false; env.poll(); await settle();
assert.equal(env.ids['onboarding-review-status'].textContent,'1 customer approval needs review.');
assert.equal(env.ids['onboarding-feedback'].textContent,'');
''')

    def test_explicit_reapproval_and_end_keep_reason_version_and_refresh_counts(self):
        self.run_ui(r'''
const env=createUI(); await settle(); env.ids['onboarding-review-open'].handlers.click(); await settle();
let form=env.ids['onboarding-due-customers'].children[0]; const approve=control(form,'approve'); approve.focus();
reasonControl(form).value='Explicit review of customer transition';
await form.handlers.submit({preventDefault(){},submitter:approve});
assert.equal(env.decisions[0].action,'approve'); assert.equal(env.decisions[0].version,1);
assert.equal(env.decisions[0].reason,'Explicit review of customer transition');
assert(!reminderVisible(env)); assert(!env.ids['onboarding-review-dialog'].open);
assert.equal(env.document.activeElement,env.opener,'When the reminder disappears, focus returns to a visible customer action');
assert.deepEqual(env.events,['daedalus-onboarding-changed']);
form=env.ids['onboarding-customers'].children[0]; const end=control(form,'end'); end.focus();
await form.handlers.submit({preventDefault(){},submitter:end});
assert.equal(env.decisions[1].action,'end'); assert.equal(env.decisions[1].version,2);
assert(!reminderVisible(env)); assert.equal(env.modalCount,1);
assert.equal(env.rows[0].onboarding.status,'ended');
''')

    def test_successful_save_waits_for_fresh_list_after_delayed_background_get(self):
        self.run_ui(r'''
const env=createUI(); await settle(); env.ids['onboarding-review-open'].handlers.click(); await settle();
const form=env.ids['onboarding-due-customers'].children[0], approve=control(form,'approve'); approve.focus();
let release; env.holdNextGet=new Promise(resolve=>{release=resolve;});
env.poll(); await settle();
const saving=form.handlers.submit({preventDefault(){},submitter:approve}); await settle();
assert(form.querySelectorAll('button').every(button=>button.disabled),'A successful POST still waits for its post-save refresh');
assert.equal(env.rows[0].onboarding.version,2); assert.equal(env.events.length,0);
release(); await saving;
assert(!reminderVisible(env)); assert(!env.ids['onboarding-review-dialog'].open);
assert.equal(env.ids['onboarding-due-customers'].textContent,'No customers need review.');
const current=env.ids['onboarding-customers'].children[0];
assert(control(current,'end') && !control(current,'end').disabled,'Fresh controls replace the disabled pre-save form');
await current.handlers.submit({preventDefault(){},submitter:control(current,'end')});
assert.equal(env.decisions[1].version,2,'The next decision uses the saved version, never the delayed GET version');
assert.equal(env.modalCount,1,'Queued refreshes never create another modal');
''')

    def test_saved_decision_with_failed_refresh_can_retry_get_without_reposting(self):
        self.run_ui(r'''
const env=createUI(); await settle(); env.ids['onboarding-review-open'].handlers.click(); await settle();
const form=env.ids['onboarding-due-customers'].children[0], approve=control(form,'approve'); approve.focus();
env.getFailure=true; await form.handlers.submit({preventDefault(){},submitter:approve});
const feedback=form.children[form.children.length-1];
assert(feedback.textContent.startsWith('Decision saved.'));
const refresh=feedback.querySelectorAll('button')[0]; assert(refresh && !refresh.disabled);
assert(control(form,'approve').disabled && control(form,'end').disabled,'Stale decision controls remain disabled after a saved decision');
await refresh.handlers.click(); assert(!refresh.disabled); assert.equal(env.decisions.length,1,'Refresh recovery performs no decision POST');
env.getFailure=false; await refresh.handlers.click();
assert(!reminderVisible(env)); assert(!env.ids['onboarding-review-dialog'].open);
assert.equal(env.decisions.length,1); assert.equal(env.rows[0].onboarding.version,2);
assert(!control(env.ids['onboarding-customers'].children[0],'end').disabled);
assert.equal(env.modalCount,1);
''')

    def test_unavailable_initial_or_zero_count_review_status_is_visible_without_popup(self):
        self.run_ui(r'''
const env=createUI([],true); await settle();
assert(reminderVisible(env));assert(env.ids['onboarding-review-status'].textContent.includes('status is unavailable'));assert.equal(env.modalCount,0);
env.getFailure=false; await env.window.daedalusOnboarding.load();assert(!reminderVisible(env));
env.getFailure=true; await env.window.daedalusOnboarding.load();assert(reminderVisible(env));
assert(env.ids['onboarding-review-status'].textContent.includes('No approvals were due at the last refresh'));assert.equal(env.modalCount,0);
''')
