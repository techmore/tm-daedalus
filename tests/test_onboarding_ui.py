import subprocess
import unittest
from pathlib import Path


class OnboardingUITests(unittest.TestCase):
    def test_review_later_refresh_and_reapproval_popup(self):
        script = r'''
const fs = require('fs');
const assert = require('assert');
class Element {
  constructor() { this.children=[]; this.handlers={}; this.dataset={}; this.open=false; }
  replaceChildren() { this.children=[]; }
  append(...items) { this.children.push(...items); }
  setAttribute() {}
  addEventListener(name, callback) { this.handlers[name]=callback; }
  contains(element) { return this.children.includes(element); }
  showModal() { this.open=true; }
  close() { this.open=false; }
  querySelectorAll(name) { return this.children.flatMap(item=>[...(name==='button' && item.tag==='button' ? [item] : []), ...item.querySelectorAll(name)]); }
}
const ids = Object.fromEntries(['onboarding-review-dialog','onboarding-review-later','onboarding-customers','onboarding-due-customers','onboarding-feedback'].map(id=>[id,new Element()]));
global.document = {hidden:false, activeElement:null, getElementById:id=>ids[id], createElement:tag=>Object.assign(new Element(),{tag}), querySelectorAll:()=>[], querySelector:()=>null};
global.window = {setInterval:()=>{}, dispatchEvent:()=>{}};
let rows=[{id:7,name:'Fixture Customer',domain:'fixture.example.org',onboarding:{version:1,status:'onboarding',review_required:true,review_due_at:'2026-10-01T00:00:00Z',reason:'Vendor transition'}}];
let decision;
global.fetch=async (url,options)=> {
  if (options.method==='POST') {decision=JSON.parse(options.body); rows[0].onboarding.review_required=false; rows[0].onboarding.version++; return {ok:true,json:async()=>({})};}
  return {ok:true,json:async()=>({customers:rows})};
};
eval(fs.readFileSync(process.argv[1],'utf8'));
(async()=>{
  await new Promise(resolve=>setImmediate(resolve));
  assert(ids['onboarding-review-dialog'].open,'Due customers must prompt on page load');
  ids['onboarding-review-later'].handlers.click();
  await window.daedalusOnboarding.load();
  assert(!ids['onboarding-review-dialog'].open,'Review later must not re-prompt every poll');
  rows.push({id:8,name:'Another due customer',domain:'second.example.org',onboarding:{...rows[0].onboarding}});
  await window.daedalusOnboarding.load();
  assert(ids['onboarding-review-dialog'].open,'New due customers must prompt');
  rows.pop();
  await window.daedalusOnboarding.load(true);
  const form=ids['onboarding-due-customers'].children[0];
  await form.handlers.submit({preventDefault(){},submitter:{value:'approve'}});
  assert.equal(decision.action,'approve');
  assert.equal(decision.version,1,'Decision must carry the observed version');
  assert(!ids['onboarding-review-dialog'].open,'Last approved customer must close the popup');
})().catch(error=>{console.error(error);process.exitCode=1});
'''
        path = Path(__file__).parents[1] / 'src/daedalus/static/js/onboarding.js'
        result = subprocess.run(['node', '-e', script, str(path)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
