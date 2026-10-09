from pathlib import Path
import shutil
import subprocess
import unittest


ROOT = Path(__file__).parents[1]
SOURCE = ROOT / "src/daedalus/static/js/dashboard.js"


@unittest.skipUnless(shutil.which("node"), "Node.js required")
class DashboardStatusBoardTests(unittest.TestCase):
    def run_node(self, assertions, *, role="member", include_loader=False, include_selection=False):
        source = SOURCE.read_text()
        end = "  function refresh(force)" if include_loader else "  async function loadWorkspacePosture("
        start = "  function workspaceAssessmentSummary(" if include_loader else "  function workspaceEvidenceTime("
        renderer = source[source.index(start):source.index(end)]
        prelude = r'''
const assert = require('node:assert/strict');
const now = Date.parse('2026-10-08T22:00:00Z'); Date.now = () => now;
class Node {
 constructor(tag='div') { this.tag=tag; this.children=[]; this.textContent=''; this.dataset={}; this.events={}; this.attributes={}; this.disabled=false; }
 append(...children) { children.forEach(child=>{child.parent=this;}); this.children.push(...children); }
 replaceChildren() { this.children=[]; this.textContent=''; }
 contains(node) { return this === node || this.children.some(child => child instanceof Node && child.contains(node)); }
 addEventListener(name, callback) { this.events[name]=callback; }
 setAttribute(name, value) { this.attributes[name]=value; }
 querySelectorAll(selector) { const result=[]; function visit(node) { if(selector==='[data-overview-mutation]' && node.dataset.overviewMutation || selector==='[data-select-workspace]' && node.dataset.selectWorkspace) result.push(node); node.children.forEach(visit); } visit(this); return result; }
 querySelector(selector) { const match=selector.match(/^\[data-(status-key|select-workspace|posture-key)="([a-z0-9-]+)"\]$/); const key=match && {'status-key':'statusKey','select-workspace':'selectWorkspace','posture-key':'postureKey'}[match[1]]; return match ? find(this, node => String(node.dataset[key]) === match[2]) : null; }
 closest(selector) { if (selector==='#portfolio-board') return portfolio.contains(this)?portfolio:null; return null; }
 focus() { document.activeElement=this; }
}
function flatten(node) { return node.textContent + ' ' + node.children.map(flatten).join(' '); }
function find(node, predicate) { if (predicate(node)) return node; for (const child of node.children) { const result=find(child,predicate); if (result) return result; } return null; }
const overview=new Node(), portfolio=new Node(), evidence=new Node(), refreshButton=new Node('button'), readNote=new Node(), observed=new Node(), board=new Node();
const customerRefresh=new Node('button'),customerNote=new Node(),customerObserved=new Node(),customerBoard=new Node(),selectionNote=new Node(),selectControl=new Node('select');
const document={activeElement:null, body:new Node('body'), querySelectorAll:selector=>overview.querySelectorAll(selector).concat(portfolio.querySelectorAll(selector)), createElement:tag=>new Node(tag), getElementById:id=>id==='workspace-priorities'?overview:id==='portfolio-board'?portfolio:id==='workspace-posture'?evidence:id==='overview-refresh'?refreshButton:id==='overview-read-note'?readNote:id==='overview-observed'?observed:id==='overview-status-board'?board:id==='portfolio-refresh'?customerRefresh:id==='portfolio-read-note'?customerNote:id==='portfolio-observed'?customerObserved:id==='portfolio-status-board'?customerBoard:id==='workspace-selection-note'?selectionNote:id==='workspace-select'?selectControl:null};
function dateLabel(value) { return value; }
function appendEmpty(host, message) { const child=new Node(); child.textContent=message; host.append(child); }
let opened=null, postureLoads=0, requests=[], responses=[];
const orgId='1'; let postureRequestSequence=0; let reloads=0,locationChanges=[]; const window={setTimeout,clearTimeout,location:{pathname:'/dashboard',search:'',reload:()=>{reloads++;}},history:{replaceState:(state,title,path)=>locationChanges.push(path)}};
const workspacePostureRead={body:null,signature:null,error:null,loading:false,controller:null,mutationBusy:false};
const portfolioRead={body:null,signature:null,error:null,loading:false,controller:null,sequence:0}; let workspaceSelectionBusy=false; let workspaceRequests=null;
function activateTab(key, location) { opened={key,location}; }
async function loadWorkspacePosture() { postureLoads++; }
async function fetch(path, options) { requests.push({path,options}); const response=responses.shift(); if (response instanceof Error) throw response; return response; }
const dated='2026-10-08T21:00:00Z';
const customerBody=(workspaces,extra={})=>({organization_id:1,can_switch_workspaces:true,assessed_at:dated,workspaces,...extra});
const postureBody=(areas,extra={})=>({organization_id:1,domain:'cybersecuritypilot.org',can_manage:role==='admin',assessed_at:dated,areas,...extra});
const area=(key,state,extra={})=>({key,title:key.toUpperCase(),state,updated_at:state==='not_assessed'?null:dated,summary:key+' evidence summary',...extra});
'''
        if include_selection:
            renderer += source[source.index('  async function postJson('):source.index('  var reportPollTimer =')]
            renderer += source[source.index('  function setWorkspaceSelectionBusy('):source.index('  document.addEventListener("click", function (event) {', source.index('  function setWorkspaceSelectionBusy('))]
        script = prelude + "\nconst role=" + repr(role) + ";\nworkspacePostureRead.body={can_manage:role==='admin'};\n" + renderer + "\n" + assertions
        result = subprocess.run(["node", "-e", script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_shared_summary_retains_incomplete_coverage_and_unknown_dates(self):
        self.run_node(r'''
const areas=[area('dns','recorded'),area('cis','not_assessed'),area('meraki','running'),area('scanners','unrecognized',{updated_at:null})];
const original=JSON.stringify(areas), result=workspaceStatusSummary(areas,now);
assert.equal(result.review,1); assert.equal(result.missing,1); assert.equal(result.running,1); assert.equal(result.saved,2); assert.equal(result.unknown,1);
assert.equal(result.headline,'1 area needs review'); assert.match(result.detail,/1 not assessed/); assert.match(result.detail,/1 in progress/);
assert.equal(JSON.stringify(areas),original);
const onlyDated=workspaceStatusSummary([area('dns','recorded')],now);
assert.equal(onlyDated.headline,'Saved evidence available'); assert.equal(onlyDated.level,'ok');
const incomplete=workspaceStatusSummary([area('dns','recorded'),area('cis','not_assessed')],now);
assert.equal(incomplete.headline,'1 area not assessed'); assert.equal(incomplete.level,'idle');
for (const value of [null,undefined,'invalid',true,0,'2026-10-08T21:00:00','2026-10-09T21:00:00Z']) {
 const row=workspaceAreaPresentation(area('dns','recorded',{updated_at:value}),now);
 assert.equal(row.level,'warn'); assert.equal(row.verdict,'Evidence time unknown'); assert.equal(row.hasEvidence,false);
}
assert.equal(workspaceAreaPresentation(area('dns','recorded',{updated_at:'2026-10-05T21:00:00Z'}),now).verdict,'Evidence needs refresh');
assert.equal(workspaceAreaPresentation(null,now).verdict,'Assessment status unknown');
assert.equal(workspaceAreaPresentation(area('dns','future-state'),now).hasEvidence,false);
assert.equal(workspaceAreaPresentation(area('dns','future-state'),now).when,'Saved evidence source unknown');
assert.equal(workspaceStatusSummary(null,now).headline,'Assessment coverage unavailable');
assert.equal(areaLevel(area('dns','unrecognized',{updated_at:null})),'warn');
''')

    def test_overview_shows_every_summary_date_and_review_action_for_member(self):
        self.run_node(r'''
const areas=[area('dns','recorded',{summary:'<script>literal evidence</script>'}),area('cis','not_assessed'),area('scanners','running')];
const original=JSON.stringify(areas); renderStatusBoard(areas);
assert.equal(overview.children[0].children[0].textContent,'1 area not assessed');
assert.match(flatten(overview),/1 not assessed/); assert.match(flatten(overview),/1 in progress/);
assert.doesNotMatch(flatten(overview),/All good|Daily|OK/);
assert.match(flatten(overview),/Saved evidence is not a security verdict/);
assert.match(flatten(overview),/<script>literal evidence<\/script>/);
assert.match(flatten(overview),/Saved evidence 2026-10-08T21:00:00Z/);
assert.match(flatten(overview),/cis evidence summary/); assert.match(flatten(overview),/scanners evidence summary/);
assert.equal(find(overview,node=>node.textContent==='Check DNS & website now'),null);
const action=find(overview,node=>node.dataset.statusKey==='cis-review');
assert.equal(action.textContent,'Review setup'); assert.equal(action.attributes['aria-label'],'Review setup: CIS');
action.events.click(); assert.deepEqual(opened,{key:'cis',location:true});
document.activeElement=action; renderStatusBoard(areas);
assert.equal(document.activeElement,find(overview,node=>node.dataset.statusKey==='cis-review'));
assert.equal(JSON.stringify(areas),original);
''')

    def test_failed_and_running_attempts_keep_prior_evidence_and_dated_deeper_audit(self):
        self.run_node(r'''
renderStatusBoard([area('dns','unavailable'),area('web','running',{audit_summary:'Older deeper observations',audit_updated_at:'2026-10-05T12:00:00Z'})]);
assert.match(flatten(overview),/Latest attempt failed/); assert.match(flatten(overview),/Check running/);
assert.match(flatten(overview),/earlier evidence retained/); assert.match(flatten(overview),/dns evidence summary/);
assert.match(flatten(overview),/Older deeper observations · Audit evidence 2026-10-05T12:00:00Z/);
assert.equal(find(overview,node=>node.dataset.statusKey==='dns-review').textContent,'Review attempt');
assert.equal(find(overview,node=>node.dataset.statusKey==='web-review').textContent,'Review progress');
renderStatusBoard([area('dns','unavailable',{updated_at:null}),area('web','running',{updated_at:null})]);
assert.doesNotMatch(flatten(overview),/earlier evidence retained/);
assert.match(flatten(overview),/0 of 2 areas have dated saved evidence/);
assert.match(flatten(overview),/No saved assessment time/);
''')

    def test_full_evidence_cards_share_unknown_and_stale_presentation(self):
        self.run_node(r'''
(async()=>{
const rows=[area('dns','recorded',{updated_at:null}),area('web','recorded',{updated_at:'2026-10-09T12:00:00Z'}),
 area('cis','recorded',{updated_at:'2026-10-05T12:00:00Z'}),area('meraki','unavailable',{audit_summary:'Older audit',audit_updated_at:'invalid'})];
responses.push({ok:true,json:async()=>postureBody(rows)}); await loadWorkspacePosture();
assert.equal(evidence.children.length,4);
for (const key of ['dns','web']) {
 const card=find(evidence,node=>node.dataset.postureKey===key);
 assert.equal(card.children[1].textContent,'Evidence time unknown');
 assert.equal(card.children[1].className,'posture-state is-attention');
 assert.equal(card.children[3].textContent,'Saved evidence time needs review');
}
assert.equal(find(evidence,node=>node.dataset.postureKey==='cis').children[1].textContent,'Evidence needs refresh');
assert.match(flatten(evidence),/earlier evidence retained/); assert.match(flatten(evidence),/Audit evidence time unknown/);
assert.doesNotMatch(flatten(evidence),/Evidence saved|All good/);
})().catch(error=>{console.error(error);process.exitCode=1;});
''', include_loader=True)

    def test_schedule_context_preserves_weekly_interval_without_implying_daily(self):
        self.run_node(r'''
(async()=>{
const rows=[area('dns','recorded',{schedule:{enabled:false,interval_hours:168}}),area('web','recorded',{schedule:{enabled:true,interval_hours:168}})];
renderStatusBoard(rows);
assert.equal(overview.children[0].children[0].textContent,'Saved evidence available');
assert.match(flatten(overview),/Automatic checks off/); assert.match(flatten(overview),/Automatic checks every 168 hours/);
assert.doesNotMatch(flatten(overview),/Daily|All good/);
const enable=find(overview,node=>node.dataset.statusKey==='dns-schedule'); assert.ok(enable);
responses.push({ok:true}); await enable.events.click();
assert.equal(requests[0].path,'/api/external-checks/dns/schedule');
assert.deepEqual(JSON.parse(requests[0].options.body),{enabled:true,interval_hours:168}); assert.equal(postureLoads,1);
assert.equal(workspaceAreaPresentation(area('dns','recorded',{schedule:{enabled:false,interval_hours:72}}),now).enableSchedule,false);
assert.equal(workspaceAreaPresentation(area('cis','recorded',{schedule:{enabled:false,interval_hours:24}}),now).enableSchedule,false);
})().catch(error=>{console.error(error);process.exitCode=1;});
''', role="admin")
        self.run_node(r'''
renderStatusBoard([area('dns','recorded',{schedule:{enabled:false,interval_hours:168}})]);
assert.equal(find(overview,node=>node.dataset.statusKey==='dns-schedule'),null);
assert.ok(find(overview,node=>node.dataset.statusKey==='dns-review'));
''')

    def test_public_refresh_reports_partial_failure_and_retries_only_failed_request(self):
        self.run_node(r'''
(async()=>{
renderStatusBoard([area('dns','recorded')]);
const button=find(overview,node=>node.dataset.statusKey==='public-refresh');
assert.equal(button.textContent,'Check DNS & website now');
responses.push({ok:true},{ok:false}); await button.events.click();
assert.equal(button.disabled,false); assert.equal(button.textContent,'Retry website');
assert.match(flatten(overview),/DNS & email check requested/); assert.match(flatten(overview),/Could not request website checks/);
assert.equal(postureLoads,0); assert.deepEqual(requests.map(request=>request.path),['/api/external-checks/dns/run','/api/external-checks/web/run']);
responses.push({ok:true}); await button.events.click();
assert.equal(postureLoads,1); assert.equal(requests.length,3); assert.equal(requests[2].path,'/api/external-checks/web/run');
renderStatusBoard([area('dns','recorded')]); const networkButton=find(overview,node=>node.dataset.statusKey==='public-refresh');
responses.push(new Error('offline'),new Error('offline')); await networkButton.events.click();
assert.equal(networkButton.disabled,false); assert.match(flatten(overview),/Could not request DNS & email and website checks/);
})().catch(error=>{console.error(error);process.exitCode=1;});
''', role="admin")

    def test_portfolio_shows_unassessed_topics_and_coverage_without_health_verdict(self):
        self.run_node(r'''
(async()=>{
const workspaces=[{id:1,name:'Customer A',domain:'a.example',role:'admin',verification_status:'verified',areas:[area('dns','recorded'),area('scanners','not_assessed'),area('cis','not_assessed'),area('meraki','running')]},
 {id:2,name:'Customer B',domain:'b.example',role:'member',verification_status:'pending',areas:[area('web','recorded')]}];
const original=JSON.stringify(workspaces); responses.push({ok:true,json:async()=>customerBody(workspaces)}); await loadPortfolio();
assert.equal(portfolio.children[0].children[0].textContent,'1 of 2 customers have unassessed areas');
assert.match(flatten(portfolio),/SCANNERS: Not assessed/); assert.match(flatten(portfolio),/CIS: Not assessed/);
assert.match(flatten(portfolio),/MERAKI: Check running/); assert.match(flatten(portfolio),/2 not assessed/);
assert.match(flatten(portfolio),/Latest saved evidence 2026-10-08T21:00:00Z/);
assert.match(flatten(portfolio),/Saved customer|Saved evidence available/); assert.doesNotMatch(flatten(portfolio),/All good|look good/);
assert.equal(find(portfolio,node=>node.dataset.selectWorkspace===1).attributes['aria-label'],'Review Customer A');
assert.equal(JSON.stringify(workspaces),original);
responses.push({ok:true,json:async()=>customerBody([])}); await loadPortfolio();
assert.equal(portfolio.children[0].children[0].textContent,'No customers available');
responses.push({ok:true,json:async()=>customerBody([{id:3,name:'Unknown',domain:'unknown.example',role:'member',verification_status:'pending',areas:[area('web','future-state',{updated_at:null})]}])}); await loadPortfolio();
assert.match(flatten(portfolio),/1 of 1 customers need review/); assert.match(flatten(portfolio),/Assessment status unknown/);
})().catch(error=>{console.error(error);process.exitCode=1;});
''')

    def test_board_styles_wrap_full_evidence_and_controls(self):
        css = (ROOT / "src/daedalus/static/css/app.css").read_text()
        start = css.index("\n.status-why {")
        rule = css[start:css.index("}", start)]
        self.assertIn("white-space: normal", rule)
        self.assertIn("overflow-wrap: anywhere", rule)
        self.assertNotIn("text-overflow: ellipsis", rule)
        self.assertNotIn(".portfolio-chips { flex-wrap: nowrap; }", css)
        self.assertIn(".status-action-slot { justify-content: flex-start; }", css)
