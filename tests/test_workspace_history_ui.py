import json
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).parents[1]


@unittest.skipUnless(shutil.which('node'), 'Node.js required for dashboard history fixtures')
class WorkspaceHistoryUITests(unittest.TestCase):
    def run_node(self, script):
        setup = """const assert = require('node:assert/strict');
const fs = require('node:fs');
global.window = {location:{origin:'https://portal.example'}};
""" + 'eval(fs.readFileSync(' + json.dumps(str(ROOT / 'src/daedalus/static/js/history.js')) + ", 'utf8'));\n"
        result = subprocess.run(['node', '-'], input=setup + '(async()=>{\n' + script + '\n})().catch(error=>{console.error(error);process.exitCode=1;});', text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_refresh_keeps_loaded_older_boundary_and_filter_resets_history(self):
        self.run_node("""
let rows = [9,8,7,6,5,4].map(id=>({id})); let calls=[]; let changes=[];
global.fetch=async (path, options)=>{
  const url=new URL(path,window.location.origin); calls.push(url);
  assert.equal(options.credentials,'same-origin');assert.equal(options.cache,'no-store');
  const filtered=rows.filter(row=>url.searchParams.get('unread_only')!=='true'||row.id%2===1);
  const before=Number(url.searchParams.get('before'))||Infinity;
  const older=filtered.filter(row=>row.id<before);const page=older.slice(0,2);
  return {ok:true,json:async()=>({notifications:page,unread_count:3,total_count:filtered.length,has_more:older.length>2,next_before:older.length>2?page.at(-1).id:null})};
};
const pager=window.daedalusHistory.create({url:'/api/notifications',field:'notifications',changed:(s,commit)=>changes.push({ids:s.rows.map(r=>r.id),busy:s.busy,commit})});
await pager.refresh({unread_only:'false'}); await pager.older();
assert.deepEqual(pager.state.rows.map(row=>row.id),[9,8,7,6]);assert.equal(pager.state.body.next_before,6);
rows=[{id:11},{id:10},...rows]; await pager.refresh();
assert.deepEqual(pager.state.rows.map(row=>row.id),[11,10,9,8,7,6]);assert.equal(pager.state.body.next_before,6);
await pager.older();assert.deepEqual(pager.state.rows.map(row=>row.id),[11,10,9,8,7,6,5,4]);assert.equal(pager.state.body.has_more,false);
await pager.refresh({unread_only:'true'});assert.deepEqual(pager.state.rows.map(row=>row.id),[11,9]);
assert.equal(pager.state.body.total_count,4);assert.ok(changes.some(change=>change.commit&&change.ids.length===0));
assert.ok(calls.every(url=>url.searchParams.has('unread_only')));
""")

    def test_failed_older_and_refresh_preserve_evidence_and_allow_retry(self):
        self.run_node("""
let failure=false;let malformed=false;let calls=0;
global.fetch=async path=>{calls++;if(failure)throw new Error('Offline');
 const older=new URL(path,window.location.origin).searchParams.has('before');
 return {ok:true,json:async()=>malformed?{reports:[]}:{reports:older?[{id:1}]:[{id:3},{id:2}],total_count:3,has_more:!older,next_before:older?null:2}};
};
const pager=window.daedalusHistory.create({url:'/api/reports',field:'reports',changed:()=>{}});
await pager.refresh({report_type:'meraki_security'});failure=true;await pager.older();
assert.deepEqual(pager.state.rows.map(r=>r.id),[3,2]);assert.equal(pager.state.error,'Offline');assert.equal(pager.state.busy,false);
await pager.refresh();assert.deepEqual(pager.state.rows.map(r=>r.id),[3,2]);
failure=false;malformed=true;await pager.refresh();assert.match(pager.state.error,/incomplete/);assert.deepEqual(pager.state.rows.map(r=>r.id),[3,2]);
malformed=false;await pager.older();assert.deepEqual(pager.state.rows.map(r=>r.id),[3,2,1]);assert.equal(pager.state.error,null);
const count=calls;await pager.older();assert.equal(calls,count);
""")

    def test_stale_older_page_cannot_overwrite_a_new_filter_or_refresh(self):
        self.run_node("""
let release; let slow=false;
global.fetch=async path=>{const url=new URL(path,window.location.origin);
 if(slow&&url.searchParams.has('before'))await new Promise(resolve=>{release=resolve});
 const filtered=url.searchParams.get('report_type')==='cis_endpoint';
 return {ok:true,json:async()=>({reports:filtered?[{id:20}]:url.searchParams.has('before')?[{id:1}]:[{id:3},{id:2}],total_count:filtered?1:3,has_more:!filtered&&!url.searchParams.has('before'),next_before:!filtered&&!url.searchParams.has('before')?2:null})};
};
const pager=window.daedalusHistory.create({url:'/api/reports',field:'reports',changed:()=>{}});
await pager.refresh({report_type:'meraki_security'});slow=true;const old=pager.older();
await new Promise(resolve=>setImmediate(resolve));assert.equal(pager.state.busy,true);
await pager.refresh({report_type:'cis_endpoint'});release();await old;
assert.deepEqual(pager.state.rows.map(r=>r.id),[20]);assert.equal(pager.state.body.total_count,1);assert.equal(pager.state.busy,false);
""")

    def test_unread_boundary_removed_during_refresh_reaches_remaining_old_notices(self):
        self.run_node("""
let rows=[6,5,4,3,2,1];
global.fetch=async path=>{const before=Number(new URL(path,window.location.origin).searchParams.get('before'))||Infinity;
const remaining=rows.filter(id=>id<before);const selected=remaining.slice(0,2);
return {ok:true,json:async()=>({notifications:selected.map(id=>({id})),unread_count:rows.length,total_count:rows.length,has_more:remaining.length>2,next_before:remaining.length>2?selected.at(-1):null})};};
const pager=window.daedalusHistory.create({url:'/api/notifications',field:'notifications',changed:()=>{}});
await pager.refresh({unread_only:'true'});await pager.older();assert.equal(pager.state.rows.at(-1).id,3);
rows=rows.filter(id=>id!==3);await pager.refresh();assert.deepEqual(pager.state.rows.map(r=>r.id),[6,5,4,2,1]);assert.equal(pager.state.body.has_more,false);
""")

    def test_page_contract_rejects_repeated_cursor_duplicate_rows_and_unknown_counts(self):
        self.run_node("""
let body={reports:[{id:5},{id:4}],total_count:6,has_more:true,next_before:4};
global.fetch=async()=>({ok:true,json:async()=>body});
const pager=window.daedalusHistory.create({url:'/api/reports',field:'reports',changed:()=>{}});
await pager.refresh();const original=pager.state.rows;
for(const invalid of [{reports:[{id:5},{id:5}],total_count:6,has_more:false,next_before:null},
{reports:[{id:4}],total_count:6,has_more:true,next_before:99},
{reports:[],total_count:-1,has_more:false,next_before:null},
{reports:[],has_more:false,next_before:null}]){
body=invalid;await pager.refresh();assert.equal(pager.state.rows,original);assert.ok(pager.state.error);
}
""")

    def test_notification_render_retains_focus_literal_evidence_and_errors(self):
        source = (ROOT / 'src/daedalus/static/js/dashboard.js').read_text()
        helpers = source[source.index('  function notificationReviewLabel('):source.index('  function restoreNotificationFilter(')]
        script = r"""
class Node {
 constructor(tag='div'){this.tag=tag;this.children=[];this.dataset={};this.textContent='';this.parentElement=null;this.value='all';this.classes=new Set();this.classList={toggle:(name,on)=>{if(on)this.classes.add(name);else this.classes.delete(name);}};}
 append(...nodes){nodes.forEach(n=>{n.parentElement=this;this.children.push(n);});}
 replaceChildren(...nodes){this.children=[];this.append(...nodes);}
 contains(node){return this===node||this.children.some(child=>child.contains(node));}
 closest(){return this.dataset.notificationOpen?this:this.parentElement?this.parentElement.closest():null;}
 querySelectorAll(){return this.children.flatMap(child=>[...(child.dataset.notificationOpen?[child]:[]),...child.querySelectorAll()]);}
 focus(){document.activeElement=this;}
}
const ids=Object.fromEntries(['notification-list','notification-inbox-status','notification-filter','notification-older','notification-refresh','notification-badge'].map(id=>[id,new Node()]));
const document={getElementById:id=>ids[id],createElement:tag=>new Node(tag),activeElement:ids['notification-filter']};
const text=(node,value)=>{if(node)node.textContent=value;};
const dateLabel=value=>value;const appendEmpty=(list,value)=>{const node=new Node();node.textContent=value;list.append(node);};
let orgId=1, notificationHistory=null, failure=false;
let rows=[3,2,1].map(id=>({id,title:'<script>literal</script>',summary:'DNS evidence',reason:'changes',detected_at:'2026-10-08T00:00:00Z',read_at:null,tab:'dns'}));
global.fetch=async path=>{if(failure)throw new Error('Offline');const url=new URL(path,window.location.origin);const before=Number(url.searchParams.get('before'))||Infinity;
const remaining=rows.filter(row=>row.id<before);const selected=remaining.slice(0,2);
return {ok:true,json:async()=>({notifications:selected,total_count:rows.length,unread_count:rows.length,has_more:remaining.length>2,next_before:remaining.length>2?selected.at(-1).id:null})};};
""" + helpers + r"""
await loadNotifications();assert.equal(ids['notification-list'].children.length,2);
assert.equal(ids['notification-list'].children[0].children[0].children[0].textContent,'<script>literal</script>');
assert.equal(ids['notification-older'].classes.has('hidden'),false);
let focus=ids['notification-list'].querySelectorAll().find(button=>button.dataset.notificationOpen==='2');focus.focus();
await notificationHistory.older();assert.equal(ids['notification-list'].children.length,3);assert.equal(document.activeElement.dataset.notificationOpen,'2');
assert.equal(ids['notification-older'].classes.has('hidden'),true);
const oldRows=ids['notification-list'].children;failure=true;await loadNotifications();
assert.equal(ids['notification-list'].children,oldRows);assert.match(ids['notification-inbox-status'].textContent,/Previously loaded/);assert.equal(ids['notification-refresh'].disabled,false);
failure=false;rows=rows.filter(row=>row.id!==2);await loadNotifications();assert.equal(ids['notification-list'].children.length,2);assert.equal(document.activeElement,ids['notification-filter']);
ids['notification-filter'].value='unread';rows=[];await loadNotifications();assert.match(ids['notification-list'].children[0].textContent,/No unread/);
"""
        self.run_node(script)

    def test_report_group_loader_filters_topics_and_isolates_failed_refreshes(self):
        source = (ROOT / 'src/daedalus/static/js/dashboard.js').read_text()
        helpers = source[source.index('  var reportHistoryGroups = ['):source.index('  var merakiOrgOptions = []')]
        script = r"""
class Node {
 constructor(){this.children=[];this.dataset={};this.classes=new Set();this.classList={toggle:(name,on)=>{if(on)this.classes.add(name);else this.classes.delete(name);}};}
 append(...nodes){this.children.push(...nodes);}
 replaceChildren(...nodes){this.children=nodes;}
 addEventListener(){} contains(){return false;} querySelectorAll(){return [];}
 querySelector(selector){return this.children.find(n=>selector==='[data-history-older]'?n.dataset.historyOlder:n.dataset.historyRefresh);}
 after(node){ids[node.id]=node;}
}
const names=['report-job-list','report-library-status','scanner-report-job-list','scanner-report-library-status','posture-report-job-list','posture-report-library-status','meraki-report-job-list','meraki-report-library-status','cis-pdf-job-list','cis-pdf-library-status','google-admin-report-job-list','google-admin-report-library-status','google-admin-library-list','google-admin-library-status'];
const ids=Object.fromEntries(names.map(id=>{let n=new Node();n.id=id;return [id,n];}));
const document={getElementById:id=>ids[id],createElement:()=>new Node(),activeElement:null};
window.clearTimeout=()=>{};window.setTimeout=()=>{};
let orgId=1, activeTab='reports', driveState={}, reportPollTimer=null, reportHistories={}, failure=false, calls=[], renders=[];
const loadDriveStatus=async()=>{};const text=(node,value)=>{node.textContent=value;};const appendEmpty=(node,value)=>{node.empty=value;};
const reportJobStatusSummary=rows=>rows.length+' saved';
const renderReportJobs=(rows,id,status,topic,latest)=>{renders.push({rows,id,topic,latest});ids[id].rows=rows;};
global.fetch=async path=>{const url=new URL(path,window.location.origin), topic=url.searchParams.get('report_type');calls.push(topic);
if(failure&&topic==='scanner_results')throw new Error('Scanner history offline');
return {ok:true,json:async()=>({reports:[{id:20,report_type:topic.split(',')[0],status:'failed'}],total_count:1,has_more:false,next_before:null,latest_completed:{id:1,report_type:topic.split(',')[0],status:'completed'}})};};
""" + helpers + r"""
await loadReports();assert.deepEqual(new Set(calls),new Set(['external_posture','scanner_results','meraki_security,cis_endpoint','google_admin_security']));
assert.equal(renders.length,5);assert.equal(ids['scanner-report-job-list'].rows[0].report_type,'scanner_results');
assert.equal(ids['scanner-report-job-list-history-controls'].querySelector('[data-history-older]').classes.has('hidden'),true);
const oldRows=ids['scanner-report-job-list'].rows;failure=true;await loadReports();assert.equal(ids['scanner-report-job-list'].rows,oldRows);assert.match(ids['scanner-report-library-status'].textContent,/Previously loaded/);
assert.match(ids['report-library-status'].textContent,/Showing 1 of 1/);
calls=[];activeTab='meraki';await loadReports();assert.deepEqual(calls,['meraki_security']);assert.equal(renders.at(-1).latest.id,1);assert.equal(renders.at(-1).id,'meraki-report-job-list');
"""
        self.run_node(script)

    def test_dashboard_wires_each_topic_and_preserves_filter_and_refresh_context(self):
        source = (ROOT / 'src/daedalus/static/js/dashboard.js').read_text()
        template = (ROOT / 'src/daedalus/templates/dashboard.html').read_text()
        for topic in ('external_posture', 'scanner_results', 'meraki_security,cis_endpoint', 'meraki_security', 'cis_endpoint', 'google_admin_security'):
            self.assertIn(f'topic: "{topic}"', source)
        self.assertIn('state.body && state.body.latest_completed', source)
        self.assertIn('report_type: group.topic', source)
        self.assertIn('Previously loaded notices remain below', source)
        self.assertIn('replacement.focus({ preventScroll: true })', source)
        self.assertIn('url.pathname + url.search + url.hash', source)
        self.assertIn('unread_only:', source)
        self.assertIn('id="notification-filter"', template)
        self.assertIn('id="notification-older"', template)
        self.assertLess(template.index('/static/js/history.js'), template.index('/static/js/dashboard.js'))
        self.assertIn('Refresh notices', template)
