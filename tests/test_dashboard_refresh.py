import shutil
import subprocess
import unittest
from pathlib import Path


class DashboardRefreshTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'), 'Node.js is needed for the JavaScript fixture')
    def test_skip_content_focus_preserves_topic_fragment(self):
        source = (Path(__file__).parents[1] / 'src/daedalus/static/js/dashboard.js').read_text()
        start = source.index('  function handleSkipToContent(')
        end = source.index('  var skipLink', start)
        script = "const assert = require('node:assert/strict'); let focused=false, prevented=false; const document={getElementById:()=>({focus:()=>{focused=true;}})};" + source[start:end] + "handleSkipToContent({preventDefault:()=>{prevented=true;}});assert.equal(focused,true);assert.equal(prevented,true);"
        result = subprocess.run(['node', '-'], input=script, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('location', source[start:end])

    @unittest.skipUnless(shutil.which('node'), 'Node.js is needed for the JavaScript fixture')
    def test_live_feed_reconnect_backoff_is_bounded_without_reloading_dashboard(self):
        source = (Path(__file__).parents[1] / 'src/daedalus/static/js/dashboard.js').read_text()
        start = source.index('  function liveReconnectDelay(')
        end = source.index('\n  if (orgId) {', start)
        reconnect = source[start:end]
        script = "const assert = require('node:assert/strict');\n" + reconnect + """
assert.equal(liveReconnectDelay(-1), 1000);
assert.equal(liveReconnectDelay(0), 1000);
assert.equal(liveReconnectDelay(1), 2000);
assert.equal(liveReconnectDelay(2), 4000);
assert.equal(liveReconnectDelay(5), 30000);
assert.equal(liveReconnectDelay(100), 30000);
"""
        result = subprocess.run(['node', '-'], input=script, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        live_block = source[end:source.index('\n  function showError(', end)]
        self.assertIn('connectLiveSocket();', live_block)
        self.assertIn('currentSocket.readyState === WebSocket.OPEN', live_block)
        self.assertNotIn('window.location.reload()', live_block)

    @unittest.skipUnless(shutil.which('node'), 'Node.js is needed for the JavaScript fixture')
    def test_active_dashboard_navigation_is_exposed_as_the_current_page(self):
        source = (Path(__file__).parents[1] / 'src/daedalus/static/js/dashboard.js').read_text()
        start = source.index('  function activateTab(')
        end = source.index('\n  function showMembershipNotice(', start)
        function = source[start:end]
        script = "const assert = require('node:assert/strict');\n" + """
const makeNode = (id, classes, tab) => {
  const names = new Set(classes);
  const attributes = {};
  return {
    id, dataset: {tab}, textContent: '', attributes,
    classList: {
      contains: (name) => names.has(name),
      toggle: (name, force) => force ? names.add(name) : names.delete(name)
    },
    setAttribute: (name, value) => { attributes[name] = value; },
    removeAttribute: (name) => { delete attributes[name]; }
  };
};
const items = [makeNode('', ['nav-item', 'active'], 'overview'), makeNode('', ['nav-item'], 'cis'), makeNode('', ['module-card'], 'cis')];
const panels = [makeNode('tab-overview', ['tab-panel', 'active']), makeNode('tab-cis', ['tab-panel'])];
const title = makeNode('page-title', []);
const pushes = [];
const document = {
  querySelectorAll: (selector) => selector === '[data-tab]' ? items : panels,
  getElementById: () => title
};
const window = {
  location: {hash: '#overview', pathname: '/dashboard', search: ''},
  history: {pushState: (...args) => pushes.push(args)}
};
const titleMap = {overview: 'Overview', cis: 'CIS profiles'};
let activeTab = 'overview';
const text = (element, value) => { element.textContent = value; };
let postureLoads = 0; const loadWorkspacePosture = () => { postureLoads++; };
const loadCIS = () => {}; const loadReports = () => {};
const loadMeraki = () => {}; const loadExternalCheck = () => {};
const loadActiveExposure = () => {}; const loadNotifications = () => {};
""" + function + """
activateTab('cis', true);
assert.equal(items[1].attributes['aria-current'], 'page');
assert.equal(items[1].classList.contains('active'), true);
assert.equal(items[0].attributes['aria-current'], undefined);
assert.equal(items[2].attributes['aria-current'], undefined);
assert.equal(panels[1].classList.contains('active'), true);
assert.equal(title.textContent, 'CIS profiles');
assert.equal(pushes[0][2], '/dashboard#cis');
activateTab('unsupported', false);
assert.equal(items[0].attributes['aria-current'], 'page');
assert.equal(items[1].attributes['aria-current'], undefined);
assert.equal(postureLoads, 1);
"""
        result = subprocess.run(['node', '-'], input=script, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        template = (Path(__file__).parents[1] / 'src/daedalus/templates/dashboard.html').read_text()
        self.assertIn('<nav class="main-nav" aria-label="Administration">', template)

    @unittest.skipUnless(shutil.which('node'), 'Node.js is needed for the JavaScript fixture')
    def test_meraki_organization_selection_defaults_to_authorized_scope(self):
        source = (Path(__file__).parents[1] / 'src/daedalus/static/js/dashboard.js').read_text()
        start = source.index('  function preferredMerakiOrganizationId(')
        end = source.index('\n  function renderMerakiOrganizations(', start)
        function = source[start:end]
        script = "const assert = require('node:assert/strict');\n" + function + """
const orgs = [
  {id:'191018', authorized:false},
  {id:'1678722', authorized:true},
  {id:'296035', authorized:false}
];
assert.equal(preferredMerakiOrganizationId(orgs), '1678722');
assert.equal(preferredMerakiOrganizationId(orgs, '296035'), '296035');
assert.equal(preferredMerakiOrganizationId(orgs, 'unknown'), '1678722');
assert.equal(preferredMerakiOrganizationId([{id:'first', authorized:false}], ''), 'first');
assert.equal(preferredMerakiOrganizationId([]), '');
"""
        result = subprocess.run(['node', '-'], input=script, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_meraki_reports_offer_workspace_scoped_saved_details(self):
        root = Path(__file__).parents[1]
        source = (root / 'src/daedalus/static/js/dashboard.js').read_text()
        template = (root / 'src/daedalus/templates/dashboard.html').read_text()
        self.assertIn('/api/meraki/reports/" + encodeURIComponent(reportId) + "/details', source)
        self.assertIn('View saved report details', source)
        self.assertIn('evidence_preview', source)
        self.assertIn('id="meraki-report-job-list"', template)
        self.assertIn('meraki-detail-metrics', (root / 'src/daedalus/static/css/app.css').read_text())

    @unittest.skipUnless(shutil.which('node'), 'Node.js is needed for the JavaScript fixture')
    def test_notification_review_labels_open_the_relevant_workspace_tab(self):
        source = (Path(__file__).parents[1] / 'src/daedalus/static/js/dashboard.js').read_text()
        start = source.index('  function notificationReviewLabel(')
        end = source.index('\n  async function loadNotifications(', start)
        function = source[start:end]
        script = "const assert = require('node:assert/strict');\n" + function + """
assert.equal(notificationReviewLabel('dns'), 'Review DNS');
assert.equal(notificationReviewLabel('web'), 'Review website');
assert.equal(notificationReviewLabel('meraki'), 'Review Meraki');
assert.equal(notificationReviewLabel('cis'), 'Review CIS');
assert.equal(notificationReviewLabel('scanners'), 'Review scanners');
assert.equal(notificationReviewLabel('members'), 'Review access');
assert.equal(notificationReviewLabel('unknown'), 'Review website');
assert.match(notificationEmptyMessage(), /security changes, warnings, or audit notices/);
assert.match(notificationEmptyMessage(), /for this workspace/);
"""
        result = subprocess.run(['node', '-'], input=script, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which('node'), 'Node.js is needed for the JavaScript fixture')
    def test_raw_scanner_command_history_is_admin_only(self):
        source = (Path(__file__).parents[1] / 'src/daedalus/static/js/dashboard.js').read_text()
        start = source.index('  function canViewScannerCommandHistory(')
        end = source.index('\n  }', start) + len('\n  }')
        function = source[start:end]
        script = "const assert = require('node:assert/strict');\n" + function + """
assert.equal(canViewScannerCommandHistory('admin'), true);
assert.equal(canViewScannerCommandHistory('user'), false);
assert.equal(canViewScannerCommandHistory(''), false);
"""
        result = subprocess.run(['node', '-'], input=script, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(source, r'if \(canViewScannerCommandHistory\(role\)\) \{\s+var history = document\.createElement\("details"\)')

    @unittest.skipUnless(shutil.which('node'), 'Node.js is needed for the JavaScript fixture')
    def test_scanner_pdf_jobs_are_exposed_in_the_workspace_report_library(self):
        root = Path(__file__).parents[1]
        source = (root / 'src/daedalus/static/js/dashboard.js').read_text()
        start = source.index('  function matchingReportJobs(')
        end = source.index('\n  function renderReportJobs(', start)
        function = source[start:end]
        script = "const assert = require('node:assert/strict');\n" + function + """
const jobs = [
  {id:20, report_type:'scanner_results'},
  {id:19, report_type:'external_posture'},
  {id:18, report_type:'meraki_security'},
  {id:17, report_type:'cis_endpoint'}
];
assert.deepEqual(matchingReportJobs(jobs, 'scanner_results').map(job => job.id), [20]);
assert.deepEqual(matchingReportJobs(jobs, ['external_posture', 'scanner_results']).map(job => job.id), [20, 19]);
assert.deepEqual(matchingReportJobs(jobs, 'meraki_security').map(job => job.id), [18]);
"""
        result = subprocess.run(['node', '-'], input=script, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        template = (root / 'src/daedalus/templates/dashboard.html').read_text()
        self.assertIn('id="scanner-report-job-list"', template)
        self.assertIn('renderReportJobs(reports, "scanner-report-job-list", "scanner-report-library-status", "scanner_results")', source)

    @unittest.skipUnless(shutil.which('node'), 'Node.js is needed for the JavaScript fixture')
    def test_dns_history_warns_when_latest_lookup_cannot_confirm_a_saved_record_change(self):
        source = (Path(__file__).parents[1] / 'src/daedalus/static/js/dashboard.js').read_text()
        start = source.index('  function dnsChangeUncertainty(')
        end = source.index('  function renderCheckHistory(', start)
        function = source[start:end]
        script = "const assert = require('node:assert/strict');\n" + function + """
const snapshot = {resolver_errors: {'www A': 'SERVFAIL', 'www AAAA': 'TIMEOUT'}};
assert.match(dnsChangeUncertainty({field_path:'records.WWW_A'}, snapshot), /SERVFAIL/);
assert.match(dnsChangeUncertainty({field_path:'records.WWW_A'}, snapshot), /cannot confirm/);
assert.match(dnsChangeUncertainty({field_path:'records.WWW_AAAA'}, snapshot), /TIMEOUT/);
assert.equal(dnsChangeUncertainty({field_path:'records.WWW_CNAME'}, snapshot), '');
assert.equal(dnsChangeUncertainty({field_path:'records.SPF'}, snapshot), '');
assert.equal(dnsChangeUncertainty({field_path:'resolver_errors.www A'}, snapshot), '');
assert.equal(dnsChangeUncertainty({field_path:'records.WWW_A'}, null), '');
"""
        result = subprocess.run(['node', '-'], input=script, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which('node'), 'Node.js is needed for the JavaScript fixture')
    def test_external_check_toast_distinguishes_warnings_from_clean_no_change_runs(self):
        source = (Path(__file__).parents[1] / 'src/daedalus/static/js/dashboard.js').read_text()
        start = source.index('  function notifyExternalCheck(')
        end = source.index('  function notifyScannerUpdate(', start)
        function = source[start:end]
        script = "const assert = require('node:assert/strict');\n" + function + """
let content = '', hidden = true, hideTimer = null;
const toast = {classList: {remove() { hidden = false; }, add() { hidden = true; }}};
const document = {getElementById(id) { return id === 'check-toast' ? toast : null; }};
const window = {clearTimeout() {}, setTimeout(callback) { hideTimer = callback; return 1; }};
const notifiedCheckRuns = {};
function text(_node, value) { content = value; }
notifyExternalCheck({run_id:32, check_type:'dns', domain:'example.org', status:'completed_with_warnings', change_count:0});
assert.match(content, /completed with warnings/);
assert.match(content, /No confirmed changes/);
assert.match(content, /Some checks may be unknown/);
assert.equal(hidden, false);
const firstMessage = content;
notifyExternalCheck({run_id:32, check_type:'dns', domain:'example.org', status:'completed', change_count:4});
assert.equal(content, firstMessage, 'duplicate live delivery must not replace the first notification');
notifyExternalCheck({run_id:33, check_type:'web', domain:'example.org', status:'completed_with_warnings', change_count:2});
assert.match(content, /2 change\\(s\\) were detected/);
notifyExternalCheck({run_id:34, check_type:'web', domain:'example.org', status:'completed', change_count:0});
assert.match(content, /completed .* with no detected changes/);
notifyExternalCheck({run_id:35, check_type:'dns', domain:'example.org', status:'failed', change_count:0});
assert.match(content, /check failed/);
"""
        result = subprocess.run(['node', '-'], input=script, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which('node'), 'Node.js is needed for the JavaScript fixture')
    def test_dns_metrics_show_interpreted_email_policy_without_overclaiming(self):
        source = (Path(__file__).parents[1] / 'src/daedalus/static/js/dashboard.js').read_text()
        function = source[source.index('  function emailAuthenticationMetrics('):source.index('  function renderDnsSnapshot(')]
        script = "const assert = require('node:assert/strict');\n" + function + """
const metrics = emailAuthenticationMetrics({
  spf: {label: 'Allows all', summary: '+all passes every sender', tone: 'attention'},
  dmarc: {status: 'published', label: 'Monitor only', summary: 'Monitoring, no enforcement', tone: 'neutral',
    effective_subdomain_policy: 'none', effective_nonexistent_subdomain_policy: 'none',
    alignment: {aspf: 'relaxed', adkim: 'strict'}}
});
assert.equal(metrics[0].value, 'Allows all');
assert.equal(metrics[0].state, 'attention');
assert.equal(metrics[1].value, 'Monitor only');
assert(metrics[1].detail.includes('existing none'));
assert(metrics[1].detail.includes('DKIM strict'));
assert.equal(emailAuthenticationMetrics(null)[0].value, 'Not assessed');
"""
        result = subprocess.run(['node', '-'], input=script, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which('node'), 'Node.js is needed for the JavaScript fixture')
    def test_refresh_shares_inflight_request_and_recovers_after_failure(self):
        source = (Path(__file__).parents[1] / 'src/daedalus/static/js/dashboard.js').read_text()
        function = source[source.index('  function refresh(force) {'):source.index('  async function sendCommand')]
        script = '''const assert = require('node:assert/strict');
let dashboardRefreshPromise = null, calls = 0, rendered = [], release, inlineConfirmationOpen = false;
let fetch = () => { calls++; return new Promise(resolve => { release = resolve; }); };
let render = value => rendered.push(value);
let document = {querySelector(selector) { assert.equal(selector, '.inline-confirmation'); return inlineConfirmationOpen ? {} : null; }};
''' + function + '''
(async () => {
  const first = refresh(), second = refresh();
  assert.strictEqual(first, second);
  assert.equal(calls, 1);
  release({ok: true, json: async () => ({status: 'offline'})});
  await first;
  assert.deepEqual(rendered, [{status: 'offline'}]);
  assert.equal(dashboardRefreshPromise, null);
  fetch = async () => { throw new Error('offline fixture'); };
  await refresh();
  assert.equal(dashboardRefreshPromise, null);
  fetch = async () => ({ok: true, json: async () => ({status: 'online'})});
  await refresh();
  assert.equal(rendered.length, 2);
  inlineConfirmationOpen = true;
  fetch = async () => ({ok: true, json: async () => ({status: 'newer'})});
  await refresh();
  assert.equal(rendered.length, 2, 'passive refresh must leave an open confirmation in place');
  await refresh(true);
  assert.deepEqual(rendered.at(-1), {status: 'newer'}, 'confirmed actions can force the dashboard update');
})().catch(error => { console.error(error); process.exitCode = 1; });
'''
        result = subprocess.run(['node', '-'], input=script, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which('node'), 'Node.js is needed for the JavaScript fixture')
    def test_membership_live_events_refresh_admin_lists_and_give_requesters_actions(self):
        source = (Path(__file__).parents[1] / 'src/daedalus/static/js/dashboard.js').read_text()
        start = source.index('  function handleMembershipLiveMessage(')
        end = source.index('\n  var pendingMembershipSockets', start)
        function = source[start:end]
        script = '''const assert = require('node:assert/strict');
let role = 'admin', calls = [], notices = [], selectedWorkspace = null, activeTab = null;
let requestDomain = {value: ''}, dialogOpened = false;
const workspaceDialog = {open: false, showModal() { dialogOpened = true; }};
const document = {getElementById(id) { return id === 'request-access-form' ? {elements: {domain: requestDomain}} : null; }};
function loadMemberships() { calls.push('members'); }
function loadAuditLog() { calls.push('audit'); }
function loadWorkspaces() { calls.push('workspaces'); }
function showMembershipNotice(message, action) { notices.push({message, action}); }
function activateTab(tab) { activeTab = tab; }
function selectWorkspace(id) { selectedWorkspace = id; }
''' + function + '''
handleMembershipLiveMessage({type: 'membership_request_received'});
assert.deepEqual(calls, ['members', 'audit']);
assert.match(notices[0].message, /waiting for your review/);
notices[0].action.run();
assert.equal(activeTab, 'members');
calls = [];
handleMembershipLiveMessage({type: 'membership_list_changed'});
assert.deepEqual(calls, ['members', 'audit']);
role = 'user'; calls = [];
handleMembershipLiveMessage({type: 'membership_decision', status: 'approved', organization: 'CSP', organization_id: 9});
assert.deepEqual(calls, ['workspaces', 'members']);
assert.match(notices.at(-1).message, /CSP was approved/);
notices.at(-1).action.run();
assert.equal(selectedWorkspace, 9);
handleMembershipLiveMessage({type: 'membership_decision', status: 'denied', organization: 'CSP', organization_id: 9, domain: 'cybersecuritypilot.org'});
assert.match(notices.at(-1).message, /declined/);
notices.at(-1).action.run();
assert.equal(requestDomain.value, 'cybersecuritypilot.org');
assert.equal(dialogOpened, true);
'''
        result = subprocess.run(['node', '-'], input=script, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which('node'), 'Node.js is needed for the JavaScript fixture')
    def test_inventory_values_preserve_unknown_and_zero_storage(self):
        source = (Path(__file__).parents[1] / 'src/daedalus/static/js/dashboard.js').read_text()
        function = source[source.index('  function inventoryDisplayValue('):source.index('  var shell =')]
        script = "const assert = require('node:assert/strict');\n" + function + """
assert.equal(inventoryDisplayValue('total_memory_bytes', 32*1073741824), '32.0 GiB');
assert.equal(inventoryDisplayValue('data_volume_free_bytes', 0), '0.0 GiB');
for (const invalid of [null, undefined, 'unknown', false, -1, Infinity, NaN, '1024']) {
  assert.equal(inventoryDisplayValue('total_memory_bytes', invalid), 'Unknown');
}
assert.equal(inventoryDisplayValue('cpu_count', 10), '10');
assert.equal(inventoryDisplayValue('cpu_count', 0), 'Unknown');
assert.equal(inventoryDisplayValue('platform', {}), 'Unknown');
assert.equal(inventoryDisplayValue('architecture', 'arm64'), 'arm64');
"""
        result = subprocess.run(['node', '-'], input=script, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which('node'), 'Node.js is needed for the JavaScript fixture')
    def test_command_timeline_does_not_claim_unconfirmed_completion(self):
        source = (Path(__file__).parents[1] / 'src/daedalus/static/js/dashboard.js').read_text()
        function = source[source.index('  function commandTimeline('):source.index('  function inventoryDisplayValue(')]
        script = "const assert = require('node:assert/strict');\n" + function + """
const pending = commandTimeline({created_at:'2026-09-29T00:00:00Z', delivered_at:'2026-09-29T00:01:00Z', deadline_at:'2026-09-29T02:00:00Z'});
assert(pending.includes('Requested ')); assert(pending.includes('Delivered ')); assert(pending.includes('Confirmation deadline '));
const timedOut = commandTimeline({completed_at:'2026-09-29T02:00:00Z', deadline_at:'2026-09-29T02:00:00Z'});
assert(timedOut.includes('Status recorded ')); assert(!timedOut.includes('Completed')); assert(!timedOut.includes('deadline'));
assert.equal(commandTimeline({created_at:'invalid'}), '');
"""
        result = subprocess.run(['node', '-'], input=script, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which('node'), 'Node.js is needed for the JavaScript fixture')
    def test_os_update_history_uses_text_nodes_for_readable_results(self):
        source = (Path(__file__).parents[1] / 'src/daedalus/static/js/dashboard.js').read_text()
        start = source.index('                var updateSummary = document.createElement("p");')
        end = source.index('                return;', start) + len('                return;')
        branch = source[start:end]
        script = r'''const assert = require('node:assert/strict');
const appended = [];
function node(tag) { return {tag, textContent:'', className:'', childNodes:[], append(...items) { this.childNodes.push(...items); }, } }
const document = {createElement: node};
const command = {action:'check_os_updates'};
const decoded = {schema_version:1, status:'updates_available', observed_at:'2026-09-30T12:00:00Z', updates:[{title:'macOS <Tahoe>, Version: 26.1, Size: 3GB', label:'macOS-26.1'}]};
const entry = node('entry');
const evidence = node('pre');
const historyBody = node('history');
function render() {
''' + branch + r'''
}
render();
assert.equal(entry.childNodes[0].textContent.startsWith('Updates are available · Checked '), true);
assert.equal(entry.childNodes[1].childNodes[0].textContent, 'macOS <Tahoe> (macOS-26.1)');
assert.equal(entry.childNodes[1].childNodes[0].tag, 'li');
assert.equal(entry.childNodes[2].tag, 'details');
assert.equal(entry.childNodes[2].childNodes[0].textContent, 'Raw update catalog receipt');
assert.equal(historyBody.childNodes[0], entry);
'''
        result = subprocess.run(['node', '-'], input=script, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which('node'), 'Node.js is needed for the JavaScript fixture')
    def test_macos_update_button_uses_dashboard_api_platform_field(self):
        source = (Path(__file__).parents[1] / 'src/daedalus/static/js/dashboard.js').read_text()
        function = source[source.index('  function supportsMacOSUpdateCheck('):source.index('  var shell =')]
        script = "const assert = require('node:assert/strict');\n" + function + """
assert.equal(supportsMacOSUpdateCheck({platform:'Darwin', command_protocol_version:3}), true);
assert.equal(supportsMacOSUpdateCheck({platform:'Darwin', command_protocol_version:2}), false);
assert.equal(supportsMacOSUpdateCheck({platform:'Linux', command_protocol_version:3}), false);
assert.equal(supportsMacOSUpdateCheck({host_platform:'Darwin', command_protocol_version:3}), false);
assert.equal(supportsMacOSUpdateCheck({platform:'Darwin', command_protocol_version:'3'}), false);
"""
        result = subprocess.run(['node', '-'], input=script, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which('node'), 'Node.js is needed for the JavaScript fixture')
    def test_cis_client_config_pins_the_selected_profile_and_scoped_endpoints(self):
        source = (Path(__file__).parents[1] / 'src/daedalus/static/js/dashboard.js').read_text()
        start = source.index('  function buildCISClientConfig(')
        end = source.index('  var shell =', start)
        function = source[start:end]
        script = "const assert = require('node:assert/strict');\n" + function + r'''
const body = {
  report_endpoint: 'https://app.cybersecuritypilot.org/api/cis/report',
  profiles_endpoint: 'https://app.cybersecuritypilot.org/api/cis/client/profiles',
  domain: 'cybersecuritypilot.org',
  api_key: 'fixture-only-key'
};
const config = buildCISClientConfig(body, 'cis-macos-26-tahoe-level-2');
assert.match(config, /  endpoint: "https:\/\/app\.cybersecuritypilot\.org\/api\/cis\/report"\n/);
assert.match(config, /  profiles_endpoint: "https:\/\/app\.cybersecuritypilot\.org\/api\/cis\/client\/profiles"\n/);
assert.match(config, /  profile_slug: "cis-macos-26-tahoe-level-2"\n/);
assert.match(config, /  domain: "cybersecuritypilot\.org"\n/);
assert.match(config, /  api_key: "fixture-only-key"\n/);
assert.equal(buildCISClientConfig(body, '').includes('  profile_slug: ""\n'), true);
const hostile = buildCISClientConfig(body, 'safe"\napi_key: "injected');
assert.equal(hostile.split('\n').filter((line) => line.startsWith('  api_key:')).length, 1);
'''
        result = subprocess.run(['node', '-'], input=script, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
