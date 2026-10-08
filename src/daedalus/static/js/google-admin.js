(function () {
  "use strict";
  var current = null, busy = false, poll = null, sequence = 0, checklistSignature = null, scheduleDirty = false, confirming = false, reviewedReportId = null;
  function node(id) { return document.getElementById("google-admin-" + id); }
  function write(id, value) { var target = node(id); if (target) target.textContent = value; }
  async function request(path, method, body) {
    var response = await fetch("/api/google-admin" + path, {method: method || "GET", credentials: "same-origin", headers: {"Content-Type": "application/json"}, body: body === undefined ? undefined : JSON.stringify(body)});
    var data = await response.json();
    if (!response.ok) throw new Error(typeof data.detail === "string" ? data.detail : "The audit request could not be completed.");
    return data;
  }
  function permissions() {
    var admin = current && current.is_admin, ready = admin && current.verified && current.configured, consent = node("customer-consent");
    var running = current && current.latest_attempt && ["queued", "running"].includes(current.latest_attempt.status);
    [["connect", !ready || busy || running || !consent || !consent.checked], ["collect", !ready || !current.connected || busy || running],
      ["disconnect", !admin || !current.connected || busy || confirming], ["save-schedule", !ready || !current.connected || busy || (node("schedule") && node("schedule").value !== "0" && (!node("schedule-review").checked || !current.latest))],
      ["review-save", !admin || !current.verified || !current.connected || busy]].forEach(function (pair) { var button = node(pair[0]); if (button) button.disabled = Boolean(pair[1]); });
  }
  function line(host, label, value) { var p = document.createElement("p"), strong = document.createElement("strong"); strong.textContent = label + ": "; p.append(strong, document.createTextNode(String(value))); host.append(p); }
  function render(data) {
    var connection = data.connected ? "Approved customer " + data.customer_id + " / " + data.binding.domains.join(", ") + ". Last validated " + new Date(data.last_verified_at).toLocaleString() + "." : "Audit account is not connected.";
    if (!data.configured) connection += " The host needs a dedicated Google Admin OAuth project and encryption configuration.";
    if (!data.verified) connection += " Verify workspace domain ownership before connecting.";
    if (data.last_error) connection += " Last problem: " + data.last_error;
    if (data.next_run_at) connection += " Next scheduled audit: " + new Date(data.next_run_at).toLocaleString() + ".";
    write("connection", connection);
    var latestId = data.latest && data.latest.report_id;
    if (latestId !== reviewedReportId) { reviewedReportId = latestId; var reviewAck = node("schedule-review"); if (reviewAck) reviewAck.checked = false; }
    var assessment = data.latest && data.latest.assessment, summary = assessment && assessment.summary;
    var description = summary ? "Last completed " + new Date(data.latest.completed_at).toLocaleString() + ": " + summary.definitive + "/" + summary.applicable + " checks assessed; " + summary.fail + " failed; " + summary.manual_review + " need manual review; " + summary.unavailable + " unavailable. Assessment coverage " + summary.coverage_percent + "%; observed pass rate " + (summary.observed_pass_rate === null ? "not available" : summary.observed_pass_rate + "%") + "." : "Not assessed. Connect an authorized Google administrator and run the first read-only audit.";
    if (data.latest_attempt && (!data.latest || data.latest_attempt.id !== data.latest.report_id)) description += " Latest attempt: " + data.latest_attempt.status + " / " + data.latest_attempt.stage + ".";
    var comparison = data.latest && data.latest.comparison;
    if (comparison) description += comparison.baseline ? " First comparison baseline." : " Comparison: " + comparison.configuration_changes.length + " account/role observation changes; " + comparison.coverage_changes.length + " coverage changes; " + comparison.baseline_changes.length + " baseline/evidence changes.";
    write("summary", description);
    var list = node("checklist");
    var signature = JSON.stringify([assessment ? assessment.checks : data.checklist, assessment && assessment.manual_evidence]);
    if (list && signature !== checklistSignature) {
      var expanded = new Set(Array.from(list.querySelectorAll("details[open]")).map(function (card) { return card.dataset.checkId; }));
      checklistSignature = signature;
      list.replaceChildren();
      (assessment ? assessment.checks : data.checklist).forEach(function (check) {
        var card = document.createElement("details"); card.className = "google-admin-check"; card.dataset.checkId = check.id; card.open = expanded.has(check.id);
        var title = document.createElement("summary"); title.textContent = check.id + " / " + check.title + " / " + check.status.replace(/_/g, " "); card.append(title);
        line(card, "Observed", check.observed || "No evidence captured"); line(card, "Expected", check.expected); line(card, "Control mapping", check.cis_controls);
        if (check.rationale) line(card, "Reason", check.rationale);
        if (check.validation) line(card, "Validation", check.validation);
        if (check.source) { var link = document.createElement("a"); link.href = check.source; link.textContent = "Google guidance"; link.target = "_blank"; link.rel = "noopener noreferrer"; card.append(link); }
        var manual = assessment && assessment.manual_evidence && assessment.manual_evidence[check.id];
        if (manual) { line(card, "Manual evidence captured", new Date(manual.captured_at).toLocaleString()); ["policy_scope", "observed", "expected", "rationale", "source_reference", "owner", "validation"].forEach(function (key) { line(card, key.replace(/_/g, " "), manual[key]); }); }
        list.append(card);
      });
    }
    var select = node("review-check");
    if (select && !select.options.length) data.checklist.forEach(function (check) { var option = document.createElement("option"); option.value = check.id; option.textContent = check.id + " / " + check.title; select.append(option); });
    var schedule = node("schedule"); if (schedule && !scheduleDirty && document.activeElement !== schedule) schedule.value = String(data.schedule_days);
    permissions();
  }
  async function load() {
    var requestSequence = ++sequence;
    window.clearTimeout(poll);
    try { var data = await request(""); if (requestSequence !== sequence) return; current = data; render(data); }
    catch (error) { if (requestSequence !== sequence) return; current = null; write("summary", error.message); permissions(); }
    if (window.location.hash === "#google-admin") poll = window.setTimeout(load, 5000);
  }
  async function act(path, method, body) {
    busy = true; permissions(); write("feedback", "Working...");
    try {
      var data = await request(path, method, body);
      if (data.authorization_url) { window.location.assign(data.authorization_url); return; }
      if (path === "/schedule") scheduleDirty = false;
      write("feedback", path === "" && method === "DELETE" && !data.revocation_confirmed ? "Disconnected locally. Google revocation was not confirmed; remove the dedicated audit app grant in Google Account settings." : "Saved. Reports retain their original evidence.");
      await load();
      window.dispatchEvent(new CustomEvent("google-admin-changed"));
    } catch (error) { write("feedback", error.message); }
    finally { busy = false; permissions(); }
  }
  document.addEventListener("DOMContentLoaded", function () {
    var consent = node("customer-consent"); if (consent) consent.addEventListener("change", permissions);
    var connect = node("connect"); if (connect) connect.addEventListener("click", function () { act("/connect", "POST", {authorize_entire_customer: consent.checked}); });
    var collect = node("collect"); if (collect) collect.addEventListener("click", function () { act("/reports", "POST"); });
    var disconnect = node("disconnect"); if (disconnect) disconnect.addEventListener("click", function () {
      var confirm = document.createElement("button"); confirm.type = "button"; confirm.className = "button button-quiet"; confirm.textContent = "Confirm disconnect and stop recurring audits";
      var cancel = document.createElement("button"); cancel.type = "button"; cancel.className = "button button-quiet"; cancel.textContent = "Cancel";
      if (confirming) return; confirming = true;
      disconnect.disabled = true; disconnect.parentElement.append(confirm, cancel);
      confirm.addEventListener("click", function () { confirm.remove(); cancel.remove(); confirming = false; act("", "DELETE"); });
      cancel.addEventListener("click", function () { confirm.remove(); cancel.remove(); confirming = false; permissions(); disconnect.focus(); }); confirm.focus();
    });
    var schedule = node("schedule"); if (schedule) schedule.addEventListener("change", function () { scheduleDirty = true; permissions(); });
    var reviewAck = node("schedule-review"); if (reviewAck) reviewAck.addEventListener("change", permissions);
    var save = node("save-schedule"); if (save) save.addEventListener("click", function () { act("/schedule", "POST", {days: Number(node("schedule").value), reviewed_report_id: node("schedule-review").checked && current.latest ? current.latest.report_id : null}); });
    var form = node("review-form"); if (form) form.addEventListener("submit", async function (event) {
      event.preventDefault(); var body = Object.fromEntries(new FormData(form)); body.evidence_collected_at = new Date(body.evidence_collected_at).toISOString(); busy = true; permissions();
      try { var result = await request("/reviews", "POST", body); write("review-feedback", result.message); }
      catch (error) { write("review-feedback", error.message); } finally { busy = false; permissions(); }
    });
  });
  window.daedalusGoogleAdmin = {load: load};
})();
