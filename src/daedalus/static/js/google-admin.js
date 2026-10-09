(function () {
  "use strict";
  var current = null, busy = false, poll = null, sequence = 0, checklistSignature = null, scheduleDirty = false, confirming = false, reviewedReportId = null;
  var shell = document.querySelector(".app-shell"), organizationId = shell && Number(shell.dataset.organizationId);
  var reading = false, fresh = false, invalidated = false, readError = null, controller = null, reviewChecklistSignature = null, pendingSignature = null;
  function node(id) { return document.getElementById("google-admin-" + id); }
  function write(id, value) { var target = node(id); if (target && target.textContent !== String(value)) target.textContent = value; }
  async function request(path, method, body, signal) {
    var headers = {"Content-Type": "application/json"};
    if (method && method !== "GET" && path !== "/connect" && current) headers["X-Daedalus-Audit-Connection"] = current.connection_reference || "none";
    var response = await fetch("/api/google-admin" + path, {method: method || "GET", credentials: "same-origin", cache: "no-store", signal: signal, headers: headers, body: body === undefined ? undefined : JSON.stringify(body)});
    var data = await response.json();
    if (!response.ok) throw new Error(data && typeof data.detail === "string" ? data.detail : "The audit request could not be completed.");
    return data;
  }
  function validate(data) {
    function object(value) { return value && typeof value === "object" && !Array.isArray(value); }
    function count(value) { return Number.isSafeInteger(value) && value >= 0; }
    function percent(value) { return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 100; }
    function checks(rows) {
      return Array.isArray(rows) && rows.length > 0 && rows.length <= 500 && rows.every(function (check) {
        return object(check) && typeof check.id === "string" && check.id && typeof check.title === "string" &&
          ["pass", "fail", "manual_review", "unavailable", "not_applicable", "error", "not_assessed"].includes(check.status) && typeof check.expected === "string" && typeof check.cis_controls === "string" &&
          (!check.source || typeof check.source === "string" && check.source.startsWith("https://"));
      }) && new Set(rows.map(function (check) { return check.id; })).size === rows.length;
    }
    if (!object(data) || data.organization_id !== organizationId) throw new Error("The Google Admin workspace changed. Reload this page before reviewing it.");
    if (!["configured", "connected", "is_admin", "verified", "latest_matches_connection"].every(function (key) { return typeof data[key] === "boolean"; }) ||
        typeof data.observed_at !== "string" || !Number.isFinite(Date.parse(data.observed_at)) ||
        ![0, 1, 7, 30].includes(data.schedule_days) || !checks(data.checklist) ||
        data.connected && (!object(data.binding) || !Array.isArray(data.binding.domains) || !data.binding.domains.length || data.binding.domains.some(function (domain) { return typeof domain !== "string" || !domain; }) ||
          typeof data.connection_reference !== "string" || !/^[a-f0-9]{64}$/.test(data.connection_reference) || typeof data.customer_id !== "string" || !data.customer_id || data.binding.customer_id !== data.customer_id || typeof data.last_verified_at !== "string" || !Number.isFinite(Date.parse(data.last_verified_at)) || typeof data.connected_at !== "string" || !Number.isFinite(Date.parse(data.connected_at)))) {
      throw new Error("Saved Google Admin connection metadata is incomplete. Please retry.");
    }
    function evidence(map) {
      return object(map) && Object.values(map).every(function (item) {
        return object(item) && Number.isSafeInteger(item.review_id) && item.review_id > 0 &&
          ["captured_at", "recorded_at"].every(function (key) { return typeof item[key] === "string" && Number.isFinite(Date.parse(item[key])); }) &&
          ["policy_scope", "observed", "expected", "rationale", "source_reference", "owner", "validation"].every(function (key) { return typeof item[key] === "string"; });
      });
    }
    var pending = data.pending_manual_evidence;
    if (!evidence(pending) || !data.connected && Object.keys(pending).length) throw new Error("Pending manual evidence is incomplete. Please retry.");
    var latest = data.latest;
    if (latest !== null) {
      if (!object(latest) || !Number.isSafeInteger(latest.report_id) || latest.report_id < 1 || !object(latest.assessment) || !checks(latest.assessment.checks) ||
          typeof latest.completed_at !== "string" || !Number.isFinite(Date.parse(latest.completed_at))) throw new Error("Saved Google Admin assessment metadata is incomplete. Please retry.");
      var summary = latest.assessment.summary;
      var categories = ["pass", "fail", "manual_review", "unavailable", "not_applicable", "error"];
      if (!object(summary) || !categories.concat(["applicable", "definitive"]).every(function (key) { return count(summary[key]); }) ||
          categories.reduce(function (sum, key) { return sum + summary[key]; }, 0) !== summary.applicable || summary.applicable !== latest.assessment.checks.length ||
          summary.definitive !== summary.pass + summary.fail || !percent(summary.coverage_percent) ||
          categories.some(function (status) { return summary[status] !== latest.assessment.checks.filter(function (check) { return check.status === status; }).length; }) ||
          Math.abs(summary.coverage_percent - (summary.applicable ? 100 * summary.definitive / summary.applicable : 0)) > 0.011 ||
          (summary.definitive === 0 ? summary.observed_pass_rate !== null : !percent(summary.observed_pass_rate) || Math.abs(summary.observed_pass_rate - 100 * summary.pass / summary.definitive) > 0.011)) {
        throw new Error("Saved Google Admin assessment counts are incomplete. Please retry.");
      }
      var comparison = latest.comparison;
      if (comparison !== null && (!object(comparison) || typeof comparison.baseline !== "boolean" ||
          !["configuration_changes", "coverage_changes", "baseline_changes"].every(function (key) { return Array.isArray(comparison[key]); }))) throw new Error("Saved Google Admin comparison metadata is incomplete. Please retry.");
      var manual = latest.assessment.manual_evidence;
      if (manual !== undefined && !evidence(manual)) throw new Error("Saved manual evidence is incomplete. Please retry.");
    }
    if (data.latest_matches_connection && (!latest || !data.connected)) throw new Error("The saved assessment connection needs review. Please retry.");
    if (data.latest_attempt !== null && (!object(data.latest_attempt) || !Number.isSafeInteger(data.latest_attempt.id) || data.latest_attempt.id < 1 || typeof data.latest_attempt.status !== "string" || typeof data.latest_attempt.stage !== "string")) throw new Error("The saved attempt metadata is incomplete. Please retry.");
  }
  function allowed(action) {
    if (!fresh || reading || busy || !current || !current.is_admin) return false;
    var ready = current.verified && current.configured;
    var running = current.latest_attempt && ["queued", "running"].includes(current.latest_attempt.status);
    if (action === "connect") return Boolean(ready && !running && node("customer-consent") && node("customer-consent").checked);
    if (action === "collect") return Boolean(ready && current.connected && !running);
    if (action === "disconnect") return Boolean(current.connected);
    if (action === "save-schedule") return Boolean(current.connected && (node("schedule").value === "0" || ready && current.latest_matches_connection && node("schedule-review").checked));
    if (action === "review-save") return Boolean(current.verified && current.connected && node("review-check") && current.checklist.some(function (check) { return check.id === node("review-check").value; }));
    return false;
  }
  function permissions() {
    ["connect", "collect", "disconnect", "save-schedule", "review-save"].forEach(function (id) {
      var button = node(id);
      if (button) { button.disabled = false; button.setAttribute("aria-disabled", String(!allowed(id) || id === "disconnect" && confirming)); button.setAttribute("aria-describedby", "google-admin-refresh-status"); }
    });
    var refresh = node("refresh");
    if (refresh) { refresh.setAttribute("aria-disabled", String(reading || busy)); refresh.setAttribute("aria-busy", String(reading)); }
    var note = "";
    if (readError || invalidated) {
      note = current ? (readError ? "Could not refresh. " : "An audit action is pending. ") + "Previously loaded assessment and connection data remain visible and may be out of date. Last successful workspace read: " + new Date(current.observed_at).toLocaleString() + "."
        : "Saved Google Admin data is unavailable. Refresh saved Google Admin data to retry.";
      if (readError) note += " " + readError;
      if (invalidated) note += " Refresh before making another audit or setup change.";
    } else if (reading && !current) note = "Loading saved Google Admin data…";
    write("refresh-status", note);
  }
  function line(host, label, value) { var p = document.createElement("p"), strong = document.createElement("strong"); strong.textContent = label + ": "; p.append(strong, document.createTextNode(String(value))); host.append(p); }
  function render(data) {
    var connection = data.connected ? "Approved customer " + data.customer_id + " / " + data.binding.domains.join(", ") + ". Last validated " + new Date(data.last_verified_at).toLocaleString() + "." : "Audit account is not connected.";
    if (!data.configured) connection += " The host needs a dedicated Google Admin OAuth project and encryption configuration.";
    if (!data.verified) connection += " Verify workspace domain ownership before connecting.";
    if (data.last_error) connection += " Last problem: " + data.last_error;
    if (data.next_run_at) connection += " Next scheduled audit: " + new Date(data.next_run_at).toLocaleString() + ".";
    write("connection", connection);
    var latestId = JSON.stringify([data.latest && data.latest.report_id, data.latest_matches_connection, data.connection_reference]);
    if (latestId !== reviewedReportId) { reviewedReportId = latestId; var reviewAck = node("schedule-review"); if (reviewAck) reviewAck.checked = false; }
    var assessment = data.latest && data.latest.assessment, summary = assessment && assessment.summary;
    var description = summary ? "Last completed " + new Date(data.latest.completed_at).toLocaleString() + ": " + summary.definitive + "/" + summary.applicable + " checks assessed; " + summary.fail + " failed; " + summary.manual_review + " need manual review; " + summary.unavailable + " unavailable. Assessment coverage " + summary.coverage_percent + "%; observed pass rate " + (summary.observed_pass_rate === null ? "not available" : summary.observed_pass_rate + "%") + "." : "Not assessed. Connect an authorized Google administrator and run the first read-only audit.";
    if (data.latest_attempt && (!data.latest || data.latest_attempt.id !== data.latest.report_id)) description += " Latest attempt: " + data.latest_attempt.status + " / " + data.latest_attempt.stage + ".";
    var comparison = data.latest && data.latest.comparison;
    if (comparison) description += comparison.baseline ? " First comparison baseline." : " Comparison: " + comparison.configuration_changes.length + " account/role observation changes; " + comparison.coverage_changes.length + " coverage changes; " + comparison.baseline_changes.length + " baseline/evidence changes.";
    if (data.latest && !data.latest_matches_connection) description += (data.connected ? " This saved assessment belongs to a previous audit connection. Run and review an assessment on the current connection before enabling recurring audits." : " This saved assessment belongs to a previous audit connection. Connect an audit account, then complete and review its assessment before enabling recurring audits.");
    write("summary", description);
    write("observation", "Workspace data last read " + new Date(data.observed_at).toLocaleString() + ". This read does not collect new Google evidence.");
    var list = node("checklist");
    var signature = JSON.stringify([assessment ? assessment.checks : data.checklist, assessment && assessment.manual_evidence]);
    if (list && signature !== checklistSignature) {
      var expanded = new Set(Array.from(list.querySelectorAll("details[open]")).map(function (card) { return card.dataset.checkId; }));
      var focused = document.activeElement, hadFocus = list.contains(focused);
      var oldCards = new Map(Array.from(list.querySelectorAll("[data-check-id]")).map(function (card) { return [card.dataset.checkId, card]; }));
      checklistSignature = signature;
      list.replaceChildren();
      (assessment ? assessment.checks : data.checklist).forEach(function (check) {
        var manual = assessment && assessment.manual_evidence && assessment.manual_evidence[check.id];
        var cardSignature = JSON.stringify([check, manual]), saved = oldCards.get(check.id);
        if (saved && saved.dataset.signature === cardSignature) { list.append(saved); return; }
        var card = document.createElement("details"); card.className = "google-admin-check"; card.dataset.checkId = check.id; card.dataset.signature = cardSignature; card.open = expanded.has(check.id);
        var title = document.createElement("summary"); title.textContent = check.id + " / " + check.title + " / " + check.status.replace(/_/g, " "); card.append(title);
        line(card, "Observed", check.observed || "No evidence captured"); line(card, "Expected", check.expected); line(card, "Control mapping", check.cis_controls);
        if (check.rationale) line(card, "Reason", check.rationale);
        if (check.validation) line(card, "Validation", check.validation);
        if (check.source) { var link = document.createElement("a"); link.href = check.source; link.textContent = "Google guidance"; link.target = "_blank"; link.rel = "noopener noreferrer"; card.append(link); }
        if (manual) { line(card, "Manual evidence captured", new Date(manual.captured_at).toLocaleString()); ["policy_scope", "observed", "expected", "rationale", "source_reference", "owner", "validation"].forEach(function (key) { line(card, key.replace(/_/g, " "), manual[key]); }); }
        list.append(card);
      });
      if (hadFocus) {
        if (list.contains(focused)) focused.focus();
        else {
          var old = Array.from(oldCards.values()).find(function (card) { return card.contains(focused); });
          var replacement = old && Array.from(list.children).find(function (card) { return card.dataset.checkId === old.dataset.checkId; });
          var target = replacement ? replacement.querySelector("summary") : node("refresh");
          if (target) target.focus();
        }
      }
    }
    var select = node("review-check"), pickerSignature = JSON.stringify(data.checklist);
    if (select && reviewChecklistSignature !== pickerSignature) {
      var selected = select.value;
      select.replaceChildren();
      if (selected && !data.checklist.some(function (check) { return check.id === selected; })) {
        var retired = document.createElement("option"); retired.value = selected; retired.textContent = selected + " / No longer in the current checklist; choose a current item"; retired.disabled = true; select.append(retired);
      }
      data.checklist.forEach(function (check) { var option = document.createElement("option"); option.value = check.id; option.textContent = check.id + " / " + check.title; select.append(option); });
      if (selected) select.value = selected;
      reviewChecklistSignature = pickerSignature;
    }
    var pendingList = node("pending-evidence"), pendingData = data.pending_manual_evidence, nextSignature = JSON.stringify(pendingData);
    if (pendingList && pendingSignature !== nextSignature) {
      var pendingFocus = document.activeElement, hadPendingFocus = pendingList.contains(pendingFocus);
      var savedPending = new Map(Array.from(pendingList.querySelectorAll("[data-check-id]")).map(function (card) { return [card.dataset.checkId, card]; }));
      pendingList.replaceChildren();
      Object.entries(pendingData).forEach(function (entry) {
        var id = entry[0], evidence = entry[1], signature = JSON.stringify(evidence), saved = savedPending.get(id);
        if (saved && saved.dataset.signature === signature) { pendingList.append(saved);return; }
        var card = document.createElement("details");card.className = "google-admin-check";card.dataset.checkId = id;card.dataset.signature = signature;card.open = Boolean(saved && saved.open);
        var title = document.createElement("summary");title.textContent = id + " / Recorded " + new Date(evidence.recorded_at).toLocaleString();card.append(title);
        line(card, "Source evidence collected", new Date(evidence.captured_at).toLocaleString());
        ["policy_scope", "observed", "expected", "rationale", "source_reference", "owner", "validation"].forEach(function (key) { line(card, key.replace(/_/g, " "), evidence[key]); });
        pendingList.append(card);
      });
      if (!Object.keys(pendingData).length) { var empty = document.createElement("p");empty.textContent = "No recorded manual evidence is waiting for the next assessment.";pendingList.append(empty); }
      pendingSignature = nextSignature;
      if (hadPendingFocus) {
        if (pendingList.contains(pendingFocus)) pendingFocus.focus();
        else {
          var oldPending = Array.from(savedPending.values()).find(function (card) { return card.contains(pendingFocus); });
          var newPending = oldPending && Array.from(pendingList.children).find(function (card) { return card.dataset.checkId === oldPending.dataset.checkId; });
          var focusTarget = newPending ? newPending.querySelector("summary") : node("refresh");if (focusTarget) focusTarget.focus();
        }
      }
    }
    var schedule = node("schedule"); if (schedule && !scheduleDirty && document.activeElement !== schedule) schedule.value = String(data.schedule_days);
    permissions();
  }
  function schedulePoll() {
    window.clearTimeout(poll);
    if (window.location.hash === "#google-admin") {
      var running = current && current.latest_attempt && ["queued", "running"].includes(current.latest_attempt.status);
      poll = window.setTimeout(function () { load(true); }, running ? 5000 : 30000);
    }
  }
  async function load(background) {
    if (!organizationId || busy || background && reading) return false;
    window.clearTimeout(poll);
    if (controller) controller.abort();
    var ownController = new AbortController(), requestSequence = ++sequence, timedOut = false;
    controller = ownController; reading = true; permissions();
    var deadline = window.setTimeout(function () { timedOut = true; ownController.abort(); }, 20000);
    try {
      var data = await request("", undefined, undefined, ownController.signal);
      if (requestSequence !== sequence) return false;
      if (timedOut) throw new Error("The refresh timed out. Please retry.");
      validate(data);
      render(data);
      current = data; fresh = true; invalidated = false; readError = null;
      return true;
    } catch (error) {
      if (requestSequence !== sequence) return false;
      ownController.abort();fresh = false;readError = timedOut ? "The refresh timed out. Please retry." : error.message;
      if (!current) { write("summary", "Saved assessment unavailable.");write("connection", "Connection status unavailable.");write("checklist", "Saved checklist evidence unavailable.");write("pending-evidence", "Recorded manual evidence unavailable."); }
      return false;
    } finally {
      window.clearTimeout(deadline);
      if (requestSequence === sequence) { reading = false;controller = null;permissions();schedulePoll(); }
    }
  }
  function startAction(action) {
    if (!allowed(action)) return false;
    window.clearTimeout(poll);busy = true;fresh = false;invalidated = true;permissions();return true;
  }
  async function finishAction() { busy = false;await load(); }
  async function act(action, path, method, body) {
    if (!startAction(action)) return false;
    write("feedback", "Working…");
    var navigating = false;
    try {
      var data = await request(path, method, body);
      if (data.authorization_url) { navigating = true;window.location.assign(data.authorization_url);return true; }
      if (path === "/schedule") scheduleDirty = false;
      write("feedback", path === "" && method === "DELETE" && !data.revocation_confirmed ? "Disconnected locally. Google revocation was not confirmed; remove the dedicated audit app grant in Google Account settings." : "Saved. Reports retain their original evidence.");
      window.dispatchEvent(new CustomEvent("google-admin-changed"));
      return true;
    } catch (error) { write("feedback", error.message);return false; }
    finally { if (navigating) { busy = false;permissions(); } else await finishAction(); }
  }
  document.addEventListener("DOMContentLoaded", function () {
    var refresh = node("refresh");if (refresh) refresh.addEventListener("click", function () { if (!reading && !busy) return load(); });
    var consent = node("customer-consent");if (consent) consent.addEventListener("change", permissions);
    var connect = node("connect");if (connect) connect.addEventListener("click", function () { return act("connect", "/connect", "POST", {authorize_entire_customer: Boolean(consent && consent.checked)}); });
    var collect = node("collect");if (collect) collect.addEventListener("click", function () { return act("collect", "/reports", "POST"); });
    var disconnect = node("disconnect");if (disconnect) disconnect.addEventListener("click", function () {
      if (confirming || !allowed("disconnect")) return;
      var observedConnection = current.connection_reference;
      var confirm = document.createElement("button");confirm.type = "button";confirm.className = "button button-quiet";confirm.textContent = "Confirm disconnect and stop recurring audits";
      var cancel = document.createElement("button");cancel.type = "button";cancel.className = "button button-quiet";cancel.textContent = "Cancel";
      confirming = true;permissions();disconnect.parentElement.append(confirm, cancel);
      confirm.addEventListener("click", function () {
        if (!allowed("disconnect")) { write("feedback", "Refresh the workspace connection before confirming disconnect.");return; }
        if (current.connection_reference !== observedConnection) { confirm.remove();cancel.remove();confirming = false;permissions();write("feedback", "The audit connection changed. Review it before starting disconnect again.");disconnect.focus();return; }
        confirm.remove();cancel.remove();confirming = false;return act("disconnect", "", "DELETE");
      });
      cancel.addEventListener("click", function () { confirm.remove();cancel.remove();confirming = false;permissions();disconnect.focus(); });confirm.focus();
    });
    var schedule = node("schedule");if (schedule) schedule.addEventListener("change", function () { scheduleDirty = true;permissions(); });
    var reviewAck = node("schedule-review");if (reviewAck) reviewAck.addEventListener("change", permissions);
    var select = node("review-check");if (select) select.addEventListener("change", permissions);
    var save = node("save-schedule");if (save) save.addEventListener("click", function () {
      if (!allowed("save-schedule")) return;
      return act("save-schedule", "/schedule", "POST", {days: Number(node("schedule").value), reviewed_report_id: node("schedule-review").checked && current.latest_matches_connection && current.latest ? current.latest.report_id : null});
    });
    var form = node("review-form");if (form) form.addEventListener("submit", async function (event) {
      event.preventDefault();if (!allowed("review-save")) return;
      var body = Object.fromEntries(new FormData(form)), collected = new Date(body.evidence_collected_at);
      if (!Number.isFinite(collected.getTime())) { write("review-feedback", "Choose a valid source evidence date and time.");return; }
      body.evidence_collected_at = collected.toISOString();if (!startAction("review-save")) return;
      try { var result = await request("/reviews", "POST", body);write("review-feedback", result.message); }
      catch (error) { write("review-feedback", error.message); } finally { await finishAction(); }
    });
    permissions();
  });
  window.daedalusGoogleAdmin = {load: load};
})();
