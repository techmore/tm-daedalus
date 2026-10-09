/* Dated approval status and explicit decisions with read-only recovery. */
(function () {
  "use strict";
  window.DaedalusProbationApproval = {create: function (options) {
    var card = document.getElementById("probation-override-card");
    if (!card) return null;
    var host = document.getElementById("override-actions"), feedback = document.getElementById("override-feedback");
    var note = document.getElementById("override-read-note"), observed = document.getElementById("override-observed");
    var refresh = document.getElementById("override-refresh"), heading = document.getElementById("override-summary");
    var path = "/api/workspaces/" + options.organizationId + "/probation-overrides";
    var state = {body:null, fresh:false, loading:false, busy:false, sequence:0, controller:null, error:null, unconfirmed:false};
    var rendered = null, draft = "";
    function validDate(value) {return typeof value === "string" && /(?:Z|[+-]\d{2}:\d{2})$/.test(value) && Number.isFinite(Date.parse(value));}
    function date(value) {return new Date(value).toLocaleString(undefined, {year:"numeric",month:"short",day:"numeric",hour:"numeric",minute:"2-digit",timeZoneName:"short"});}
    function metadata(body) {
      if (!body || body.organization_id !== Number(options.organizationId) || !validDate(body.observed_at) || Date.parse(body.observed_at) > Date.now()+60000 ||
          !["pending","verified"].includes(body.verification_status) || typeof body.controls_enabled !== "boolean" ||
          typeof body.state_reference !== "string" || !/^[a-f0-9]{64}$/.test(body.state_reference)) throw new Error("Approval status could not be confirmed for this workspace.");
      return body;
    }
    function validate(body) {
      metadata(body);
      if (!Array.isArray(body.overrides)) throw new Error("The approval history could not be confirmed.");
      var ids = new Set(), active = 0;
      body.overrides.forEach(function (item) {
        if (!item || !Number.isSafeInteger(item.id) || item.id < 1 || ids.has(item.id) || typeof item.reason !== "string" ||
            typeof item.granted_by !== "string" || !validDate(item.starts_at) || !validDate(item.expires_at) ||
            Date.parse(item.expires_at) <= Date.parse(item.starts_at) || Date.parse(item.starts_at) > Date.parse(body.observed_at) ||
            (item.revoked_at !== null && (!validDate(item.revoked_at) || Date.parse(item.revoked_at) < Date.parse(item.starts_at) || Date.parse(item.revoked_at) > Date.parse(body.observed_at))) ||
            typeof item.active !== "boolean" || item.active !== (item.revoked_at === null && Date.parse(item.expires_at) > Date.parse(body.observed_at))) throw new Error("A dated approval could not be confirmed.");
        ids.add(item.id);if (item.active) active++;
      });
      if (active > 1 || active && !body.controls_enabled) throw new Error("Current approval availability is inconsistent. Refresh before deciding.");
      return body;
    }
    function current() {return state.body && state.body.overrides.find(function (item) {return item.active;});}
    function controls() {
      host.querySelectorAll("button").forEach(function (button) {button.disabled = !state.fresh || state.loading || state.busy;});
      refresh.disabled = state.busy;
      refresh.setAttribute("aria-busy", String(state.loading));
      host.setAttribute("aria-busy", String(state.busy));
      observed.textContent = state.body ? (state.fresh ? "Approval status read " : "Last observed ") + date(state.body.observed_at) + "." : "No approval status read yet.";
      note.hidden = !state.error && (!state.loading || !!state.body);
      note.textContent = state.error ? state.error + " " + (state.body ? "The last observed approval remains visible. " : "") + "Refresh approval status before deciding again."
        : state.loading ? "Reading temporary approval status…" : "";
    }
    function render() {
      var body = state.body, active = current(), key = active ? "active:"+active.id : body.verification_status;
      var input = host.querySelector('input[name="reason"]');if (input) draft = input.value;
      heading.textContent = active ? "Manage the current 14-day approval" : body.verification_status === "verified" ? "Temporary approval is unnecessary" : "Request a temporary 14-day approval";
      card.hidden = false;
      card.dataset.overrideExpires = active ? active.expires_at : "";
      if (key === rendered) return;
      var focused = host.contains(document.activeElement);
      host.replaceChildren();rendered = key;
      var description = document.createElement("p");description.className = "muted";
      if (active) {
        description.textContent = "Approved by " + active.granted_by + " through " + date(active.expires_at) + ". Reason: " + active.reason + ". Revocation removes this approval. Controls close and scans are cancelled if no other authorization remains.";
        var revoke = document.createElement("button");revoke.type = "button";revoke.className = "button button-quiet";
        revoke.dataset.revokeOverride = String(active.id);revoke.textContent = "Revoke approval";host.append(description,revoke);
      } else if (body.verification_status === "verified") {
        description.textContent = "Domain ownership is verified. No temporary approval is required.";host.append(description);
      } else {
        description.textContent = "A workspace admin can approve active checks, scanner management and sharing for 14 days. Each grant, expiry and revocation is recorded with its reason.";
        var form = document.createElement("form");form.id = "grant-override-form";form.className = "override-form";
        var label = document.createElement("label");label.htmlFor = "override-reason";label.textContent = "Reason for temporary approval";
        input = document.createElement("input");input.id = "override-reason";input.name = "reason";input.minLength = 8;input.maxLength = 500;input.required = true;
        input.placeholder = "Why are these controls needed now?";input.value = draft;
        var submit = document.createElement("button");submit.type = "submit";submit.className = "button button-primary";submit.textContent = "Approve access for 14 days";
        form.append(label,input,submit);host.append(description,form);
      }
      var latest = body.overrides[0];
      if (!active && latest) {var prior = document.createElement("p");prior.className = "fine-print";prior.textContent = "Previous approval #"+latest.id+" " + (latest.revoked_at ? "revoked " + date(latest.revoked_at) : "expired " + date(latest.expires_at)) + ". Review the workspace action history for its recorded decisions.";host.append(prior);}
      if (focused) refresh.focus({preventScroll:true});
    }
    async function request(method, suffix, payload, reference) {
      var controller = new AbortController(), timer, deadline;
      var timeout = new Promise(function (_,reject) {deadline = reject;});
      timer = window.setTimeout(function () {controller.abort();deadline(new Error("Approval request timed out."));},20000);
      state.controller = controller;
      try {
        var headers = new Headers();if (payload !== undefined) headers.set("Content-Type","application/json");
        if (reference) headers.set("X-Daedalus-Approval-State",reference);
        return await Promise.race([timeout,(async function () {
          var response = await options.fetch(path+suffix,{method:method,credentials:"same-origin",cache:"no-store",headers:headers,
            body:payload === undefined ? undefined : JSON.stringify(payload),signal:controller.signal});
          var body;try {body = await response.json();} catch (_) {body = null;}
          if (!response.ok) throw new Error(body && typeof body.detail === "string" ? body.detail : "Approval request could not be confirmed.");
          return body;
        })()]);
      } finally {window.clearTimeout(timer);if (state.controller === controller) state.controller = null;}
    }
    async function load() {
      if (state.busy || state.loading) return;
      var sequence = ++state.sequence;state.loading = true;state.error = null;controls();
      try {
        var body = validate(await request("GET",""));
        if (sequence !== state.sequence) return;
        state.body = body;state.fresh = true;render();
        if (state.unconfirmed) {
          var active = current(), latest = body.overrides[0];
          feedback.textContent = "Status refreshed " + date(body.observed_at) + ". " + (active
            ? "Approval #" + active.id + " is active through " + date(active.expires_at) + ", granted by " + active.granted_by + "."
            : "No current 14-day approval." + (latest ? " Previous approval #" + latest.id + (latest.revoked_at ? " was revoked " + date(latest.revoked_at) : " expired " + date(latest.expires_at)) + "." : ""));
          state.unconfirmed = false;
        }
      } catch (error) {if (sequence === state.sequence) {state.fresh = false;state.error = error.message;}}
      finally {if (sequence === state.sequence) {state.loading = false;controls();}}
    }
    async function decide(kind, id) {
      if (!state.fresh || state.loading || state.busy) return;
      var active = current(), input = host.querySelector('input[name="reason"]');
      var reason = input ? input.value.trim() : "";
      if (kind === "grant" && (active || state.body.verification_status === "verified")) return;
      if (kind === "revoke" && (!active || active.id !== id)) return;
      if (kind === "grant" && (reason.length < 8 || reason.length > 500)) {feedback.textContent = "Enter a reason between 8 and 500 characters.";return;}
      var reference = state.body.state_reference, trigger = document.activeElement;
      var restoreFocus = host.contains(trigger);
      state.busy = true;state.fresh = false;controls();
      feedback.textContent = kind === "grant" ? "Recording the 14-day approval…" : "Recording approval revocation…";
      var saved = false;
      try {
        var body = metadata(await request("POST",kind === "grant" ? "" : "/"+id+"/revoke",kind === "grant" ? {reason:reason} : undefined,reference));
        if (!Number.isSafeInteger(body.id) || body.id < 1 || (kind === "revoke" && (body.id !== id || body.active !== false || !validDate(body.revoked_at) || Date.parse(body.revoked_at)>Date.parse(body.observed_at))) ||
            (kind === "grant" && (body.active !== true || body.reason !== reason || !validDate(body.starts_at) || !validDate(body.expires_at) || Date.parse(body.expires_at)-Date.parse(body.starts_at) !== 14*86400000 || Date.parse(body.starts_at)>Date.parse(body.observed_at)))) throw new Error("The approval decision could not be confirmed.");
        saved = true;
        feedback.textContent = kind === "grant" ? "Approval #"+body.id+" saved through "+date(body.expires_at)+". Recorded "+date(body.observed_at)+" in the workspace action history."
          : "Approval #"+body.id+" revoked "+date(body.revoked_at)+". The decision is recorded in the workspace action history.";
        // Retain edits made during a pending request, including a lost response.
        if (kind === "grant" && input && input.value.trim() === reason) {input.value = "";draft = "";}
      } catch (error) {
        state.error = error.message;state.unconfirmed = true;
        feedback.textContent = "The decision was not confirmed. "+error.message+" Your entered reason is retained. Refresh approval status to check what was saved before trying again.";
      } finally {state.busy = false;controls();}
      if (saved) {
        await load();
        if (restoreFocus && (!document.activeElement || document.activeElement === document.body ||
            document.activeElement === trigger && !host.contains(trigger))) refresh.focus({preventScroll:true});
        // The status read owns its failure note; it never replaces saved feedback.
        try {await options.onSaved();} catch (_) {}
      }
    }
    host.addEventListener("submit", function (event) {if (event.target.id === "grant-override-form") {event.preventDefault();return decide("grant");}});
    host.addEventListener("click", function (event) {var button = event.target.closest("[data-revoke-override]");if (button && host.contains(button)) return decide("revoke",Number(button.dataset.revokeOverride));});
    refresh.addEventListener("click", load);
    function observe(organization) {
      if (state.busy || !state.body || state.loading || !state.fresh) return;
      var active = current();
      if (organization.verification_status !== state.body.verification_status || (organization.probation_override_expires_at || "") !== (active ? active.expires_at : "")) {
        state.fresh = false;state.error = "Workspace access changed since this approval status was read.";controls();
        // Another administrator, expiry or an older dashboard response can
        // change the posture. Reconcile through the approval read, preserving
        // its own authority/reference and never repeating a decision.
        load();
      }
    }
    controls();
    return {state:state,load:load,decide:decide,observe:observe};
  }};
})();
