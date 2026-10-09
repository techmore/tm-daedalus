/* Reviewed ownership proof, dated DNS outcomes and read-only recovery. */
(function () {
  "use strict";
  window.DaedalusDomainVerification = {create: function (options) {
    var details = document.getElementById("domain-verification-details");
    if (!details) return null;
    var refresh = document.getElementById("domain-instructions-refresh"), observed = document.getElementById("domain-instructions-observed");
    var note = document.getElementById("domain-instructions-read-note"), instructions = document.getElementById("verification-instructions");
    var feedback = document.getElementById("verification-feedback"), lastCheck = document.getElementById("domain-last-check");
    var ensure = document.getElementById("issue-domain-challenge"), verify = document.getElementById("verify-domain");
    var replace = document.getElementById("replace-domain-challenge"), replacement = document.getElementById("challenge-replacement");
    var challenge = document.getElementById("dns-challenge"), name = document.getElementById("challenge-record-name"), value = document.getElementById("challenge-record-value");
    var expiry = document.getElementById("challenge-expires"), summary = document.getElementById("domain-verification-summary");
    var path = "/api/workspaces/" + options.organizationId;
    var state = {body:null,fresh:false,loading:false,busy:false,error:null,unconfirmed:false}, confirmation = null;
    function validDate(v) {return typeof v === "string" && /(?:Z|[+-]\d{2}:\d{2})$/.test(v) && Number.isFinite(Date.parse(v));}
    function date(v) {return new Date(v).toLocaleString(undefined,{year:"numeric",month:"short",day:"numeric",hour:"numeric",minute:"2-digit",timeZoneName:"short"});}
    function validate(body) {
      if (!body || body.organization_id !== Number(options.organizationId) || body.user_id !== Number(options.userId) || body.domain !== options.domain ||
          !validDate(body.observed_at) || Date.parse(body.observed_at)>Date.now()+60000 || !["active","expired","none","verified"].includes(body.state) ||
          typeof body.verified !== "boolean" || body.verified !== (body.state === "verified") || typeof body.state_reference !== "string" || !/^[a-f0-9]{64}$/.test(body.state_reference) ||
          (body.verified_at !== null && (!body.verified || !validDate(body.verified_at) || Date.parse(body.verified_at)>Date.parse(body.observed_at)))) throw new Error("TXT instructions could not be confirmed for this account and domain.");
      var record = body.txt;
      if (["none","verified"].includes(body.state)) {if (record !== null) throw new Error("The ownership record state is inconsistent.");}
      else if (!record || !Number.isSafeInteger(record.challenge_id) || record.challenge_id<1 || record.record_name !== "_daedalus-verification."+options.domain ||
          !validDate(record.expires_at) || typeof record.value_available !== "boolean" ||
          (record.created_at !== null && (!validDate(record.created_at) || Date.parse(record.created_at)>Date.parse(body.observed_at) || Date.parse(record.created_at)>=Date.parse(record.expires_at))) ||
          (record.value_available ? typeof record.record_value !== "string" || !/^daedalus-verification=[A-Za-z0-9_-]{32}$/.test(record.record_value) : record.record_value !== null) ||
          (body.state === "active") !== (Date.parse(record.expires_at)>Date.parse(body.observed_at))) throw new Error("The current TXT record could not be confirmed.");
      if (body.last_check !== null) {
        var check = body.last_check;
        if (!check || !["verified","not_found","lookup_failed"].includes(check.outcome) || !validDate(check.checked_at) || Date.parse(check.checked_at)>Date.parse(body.observed_at) ||
            !Number.isSafeInteger(check.challenge_id) || check.challenge_id<1 || check.record_name !== "_daedalus-verification."+options.domain) throw new Error("The saved DNS check could not be confirmed.");
      }
      return body;
    }
    function active() {return Boolean(state.body && state.body.state === "active" && Date.parse(state.body.txt.expires_at)>Date.now());}
    function canAct(kind, reference) {return ["ensure","verify","replace"].includes(kind) && state.fresh && !state.loading && !state.busy && !state.body.verified &&
      (!reference || reference === state.body.state_reference) && (kind === "ensure" || active());}
    function controls() {
      refresh.disabled = state.busy;refresh.setAttribute("aria-busy",String(state.loading));
      [[ensure,"ensure"],[verify,"verify"],[replace,"replace"]].forEach(function (pair) {pair[0].disabled = !canAct(pair[1]);pair[0].setAttribute("aria-disabled",String(pair[0].disabled));});
      if (confirmation) {confirmation.confirm.disabled = !canAct("replace",confirmation.reference);confirmation.cancel.disabled = state.busy;}
      observed.textContent = state.body ? (state.fresh ? "TXT instructions read " : "Last observed ")+date(state.body.observed_at)+"." : "No ownership instructions read yet.";
      note.hidden = !state.error && (!state.loading || !!state.body);
      note.textContent = state.error ? state.error+" "+(state.body ? "The displayed instructions are last observed. " : "")+"Refresh TXT instructions before publishing or changing a record."
        : state.loading ? "Reading the saved ownership instructions…" : "";
      details.dataset.readStale = String(!state.fresh);
      details.setAttribute("aria-busy",String(state.busy));
    }
    function closeConfirmation() {
      if (!confirmation) return;
      var focused = confirmation.panel.contains(document.activeElement);
      confirmation.panel.remove();confirmation = null;
      replace.setAttribute("aria-expanded","false");replace.removeAttribute("aria-controls");
      if (focused) (replace.disabled ? refresh : replace).focus({preventScroll:true});
    }
    function render() {
      var body = state.body, record = body.txt, current = body.state === "active";
      details.hidden = false;
      summary.textContent = body.verified ? "Domain ownership verified" : "Verify "+options.domain+" with a DNS TXT record";
      challenge.classList.toggle("hidden",!current);
      name.textContent = current ? record.record_name : "";
      value.textContent = current ? record.value_available ? record.record_value : "The original value cannot be redisplayed." : "";
      expiry.textContent = current ? (record.created_at ? "Prepared "+date(record.created_at)+". " : "Preparation date unavailable. ")+"Record expires "+date(record.expires_at)+"." : "";
      instructions.textContent = body.verified ? "Domain ownership is verified"+(body.verified_at ? " as recorded "+date(body.verified_at)+"." : ". The verification date is unavailable.")
        : current && !record.value_available ? "The current record remains valid. If you already published it, check DNS now. Use Replace TXT record if you need a new value."
        : current ? "Publish this record at your DNS provider, then check DNS here. Refreshing keeps the same record."
        : body.state === "expired" ? "The previous record expired "+date(record.expires_at)+". Show DNS TXT record prepares a new one."
        : "Show DNS TXT record prepares the ownership instructions.";
      ensure.hidden = body.verified || current;verify.hidden = !current;replacement.hidden = !current;
      var check = body.last_check;
      lastCheck.hidden = !check;
      lastCheck.textContent = check ? "Last DNS check "+date(check.checked_at)+": "+({verified:"ownership verified",not_found:"TXT record not found",lookup_failed:"DNS lookup failed; ownership was not verified"}[check.outcome])+
        (record && record.challenge_id !== check.challenge_id ? " · checked an earlier record" : "")+"." : "";
      if (confirmation && (confirmation.reference !== body.state_reference || !current || body.verified)) closeConfirmation();
    }
    async function request(suffix, method, reference) {
      var controller = new AbortController(), rejectDeadline;
      var timeout = new Promise(function (_,reject) {rejectDeadline = reject;});
      var timer = window.setTimeout(function () {controller.abort();rejectDeadline(new Error("The TXT request timed out."));},20000);
      try {
        return await Promise.race([timeout,(async function () {
          var headers = new Headers();if (reference) headers.set("X-Daedalus-Domain-State",reference);
          var response = await options.fetch(path+suffix,{method:method,credentials:"same-origin",cache:"no-store",headers:headers,signal:controller.signal});
          var body;try {body = await response.json();} catch (_) {body = null;}
          return {body:body,status:response.status,ok:response.ok};
        })()]);
      } finally {window.clearTimeout(timer);}
    }
    function responseError(result) {return new Error(result.body && typeof result.body.detail === "string" ? result.body.detail : "The TXT request could not be confirmed.");}
    function changedToVerified(previous) {return state.body.verified && (!previous || !previous.verified);}
    function restoreReviewFocus(trigger) {
      var focused = document.activeElement;
      if (focused && focused !== document.body && focused !== trigger) return;
      if (!details.contains(trigger) || trigger.disabled || trigger.hidden) refresh.focus({preventScroll:true});
      else if (focused !== trigger) trigger.focus({preventScroll:true});
    }
    async function load() {
      if (state.busy || state.loading) return;
      var trigger = document.activeElement, restoreFocus = details.contains(trigger);
      state.loading = true;state.error = null;controls();var previous = state.body, becameVerified = false;
      try {
        var result = await request("/domain-challenge","GET");if (!result.ok) throw responseError(result);
        state.body = validate(result.body);state.fresh = true;render();becameVerified = changedToVerified(previous);
        if (state.unconfirmed) {
          feedback.textContent = "Ownership status refreshed "+date(state.body.observed_at)+". "+(state.body.verified ? "Domain ownership is verified."
            : state.body.state === "active" ? "The saved current TXT record is shown below. Review it before updating DNS." : "Domain ownership is pending. "+instructions.textContent);
          state.unconfirmed = false;
        }
      } catch (error) {state.fresh = false;state.error = error.message;}
      finally {state.loading = false;controls();if (restoreFocus) restoreReviewFocus(trigger);}
      if (becameVerified) {try {await options.onVerified();} catch (_) {}}
    }
    async function perform(kind, reference) {
      if (!canAct(kind,reference)) {feedback.textContent = "Refresh TXT instructions before deciding again. The displayed record is no longer current.";return;}
      var previous = state.body, oldId = previous.txt && previous.txt.challenge_id, trigger = document.activeElement, restoreFocus = details.contains(trigger);
      state.busy = true;state.error = null;controls();
      feedback.textContent = kind === "verify" ? "Checking the public DNS TXT record…" : kind === "replace" ? "Saving a replacement TXT record…" : "Preparing the current TXT instructions…";
      var becameVerified = false, checked = false;
      try {
        var result = await request(kind === "verify" ? "/verify-domain" : kind === "ensure" ? "/domain-challenge/ensure" : "/domain-challenge","POST",previous.state_reference);
        var lookupFailed = kind === "verify" && result.status === 503 && result.body && result.body.last_check && result.body.last_check.outcome === "lookup_failed";
        if (!result.ok && !lookupFailed) throw responseError(result);
        var body = validate(result.body);
        if (!body.verified && (kind === "verify" ? body.state !== "active" || !body.last_check || body.last_check.challenge_id !== oldId || !["not_found","lookup_failed"].includes(body.last_check.outcome) || (body.last_check.outcome === "lookup_failed") !== lookupFailed
            : body.state !== "active" || typeof body.created !== "boolean" || (body.created && (body.txt.challenge_id === oldId || body.state_reference === previous.state_reference)) ||
              (kind === "replace" && !body.created) || (kind === "ensure" && !body.created && body.txt.challenge_id !== oldId))) throw new Error("The TXT decision response is incomplete.");
        state.body = body;state.fresh = true;state.unconfirmed = false;render();becameVerified = changedToVerified(previous);checked = kind === "verify";
        feedback.textContent = body.verified ? "Domain ownership verified. "+(body.verified_at ? "Recorded "+date(body.verified_at)+"." : "The verification date is unavailable.")
          : kind === "verify" ? (lookupFailed ? "DNS lookup failed. " : "The verification TXT record was not found yet. ")+"Checked "+date(body.last_check.checked_at)+". "+(lookupFailed && typeof body.detail === "string" ? body.detail+" " : "")+"Ownership remains pending."
          : kind === "replace" ? "Replacement TXT record saved "+date(body.txt.created_at||body.observed_at)+". The previous value no longer verifies this domain. Publish the new record below."
          : body.created ? "TXT instructions prepared "+date(body.txt.created_at||body.observed_at)+". Publish the record below." : "Current TXT instructions read "+date(body.observed_at)+". The same active record is retained.";
      } catch (error) {
        state.fresh = false;state.error = error.message;state.unconfirmed = true;
        feedback.textContent = "The "+(kind === "verify" ? "DNS check" : "TXT decision")+" was not confirmed. "+error.message+" Refresh TXT instructions to check what was saved before trying again.";
      } finally {state.busy = false;closeConfirmation();controls();}
      if (restoreFocus) restoreReviewFocus(trigger);
      if (becameVerified) {try {await options.onVerified();} catch (_) {}}
      else if (checked) {try {await options.onChecked();} catch (_) {}}
    }
    replace.addEventListener("click",function () {
      if (!canAct("replace") || confirmation) return;
      var panel = document.createElement("div");panel.className = "inline-confirmation";panel.id = "domain-replacement-confirmation";panel.setAttribute("role","group");
      var description = document.createElement("p");description.id = "domain-replacement-message";description.className = "inline-confirmation-message";
      description.textContent = "Replace the current TXT record? The previous value will stop verifying this domain. Update DNS with the new value afterward.";
      panel.setAttribute("aria-labelledby",description.id);
      var actions = document.createElement("div");actions.className = "inline-confirmation-actions";
      var confirm = document.createElement("button"), cancel = document.createElement("button");confirm.type = cancel.type = "button";
      confirm.className = "button button-small";confirm.textContent = "Replace record";confirm.setAttribute("aria-describedby",description.id);
      cancel.className = "button button-small button-quiet";cancel.textContent = "Cancel";
      actions.append(confirm,cancel);panel.append(description,actions);replacement.append(panel);
      confirmation = {panel:panel,confirm:confirm,cancel:cancel,reference:state.body.state_reference};
      replace.setAttribute("aria-expanded","true");replace.setAttribute("aria-controls",panel.id);
      confirm.addEventListener("click",function () {if (confirmation) return perform("replace",confirmation.reference);});
      cancel.addEventListener("click",function () {closeConfirmation();if (!replace.disabled) replace.focus();else refresh.focus();});
      confirm.focus();controls();
    });
    ensure.addEventListener("click",function () {return perform("ensure");});verify.addEventListener("click",function () {return perform("verify");});
    refresh.addEventListener("click",load);
    function observe(organization) {
      if (!state.fresh || state.loading || state.busy || !state.body) return;
      if (state.body.verified !== (organization.verification_status === "verified") || state.body.state === "active" && !active()) load();
    }
    controls();return {state:state,load:load,perform:perform,observe:observe};
  }};
})();
