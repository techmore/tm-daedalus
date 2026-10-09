"use strict";
(() => {
  const feedback = document.getElementById("key-feedback");
  const account = document.getElementById("access-key-account");
  const orgId = account ? Number(account.dataset.organizationId) : null;
  async function keyRequest(url, options = {}) {
    const headers = new Headers(options.headers || {});
    headers.set("Content-Type", "application/json");
    if (account && url.startsWith("/api/")) headers.set("X-Daedalus-Workspace", String(orgId));
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), 20000);
    try {
      const response = await fetch(url, {...options, headers, cache: "no-store", signal: controller.signal});
      let data;
      try { data = await response.json(); } catch (_) { data = {}; }
      if (!response.ok) {
        const error = new Error(typeof data.detail === "string" ? data.detail : "Request failed. Refresh and try again.");
        error.status = response.status;
        throw error;
      }
      return data;
    } catch (error) {
      if (controller.signal.aborted) throw new Error("The request timed out. Refresh keys to check the saved state before retrying.");
      throw error;
    } finally { window.clearTimeout(timer); }
  }
  const login = document.getElementById("token-login");
  let loginBusy = false;
  if (login) login.addEventListener("submit", async event => {
    event.preventDefault();
    if (loginBusy) return;
    loginBusy = true;
    const button = login.querySelector("button"); button.disabled = true;
    feedback.textContent = "Signing in…";
    try {
      const result = await keyRequest("/auth/token", {method: "POST", body: JSON.stringify({token: login.elements.token.value})});
      if (result.redirect !== "/dashboard") throw new Error("Sign-in could not be confirmed. Try signing in again.");
      login.reset(); location.assign("/dashboard");
    } catch (error) { feedback.textContent = error.message; }
    finally { loginBusy = false; button.disabled = false; }
  });
  if (!account) return;

  const create = document.getElementById("create-key");
  const list = document.getElementById("key-list");
  const refresh = document.getElementById("refresh-keys");
  const readFeedback = document.getElementById("key-read-feedback");
  const observed = document.getElementById("key-observed");
  const panel = document.getElementById("new-key-panel");
  const tokenField = document.getElementById("new-key");
  let saved = null, signature = null, fresh = false, readBusy = false, mutationBusy = false, readSequence = 0;
  function keyDate(value) {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? "Unknown" : date.toLocaleString(undefined, {
      year: "numeric", month: "short", day: "numeric", hour: "numeric", minute: "2-digit", timeZoneName: "short"
    });
  }
  function updateControls() {
    refresh.disabled = mutationBusy;
    refresh.setAttribute("aria-busy", String(readBusy));
    list.setAttribute("aria-busy", String(readBusy));
    if (create) {
      create.querySelector("button").disabled = mutationBusy || readBusy || !fresh || !saved?.can_create || !panel.hidden;
      document.getElementById("key-create-note").hidden = !saved || saved.can_create;
    }
    for (const button of list.querySelectorAll("button")) {
      button.setAttribute("aria-disabled", String(mutationBusy || readBusy || !fresh));
      button.setAttribute("aria-busy", String(mutationBusy && button.dataset.pending === "true"));
    }
    for (const status of list.querySelectorAll(".key-status")) {
      status.textContent = (fresh ? "" : "Last observed: ") + status.dataset.status;
    }
  }
  function validDate(value) { return typeof value === "string" && /(?:Z|[+-]\d{2}:\d{2})$/.test(value) && Number.isFinite(Date.parse(value)); }
  function validate(body) {
    if (!body || body.organization_id !== orgId || typeof body.can_create !== "boolean" ||
        !validDate(body.observed_at) || Date.parse(body.observed_at) > Date.now() + 60000 || !Array.isArray(body.keys) ||
        (body.current_key_id !== null && (!Number.isSafeInteger(body.current_key_id) || body.current_key_id <= 0))) throw new Error("The workspace key list could not be confirmed. Refresh the page before continuing.");
    const ids = new Set();
    for (const key of body.keys) {
      if (!key || !Number.isSafeInteger(key.id) || key.id <= 0 || ids.has(key.id) || typeof key.name !== "string" ||
          !validDate(key.created_at) || !validDate(key.expires_at) || (key.revoked_at !== null && !validDate(key.revoked_at))) throw new Error("The saved key list is incomplete. Refresh keys to try again.");
      ids.add(key.id);
    }
    if (body.current_key_id !== null && !ids.has(body.current_key_id)) throw new Error("The current sign-in key could not be confirmed. Refresh the page before continuing.");
    return body;
  }
  function render(body) {
    const active = document.activeElement;
    const focusedId = active?.dataset?.revokeKey;
    const nextSignature = JSON.stringify([body.can_create, body.current_key_id, body.keys,
      body.keys.map(key => Date.parse(key.expires_at) <= Date.parse(body.observed_at))]);
    if (signature !== nextSignature) {
      list.replaceChildren();
      if (!body.keys.length) { const empty = document.createElement("p"); empty.textContent = "No personal keys for this workspace yet."; list.append(empty); }
      for (const key of body.keys) {
        const row = document.createElement("article"); row.className = "access-key-row";
        const name = document.createElement("strong"); name.textContent = key.name;
        const status = document.createElement("span"); status.className = "key-status";
        const expired = Date.parse(key.expires_at) <= Date.parse(body.observed_at);
        status.dataset.status = key.revoked_at ? "Revoked" : expired ? "Expired" : "Active when checked";
        if (key.id === body.current_key_id) status.dataset.status += " · current sign-in key";
        const detail = document.createElement("span");
        detail.textContent = key.revoked_at ? `Revoked ${keyDate(key.revoked_at)}` : `Expires ${keyDate(key.expires_at)}`;
        const created = document.createElement("span"); created.textContent = `Created ${keyDate(key.created_at)}`;
        row.append(name, status, detail, created);
        if (!key.revoked_at && !expired) {
          const button = document.createElement("button"); button.type = "button"; button.textContent = "Revoke";
          button.className = "button button-secondary"; button.dataset.revokeKey = String(key.id);
          button.setAttribute("aria-label", `Revoke ${key.name}`);
          button.addEventListener("click", () => revokeKey(key, button)); row.append(button);
        }
        list.append(row);
      }
      signature = nextSignature;
      if (focusedId && list.contains(active) === false) {
        const replacement = [...list.querySelectorAll("button")].find(button => button.dataset.revokeKey === focusedId);
        (replacement || refresh).focus();
      }
    }
    observed.textContent = `Checked ${keyDate(body.observed_at)}`;
  }
  async function loadKeys(reconcile = false) {
    if (mutationBusy && !reconcile) return;
    const sequence = ++readSequence; readBusy = true; fresh = false; updateControls();
    try {
      const body = validate(await keyRequest("/api/user-keys"));
      if (sequence !== readSequence) return;
      render(body); saved = body; fresh = true; readFeedback.hidden = true; readFeedback.textContent = "";
    } catch (error) {
      if (sequence !== readSequence) return;
      if (error.status === 401) { location.assign("/"); return; }
      readFeedback.hidden = false;
      readFeedback.textContent = (saved ? "Your saved key list is retained; access is last observed. " : "Your keys are unavailable. ") + error.message;
      if (saved) observed.textContent = `Last observed ${keyDate(saved.observed_at)}`;
      else list.textContent = "Refresh keys to try again.";
    } finally { if (sequence === readSequence) { readBusy = false; updateControls(); } }
  }
  async function revokeKey(key, button) {
    if (mutationBusy || readBusy || !fresh) return;
    mutationBusy = true; button.dataset.pending = "true"; updateControls();
    feedback.textContent = `Revoking ${key.name}…`;
    try {
      const result = await keyRequest(`/api/user-keys/${key.id}`, {method: "DELETE"});
      if (result.organization_id !== orgId || result.id !== key.id || result.status !== "revoked" || !validDate(result.revoked_at) || typeof result.ends_current_session !== "boolean") throw new Error("Revocation could not be confirmed. Refresh keys before retrying.");
      feedback.textContent = `${key.name} was revoked. Its API access and sign-in sessions have ended.`;
      if (result.ends_current_session) { tokenField.value = ""; location.assign("/"); return; }
      await loadKeys(true);
    } catch (error) {
      if (error.status === 401) { location.assign("/"); return; }
      fresh = false; feedback.textContent = `${error.message} Refresh keys to check whether revocation was saved.`;
    } finally { mutationBusy = false; button.dataset.pending = "false"; updateControls(); }
  }
  refresh.addEventListener("click", () => loadKeys());
  document.getElementById("hide-new-key").addEventListener("click", () => {
    tokenField.value = ""; panel.hidden = true; updateControls();
    if (create && !create.querySelector("button").disabled) create.elements.name.focus(); else refresh.focus();
  });
  if (create) create.addEventListener("submit", async event => {
    event.preventDefault();
    if (mutationBusy || readBusy || !fresh || !saved?.can_create || !panel.hidden) return;
    mutationBusy = true; updateControls(); feedback.textContent = "Creating your key…";
    try {
      const result = await keyRequest("/api/user-keys", {method: "POST", body: JSON.stringify({name: create.elements.name.value, expires_days: Number(create.elements.expires_days.value)})});
      if (result.organization_id !== orgId || !Number.isSafeInteger(result.id) || typeof result.token !== "string" || !/^dd_user_[A-Za-z0-9_-]{64}$/.test(result.token) || !validDate(result.expires_at)) throw new Error("The new key could not be confirmed. Refresh keys to check whether it was saved.");
      tokenField.value = result.token; panel.hidden = false;
      document.getElementById("new-key-detail").textContent = `Expires ${keyDate(result.expires_at)}. Save it before creating another key.`;
      feedback.textContent = "Your key was created. Copy it now; it will not be shown again.";
      create.reset(); tokenField.focus(); tokenField.select(); await loadKeys(true);
    } catch (error) {
      if (error.status === 401) { location.assign("/"); return; }
      fresh = false; feedback.textContent = `${error.message} Refresh keys before creating another key.`;
    } finally { mutationBusy = false; updateControls(); }
  });
  loadKeys();
})();
