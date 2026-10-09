(function () {
  "use strict";
  window.DaedalusMembershipReview = {create: function (options) {
    var orgId = Number(options.organizationId);
    var list = document.getElementById("membership-list");
    var refresh = document.getElementById("membership-refresh");
    var note = document.getElementById("membership-read-note");
    var observed = document.getElementById("membership-observed");
    var summary = document.getElementById("membership-summary");
    var feedback = document.getElementById("member-access-note");
    var pendingHost = document.getElementById("pending-approvals");
    if (!list || !refresh || !Number.isSafeInteger(orgId) || orgId <= 0) return null;
    var state = {body: null, fresh: false, loading: false, busy: false, sequence: 0, controller: null, error: null};
    var rows = new Map(), pendingRows = new Map();
    var pendingCard, pendingTitle, pendingList, pendingNote, pendingFeedback, pendingRefresh;
    if (pendingHost) {
      pendingCard = document.createElement("section"); pendingCard.className = "approval-card";
      pendingTitle = document.createElement("strong");
      pendingRefresh = document.createElement("button"); pendingRefresh.type = "button"; pendingRefresh.className = "button button-quiet button-small"; pendingRefresh.textContent = "Refresh access requests";
      pendingList = document.createElement("div"); pendingNote = document.createElement("p"); pendingNote.className = "status-when"; pendingNote.setAttribute("role", "status");
      pendingFeedback = document.createElement("p"); pendingFeedback.className = "status-when"; pendingFeedback.setAttribute("role", "status"); pendingFeedback.hidden = true;
      pendingCard.append(pendingTitle, pendingRefresh, pendingNote, pendingList, pendingFeedback); pendingCard.hidden = true; pendingHost.append(pendingCard);
      pendingRefresh.addEventListener("click", function () { load(); });
    }
    function dateLabel(value) { return new Date(value).toLocaleString(undefined, {year:"numeric",month:"short",day:"numeric",hour:"numeric",minute:"2-digit",timeZoneName:"short"}); }
    function validDate(value) { return typeof value === "string" && /(?:Z|[+-]\d{2}:\d{2})$/.test(value) && Number.isFinite(Date.parse(value)); }
    function validate(body) {
      if (!body || body.organization_id !== orgId || typeof body.can_manage !== "boolean" || typeof body.controls_enabled !== "boolean" ||
          !Number.isSafeInteger(body.approved_admin_count) || body.approved_admin_count < 1 || !validDate(body.observed_at) || Date.parse(body.observed_at) > Date.now()+60000 || !Array.isArray(body.members)) throw new Error("The workspace member list could not be confirmed. Refresh this page before continuing.");
      var ids = new Set(), selves = 0;
      body.members.forEach(function (member) {
        if (!member || !Number.isSafeInteger(member.id) || member.id <= 0 || ids.has(member.id) || typeof member.email !== "string" || typeof member.name !== "string" ||
            !["user","admin"].includes(member.role) || !["pending","approved","denied","revoked"].includes(member.status) || typeof member.is_self !== "boolean" ||
            typeof member.state_reference !== "string" || !/^[a-f0-9]{64}$/.test(member.state_reference) || !body.can_manage && !member.is_self) throw new Error("The saved member list is incomplete. Refresh members to try again.");
        ids.add(member.id); if (member.is_self) selves++;
      });
      if (selves !== 1 || !body.members.some(function (member) {return member.is_self && member.status === "approved" && (member.role === "admin") === body.can_manage;})) throw new Error("Your workspace role could not be confirmed. Refresh this page before continuing.");
      if (body.can_manage && body.members.filter(function (member) {return member.status === "approved" && member.role === "admin";}).length !== body.approved_admin_count) throw new Error("Administrator coverage could not be confirmed. Refresh members before changing roles.");
      return body;
    }
    function showOutcome(message) {
      feedback.textContent = message; feedback.classList.remove("hidden");
      if (pendingFeedback) { pendingFeedback.textContent = message; pendingFeedback.hidden = false; }
    }
    function updateControls() {
      var paused = !state.fresh || state.busy;
      list.setAttribute("aria-busy", String(state.loading));
      refresh.disabled = state.busy; refresh.setAttribute("aria-busy", String(state.loading));
      if (pendingRefresh) pendingRefresh.disabled = state.busy;
      [list, pendingList].filter(Boolean).forEach(function (host) {
        host.querySelectorAll("[data-member-action]").forEach(function (button) {
          var requiresApproval = button.dataset.requiresApproval === "true";
          button.setAttribute("aria-disabled", String(paused || requiresApproval && (!state.body || !state.body.controls_enabled)));
          button.disabled = requiresApproval && state.body && !state.body.controls_enabled;
        });
      });
      if (state.body) {
        observed.textContent = (state.fresh ? "Members checked " : "Last observed ") + dateLabel(state.body.observed_at) + ".";
        function countLabel(count,label) {return count + " " + label + (count === 1 ? "" : "s");}
        summary.textContent = state.body.can_manage
          ? countLabel(state.body.members.filter(function (m) {return m.status === "pending";}).length,"pending request") + " · " + countLabel(state.body.members.filter(function (m) {return m.status === "approved";}).length,"approved member") + " · " + countLabel(state.body.approved_admin_count,"admin") + "."
          : "Your approved user membership. Workspace admins manage access and roles.";
      }
      note.hidden = !state.error;
      note.textContent = state.error ? (state.body ? "Saved members are retained; access and roles are last observed. " : "Workspace members are unavailable. ") + state.error + " Changes are paused until a successful refresh." : "";
      if (pendingCard) {
        var count = state.body && state.body.can_manage ? state.body.members.filter(function (m) {return m.status === "pending";}).length : 0;
        pendingCard.hidden = !count && !state.error && pendingFeedback.hidden;
        pendingTitle.textContent = count ? count + (count === 1 ? " person is waiting for access" : " people are waiting for access") : state.error ? "Access requests could not be refreshed" : "Access request review";
        pendingNote.textContent = state.error ? note.textContent : state.body ? "Members checked " + dateLabel(state.body.observed_at) + "." : "";
      }
    }
    async function request(path, requestOptions, controller) {
      controller = controller || new AbortController();
      var headers = new Headers(requestOptions && requestOptions.headers || {});
      headers.set("Content-Type", "application/json"); headers.set("X-Daedalus-Workspace", String(orgId));
      var timer = window.setTimeout(function () { controller.abort(); }, 20000);
      try {
        var response = await options.fetch(path, Object.assign({}, requestOptions, {headers:headers,credentials:"same-origin",cache:"no-store",signal:controller.signal}));
        var body; try { body = await response.json(); } catch (_) { body = {}; }
        if (!response.ok) { var error = new Error(body && typeof body.detail === "string" ? body.detail : "Workspace access could not be read."); error.status = response.status; throw error; }
        return body;
      } catch (error) { if (controller.signal.aborted) throw new Error("The request timed out. Refresh members to check the saved state."); throw error; }
      finally { window.clearTimeout(timer); }
    }
    function actionButton(member, kind, value, label) {
      var button = document.createElement("button"); button.type = "button"; button.className = "button button-small button-quiet";
      button.textContent = label; button.dataset.memberAction = kind; button.dataset.memberId = String(member.id); button.dataset.memberValue = value;
      button.dataset.requiresApproval = String(kind === "role" || kind === "decision" && value === "true");
      button.setAttribute("aria-label", label + ": " + member.email);
      button.addEventListener("click", function (event) {
        event.stopPropagation();
        if (!canAct(member, kind, value)) {
          if (!state.busy) showOutcome("Refresh members before changing access. The displayed membership or workspace approval is no longer current.");
          return;
        }
        if (kind === "decision") return perform(member, kind, value).catch(function () {});
        var description = kind === "revoke" ? "Remove " + member.email + " from this workspace? They will need approval to rejoin."
          : member.is_self ? "Switch your account to the user role? The other approved admins will retain control."
          : (value === "admin" ? "Give administrator access to " : "Change to the user role: ") + member.email + "?";
        options.confirm(button, description, kind === "revoke" ? "Remove access" : value === "admin" ? "Promote to admin" : member.is_self ? "Transfer admin" : "Change to user", function () {return perform(member, kind, value);});
      });
      return button;
    }
    function canAct(member, kind, value) {
      if (!state.body || !state.fresh || state.busy || !state.body.can_manage) return false;
      var current = state.body.members.find(function (m) {return m.id === member.id;});
      if (!current || current.state_reference !== member.state_reference) return false;
      if ((kind === "role" || kind === "decision" && value === "true") && !state.body.controls_enabled) return false;
      return kind === "decision" ? current.status === "pending" : kind === "revoke" ? current.status === "approved" && current.role === "user" && !current.is_self
        : current.status === "approved" && (value === "admin" && current.role === "user" || value === "user" && current.role === "admin" && state.body.approved_admin_count > 1);
    }
    function memberRow(member, body) {
      var row = document.createElement("article"); row.className = "membership-row"; row.dataset.memberRow = String(member.id);
      var person = document.createElement("div"); person.className = "membership-person";
      var name = document.createElement("strong"); name.textContent = member.name || member.email;
      var email = document.createElement("small"); email.textContent = member.email; person.append(name,email);
      var meta = document.createElement("div"); meta.className = "membership-meta"; meta.textContent = (member.role === "admin" ? "Admin" : "User") + " · " + member.status + (member.is_self ? " · you" : "");
      row.append(person,meta);
      var actions = document.createElement("div"); actions.className = "membership-actions";
      if (body.can_manage && member.status === "pending") {
        actions.append(actionButton(member,"decision","true","Approve as user"),actionButton(member,"decision","false","Deny"));
      } else if (body.can_manage && member.status === "approved") {
        if (member.role === "user") {
          actions.append(actionButton(member,"role","admin","Promote to admin"));
          if (!member.is_self) actions.append(actionButton(member,"revoke","","Remove access"));
        } else if (body.approved_admin_count > 1) actions.append(actionButton(member,"role","user",member.is_self ? "Transfer admin and switch to user" : "Change to user"));
      }
      if (actions.childElementCount) row.append(actions);
      return row;
    }
    function reconcile(host, cache, members, body, pending) {
      if (!host) return;
      var active = document.activeElement, focused = host.contains(active);
      var next = new Map();
      members.forEach(function (member) {
        var signature = JSON.stringify([member,body.can_manage,body.controls_enabled,body.approved_admin_count]);
        var previous = cache.get(member.id), entry;
        if (previous && previous.signature === signature) entry = previous;
        else {
          var row;
          if (pending) {
            row = document.createElement("div"); row.className = "approval-row";
            var who = document.createElement("span"); who.className = "approval-who"; who.textContent = member.email;
            row.append(who,actionButton(member,"decision","true","Approve"),actionButton(member,"decision","false","Deny"));
          } else row = memberRow(member,body);
          entry = {signature:signature,row:row};
        }
        next.set(member.id,entry);
      });
      // Avoid detaching unchanged nodes, including an open inline confirmation.
      Array.from(host.children).forEach(function (row) {if (![...next.values()].some(function (entry) {return entry.row === row;})) row.remove();});
      var cursor = host.firstElementChild;
      next.forEach(function (entry) {
        if (entry.row !== cursor) host.insertBefore(entry.row,cursor);
        cursor = entry.row.nextElementSibling;
      });
      if (focused && !host.contains(active)) (pending ? pendingRefresh : refresh).focus();
      else if (focused && document.activeElement !== active) active.focus({preventScroll:true});
      cache.clear(); next.forEach(function (entry,id) {cache.set(id,entry);});
    }
    function render(body) {
      reconcile(list,rows,body.members,body,false);
      reconcile(pendingList,pendingRows,body.can_manage ? body.members.filter(function (member) {return member.status === "pending";}) : [],body,true);
    }
    async function load(background, reconcileWrite) {
      if (state.busy && !reconcileWrite || background && (state.loading || state.error || list.querySelector(".inline-confirmation"))) return;
      var sequence = ++state.sequence;
      if (state.controller) state.controller.abort();
      var controller = new AbortController(); state.controller = controller; state.loading = true;
      if (!background) state.fresh = false;
      updateControls();
      try {
        var body = validate(await request("/api/memberships",null,controller));
        if (sequence !== state.sequence) return;
        render(body); state.body = body; state.fresh = true; state.error = null;
        if (options.onRoleObserved) options.onRoleObserved(body.can_manage);
      } catch (error) {
        if (sequence !== state.sequence) return;
        state.fresh = false;
        state.error = error.message;
        if (!state.body) list.textContent = "Use Refresh members to try again.";
      } finally {if (sequence === state.sequence) {state.loading = false; state.controller = null; updateControls();}}
    }
    async function perform(member, kind, value) {
      if (!canAct(member,kind,value)) throw new Error("Member access is no longer current. Refresh members before deciding again.");
      // A write supersedes any background read. Its response must not restore
      // the earlier membership snapshot while this decision is being saved.
      ++state.sequence;
      if (state.controller) state.controller.abort();
      state.controller = null; state.loading = false;
      state.busy = true; updateControls(); showOutcome("Saving access decision for " + member.email + "…");
      try {
        var body = await request("/api/memberships/"+member.id+"/"+kind,{method:"POST",headers:{"X-Daedalus-Membership-State":member.state_reference},body:JSON.stringify(kind === "decision" ? {approve:value === "true"} : kind === "role" ? {role:value} : {})});
        if (!body || body.organization_id !== orgId || body.id !== member.id || kind === "role" && (body.role !== value || typeof body.changed !== "boolean") ||
            kind !== "role" && (body.role !== "user" || body.status !== (kind === "revoke" ? "revoked" : value === "true" ? "approved" : "denied"))) throw new Error("The access decision could not be confirmed. Refresh members to check the saved state.");
        showOutcome(kind === "revoke" ? "Access removed for " + member.email + ". The decision is recorded in the audit log."
          : kind === "role" ? "Role updated for " + member.email + ". The decision is recorded in the audit log."
          : value === "true" ? member.email + " was approved as a user. The decision is recorded in the audit log." : "Access request declined for " + member.email + ". The decision is recorded in the audit log.");
        if (kind === "role" && member.is_self) {options.onSelfRoleChange();return;}
        await load(false,true); await options.onSaved();
      } catch (error) {state.fresh = false; state.error = "The write outcome requires a fresh member read."; showOutcome(error.message + " Refresh members before retrying."); throw error;}
      finally {state.busy = false; updateControls();}
    }
    refresh.addEventListener("click",function () {load();});
    return {load:load,state:state,pauseApproval:function () {
      if (state.body) {state.body.controls_enabled = false; updateControls();}
    }};
  }};
})();
