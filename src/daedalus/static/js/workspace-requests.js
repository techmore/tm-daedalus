/* Account-owned workspace requests; independent from workspace admin decisions. */
(function () {
  "use strict";
  window.DaedalusWorkspaceRequests = {create: function (options) {
    var userId = Number(options.userId);
    var views = ["dialog-workspace","account-workspace"].map(function (prefix) {
      return {list:document.getElementById(prefix+"-list"),refresh:document.getElementById(prefix+"-refresh"),
        observed:document.getElementById(prefix+"-observed"),note:document.getElementById(prefix+"-read-note"),cache:new Map()};
    }).filter(function (view) {return view.list && view.refresh;});
    if (!views.length || !Number.isSafeInteger(userId) || userId <= 0) return null;
    var state = {body:null,fresh:false,loading:false,error:null,sequence:0}, controller = null;
    var select = document.getElementById("workspace-select");
    function validDate(value) {return typeof value === "string" && /(?:Z|[+-]\d{2}:\d{2})$/.test(value) && Number.isFinite(Date.parse(value));}
    function dateLabel(value) {return new Date(value).toLocaleString(undefined,{year:"numeric",month:"short",day:"numeric",hour:"numeric",minute:"2-digit",timeZoneName:"short"});}
    function validate(body) {
      if (!body || body.user_id !== userId || !validDate(body.observed_at) || Date.parse(body.observed_at)>Date.now()+60000 || !Array.isArray(body.workspaces)) throw new Error("Your workspace requests could not be confirmed. Reload this page before continuing.");
      var ids = new Set();
      body.workspaces.forEach(function (workspace) {
        if (!workspace || !Number.isSafeInteger(workspace.id) || workspace.id <= 0 || ids.has(workspace.id) ||
            typeof workspace.name !== "string" || !workspace.name || typeof workspace.domain !== "string" || !workspace.domain ||
            !["admin","user"].includes(workspace.role) || !["approved","pending","denied","revoked"].includes(workspace.status) ||
            !validDate(workspace.membership_created_at) || workspace.requested_at !== null && !validDate(workspace.requested_at)) throw new Error("Your saved workspace list is incomplete. Refresh workspaces to try again.");
        ids.add(workspace.id);
      });
      return body;
    }
    function canSelect(id) {
      return Boolean(state.fresh && !state.loading && state.body && state.body.workspaces.some(function (workspace) {return workspace.id === Number(id) && workspace.status === "approved";}));
    }
    function updateControls() {
      views.forEach(function (view) {
        view.list.setAttribute("aria-busy",String(state.loading)); view.refresh.setAttribute("aria-busy",String(state.loading));
        view.list.querySelectorAll("[data-workspace-review-open]").forEach(function (button) {
          button.setAttribute("aria-disabled",String(!canSelect(button.dataset.workspaceReviewOpen) || options.selectionBusy()));
        });
        view.note.hidden = !state.error;
        view.note.textContent = state.error ? (state.body ? "Saved workspaces and requests are retained; access is last observed. " : "Workspace requests are unavailable. ") + state.error + " Use Refresh workspaces to try again." : "";
        if (state.body) {
          var approved = state.body.workspaces.filter(function (w) {return w.status === "approved";}).length;
          var pending = state.body.workspaces.filter(function (w) {return w.status === "pending";}).length;
          view.observed.textContent = approved + " approved workspace" + (approved===1 ? "" : "s") + " · " + pending + " request" + (pending===1 ? "" : "s") + " awaiting approval. " +
            (state.fresh ? "Checked " : "Last checked ") + dateLabel(state.body.observed_at) + ".";
        } else view.observed.textContent = state.loading ? "Reading your saved workspaces and requests…" : "No successful workspace read yet.";
      });
      if (select) {
        select.disabled = options.selectionBusy() || !state.fresh || state.loading;
        select.setAttribute("aria-busy",String(state.loading));
      }
    }
    function row(workspace) {
      var article = document.createElement("div"); article.className = "workspace-request-row"; article.dataset.workspaceRequestRow = String(workspace.id);
      var details = document.createElement("div"),name = document.createElement("strong"),domain = document.createElement("small");
      name.textContent = workspace.name;domain.textContent = workspace.domain;details.append(name,domain);
      if (workspace.requested_at) {var when = document.createElement("small");when.textContent = "Request recorded " + dateLabel(workspace.requested_at) + ".";details.append(when);}
      else if (workspace.status === "pending") {var unknown = document.createElement("small");unknown.textContent = "Request date unavailable.";details.append(unknown);}
      var label = document.createElement("span"); label.className = "workspace-state";
      label.textContent = workspace.status === "approved" ? "Approved " + workspace.role : workspace.status === "pending" ? "Awaiting admin approval" : workspace.status === "denied" ? "Request declined" : "Access removed";
      article.append(details,label);
      if (workspace.status === "approved") {
        var open = document.createElement("button");open.type = "button";open.className = "button button-small button-quiet";open.textContent = "Open";
        open.dataset.workspaceReviewOpen = String(workspace.id);open.setAttribute("aria-label","Open workspace: " + workspace.domain);
        open.addEventListener("click",function (event) {event.stopPropagation();if (canSelect(workspace.id) && !options.selectionBusy()) options.select(workspace.id,open);});article.append(open);
      }
      return article;
    }
    function reconcile(view,workspaces) {
      var active = document.activeElement,focused = view.list.contains(active),next = new Map();
      workspaces.forEach(function (workspace) {var signature = JSON.stringify(workspace),old = view.cache.get(workspace.id);next.set(workspace.id,old && old.signature===signature ? old : {signature:signature,row:row(workspace)});});
      var retained = new Set([...next.values()].map(function (entry) {return entry.row;}));
      Array.from(view.list.children).forEach(function (node) {if (!retained.has(node)) node.remove();});
      var cursor = view.list.firstElementChild;
      next.forEach(function (entry) {if (entry.row!==cursor) view.list.insertBefore(entry.row,cursor);cursor = entry.row.nextElementSibling;});
      if (!workspaces.length) {var empty = document.createElement("div");empty.className = "empty-events";empty.textContent = "You have no workspace memberships or saved access requests yet.";view.list.append(empty);}
      if (focused && !view.list.contains(active)) view.refresh.focus();
      else if (focused && document.activeElement!==active) active.focus({preventScroll:true});
      view.cache = next;
    }
    function reconcileSelect(workspaces) {
      if (!select || options.selectionBusy()) return;
      var next = workspaces.filter(function (workspace) {return workspace.status === "approved";}).map(function (workspace) {
        var label = workspace.name + " · " + workspace.role;
        var option = Array.from(select.children).find(function (node) {return node.value===String(workspace.id) && node.textContent===label;});
        if (!option) {option = document.createElement("option");option.value = String(workspace.id);option.textContent = label;}
        return option;
      });
      Array.from(select.children).forEach(function (node) {if (!next.includes(node)) node.remove();});
      var cursor = select.firstElementChild;
      next.forEach(function (option) {if (option!==cursor) select.insertBefore(option,cursor);cursor = option.nextElementSibling;});
      select.value = String(options.organizationId || "");
    }
    async function load() {
      var sequence = ++state.sequence;
      if (controller) controller.abort(); controller = new AbortController();var activeController = controller;
      state.loading = true;updateControls();var timer = window.setTimeout(function () {activeController.abort();},20000);
      try {
        var response = await options.fetch("/api/my-workspaces",{credentials:"same-origin",cache:"no-store",signal:activeController.signal});
        var body;try {body = await response.json();} catch (_) {body = null;}
        if (sequence!==state.sequence) return false;
        if (activeController.signal.aborted) throw new Error("Workspace request read timed out.");
        if (!response.ok) throw new Error(body && typeof body.detail==="string" ? body.detail : "Your workspaces could not be read.");
        validate(body);views.forEach(function (view) {reconcile(view,body.workspaces);});reconcileSelect(body.workspaces);
        state.body = body;state.fresh = true;state.error = null;
        options.onRead(body.workspaces);return true;
      } catch (error) {
        if (sequence!==state.sequence) return false;
        state.fresh = false;state.error = activeController.signal.aborted ? "Workspace request read timed out." : error.message;
        return false;
      } finally {
        window.clearTimeout(timer);
        if (sequence===state.sequence) {state.loading = false;controller = null;updateControls();}
      }
    }
    views.forEach(function (view) {view.refresh.addEventListener("click",function () {load();});});
    return {load:load,state:state,canSelect:canSelect,updateControls:updateControls};
  }};
})();
