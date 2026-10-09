/* Read-only workspace action history; saved evidence survives failed reads. */
(function () {
  "use strict";
  window.DaedalusAuditReview = {create: function (options) {
    var orgId = Number(options.organizationId);
    var list = document.getElementById("audit-log-list");
    var refresh = document.getElementById("audit-log-refresh");
    var older = document.getElementById("audit-log-older");
    var observed = document.getElementById("audit-log-observed");
    var note = document.getElementById("audit-log-read-note");
    if (!list || !refresh || !older || !window.daedalusHistory || !Number.isSafeInteger(orgId) || orgId <= 0) return null;
    var cache = new Map();
    function validDate(value) {
      return typeof value === "string" && /(?:Z|[+-]\d{2}:\d{2})$/.test(value) && Number.isFinite(Date.parse(value));
    }
    function dateLabel(value) {
      return new Date(value).toLocaleString(undefined, {year:"numeric",month:"short",day:"numeric",hour:"numeric",minute:"2-digit",second:"2-digit",timeZoneName:"short"});
    }
    function validate(body, before) {
      if (body.organization_id !== orgId || !validDate(body.observed_at) || Date.parse(body.observed_at) > Date.now()+60000 || body.total_count < body.events.length) throw new Error("This workspace's action history could not be confirmed. Please retry.");
      var last = before == null ? Infinity : before;
      body.events.forEach(function (entry) {
        if (entry.id >= last || typeof entry.actor !== "string" || typeof entry.action !== "string" || !entry.action || !validDate(entry.created_at) ||
            !entry.details || typeof entry.details !== "object" || Array.isArray(entry.details)) throw new Error("Saved action history is incomplete. Please retry.");
        last = entry.id;
      });
    }
    function row(entry) {
      var article = document.createElement("article"); article.className = "audit-log-row"; article.dataset.auditEvent = String(entry.id);
      var main = document.createElement("div");
      var title = document.createElement("strong"); title.textContent = entry.action.replaceAll("_", " ").replaceAll(".", " · ");
      var actor = document.createElement("small"); actor.textContent = "by " + entry.actor; main.append(title,actor);
      var time = document.createElement("time"); time.textContent = dateLabel(entry.created_at); time.setAttribute("datetime", entry.created_at); article.append(main,time);
      var description = options.summary(entry);
      if (description) {var explanation = document.createElement("p"); explanation.className = "audit-event-summary"; explanation.textContent = description; article.append(explanation);}
      var disclosure = document.createElement("details"); disclosure.className = "audit-event-details";
      var label = document.createElement("summary"); label.textContent = "View saved event details";
      var evidence = document.createElement("pre"); evidence.textContent = JSON.stringify(entry.details,null,2);
      disclosure.append(label,evidence); article.append(disclosure); return article;
    }
    function reconcile(rows) {
      var active = document.activeElement, focused = list.contains(active), next = new Map();
      rows.forEach(function (entry) {
        var signature = JSON.stringify(entry), previous = cache.get(entry.id);
        next.set(entry.id,previous && previous.signature === signature ? previous : {signature:signature,row:row(entry)});
      });
      Array.from(list.children).forEach(function (node) {if (![...next.values()].some(function (entry) {return entry.row === node;})) node.remove();});
      var cursor = list.firstElementChild;
      next.forEach(function (entry) {if (entry.row !== cursor) list.insertBefore(entry.row,cursor);cursor = entry.row.nextElementSibling;});
      if (!rows.length) {var empty = document.createElement("div"); empty.className = "empty-events"; empty.textContent = "No workspace admin actions have been recorded yet."; list.append(empty);}
      if (focused && !list.contains(active)) refresh.focus();
      else if (focused && document.activeElement !== active) active.focus({preventScroll:true});
      cache = next;
    }
    function render(state, committed) {
      if (committed) reconcile(state.rows);
      list.setAttribute("aria-busy", String(state.busy));
      refresh.setAttribute("aria-disabled", String(state.busy));
      refresh.setAttribute("aria-busy", String(state.busy));
      older.setAttribute("aria-disabled", String(state.busy));
      var hasMore = Boolean(state.body && state.body.has_more);
      if (!hasMore && document.activeElement === older && !state.busy) refresh.focus();
      older.hidden = !hasMore;
      observed.textContent = state.loaded ? "Showing " + state.rows.length + " of " + state.body.total_count + " recorded actions. " +
        (state.error ? "Last checked " : "Checked ") + dateLabel(state.body.observed_at) + "." : state.busy ? "Reading saved action history…" : "No successful action history read yet.";
      note.hidden = !state.error;
      note.textContent = state.error ? (state.loaded ? "Saved action history is retained. " : "Action history is unavailable. ") + state.error + " Refresh action history to try again." : "";
    }
    var pager = window.daedalusHistory.create({
      url:"/api/audit-log",field:"events",timeoutMs:20000,validate:validate,changed:render,
      fetch:function (path,requestOptions) {
        var headers = new Headers(requestOptions.headers || {}); headers.set("X-Daedalus-Workspace",String(orgId));
        return options.fetch(path,Object.assign({},requestOptions,{headers:headers}));
      }
    });
    refresh.addEventListener("click",function () {if (!pager.state.busy) pager.refresh({limit:"40"});});
    older.addEventListener("click",function () {if (!pager.state.busy) pager.older();});
    return {load:function () {return pager.refresh({limit:"40"});},older:pager.older,state:pager.state};
  }};
})();
