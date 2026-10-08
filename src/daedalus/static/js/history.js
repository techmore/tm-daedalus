/* Workspace history: keyset pages, retained depth, and stale-request protection. */
(function () {
  "use strict";
  function create(options) {
    var state = { rows: [], body: null, loaded: false, busy: false, error: null };
    var sequence = 0;
    var filters = {};
    var controller = null;
    function notify(committed) { options.changed(state, Boolean(committed)); }
    async function page(before, requestFilters, signal) {
      var url = new URL(options.url, window.location.origin);
      Object.keys(requestFilters).forEach(function (key) { url.searchParams.set(key, requestFilters[key]); });
      if (before != null) url.searchParams.set("before", String(before));
      var response = await fetch(url.pathname + url.search, { credentials: "same-origin", cache: "no-store", signal: signal });
      var body = await response.json();
      if (!response.ok) throw new Error(typeof body.detail === "string" ? body.detail : "Could not load history.");
      var rows = body[options.field];
      if (!Array.isArray(rows) || rows.length > 100 || rows.some(function (row) { return !row || !Number.isSafeInteger(row.id) || row.id < 1; }) ||
          new Set(rows.map(function (row) { return row.id; })).size !== rows.length ||
          (before != null && rows.some(function (row) { return row.id === before; })) ||
          (options.field === "notifications" && (!Number.isSafeInteger(body.unread_count) || body.unread_count < 0)) ||
          typeof body.has_more !== "boolean" || !Number.isSafeInteger(body.total_count) || body.total_count < 0 ||
          (body.has_more && (!rows.length || body.next_before !== rows[rows.length - 1].id)) ||
          (!body.has_more && body.next_before !== null)) throw new Error("History response is incomplete. Please retry.");
      return body;
    }
    async function refresh(nextFilters) {
      var changedFilters = nextFilters && JSON.stringify(nextFilters) !== JSON.stringify(filters);
      if (nextFilters) filters = Object.assign({}, nextFilters);
      var oldest = !changedFilters && state.rows.length ? state.rows[state.rows.length - 1].id : null;
      if (controller) controller.abort();
      controller = new AbortController();
      var signal = controller.signal;
      var current = ++sequence;
      var requestFilters = Object.assign({}, filters);
      if (changedFilters) { state.rows = []; state.body = null; state.loaded = false; }
      state.busy = true; state.error = null; notify(changedFilters);
      try {
        var body = await page(null, requestFilters, signal);
        var first = body;
        var rows = body[options.field].slice();
        var cursors = new Set();
        // Re-read through the old boundary so new notices cannot push a loaded
        // older page out of view. A removed unread boundary continues to the end.
        while (oldest != null && !rows.some(function (row) { return row.id === oldest; }) && body.has_more) {
          if (cursors.has(body.next_before)) throw new Error("History did not advance. Please retry.");
          cursors.add(body.next_before);
          body = await page(body.next_before, requestFilters, signal);
          var seen = new Set(rows.map(function (row) { return row.id; }));
          rows.push.apply(rows, body[options.field].filter(function (row) { return !seen.has(row.id); }));
        }
        if (current !== sequence) return false;
        state.rows = rows;
        state.body = Object.assign({}, first, { has_more: body.has_more, next_before: body.next_before });
        state.loaded = true; state.busy = false; state.error = null; notify(true);
        return true;
      } catch (error) {
        if (current !== sequence) return false;
        state.busy = false; state.error = error.message || "Could not refresh history."; notify(false);
        return false;
      }
    }
    async function older() {
      if (state.busy || !state.body || !state.body.has_more) return false;
      var current = sequence;
      controller = new AbortController();
      state.busy = true; state.error = null; notify(false);
      try {
        var body = await page(state.body.next_before, Object.assign({}, filters), controller.signal);
        if (current !== sequence) return false;
        var seen = new Set(state.rows.map(function (row) { return row.id; }));
        state.rows = state.rows.concat(body[options.field].filter(function (row) { return !seen.has(row.id); }));
        state.body = Object.assign({}, state.body, { total_count: body.total_count, has_more: body.has_more, next_before: body.next_before });
        state.busy = false; state.error = null; notify(true);
        return true;
      } catch (error) {
        if (current !== sequence) return false;
        state.busy = false; state.error = error.message || "Could not load older history."; notify(false);
        return false;
      }
    }
    return { state: state, refresh: refresh, older: older };
  }
  window.daedalusHistory = { create: create };
}());
