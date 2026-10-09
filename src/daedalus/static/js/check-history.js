/* Saved checks: atomic refresh, independent history boundaries, and retries. */
(function () {
  "use strict";
  var fields = ["runs", "changes"];

  function create(options) {
    var state = Object.assign(options.state || {}, {
      body: null, loaded: false, loading: null, error: null, sequence: 0
    });
    var controller = null;
    function changed(committed) { options.changed(state, Boolean(committed)); }

    async function page(field, before, signal, domain) {
      var url = new URL(options.url, window.location.origin);
      if (before != null) url.searchParams.set(field + "_before", String(before));
      var response = await (options.fetch || fetch)(url.pathname + url.search, {
        credentials: "same-origin", cache: "no-store", signal: signal
      });
      var body = await response.json();
      if (!response.ok) throw new Error(typeof body.detail === "string" ? body.detail : "Could not load saved evidence.");
      if (body.check_type !== options.type || typeof body.domain !== "string" || !body.domain ||
          (domain && body.domain !== domain)) throw new Error("The workspace evidence changed. Reload this page before reviewing it.");
      var source = body.latest_snapshot_run;
      if (body.latest_snapshot !== null && (!body.latest_snapshot || typeof body.latest_snapshot !== "object" || Array.isArray(body.latest_snapshot)) ||
          (source === null ? body.latest_snapshot_run_id !== null || body.latest_snapshot !== null :
            !source || !Number.isSafeInteger(source.id) || source.id < 1 || source.id !== body.latest_snapshot_run_id ||
            !["completed", "completed_with_warnings"].includes(source.status) || body.latest_snapshot === null)) {
        throw new Error("Saved assessment evidence is incomplete. Please retry.");
      }
      fields.forEach(function (name) {
        var rows = body[name], more = body[name + "_has_more"], next = body[name + "_next_before"];
        if (!Array.isArray(rows) || rows.length > 100 ||
            rows.some(function (row, index) {
              return !row || !Number.isSafeInteger(row.id) || row.id < 1 ||
                (index > 0 && row.id >= rows[index - 1].id) ||
                (name === field && before != null && row.id >= before);
            }) || typeof more !== "boolean" ||
            (more && (!rows.length || next !== rows[rows.length - 1].id)) ||
            (!more && next !== null)) throw new Error("Saved history is incomplete. Please retry.");
      });
      return body;
    }

    async function read(olderField) {
      if (olderField && (!fields.includes(olderField) || state.loading ||
          !state.body || !state.body[olderField + "_has_more"])) return false;
      if (controller) controller.abort();
      controller = new AbortController();
      var signal = controller.signal;
      var current = ++state.sequence;
      var previous = state.body;
      state.loading = olderField || "refresh";
      changed(false);
      try {
        var body;
        if (olderField) {
          var older = await page(olderField, previous[olderField + "_next_before"], signal, previous.domain);
          if (current !== state.sequence) return false;
          body = Object.assign({}, previous);
          body[olderField] = previous[olderField].concat(older[olderField]);
          body[olderField + "_has_more"] = older[olderField + "_has_more"];
          body[olderField + "_next_before"] = older[olderField + "_next_before"];
        } else {
          body = await page(null, null, signal, previous && previous.domain);
          if (current !== state.sequence) return false;
          for (var name of fields) {
            var oldRows = previous && previous[name];
            var boundary = oldRows && oldRows.length ? oldRows[oldRows.length - 1].id : null;
            var rows = body[name].slice();
            var last = body;
            var cursors = new Set();
            while (boundary != null && !rows.some(function (row) { return row.id <= boundary; }) && last[name + "_has_more"]) {
              var cursor = last[name + "_next_before"];
              if (cursors.has(cursor)) throw new Error("Saved history did not advance. Please retry.");
              cursors.add(cursor);
              last = await page(name, cursor, signal, body.domain);
              if (current !== state.sequence) return false;
              rows.push.apply(rows, last[name]);
            }
            body[name] = rows;
            body[name + "_has_more"] = last[name + "_has_more"];
            body[name + "_next_before"] = last[name + "_next_before"];
          }
        }
        if (current !== state.sequence) return false;
        state.body = body;
        state.runs = body.runs;
        state.changes = body.changes;
        state.runsCursor = state.cursor = body.runs_next_before;
        state.changesCursor = body.changes_next_before;
        state.runsHasMore = state.hasMore = body.runs_has_more;
        state.changesHasMore = body.changes_has_more;
        state.loaded = true;
        state.loading = null;
        state.error = null;
        changed(true);
        return true;
      } catch (error) {
        if (current !== state.sequence) return false;
        state.loading = null;
        state.error = error.message || "Could not refresh saved evidence.";
        changed(false);
        return false;
      }
    }
    return { state: state, refresh: function () { return read(null); }, older: read };
  }
  window.daedalusCheckHistory = { create: create };
}());
