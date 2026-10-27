/* Command palette (Ctrl/Cmd+K or "/"), the light/dark switch and the color-scheme switch.
 * Reads the sidebar navigation, the workspace selector and existing buttons, then
 * clicks or changes those same controls, so dashboard.js keeps owning behaviour. */
(function () {
  "use strict";

  var THEME_KEY = "daedalus-theme";
  var root = document.documentElement;

  function storedMode() {
    try { var mode = window.localStorage.getItem(THEME_KEY); return mode === "dark" || mode === "system" ? mode : "light"; }
    catch (error) { return "light"; }
  }
  function applyMode(mode) {
    if (mode === "light" || mode === "dark") root.setAttribute("data-theme", mode);
    else root.removeAttribute("data-theme");
    try {
      if (mode === "light") window.localStorage.removeItem(THEME_KEY);
      else window.localStorage.setItem(THEME_KEY, mode);
    } catch (error) { /* the choice lasts for this page only */ }
    document.querySelectorAll("[data-theme-toggle]").forEach(function (button) {
      button.dataset.mode = mode;
      var label = mode === "system" ? "Theme: match system" : mode === "light" ? "Theme: light" : "Theme: dark";
      button.setAttribute("aria-label", label + ". Activate to change.");
      button.title = label;
    });
  }
  var PALETTE_KEY = "daedalus-palette";
  var PALETTES = { olive: "Olive", slate: "Slate" };
  function storedPalette() {
    try { var palette = window.localStorage.getItem(PALETTE_KEY); return PALETTES[palette] ? palette : "olive"; }
    catch (error) { return "olive"; }
  }
  function applyPalette(palette) {
    if (palette === "olive") root.removeAttribute("data-palette"); else root.setAttribute("data-palette", palette);
    try {
      if (palette === "olive") window.localStorage.removeItem(PALETTE_KEY); else window.localStorage.setItem(PALETTE_KEY, palette);
    } catch (error) { /* the choice lasts for this page only */ }
    document.querySelectorAll("[data-palette-toggle]").forEach(function (button) {
      button.setAttribute("aria-label", "Color scheme: " + PALETTES[palette] + ". Activate to change.");
      button.title = "Color scheme: " + PALETTES[palette];
    });
  }
  applyPalette(storedPalette());
  document.querySelectorAll("[data-palette-toggle]").forEach(function (button) {
    button.addEventListener("click", function () { applyPalette(storedPalette() === "olive" ? "slate" : "olive"); });
  });
  function nextMode() {
    var order = ["light", "dark", "system"];
    applyMode(order[(order.indexOf(storedMode()) + 1) % order.length]);
  }
  applyMode(storedMode());
  document.querySelectorAll("[data-theme-toggle]").forEach(function (button) {
    button.addEventListener("click", nextMode);
  });

  var ICONS = {
    go: '<path d="M5 12h14"/><path d="m13 6 6 6-6 6"/>',
    workspace: '<rect x="3" y="4" width="18" height="16" rx="3"/><path d="M3 10h18"/>',
    plus: '<path d="M12 5v14"/><path d="M5 12h14"/>',
    key: '<circle cx="7.5" cy="15.5" r="4.5"/><path d="m10.7 12.3 9.3-9.3"/><path d="m16 7 3 3"/><path d="m19 4 2 2"/>',
    sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
    moon: '<path d="M20.5 14.5A8.5 8.5 0 1 1 9.5 3.5a7 7 0 0 0 11 11z"/>',
    monitor: '<rect x="2" y="4" width="20" height="13" rx="2"/><path d="M8 21h8M12 17v4"/>',
    out: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="m16 17 5-5-5-5"/><path d="M21 12H9"/>',
    palette: '<circle cx="13.5" cy="6.5" r="1.5"/><circle cx="17.5" cy="10.5" r="1.5"/><circle cx="8.5" cy="7.5" r="1.5"/><circle cx="6.5" cy="12.5" r="1.5"/><path d="M12 2a10 10 0 0 0 0 20c.9 0 1.7-.8 1.7-1.7 0-.4-.2-.8-.4-1.1-.3-.3-.4-.7-.4-1.1 0-.9.8-1.7 1.7-1.7h2a5.6 5.6 0 0 0 5.6-5.6C22 6 17.5 2 12 2z"/>',
    search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>'
  };
  function icon(name) {
    return '<svg class="d-icon" viewBox="0 0 24 24" aria-hidden="true">' + (ICONS[name] || ICONS.go) + "</svg>";
  }

  function collectCommands() {
    var commands = [];
    document.querySelectorAll(".sidebar .nav-item[data-tab]").forEach(function (item) {
      var label = "";
      item.childNodes.forEach(function (node) { if (node.nodeType === 3) label += node.textContent; });
      label = label.trim();
      var svg = item.querySelector("svg");
      commands.push({ group: "Go to", label: label, icon: svg ? svg.outerHTML : icon("go"), keywords: item.dataset.tab, run: function () { item.click(); } });
    });
    var select = document.getElementById("workspace-select");
    if (select && !select.disabled) {
      Array.prototype.forEach.call(select.options, function (option) {
        if (option.selected) return;
        commands.push({ group: "Switch workspace", label: option.textContent.trim(), icon: icon("workspace"), run: function () {
          select.value = option.value;
          select.dispatchEvent(new Event("change", { bubbles: true }));
        } });
      });
    }
    var addWorkspace = document.querySelector("[data-open-workspace-dialog]");
    if (addWorkspace) commands.push({ group: "Actions", label: "Add or join a workspace", icon: icon("plus"), run: function () { addWorkspace.click(); } });
    var addScanner = document.getElementById("add-scanner");
    if (addScanner && !addScanner.disabled) commands.push({ group: "Actions", label: "Add a scanner", icon: icon("plus"), run: function () {
      var nav = document.querySelector('.nav-item[data-tab="scanners"]'); if (nav) nav.click(); addScanner.click();
    } });
    var keys = document.querySelector(".account-keys-link");
    if (keys) commands.push({ group: "Account", label: "Personal access keys", icon: icon("key"), run: function () { window.location.assign(keys.href); } });
    commands.push({ group: "Appearance", label: "Use light theme", icon: icon("sun"), keywords: "theme appearance", run: function () { applyMode("light"); } });
    commands.push({ group: "Appearance", label: "Use dark theme", icon: icon("moon"), keywords: "theme appearance", run: function () { applyMode("dark"); } });
    commands.push({ group: "Appearance", label: "Olive color scheme", icon: icon("palette"), keywords: "palette colors warm", run: function () { applyPalette("olive"); } });
    commands.push({ group: "Appearance", label: "Slate color scheme", icon: icon("palette"), keywords: "palette colors cool blue", run: function () { applyPalette("slate"); } });
    commands.push({ group: "Appearance", label: "Match system theme", icon: icon("monitor"), keywords: "theme appearance auto", run: function () { applyMode("system"); } });
    var logout = document.querySelector('form[action="/logout"]');
    if (logout) commands.push({ group: "Account", label: "Sign out", icon: icon("out"), run: function () { logout.requestSubmit ? logout.requestSubmit() : logout.submit(); } });
    return commands;
  }

  if (!document.querySelector(".app-shell")) return;

  var dialog = document.createElement("dialog");
  dialog.className = "d-palette";
  dialog.setAttribute("aria-label", "Command palette");
  dialog.innerHTML =
    '<div class="d-palette-search">' + icon("search") +
    '<input type="text" role="combobox" aria-expanded="true" aria-controls="d-palette-list" aria-autocomplete="list" placeholder="Jump to a page, workspace or action…" autocomplete="off" spellcheck="false">' +
    '<span class="d-kbd">Esc</span></div>' +
    '<ul class="d-palette-list" id="d-palette-list" role="listbox" aria-label="Commands"></ul>' +
    '<div class="d-palette-foot"><span><span class="d-kbd">↑</span><span class="d-kbd">↓</span> move</span><span><span class="d-kbd">↵</span> open</span><span><span class="d-kbd">Esc</span> close</span></div>';
  document.body.appendChild(dialog);
  var input = dialog.querySelector("input");
  var list = dialog.querySelector(".d-palette-list");
  var commands = [];
  var visible = [];
  var selected = 0;
  var returnFocus = null;

  function matches(command, query) {
    if (!query) return true;
    var haystack = (command.label + " " + command.group + " " + (command.keywords || "")).toLowerCase();
    return query.toLowerCase().split(/\s+/).every(function (part) { return haystack.indexOf(part) !== -1; });
  }
  function render() {
    var query = input.value.trim();
    visible = commands.filter(function (command) { return matches(command, query); });
    if (selected >= visible.length) selected = Math.max(0, visible.length - 1);
    list.innerHTML = "";
    if (!visible.length) {
      var empty = document.createElement("li"); empty.className = "d-palette-empty"; empty.textContent = "No matches for “" + query + "”";
      list.appendChild(empty); input.removeAttribute("aria-activedescendant"); return;
    }
    var group = null;
    visible.forEach(function (command, index) {
      if (command.group !== group) {
        group = command.group;
        var heading = document.createElement("li"); heading.className = "d-palette-group"; heading.setAttribute("role", "presentation"); heading.textContent = group;
        list.appendChild(heading);
      }
      var item = document.createElement("li");
      item.className = "d-palette-item"; item.id = "d-palette-option-" + index; item.setAttribute("role", "option");
      item.setAttribute("aria-selected", String(index === selected));
      item.innerHTML = command.icon;
      var text = document.createElement("span"); text.textContent = command.label; item.appendChild(text);
      item.addEventListener("mousemove", function () { if (selected !== index) { selected = index; highlight(); } });
      item.addEventListener("click", function () { run(index); });
      list.appendChild(item);
    });
    highlight();
  }
  function highlight() {
    list.querySelectorAll(".d-palette-item").forEach(function (item) {
      var on = item.id === "d-palette-option-" + selected;
      item.setAttribute("aria-selected", String(on));
      if (on) { input.setAttribute("aria-activedescendant", item.id); item.scrollIntoView({ block: "nearest" }); }
    });
  }
  function open() {
    if (dialog.open) return;
    returnFocus = document.activeElement;
    commands = collectCommands();
    input.value = ""; selected = 0; render();
    dialog.showModal(); input.focus();
  }
  function close() { if (dialog.open) dialog.close(); }
  function run(index) {
    var command = visible[index]; if (!command) return;
    returnFocus = null; close(); command.run();
  }
  dialog.addEventListener("close", function () { if (returnFocus && returnFocus.focus) returnFocus.focus(); });
  dialog.addEventListener("click", function (event) { if (event.target === dialog) close(); });
  input.addEventListener("input", function () { selected = 0; render(); });
  input.addEventListener("keydown", function (event) {
    if (event.key === "ArrowDown") { event.preventDefault(); selected = (selected + 1) % Math.max(visible.length, 1); highlight(); }
    else if (event.key === "ArrowUp") { event.preventDefault(); selected = (selected - 1 + visible.length) % Math.max(visible.length, 1); highlight(); }
    else if (event.key === "Enter") { event.preventDefault(); run(selected); }
  });

  document.querySelectorAll("[data-command-palette]").forEach(function (button) { button.addEventListener("click", open); });
  document.addEventListener("keydown", function (event) {
    var key = event.key && event.key.toLowerCase();
    if (key === "k" && (event.metaKey || event.ctrlKey) && !event.altKey) { event.preventDefault(); dialog.open ? close() : open(); return; }
    if (event.key === "/" && !event.metaKey && !event.ctrlKey && !event.altKey) {
      var target = event.target;
      var typing = target && (target.isContentEditable || /^(input|textarea|select)$/i.test(target.tagName));
      if (!typing && !document.querySelector("dialog[open]")) { event.preventDefault(); open(); }
    }
  });
  var mac = /mac|iphone|ipad/i.test(navigator.platform || navigator.userAgent);
  document.querySelectorAll("[data-command-key]").forEach(function (element) { element.textContent = mac ? "⌘K" : "Ctrl K"; });
})();
