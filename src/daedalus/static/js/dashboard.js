(function () {
  "use strict";

  function commandTimeline(command) {
    var fields = [["created_at", "Requested"], ["delivered_at", "Delivered"], ["completed_at", "Status recorded"]];
    if (!command.completed_at) fields.push(["deadline_at", "Confirmation deadline"]);
    return fields.filter(function (field) { return command[field[0]] && Number.isFinite(Date.parse(command[field[0]])); }).map(function (field) {
      return field[1] + " " + new Date(command[field[0]]).toLocaleString();
    }).join(" · ");
  }

  function inventoryDisplayValue(field, observed) {
    if (observed === null || observed === undefined || observed === "unknown") return "Unknown";
    if (field.endsWith("_bytes")) return typeof observed === "number" && Number.isFinite(observed) && observed >= 0 ? (observed / 1073741824).toFixed(1) + " GiB" : "Unknown";
    if (field === "cpu_count") return Number.isInteger(observed) && observed > 0 ? String(observed) : "Unknown";
    return typeof observed === "string" ? observed : "Unknown";
  }

  function supportsOSUpdateCheck(agent) {
    return Boolean(agent && Number.isInteger(agent.command_protocol_version) && ((agent.platform === "Darwin" && agent.command_protocol_version >= 3) || (agent.platform === "Linux" && agent.command_protocol_version >= 4)));
  }

  function canViewScannerCommandHistory(workspaceRole) {
    return workspaceRole === "admin";
  }

  function buildCISClientConfig(body, profileSlug) {
    return "# Workspace upload key; keep this file private.\n" +
      "reporting:\n  endpoint: " + JSON.stringify(body.report_endpoint) + "\n" +
      "  profiles_endpoint: " + JSON.stringify(body.profiles_endpoint) + "\n" +
      "  # This profile slug pins the selected workspace profile. Blank uses the newest compatible profile.\n" +
      "  profile_slug: " + JSON.stringify(profileSlug || "") + "\n" +
      "  domain: " + JSON.stringify(body.domain) + "\n" +
      "  api_key: " + JSON.stringify(body.api_key) + "\n";
  }

  var shell = document.querySelector(".app-shell");
  var orgId = shell ? shell.dataset.organizationId : null;
  var postureRequestSequence = 0;
  var role = shell ? shell.dataset.role : null;
  var verificationStatus = shell ? shell.dataset.verificationStatus : null;
  var controlsEnabled = shell ? shell.dataset.controlsEnabled === "true" : false;
  var notifiedCheckRuns = Object.create(null);
  var externalCheckHistory = Object.create(null);
  var activeExposureHistory = { runs: [], changes: [], runsCursor: null, changesCursor: null, runsHasMore: false, changesHasMore: false, loading: null };
  var niktoHistory = { runs: [], cursor: null, hasMore: false, busy: false, sequence: 0 };
  var openCommandHistories = new Set();
  var openScannerControls = new Set();
  var openScanHistories = new Set();
  var openRunDetails = new Set();
  var openRunEvents = new Set();
  var selectedRunBaselines = new Map();
  var openComparisonHistories = new Set();
  var openSavedComparisons = new Set();
  var notifiedScannerComparisons = new Set();
  var inlineConfirmationCount = 0;
  var scannerTargets = new Map();
  var scannerSkipDiscovery = new Map();
  var scannerNetworkInputs = new Map();
  var scannerScopeFeedback = new Map();
  var dashboardRefreshPromise = null;
  var scannerComparisonCache = new Map();
  var titleMap = {
    overview: "Workspace overview",
    scanners: "Internal network",
    meraki: "Meraki security report",
    dns: "DNS & email health",
    web: "Website health",
    cis: "Endpoint compliance",
    reports: "Report library",
    members: "Members & access",
    notifications: "Security notifications"
  };
  var activeTab = null;

  function text(node, value) {
    if (node) node.textContent = value == null ? "" : String(value);
  }

  function requestInlineConfirmation(button, message, confirmLabel, onConfirm) {
    var group = button.closest(".agent-actions, .membership-actions") || button.parentElement;
    var panelHost = button.closest(".membership-row") || group;
    if (!group || !panelHost || panelHost.querySelector(".inline-confirmation")) return;

    var confirmationId = ++inlineConfirmationCount;
    var panel = document.createElement("div");
    panel.className = "inline-confirmation";
    panel.id = "inline-confirmation-panel-" + confirmationId;
    panel.setAttribute("role", "group");
    var description = document.createElement("p");
    description.className = "inline-confirmation-message";
    description.id = "inline-confirmation-message-" + confirmationId;
    description.textContent = message;
    panel.setAttribute("aria-labelledby", description.id);
    var feedback = document.createElement("p");
    feedback.className = "inline-confirmation-error";
    feedback.setAttribute("aria-live", "polite");
    var actions = document.createElement("div");
    actions.className = "inline-confirmation-actions";
    var confirmButton = document.createElement("button");
    confirmButton.type = "button";
    confirmButton.className = "button button-small";
    confirmButton.textContent = confirmLabel;
    confirmButton.setAttribute("aria-describedby", description.id);
    var cancelButton = document.createElement("button");
    cancelButton.type = "button";
    cancelButton.className = "button button-small button-quiet";
    cancelButton.textContent = "Cancel";
    actions.append(confirmButton, cancelButton);
    panel.append(description, feedback, actions);
    panelHost.append(panel);
    button.setAttribute("aria-expanded", "true");
    button.setAttribute("aria-controls", panel.id);

    cancelButton.addEventListener("click", function () {
      panel.remove();
      button.setAttribute("aria-expanded", "false");
      button.removeAttribute("aria-controls");
      button.focus();
    });
    confirmButton.addEventListener("click", async function () {
      confirmButton.disabled = true;
      cancelButton.disabled = true;
      button.disabled = true;
      try {
        await onConfirm();
        panel.remove();
        button.setAttribute("aria-expanded", "false");
        button.removeAttribute("aria-controls");
      } catch (error) {
        text(feedback, (error && error.message) || "The action could not be completed.");
        confirmButton.disabled = false;
        cancelButton.disabled = false;
        button.disabled = false;
      }
    });
    confirmButton.focus();
  }

  function shellQuote(value) {
    return "'" + String(value).replace(/'/g, "'\\''") + "'";
  }

  function tabFromLocation() {
    var name = window.location.hash.replace(/^#/, "");
    return Object.prototype.hasOwnProperty.call(titleMap, name) ? name : "overview";
  }

  function activateTab(name, updateLocation) {
    if (!Object.prototype.hasOwnProperty.call(titleMap, name)) name = "overview";

    document.querySelectorAll("[data-tab]").forEach(function (item) {
      var isCurrentNavItem = item.dataset.tab === name && item.classList.contains("nav-item");
      item.classList.toggle("active", isCurrentNavItem);
      if (isCurrentNavItem) item.setAttribute("aria-current", "page");
      else item.removeAttribute("aria-current");
    });
    document.querySelectorAll(".tab-panel").forEach(function (panel) {
      panel.classList.toggle("active", panel.id === "tab-" + name);
    });
    var pageTitle = document.getElementById("page-title");
    text(pageTitle, titleMap[name] || "Workspace");
    // User navigation moves focus to the topic heading; live refreshes retain focus.
    if (updateLocation && activeTab !== name && pageTitle && typeof pageTitle.focus === "function") {
      pageTitle.focus();
    }

    if (updateLocation && window.location.hash !== "#" + name) {
      var nextUrl = window.location.pathname + window.location.search + "#" + name;
      window.history.pushState({ daedalusTab: name }, "", nextUrl);
    }

    if (activeTab === name) return;
    activeTab = name;
    if (name === "overview") loadWorkspacePosture();
    if (name === "meraki") loadMeraki();
    if (name === "cis") { loadCIS(); loadReports(); }
    if (name === "dns" || name === "web") loadExternalCheck(name);
    if (name === "web") { loadActiveExposure(); loadNikto(); }
    if (name === "reports") loadReports();
    if (name === "notifications") loadNotifications();
  }

  function showMembershipNotice(message, action) {
    var notice = document.getElementById("membership-live-notice");
    if (!notice) return;
    var icon = document.createElement("span");
    icon.setAttribute("aria-hidden", "true");
    icon.textContent = "ⓘ";
    var copy = document.createElement("span");
    copy.textContent = message;
    var button = document.createElement("button");
    button.type = "button";
    button.className = "button button-small button-quiet";
    button.textContent = action.label;
    button.addEventListener("click", action.run);
    notice.replaceChildren(icon, copy, button);
    notice.classList.remove("hidden");
  }

  function clearMembershipNotice() {
    var notice = document.getElementById("membership-live-notice");
    if (notice) {
      notice.replaceChildren();
      notice.classList.add("hidden");
    }
  }

  function handleMembershipLiveMessage(message) {
    if (!message) return;
    if (message.type === "membership_request_received" && role === "admin") {
      Promise.all([loadMemberships(), loadAuditLog()]);
      showMembershipNotice("A workspace access request is waiting for your review.", {
        label: "Open Members & access",
        run: function () { activateTab("members", true); }
      });
    }
    if (message.type === "membership_list_changed" && role === "admin") {
      Promise.all([loadMemberships(), loadAuditLog()]);
    }
    if (message.type === "membership_decision") {
      loadWorkspaces();
      loadMemberships();
      var organization = message.organization || "the workspace";
      if (message.status === "approved") {
        showMembershipNotice("Your request to join " + organization + " was approved.", {
          label: "Open workspace",
          run: function () { selectWorkspace(message.organization_id); }
        });
      } else if (message.status === "denied") {
        showMembershipNotice("Your request to join " + organization + " was declined. You can request access again or contact a workspace administrator.", {
          label: "Review workspaces",
          run: function () {
            var form = document.getElementById("request-access-form");
            if (form && message.domain) form.elements.domain.value = message.domain;
            if (workspaceDialog && !workspaceDialog.open) workspaceDialog.showModal();
          }
        });
      }
    }
    if (message.type === "membership_role_changed" && Number(message.organization_id) === Number(orgId)) {
      window.location.reload();
    }
  }

  var pendingMembershipSockets = new Map();
  var pendingMembershipWorkspaceIds = new Set();

  function connectPendingMembershipFeed(workspaceId) {
    var key = String(workspaceId);
    var existing = pendingMembershipSockets.get(key);
    if (existing && (existing.readyState === WebSocket.CONNECTING || existing.readyState === WebSocket.OPEN)) return;
    var scheme = location.protocol === "https:" ? "wss://" : "ws://";
    var socket = new WebSocket(scheme + location.host + "/ws/live?organization_id=" + encodeURIComponent(key) + "&membership_updates=1");
    pendingMembershipSockets.set(key, socket);
    socket.addEventListener("message", function (event) {
      var message = {};
      try { message = JSON.parse(event.data); } catch (_error) { /* ignore malformed live payload */ }
      handleMembershipLiveMessage(message);
    });
    var heartbeat = window.setInterval(function () {
      if (socket.readyState === WebSocket.OPEN) socket.send("ping");
    }, 20000);
    socket.addEventListener("close", function () {
      window.clearInterval(heartbeat);
      if (pendingMembershipSockets.get(key) === socket) pendingMembershipSockets.delete(key);
      if (pendingMembershipWorkspaceIds.has(key)) {
        window.setTimeout(function () {
          if (pendingMembershipWorkspaceIds.has(key)) connectPendingMembershipFeed(key);
        }, 5000);
      }
    });
  }

  function syncPendingMembershipFeeds(workspaces) {
    var desired = new Set((workspaces || []).filter(function (workspace) {
      return workspace.status === "pending" && String(workspace.id) !== String(orgId || "");
    }).map(function (workspace) { return String(workspace.id); }));
    pendingMembershipWorkspaceIds = desired;
    pendingMembershipSockets.forEach(function (socket, key) {
      if (!desired.has(key)) {
        pendingMembershipSockets.delete(key);
        socket.close();
      }
    });
    desired.forEach(connectPendingMembershipFeed);
  }

  document.querySelectorAll("time[data-local-time][datetime]").forEach(function (element) {
    element.textContent = dateLabel(element.getAttribute("datetime"));
  });

  var mobileNavigationToggle = document.getElementById("mobile-navigation-toggle");
  var sidebarNavigation = document.getElementById("sidebar-navigation");
  function setMobileNavigation(open) {
    if (!mobileNavigationToggle || !sidebarNavigation) return;
    sidebarNavigation.classList.toggle("is-open", open);
    mobileNavigationToggle.setAttribute("aria-expanded", String(open));
    mobileNavigationToggle.textContent = open ? "Close menu" : "Menu";
  }
  if (mobileNavigationToggle) mobileNavigationToggle.addEventListener("click", function () {
    setMobileNavigation(mobileNavigationToggle.getAttribute("aria-expanded") !== "true");
  });
  function handleMobileNavigationEscape(event) {
    if (event.key === "Escape" && window.matchMedia("(max-width: 760px)").matches) {
      setMobileNavigation(false);
      mobileNavigationToggle.focus();
    }
  }
  if (sidebarNavigation) sidebarNavigation.addEventListener("keydown", handleMobileNavigationEscape);
  if (mobileNavigationToggle) mobileNavigationToggle.addEventListener("keydown", handleMobileNavigationEscape);
  document.querySelectorAll("[data-tab]").forEach(function (item) {
    item.addEventListener("click", function () {
      activateTab(item.dataset.tab, true);
      if (window.matchMedia("(max-width: 760px)").matches) setMobileNavigation(false);
    });
  });

  function handleSkipToContent(event) {
    var main = document.getElementById("main-content");
    if (!main) return;
    event.preventDefault();
    main.focus();
  }
  var skipLink = document.querySelector(".skip-link");
  if (skipLink) skipLink.addEventListener("click", handleSkipToContent);

  window.addEventListener("popstate", function () {
    activateTab(tabFromLocation(), false);
  });
  window.addEventListener("hashchange", function () {
    activateTab(tabFromLocation(), false);
  });
  activateTab(tabFromLocation(), false);

  function renderScannerComparison(comparisonBody, comparison) {
    comparisonBody.replaceChildren();
    var coverageNote = document.createElement("p");
    coverageNote.textContent = comparison.coverage && comparison.coverage.comparable ? "Both runs report matching coverage." : "Coverage is incomplete or differs. Missing observations do not confirm removal or closure.";
    comparisonBody.append(coverageNote);
    (comparison.coverage && comparison.coverage.reasons || []).concat(comparison.limitations || []).forEach(function (message) {
      var note = document.createElement("p"); note.textContent = message; comparisonBody.append(note);
    });
    [["Newly observed hosts", comparison.hosts_added], ["Confirmed removed hosts", comparison.hosts_removed], ["Hosts not observed again", comparison.hosts_not_observed]].forEach(function (section) {
      var line = document.createElement("p");
      line.textContent = section[0] + ": " + ((section[1] || []).join(", ") || "None");
      comparisonBody.append(line);
    });
    (comparison.port_changes || []).forEach(function (change) {
      var row = document.createElement("details");
      var heading = document.createElement("summary");
      heading.textContent = change.host + " · " + change.port + "/" + change.protocol + " · " + String(change.change).replace(/_/g, " ") + (change.confirmed ? "" : " · Unconfirmed");
      var evidence = document.createElement("pre");
      var changeJson = JSON.stringify({before: change.before, after: change.after}, null, 2);
      evidence.textContent = changeJson.slice(0, 6000) + (changeJson.length > 6000 ? "\nPreview truncated." : "");
      row.append(heading, evidence); comparisonBody.append(row);
    });
    if (comparison.truncated) {
      var partial = document.createElement("p"); partial.textContent = "This comparison display is truncated. Total changes: " + JSON.stringify(comparison.counts || {}); comparisonBody.append(partial);
    }
  }

  function scannerPhaseLabel(name) {
    var labels = {job_status: "Run status", quick_scan_start: "Discovery started", quickscan_results: "Discovery summary", quick_scan_complete: "Discovery completed", scan_feedback: "Scan progress", scan_results: "Discovered hosts", deep_scan_results: "Detailed scan results", cve_array: "Reported vulnerability references", deep_scan_host_complete: "Host scan completed", deep_scan_complete: "Detailed scan completed"};
    return labels[name] || String(name).replace(/_/g, " ");
  }

  function scannerCoverageMetrics(agents) {
    var enabled = agents.filter(function (agent) { return agent.enabled !== false && agent.status !== "disabled"; });
    var online = enabled.filter(function (agent) { return agent.status === "online"; }).length;
    var ready = enabled.filter(function (agent) { return agent.status === "online" && agent.nmapui_ready === true; }).length;
    var scoped = enabled.filter(function (agent) { return Array.isArray(agent.authorized_networks) && agent.authorized_networks.length > 0; }).length;
    return {enabled: enabled.length, online: online, ready: ready, scoped: scoped};
  }

  function renderScannerAssessment(agents) {
    var host = document.getElementById("scanner-assessment");
    if (!host) return;
    host.replaceChildren();
    var counts = scannerCoverageMetrics(agents);
    var metrics = document.createElement("div"); metrics.className = "audit-metric-grid";
    metrics.append(
      makeAuditMetric("Online scanners", counts.online + "/" + counts.enabled, "Enabled scanners reporting ready status", counts.enabled && counts.online === counts.enabled ? "good" : "attention"),
      makeAuditMetric("Scan engine ready", String(counts.ready), "Online scanners with confirmed NmapUI readiness", counts.ready ? "good" : "attention"),
      makeAuditMetric("Approved scope", counts.scoped + "/" + counts.enabled, "Scanners assigned one or more private network ranges", counts.enabled && counts.scoped === counts.enabled ? "good" : "attention")
    );
    var note = document.createElement("p"); note.className = "muted";
    note.textContent = !counts.enabled ? "No enabled scanner is enrolled. Add a scanner for each network location you want to assess."
      : counts.scoped === 0 ? "No private networks are approved yet. Internal network exposure remains unassessed."
      : "Approved scope and scanner availability do not establish scan coverage. Review saved runs for targets, dates, results and collection limits.";
    host.append(metrics, note);
  }

  var scannerAssessmentCache = new Map();
  function renderSavedScannerAssessment(host, body) {
    host.replaceChildren();
    var heading = document.createElement("h4"); heading.textContent = "Latest saved network observations";
    host.append(heading);
    if (!body || !body.run) { appendEmpty(host, "No saved scan assessment yet."); return; }
    var context = document.createElement("p"); context.className = "muted";
    context.textContent = "Latest scan: " + String(body.run.status || "unknown") + " · " + dateLabel(body.run.last_occurred_at);
    host.append(context);
    if (!body.observations) { appendEmpty(host, body.reason || "Detailed observations are unavailable."); return; }
    var observation = body.observations;
    var metrics = document.createElement("div"); metrics.className = "audit-metric-grid";
    metrics.append(
      makeAuditMetric("Hosts observed", String(observation.host_count), "Saved detailed results", "neutral"),
      makeAuditMetric("Open ports observed", String(observation.open_port_count), "Explicitly open; requires contextual review", "neutral"),
      makeAuditMetric("Unknown port states", String(observation.unknown_port_state_count), "No state reported for these observations", observation.unknown_port_state_count ? "attention" : "neutral")
    );
    var note = document.createElement("p"); note.className = "check-scope-note";
    note.textContent = "Results collected " + dateLabel(observation.collected_at) + ". " +
      (Array.isArray(observation.covered_targets) ? "Reported targets: " + observation.covered_targets.join(", ") + ". " : "Target coverage was not explicitly reported. ") +
      "These observations do not establish coverage of every approved range or confirm vulnerabilities.";
    host.append(metrics, note);
  }

  function loadSavedScannerAssessment(host, agentId) {
    var cached = scannerAssessmentCache.get(agentId);
    if (!cached || Date.now() - cached.at >= 30000) {
      var promise = fetch("/api/agents/" + agentId + "/assessment", {credentials: "same-origin"}).then(async function (response) {
        var body = await response.json();
        if (!response.ok) throw new Error("Saved scan summary unavailable.");
        return body;
      });
      cached = {at: Date.now(), promise: promise};
      scannerAssessmentCache.set(agentId, cached);
      if (scannerAssessmentCache.size > 100) scannerAssessmentCache.delete(scannerAssessmentCache.keys().next().value);
    }
    cached.promise.then(function (body) { renderSavedScannerAssessment(host, body); }).catch(function () {
      host.replaceChildren(); appendEmpty(host, "Saved scan summary could not be refreshed. Review scan history or try again.");
      if (scannerAssessmentCache.get(agentId) === cached) scannerAssessmentCache.delete(agentId);
    });
  }

  function makeAgentCard(agent, domain) {
    var card = document.createElement("article");
    card.className = "agent-card";
    card.dataset.agentId = agent.id;

    var head = document.createElement("div");
    head.className = "agent-card-head";
    var icon = document.createElement("span");
    icon.className = "agent-icon";
    icon.textContent = "⌘";
    var status = document.createElement("span");
    status.className = "agent-status " + agent.status.toLowerCase().replaceAll(" ", "-");
    status.textContent = agent.status;
    head.append(icon, status);

    var name = document.createElement("h3");
    name.textContent = agent.name;
    var subtitle = document.createElement("p");
    subtitle.className = "agent-subtitle";
    subtitle.textContent = domain;
    var meta = document.createElement("div");
    meta.className = "agent-meta";
    var label = document.createElement("span");
    label.textContent = "Scanner ID";
    var id = document.createElement("code");
    id.textContent = agent.id;
    meta.append(label, id);
    var telemetry = document.createElement("p");
    telemetry.className = "agent-telemetry";
    var telemetryParts = [];
    if (agent.platform) telemetryParts.push(agent.platform);
    if (agent.bridge_version) telemetryParts.push("Bridge " + agent.bridge_version);
    if (agent.nmapui_version) telemetryParts.push("NmapUI " + agent.nmapui_version);
    telemetry.textContent = telemetryParts.join(" · ") || "Scanner details awaiting heartbeat";
    var readiness = document.createElement("p");
    readiness.className = "agent-readiness";
    readiness.textContent = agent.enabled === false || agent.status === "disabled"
      ? "Scanner access revoked · current NmapUI status unavailable"
      : agent.bridge_online !== true
        ? "Current NmapUI status unknown · scanner bridge offline"
        : agent.nmapui_ready === true
          ? "NmapUI ready"
          : (agent.nmapui_ready === false ? "NmapUI not ready" : "NmapUI health check pending");
    var lastSeen = document.createElement("p");
    lastSeen.className = "agent-last-seen";
    lastSeen.textContent = agent.last_seen_at
      ? "Last heartbeat " + new Date(agent.last_seen_at).toLocaleString()
      : "Waiting for first heartbeat";
    card.append(head, name, subtitle, telemetry, readiness, lastSeen, meta);

    var authorizedNetworks = Array.isArray(agent.authorized_networks) ? agent.authorized_networks : [];
    var detectedNetworks = Array.isArray(agent.detected_networks) ? agent.detected_networks : [];
    var detectedSummary = document.createElement("p");
    detectedSummary.textContent = agent.enabled === false || agent.status === "disabled"
      ? "Scanner access revoked · current connection unavailable"
      : agent.bridge_online !== true
        ? (detectedNetworks.length
          ? "Last reported connection: " + detectedNetworks.join(", ") + " · current connection unknown while offline"
          : "Current connection unknown · scanner bridge offline")
        : (detectedNetworks.length
          ? "Detected connection: " + detectedNetworks.join(", ")
          : "Waiting for the client to detect its connected network.");
    card.append(detectedSummary);
    var scopeSummary = document.createElement("p");
    scopeSummary.className = "scanner-scope-summary";
    scopeSummary.textContent = authorizedNetworks.length
      ? "Approved networks: " + authorizedNetworks.join(", ")
      : "No approved network scope. This scanner cannot receive scan commands until an admin assigns a CIDR.";
    card.append(scopeSummary);
    var savedAssessment = document.createElement("section"); savedAssessment.className = "scanner-saved-assessment";
    savedAssessment.textContent = "Loading saved network observations…";
    card.append(savedAssessment);
    loadSavedScannerAssessment(savedAssessment, agent.id);

    var controlDetails = document.createElement("details");
    controlDetails.className = "topic-secondary scanner-controls";
    controlDetails.open = openScannerControls.has(agent.id);
    var controlTitle = document.createElement("summary"); controlTitle.textContent = "Scan & manage this location";
    controlDetails.append(controlTitle);
    controlDetails.addEventListener("toggle", function () {
      if (controlDetails.open) openScannerControls.add(agent.id);
      else openScannerControls.delete(agent.id);
    });
    if (role === "admin" && controlsEnabled) {
      var scopeEditor = document.createElement("div");
      scopeEditor.className = "scanner-network-editor";
      var scopeLabel = document.createElement("label");
      scopeLabel.textContent = "Authorized network CIDRs · comma separated";
      var scopeInput = document.createElement("input");
      scopeInput.value = scannerNetworkInputs.has(agent.id)
        ? scannerNetworkInputs.get(agent.id)
        : (authorizedNetworks.length ? authorizedNetworks : detectedNetworks).join(", ");
      scopeInput.placeholder = "10.20.20.0/24, 10.20.21.0/24";
      scopeInput.setAttribute("aria-label", "Authorized network CIDRs for " + agent.name);
      scopeInput.addEventListener("input", function () { scannerNetworkInputs.set(agent.id, scopeInput.value); });
      scopeLabel.append(scopeInput);
      var saveScope = document.createElement("button");
      saveScope.type = "button";
      saveScope.className = "button button-small button-secondary";
      saveScope.dataset.saveScannerScope = agent.id;
      saveScope.textContent = "Save scope";
      var scopeFeedback = document.createElement("span");
      scopeFeedback.className = "scanner-scope-feedback";
      scopeFeedback.setAttribute("aria-live", "polite");
      scopeFeedback.textContent = scannerScopeFeedback.get(agent.id) || "";
      scopeEditor.append(scopeLabel, saveScope, scopeFeedback);
      controlDetails.append(scopeEditor);
    }

    if (role === "admin" && controlsEnabled) {
      var actions = document.createElement("div");
      actions.className = "agent-actions";
      var target = document.createElement("input");
      target.className = "scan-target";
      target.value = scannerTargets.get(agent.id) || authorizedNetworks[0] || "";
      target.placeholder = authorizedNetworks.length ? "Target inside " + authorizedNetworks[0] : "Set scanner network scope first";
      target.addEventListener("input", function () { scannerTargets.set(agent.id, target.value); });
      target.setAttribute("aria-label", "Scan target");
      var knownTargetLabel = document.createElement("label");
      knownTargetLabel.className = "scan-known-target-option";
      var skipDiscovery = document.createElement("input");
      skipDiscovery.type = "checkbox";
      skipDiscovery.className = "scan-skip-discovery";
      skipDiscovery.checked = scannerSkipDiscovery.get(agent.id) === true;
      skipDiscovery.disabled = (agent.command_protocol_version || 0) < 2;
      skipDiscovery.setAttribute("aria-label", "Skip host discovery for this scan");
      skipDiscovery.addEventListener("change", function () {
        scannerSkipDiscovery.set(agent.id, skipDiscovery.checked);
      });
      var knownTargetCopy = document.createElement("span");
      knownTargetCopy.textContent = "Treat target as known for this scan (-Pn)";
      knownTargetLabel.append(skipDiscovery, knownTargetCopy);
      var knownTargetHelp = document.createElement("small");
      knownTargetHelp.className = "scan-known-target-help";
      knownTargetHelp.textContent = skipDiscovery.disabled
        ? "Update this scanner kit to use per-scan options."
        : "On skips discovery; off uses normal discovery. This does not change scanner settings.";
      var scan = document.createElement("button");
      scan.className = "button button-small";
      scan.dataset.command = "start_scan";
      scan.textContent = "Run scan";
      scan.disabled = agent.status !== "online" || authorizedNetworks.length === 0;
      var stop = document.createElement("button");
      stop.className = "button button-small button-quiet";
      stop.dataset.command = "cancel_scan";
      stop.textContent = "Stop";
      stop.disabled = agent.status !== "online";
      var updates = document.createElement("button");
      updates.className = "button button-small button-quiet";
      updates.dataset.command = "check_nmapui_updates";
      updates.textContent = "Check NmapUI updates";
      updates.disabled = agent.status !== "online";
      actions.append(target, knownTargetLabel, knownTargetHelp, scan, stop, updates);
      if (supportsOSUpdateCheck(agent)) {
        var osUpdates = document.createElement("button");
        osUpdates.className = "button button-small button-quiet";
        osUpdates.dataset.command = "check_os_updates";
        osUpdates.textContent = agent.platform === "Linux" ? "Check cached Linux updates" : "Check macOS updates";
        osUpdates.disabled = !agent.bridge_online;
        osUpdates.title = agent.platform === "Linux" ? "Reads the existing APT package index; does not refresh the index or install updates." : "Reads Apple's software update catalog. Does not install updates.";
        actions.append(osUpdates);
      }
      if (agent.nmapui_restart_supported) {
        var restart = document.createElement("button");
        restart.className = "button button-small button-quiet";
        restart.dataset.command = "restart_nmapui";
        restart.textContent = "Restart NmapUI";
        restart.disabled = !agent.bridge_online;
        restart.title = "Restart the managed NmapUI service on this scanner.";
        actions.append(restart);
      }
      if (agent.command_protocol_version >= 1) {
        [["refresh_health", "Refresh health"], ["collect_diagnostics", "Collect diagnostics"]].forEach(function (item) {
          var diagnostic = document.createElement("button");
          diagnostic.className = "button button-small button-quiet";
          diagnostic.dataset.command = item[0];
          diagnostic.textContent = item[1];
          diagnostic.disabled = !agent.bridge_online;
          actions.append(diagnostic);
        });
      }
      controlDetails.append(actions);
    }
    if (role === "admin" && agent.enabled !== false && agent.status !== "disabled") {
      var enrollmentActions = document.createElement("div");
      enrollmentActions.className = "agent-actions";
      var disable = document.createElement("button");
      disable.type = "button";
      disable.className = "button button-small button-quiet";
      disable.dataset.disableScanner = agent.id;
      disable.dataset.scannerName = agent.name;
      disable.textContent = "Revoke scanner access";
      var revokeNote = document.createElement("span");
      revokeNote.className = "scanner-revoke-feedback";
      enrollmentActions.append(disable, revokeNote);
      controlDetails.append(enrollmentActions);
    }
    if (controlDetails.childNodes.length > 1) card.append(controlDetails);
    if (canViewScannerCommandHistory(role)) {
      var history = document.createElement("details");
      history.className = "agent-command-history";
      history.open = openCommandHistories.has(agent.id);
      var historyTitle = document.createElement("summary");
      historyTitle.textContent = "Command history";
      var historyBody = document.createElement("div");
      history.append(historyTitle, historyBody);
      history.addEventListener("toggle", async function () {
        if (!history.open) { openCommandHistories.delete(agent.id); return; }
        openCommandHistories.add(agent.id);
        historyBody.textContent = "Loading command history…";
        try {
          var response = await fetch("/api/agents/" + agent.id + "/commands", { credentials: "same-origin" });
          var payload = await response.json();
          if (!response.ok) throw new Error(payload.detail || "Could not load command history");
          historyBody.textContent = "";
          if (!payload.commands.length) historyBody.textContent = "No commands yet.";
          payload.commands.slice(0, 20).forEach(function (command) {
            var entry = document.createElement("div");
            entry.className = "command-entry";
            var actionNames = { start_scan: "Run scan", cancel_scan: "Stop scan", restart_nmapui: "Restart NmapUI", check_nmapui_updates: "Check NmapUI updates", check_os_updates: "Check OS updates", refresh_health: "Refresh health", collect_diagnostics: "Collect diagnostics" };
            entry.textContent = (actionNames[command.action] || command.action) + " · " + ({queued:"Queued",delivered:"Delivered",accepted:"Accepted",succeeded:"Completed",failed:"Failed",timed_out:"Completion unconfirmed",expired:"Expired",cancelled:"Cancelled"}[command.status] || command.status);
            var timeline = document.createElement("p");
            timeline.className = "command-timeline";
            timeline.textContent = commandTimeline(command);
            entry.append(timeline);
            if (command.result) {
              var evidence = document.createElement("pre");
              evidence.style.whiteSpace = "pre-wrap";
              evidence.style.overflowWrap = "anywhere";
              try {
                var decoded = JSON.parse(command.result);
                if (command.action === "collect_diagnostics" && decoded && decoded.schema_version === 1) {
                  var inventory = document.createElement("dl");
                  inventory.className = "scanner-inventory";
                  [["platform", "Operating system"], ["os_version", "OS version"], ["architecture", "Architecture"], ["cpu_count", "Logical CPUs"], ["total_memory_bytes", "Total memory"], ["data_volume_free_bytes", "Free data storage"]].forEach(function (field) {
                    var label = document.createElement("dt"); label.textContent = field[1];
                    var value = document.createElement("dd");
                    var observed = decoded[field[0]];
                    value.textContent = inventoryDisplayValue(field[0], observed);
                    inventory.append(label, value);
                  });
                  entry.append(inventory);
                  if (decoded.operational_fields_omitted) {
                    var limited = document.createElement("p"); limited.textContent = "Operational details were omitted to keep this receipt within its size limit."; entry.append(limited);
                  }
                } else if (command.action === "check_os_updates" && decoded && decoded.schema_version === 1) {
                  var updateSummary = document.createElement("p");
                  var outcome = { updates_available: "Updates are available", no_updates: "No updates are available", unavailable: "Update information is unavailable", timed_out: "The catalog check timed out", error: "The catalog check failed", unsupported: "This platform is not supported", unknown: "The catalog response could not be interpreted" };
                  if (decoded.source === "existing_apt_index") {
                    outcome.updates_available = "Cached APT index lists upgrades";
                    outcome.no_updates = "No upgrades listed in the cached APT index";
                  }
                  updateSummary.textContent = (outcome[decoded.status] || "Update check result") + (decoded.observed_at && Number.isFinite(Date.parse(decoded.observed_at)) ? " · Checked " + new Date(decoded.observed_at).toLocaleString() : "");
                  entry.append(updateSummary);
                  if (decoded.source === "existing_apt_index") {
                    var indexScope = document.createElement("p");
                    indexScope.textContent = "Based on the existing APT package index; it was not refreshed. This does not establish current repository update availability.";
                    entry.append(indexScope);
                  }
                  if (Array.isArray(decoded.updates)) {
                    var updateList = document.createElement("ul");
                    decoded.updates.slice(0, 5).forEach(function (update) {
                      if (!update || typeof update.label !== "string") return;
                      var item = document.createElement("li");
                      var shortTitle = typeof update.title === "string" ? update.title.split(/,\s*Version:/i)[0].trim() : "";
                      item.textContent = (shortTitle || update.label) + (shortTitle && shortTitle !== update.label ? " (" + update.label + ")" : "");
                      updateList.append(item);
                    });
                    if (updateList.childNodes.length) entry.append(updateList);
                  }
                  if (decoded.truncated === true) {
                    var omittedUpdates = document.createElement("p");
                    omittedUpdates.textContent = (Number.isInteger(decoded.update_count) && decoded.update_count >= 0 ? "Catalog reported " + decoded.update_count + " updates. " : "") + "Some update details were omitted from this receipt.";
                    entry.append(omittedUpdates);
                  }
                  evidence.textContent = JSON.stringify(decoded, null, 2);
                  var rawDetails = document.createElement("details");
                  var rawSummary = document.createElement("summary");
                  rawSummary.textContent = "Raw update catalog receipt";
                  rawDetails.append(rawSummary, evidence);
                  entry.append(rawDetails);
                  historyBody.append(entry);
                  return;
                }
                evidence.textContent = JSON.stringify(decoded, null, 2);
              }
              catch (_) { evidence.textContent = command.result; }
              entry.append(evidence);
            }
            historyBody.append(entry);
          });
        } catch (error) { historyBody.textContent = error.message; }
      });
      card.append(history);
    }

    var scanHistory = document.createElement("details");
    scanHistory.className = "agent-command-history agent-run-history";
    scanHistory.open = openScanHistories.has(agent.id);
    var scanHistoryTitle = document.createElement("summary");
    scanHistoryTitle.textContent = "Scan run history";
    var scanHistoryBody = document.createElement("div");
    scanHistory.append(scanHistoryTitle, scanHistoryBody);
    scanHistory.addEventListener("toggle", async function () {
      if (!scanHistory.open) { openScanHistories.delete(agent.id); return; }
      openScanHistories.add(agent.id);
      scanHistoryBody.textContent = "Loading scan runs…";
      try {
        var response = await fetch("/api/agents/" + agent.id + "/runs", { credentials: "same-origin" });
        var payload = await response.json();
        if (!response.ok) throw new Error(payload.detail || "Could not load scan history");
        scanHistoryBody.replaceChildren();
        var explanation = document.createElement("p");
        explanation.textContent = "Runs are grouped by scanner-provided IDs. Older events without a run ID remain in the event stream.";
        scanHistoryBody.append(explanation);
        if (payload.truncated) {
          var limitNote = document.createElement("p");
          limitNote.textContent = "Showing the newest " + payload.runs.length + " of " + payload.total_runs + " runs.";
          scanHistoryBody.append(limitNote);
        }
        if (!payload.runs.length) appendEmpty(scanHistoryBody, "No grouped runs yet. Update the scanner kit to retain run IDs.");
        payload.runs.forEach(function (run) {
          var runCard = document.createElement("details");
          runCard.className = "scanner-run-row";
          var runKey = agent.id + ":" + run.source_job_id;
          runCard.open = openRunDetails.has(runKey);
          var title = document.createElement("summary");
          var statusLabels = {completed: "Completed", succeeded: "Completed", running: "Running", failed: "Failed", cancelled: "Cancelled", cancelling: "Cancelling", interrupted: "Interrupted", unknown: "Status unconfirmed"};
          title.textContent = (run.source_job_type === "report" ? "Report run" : run.source_job_type === "scan" ? "Scan run" : "Scanner run") + " · " + dateLabel(run.first_occurred_at) + " · " + (statusLabels[run.status] || "Status unconfirmed") + " · " + run.event_count + " events";
          title.title = run.source_job_id;
          var eventsBody = document.createElement("div");
          runCard.append(title, eventsBody);
          var reportActions = document.createElement("div");
          reportActions.className = "agent-actions";
          var runPdf = document.createElement("button");
          runPdf.type = "button";
          runPdf.className = "button button-small";
          runPdf.dataset.scannerPdfRun = run.source_job_id;
          runPdf.dataset.scannerAgent = agent.id;
          runPdf.textContent = "Generate run PDF";
          var runFeedback = document.createElement("span");
          runFeedback.className = "scanner-pdf-feedback";
          reportActions.append(runPdf, runFeedback);
          runCard.append(reportActions);
          var earlierRuns = payload.runs.filter(function (candidate) {
            return candidate.source_job_id !== run.source_job_id && candidate.source_job_type === "scan" && new Date(candidate.first_occurred_at) < new Date(run.first_occurred_at);
          });
          if (run.source_job_type === "scan" && earlierRuns.length) {
            var comparisonActions = document.createElement("div");
            comparisonActions.className = "agent-actions";
            var baseline = document.createElement("select");
            baseline.setAttribute("aria-label", "Previous scan for comparison");
            earlierRuns.forEach(function (candidate) {
              var option = document.createElement("option");
              option.value = candidate.source_job_id;
              option.textContent = dateLabel(candidate.first_occurred_at) + " · " + (statusLabels[candidate.status] || "Status unconfirmed") + " · " + candidate.source_job_id.slice(0, 8);
              baseline.append(option);
            });
            if (earlierRuns.some(function (candidate) { return candidate.source_job_id === selectedRunBaselines.get(runKey); })) baseline.value = selectedRunBaselines.get(runKey);
            baseline.addEventListener("change", function () { selectedRunBaselines.set(runKey, baseline.value); });
            var compareButton = document.createElement("button");
            compareButton.type = "button";
            compareButton.className = "button button-small button-secondary";
            compareButton.textContent = "Compare scans";
            var comparisonBody = document.createElement("div");
            comparisonBody.className = "scanner-run-comparison";
            function comparisonKey() {
              var previous = earlierRuns.find(function (candidate) { return candidate.source_job_id === baseline.value; });
              return runKey + ":" + run.last_occurred_at + ":" + baseline.value + ":" + (previous && previous.last_occurred_at);
            }
            var cachedComparison = scannerComparisonCache.get(comparisonKey());
            if (cachedComparison) renderScannerComparison(comparisonBody, cachedComparison.value);
            baseline.addEventListener("change", function () {
              var cached = scannerComparisonCache.get(comparisonKey());
              if (cached) renderScannerComparison(comparisonBody, cached.value);
              else comparisonBody.textContent = "Select Compare scans to load this pair.";
            });
            compareButton.addEventListener("click", async function () {
              compareButton.disabled = true;
              comparisonBody.textContent = "Comparing saved observations…";
              selectedRunBaselines.set(runKey, baseline.value);
              try {
                var comparisonResponse = await fetch("/api/agents/" + agent.id + "/runs/" + encodeURIComponent(run.source_job_id) + "/comparison?previous_run_id=" + encodeURIComponent(baseline.value), {credentials: "same-origin"});
                var comparison = await comparisonResponse.json();
                if (!comparisonResponse.ok) throw new Error(comparison.detail || "Comparison unavailable");
                if (comparison.available === false) throw new Error(comparison.reason || "Both runs need saved detailed results before comparison.");
                var serializedSize = JSON.stringify(comparison).length * 2;
                if (serializedSize <= 4 * 1024 * 1024) {
                  scannerComparisonCache.set(comparisonKey(), {value: comparison, size: serializedSize});
                  var total = Array.from(scannerComparisonCache.values()).reduce(function (sum, item) { return sum + item.size; }, 0);
                  while (total > 4 * 1024 * 1024) {
                    var oldestKey = scannerComparisonCache.keys().next().value;
                    total -= scannerComparisonCache.get(oldestKey).size;
                    scannerComparisonCache.delete(oldestKey);
                  }
                }
                renderScannerComparison(comparisonBody, comparison);
              } catch (error) { comparisonBody.textContent = error.message; }
              finally { compareButton.disabled = false; }
            });
            comparisonActions.append(baseline, compareButton);
            runCard.append(comparisonActions, comparisonBody);
          }
          runCard.addEventListener("toggle", async function () {
            if (!runCard.open) { openRunDetails.delete(runKey); return; }
            openRunDetails.add(runKey);
            if (eventsBody.dataset.loaded === "true" || eventsBody.dataset.loading === "true") return;
            eventsBody.dataset.loading = "true";
            eventsBody.textContent = "Loading saved phases…";
            try {
              var detailResponse = await fetch("/api/agents/" + agent.id + "/runs/" + encodeURIComponent(run.source_job_id), { credentials: "same-origin" });
              var detail = await detailResponse.json();
              if (!detailResponse.ok) throw new Error(detail.detail || "Could not load run evidence");
              eventsBody.replaceChildren();
              if (detail.run.group_metadata_conflict) {
                var conflictNote = document.createElement("p");
                conflictNote.textContent = "Saved events disagree on run metadata. Run status is unconfirmed.";
                eventsBody.append(conflictNote);
              }
              if (detail.truncated) {
                var note = document.createElement("p");
                note.textContent = "Showing the latest " + detail.returned_event_count + " events. This view is incomplete.";
                eventsBody.append(note);
              }
              (detail.events || []).forEach(function (event) {
                var eventDetail = document.createElement("details");
                var eventKey = runKey + ":" + event.id;
                eventDetail.open = openRunEvents.has(eventKey);
                eventDetail.addEventListener("toggle", function () {
                  if (eventDetail.open) openRunEvents.add(eventKey);
                  else openRunEvents.delete(eventKey);
                });
                var eventTitle = document.createElement("summary");
                eventTitle.textContent = scannerPhaseLabel(event.event_name) + " · " + dateLabel(event.occurred_at);
                eventTitle.title = "Event " + event.id + " / " + event.event_name;
                var preview = document.createElement("pre");
                var serialized = JSON.stringify(event.payload, null, 2) || "No payload";
                preview.textContent = serialized.slice(0, 6000) + (serialized.length > 6000 ? "\nPreview truncated." : "");
                eventDetail.append(eventTitle, preview);
                if (event.artifact_download_url) {
                  var download = document.createElement("a");
                  download.href = event.artifact_download_url;
                  download.textContent = "Download complete event JSON";
                  eventDetail.append(download);
                }
                eventsBody.append(eventDetail);
              });
              eventsBody.dataset.loaded = "true";
            } catch (error) { eventsBody.textContent = error.message; }
            finally { delete eventsBody.dataset.loading; }
          });
          scanHistoryBody.append(runCard);
        });
      } catch (error) { scanHistoryBody.textContent = error.message; }
    });
    card.append(scanHistory);

    var comparisonHistory = document.createElement("details");
    comparisonHistory.className = "agent-command-history";
    comparisonHistory.open = openComparisonHistories.has(agent.id);
    var comparisonHeading = document.createElement("summary");
    comparisonHeading.textContent = "Saved scan comparisons";
    var savedComparisonBody = document.createElement("div");
    comparisonHistory.append(comparisonHeading, savedComparisonBody);
    comparisonHistory.addEventListener("toggle", async function () {
      if (!comparisonHistory.open) { openComparisonHistories.delete(agent.id); return; }
      openComparisonHistories.add(agent.id);
      savedComparisonBody.textContent = "Loading saved comparisons…";
      try {
        var response = await fetch("/api/agents/" + agent.id + "/run-comparisons", {credentials: "same-origin"});
        var history = await response.json();
        if (!response.ok) throw new Error(history.detail || "Could not load comparison history");
        savedComparisonBody.replaceChildren();
        if (!history.comparisons.length) appendEmpty(savedComparisonBody, "No completed scan comparisons saved yet.");
        history.comparisons.forEach(function (entry) {
          var row = document.createElement("details");
          row.className = "scanner-run-row";
          var savedKey = agent.id + ":" + entry.id;
          row.open = openSavedComparisons.has(savedKey);
          row.addEventListener("toggle", function () {
            if (row.open) openSavedComparisons.add(savedKey);
            else openSavedComparisons.delete(savedKey);
          });
          var heading = document.createElement("summary");
          heading.textContent = dateLabel(entry.detected_at) + " · " + entry.meaningful_change_count + " significant observed changes";
          var scope = document.createElement("p");
          scope.textContent = "Run " + entry.previous_run_id.slice(0, 8) + " → " + entry.current_run_id.slice(0, 8);
          row.append(heading, scope);
          var comparison = entry.comparison || {};
          if (entry.comparison_truncated) {
            var summaryNote = document.createElement("p");
            summaryNote.textContent = "This comparison is too large for the history preview. Download the complete saved evidence. Counts: " + JSON.stringify(comparison.counts || {});
            row.append(summaryNote);
          }
          var coverage = document.createElement("p");
          coverage.textContent = comparison.coverage && comparison.coverage.comparable ? "Matching scanner-reported coverage." : "Incomplete or different coverage; missing observations remain unconfirmed.";
          row.append(coverage);
          [["Newly observed hosts", comparison.hosts_added], ["Confirmed removed hosts", comparison.hosts_removed], ["Not observed again", comparison.hosts_not_observed]].forEach(function (section) {
            var line = document.createElement("p");
            line.textContent = section[0] + ": " + (entry.comparison_truncated ? "Details in saved evidence" : ((section[1] || []).join(", ") || "None"));
            row.append(line);
          });
          (comparison.port_changes || []).forEach(function (change) {
            var portRow = document.createElement("details");
            var portHeading = document.createElement("summary");
            portHeading.textContent = change.host + " · " + change.port + "/" + change.protocol + " · " + String(change.change).replace(/_/g, " ") + (change.confirmed ? "" : " · Unconfirmed");
            var values = document.createElement("p");
            function describe(observation) {
              if (!observation) return "Not observed";
              return [observation.state || "State not reported", typeof observation.service === "string" ? observation.service : JSON.stringify(observation.service || {}), observation.product, observation.version].filter(Boolean).join(" · ");
            }
            values.textContent = "Before: " + describe(change.before) + " → After: " + describe(change.after);
            portRow.append(portHeading, values); row.append(portRow);
          });
          (comparison.limitations || []).forEach(function (message) { var note = document.createElement("p"); note.textContent = message; row.append(note); });
          if (comparison.truncated) { var partial = document.createElement("p"); partial.textContent = "Saved comparison is bounded; some changes are omitted. Counts: " + JSON.stringify(comparison.counts || {}); row.append(partial); }
          var download = document.createElement("button");
          download.type = "button";
          download.className = "button button-small button-quiet";
          download.textContent = "Download saved comparison JSON";
          download.addEventListener("click", function () {
            if (entry.full_evidence_url) {
              var evidenceLink = document.createElement("a");
              evidenceLink.href = entry.full_evidence_url;
              evidenceLink.download = "daedalus-scanner-comparison-" + entry.id + ".json";
              document.body.append(evidenceLink); evidenceLink.click(); evidenceLink.remove();
              return;
            }
            if (entry.comparison_truncated) return;
            var url = URL.createObjectURL(new Blob([JSON.stringify(entry, null, 2)], {type: "application/json"}));
            var link = document.createElement("a"); link.href = url; link.download = "daedalus-scanner-comparison-" + entry.id + ".json";
            document.body.append(link); link.click(); link.remove();
            window.setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
          });
          row.append(download); savedComparisonBody.append(row);
        });
        if (history.truncated) {
          var note = document.createElement("p"); note.textContent = "Showing a bounded selection of saved comparisons. " + (history.truncation_reasons || []).join(" "); savedComparisonBody.append(note);
        }
      } catch (error) { savedComparisonBody.textContent = error.message; }
    });
    card.append(comparisonHistory);
    // Move saved evidence ahead of operational controls without replacing nodes.
    card.append(scanHistory, comparisonHistory);
    if (controlDetails.childNodes.length > 1) card.append(controlDetails);
    if (history) card.append(history);

    return card;
  }

  function makeEventRow(event) {
    var row = document.createElement("article");
    row.className = "event-row";
    var dot = document.createElement("span");
    dot.className = "event-dot";
    var main = document.createElement("div");
    main.className = "event-main";
    var heading = document.createElement("div");
    heading.className = "event-title";
    heading.textContent = event.event_name + " ";
    var agent = document.createElement("span");
    agent.textContent = "scanner " + event.agent_id;
    heading.append(agent);
    var payload = document.createElement("pre");
    payload.textContent = JSON.stringify(event.payload, null, 2);
    main.append(heading, payload);
    var actions = document.createElement("div");
    actions.className = "agent-actions";
    if (event.artifact_download_url) {
      var evidence = document.createElement("a");
      evidence.className = "button button-small button-quiet";
      evidence.href = event.artifact_download_url;
      evidence.textContent = "Download complete JSON" + (event.artifact_size_bytes ? " · " + formatBytes(event.artifact_size_bytes) : "");
      actions.append(evidence);
    }
    if (["scan_results", "quickscan_results", "deep_scan_results"].includes(event.event_name)) {
      var pdf = document.createElement("button");
      pdf.className = "button button-small";
      pdf.dataset.scannerPdfEvent = event.id;
      pdf.textContent = "Generate PDF report";
      actions.append(pdf);
    }
    if (actions.children.length) {
      var feedback = document.createElement("span");
      feedback.className = "scanner-pdf-feedback";
      feedback.setAttribute("aria-live", "polite");
      actions.append(feedback);
      main.append(actions);
    }
    var time = document.createElement("time");
    time.textContent = dateLabel(event.occurred_at || event.created_at);
    time.title = "Received " + dateLabel(event.created_at);
    row.append(dot, main, time);
    return row;
  }

  function render(data) {
    verificationStatus = data.organization.verification_status;
    controlsEnabled = data.organization.controls_enabled;
    if (shell) shell.dataset.verificationStatus = verificationStatus;
    if (shell) shell.dataset.controlsEnabled = String(controlsEnabled);
    text(document.getElementById("stat-domain-status"), verificationStatus.charAt(0).toUpperCase() + verificationStatus.slice(1));
    var verificationPill = document.querySelector(".verification-pill");
    if (verificationPill) {
      verificationPill.className = "verification-pill verification-" + verificationStatus;
      verificationPill.textContent = "Domain " + verificationStatus;
    }
    renderScannerAssessment(data.agents);
    var agentList = document.getElementById("agent-list");
    if (agentList) {
      var activeScannerField = document.activeElement;
      var preserveScannerEdit = agentList.contains(activeScannerField)
        && (/^(INPUT|TEXTAREA|SELECT)$/.test(activeScannerField.tagName)
          || Boolean(activeScannerField.closest(".scanner-network-editor")));
      if (!preserveScannerEdit) {
        agentList.replaceChildren();
        if (!data.agents.length) {
          var empty = document.createElement("div");
          empty.className = "empty-card";
          empty.textContent = "No scanner connected yet. Use Add scanner to enroll the Mac bridge.";
          agentList.append(empty);
        } else {
          data.agents.forEach(function (agent) {
            agentList.append(makeAgentCard(agent, data.organization.domain));
          });
        }
      }
    }
    text(document.getElementById("stat-agents"), data.agents.length);
    text(document.getElementById("stat-online"), data.agents.filter(function (agent) {
      return agent.status === "online";
    }).length);
    text(document.getElementById("stat-events"), data.events.length);

    var stream = document.getElementById("event-stream");
    if (stream) {
      stream.replaceChildren();
      if (!data.events.length) {
        var emptyEvents = document.createElement("div");
        emptyEvents.className = "empty-events";
        emptyEvents.textContent = "Scan progress and findings will appear here as they arrive.";
        stream.append(emptyEvents);
      } else {
        data.events.forEach(function (event) {
          stream.append(makeEventRow(event));
        });
      }
    }
    text(document.getElementById("event-count"), data.events.length + " recent");
  }

  function workspaceAssessmentSummary(areas) {
    var counts = {attention: 0, unavailable: 0, not_assessed: 0, running: 0, recorded: 0, unknown: 0};
    (Array.isArray(areas) ? areas : []).forEach(function (area) {
      var state = Object.prototype.hasOwnProperty.call(counts, area.state) ? area.state : "unknown";
      counts[state] += 1;
    });
    var ranks = {unavailable: 0, attention: 1, unknown: 2, not_assessed: 3, running: 4, recorded: 5};
    var ordered = (Array.isArray(areas) ? areas : []).map(function (area, index) { return {area: area, index: index}; });
    ordered.sort(function (left, right) {
      var a = Object.prototype.hasOwnProperty.call(ranks, left.area.state) ? ranks[left.area.state] : ranks.unknown;
      var b = Object.prototype.hasOwnProperty.call(ranks, right.area.state) ? ranks[right.area.state] : ranks.unknown;
      return a - b || left.index - right.index;
    });
    return {counts: counts, areas: ordered.map(function (entry) { return entry.area; })};
  }

  async function loadWorkspacePosture() {
    var host = document.getElementById("workspace-posture");
    if (!host || !orgId) return;
    var sequence = ++postureRequestSequence;
    try {
      var response = await fetch("/api/workspace-posture", { credentials: "same-origin" });
      var body = await response.json();
      if (!response.ok || !Array.isArray(body.areas) || !body.areas.length) throw new Error("Workspace assessments could not be loaded.");
      if (sequence !== postureRequestSequence) return;
      var focusedKey = host.contains(document.activeElement) ? document.activeElement.dataset.postureKey : null;
      host.replaceChildren();
      var labels = {recorded:"Evidence saved", attention:"Review evidence", not_assessed:"Not assessed", running:"Check running", unavailable:"Latest attempt failed"};
      var assessment = workspaceAssessmentSummary(body.areas);
      var priorities = document.getElementById("workspace-priorities");
      if (priorities) {
        priorities.replaceChildren();
        var metrics = document.createElement("div"); metrics.className = "audit-metric-grid";
        metrics.append(
          makeAuditMetric("Areas to review", String(assessment.counts.attention), "Saved observations requiring review", assessment.counts.attention ? "attention" : "neutral"),
          makeAuditMetric("Failed collections", String(assessment.counts.unavailable), "Latest attempt unavailable; review prior evidence", assessment.counts.unavailable ? "attention" : "neutral"),
          makeAuditMetric("Unassessed areas", String(assessment.counts.not_assessed + assessment.counts.unknown), "Missing or unknown assessment evidence", "neutral")
        );
        priorities.append(metrics);
        var note = document.createElement("p"); note.className = "check-scope-note";
        note.textContent = "Review areas below in priority order. Saved evidence and active checks do not establish that an area is secure.";
        priorities.append(note);
      }
      assessment.areas.forEach(function (area) {
        var card = document.createElement("button"); card.type = "button"; card.className = "posture-card"; card.dataset.postureKey = area.key;
        var heading = document.createElement("strong"); heading.textContent = area.title;
        var state = document.createElement("span"); state.className = "posture-state is-" + area.state; state.textContent = labels[area.state] || "Unknown";
        var summary = document.createElement("p"); summary.textContent = area.summary;
        var date = document.createElement("small"); date.textContent = area.updated_at ? "Saved evidence / check-in " + dateLabel(area.updated_at) : "No saved assessment time";
        var link = document.createElement("span"); link.className = "module-link"; link.textContent = "Review this area →";
        card.append(heading, state, summary, date);
        if (area.audit_summary) {
          var audit = document.createElement("p"); audit.textContent = area.audit_summary;
          var captured = document.createElement("small"); captured.textContent = "Audit evidence " + dateLabel(area.audit_updated_at);
          card.append(audit, captured);
        }
        card.append(link);
        card.addEventListener("click", function () { activateTab(area.key, true); });
        host.append(card);
      });
      if (focusedKey) { var focused = host.querySelector('[data-posture-key="' + focusedKey + '"]'); if (focused) focused.focus({preventScroll:true}); }
    } catch (error) { if (sequence === postureRequestSequence) {
      host.replaceChildren(); appendEmpty(host, error.message);
      var priorities = document.getElementById("workspace-priorities");
      if (priorities) { priorities.replaceChildren(); appendEmpty(priorities, "Current assessment coverage is unavailable. Refresh to try again."); }
    } }
  }

  function refresh(force) {
    if (dashboardRefreshPromise) {
      if (force) return dashboardRefreshPromise.then(function () { return refresh(true); });
      return dashboardRefreshPromise;
    }
    dashboardRefreshPromise = (async function () {
      try {
        var response = await fetch("/api/dashboard", { credentials: "same-origin" });
        if (!response.ok) return;
        var data = await response.json();
        if (!force && document.querySelector(".inline-confirmation")) return;
        render(data);
        if (activeTab === "overview") await loadWorkspacePosture();
      } catch (_error) {
        // Periodic refresh retries transient failures without changing saved evidence.
      }
    })().finally(function () { dashboardRefreshPromise = null; });
    return dashboardRefreshPromise;
  }

  async function sendCommand(button) {
    var card = button.closest("[data-agent-id]");
    if (!card) return;
    var action = button.dataset.command;
    var targetInput = card.querySelector(".scan-target");
    var skipDiscoveryInput = card.querySelector(".scan-skip-discovery");
    button.disabled = true;
    var original = button.textContent;
    button.textContent = "Sending…";
    try {
      var response = await fetch("/api/agents/" + card.dataset.agentId + "/commands", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          action: action,
          target: action === "start_scan" && targetInput ? targetInput.value : null,
          skip_host_discovery: action === "start_scan" && skipDiscoveryInput ? skipDiscoveryInput.checked : false
        })
      });
      var body = await response.json();
      if (!response.ok) throw new Error(body.detail || "Could not queue command");
      button.textContent = "Queued";
      await refresh(true);
      window.setTimeout(function () {
        button.textContent = original;
        button.disabled = false;
      }, 1800);
    } catch (error) {
      button.textContent = error.message;
      window.setTimeout(function () {
        button.textContent = original;
        button.disabled = false;
      }, 2800);
      throw error;
    }
  }

  function runCommand(button) {
    if (button.dataset.command === "restart_nmapui") {
      requestInlineConfirmation(button, "Restart the managed NmapUI service? Active scans will stop.", "Restart service", function () {
        return sendCommand(button);
      });
      return;
    }
    sendCommand(button).catch(function () {});
  }

  async function saveScannerScope(button) {
    var card = button.closest("[data-agent-id]");
    if (!card) return;
    var agentId = card.dataset.agentId;
    var input = card.querySelector(".scanner-network-editor input");
    var feedback = card.querySelector(".scanner-scope-feedback");
    var networks = input ? input.value.split(/[\n,;]+/).map(function (value) { return value.trim(); }).filter(Boolean) : [];
    button.disabled = true;
    if (feedback) feedback.textContent = "Saving approved scanner scope…";
    try {
      var response = await fetch("/api/agents/" + encodeURIComponent(agentId) + "/network-scope", {
        method: "PUT",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ authorized_networks: networks })
      });
      var body = await response.json();
      if (!response.ok) throw new Error(body.detail || "Could not save scanner scope");
      scannerNetworkInputs.set(agentId, body.authorized_networks.join(", "));
      var message = body.authorized_networks.length
        ? "Scope saved. " + body.authorized_networks.length + " network(s) approved."
        : "Scope cleared. Scans are disabled until a network is approved.";
      if (body.cancelled_queued_scan_count) message += " Cancelled " + body.cancelled_queued_scan_count + " queued scan(s) outside the new scope.";
      if (body.cancellation_request_queued_count) message += " Requested cancellation for " + body.unconfirmed_active_scan_count + " already-delivered scan(s). This is best-effort; their status remains unconfirmed until the scanner reports a terminal result.";
      else if (body.cancellation_request_skipped_offline_count) message += " " + body.unconfirmed_active_scan_count + " already-delivered scan(s) remain unconfirmed; the scanner is offline, so cancellation could not be requested.";
      else if (body.cancellation_request_skipped_mixed_scope_count) message += " " + body.unconfirmed_active_scan_count + " out-of-scope scan(s) remain unconfirmed. Cancellation was not requested because NmapUI also has an in-scope active scan.";
      else if (body.unconfirmed_active_scan_count) message += " " + body.unconfirmed_active_scan_count + " scan(s) remain unconfirmed; an earlier cancellation request may still be pending.";
      scannerScopeFeedback.set(agentId, message);
      await refresh();
    } catch (error) {
      scannerScopeFeedback.set(agentId, error.message);
      if (feedback) feedback.textContent = error.message;
    } finally {
      button.disabled = false;
    }
  }

  document.addEventListener("click", function (event) {
    var scopeButton = event.target.closest("[data-save-scanner-scope]");
    if (scopeButton) {
      saveScannerScope(scopeButton);
      return;
    }
    var button = event.target.closest("[data-command]");
    if (button) {
      runCommand(button);
      return;
    }
    if (event.target.closest("[data-open-enrollment]")) {
      var addButton = document.getElementById("add-scanner");
      if (addButton) addButton.click();
    }
  });

  var addScanner = document.getElementById("add-scanner");
  if (addScanner) {
    addScanner.addEventListener("click", function () {
      var card = document.getElementById("enrollment-card");
      card.classList.remove("hidden");
      document.getElementById("enrollment-scanner-name").focus();
    });
  }
  function scannerInstaller(platform) {
    if (platform === "macos") return "install-service-macos.sh";
    if (platform === "linux") return "install-service-linux.sh";
    if (platform === "foreground") return "install.sh";
    throw new Error("Choose the scanner operating system.");
  }

  var enrollmentPlatform = document.getElementById("enrollment-platform");
  if (enrollmentPlatform) {
    enrollmentPlatform.value = /Linux/i.test(navigator.platform || navigator.userAgent) ? "linux" : "macos";
    enrollmentPlatform.addEventListener("change", function () {
      var command = document.getElementById("enrollment-command");
      var installer = scannerInstaller(enrollmentPlatform.value);
      if (command.dataset.scannerName) text(command, "cd \"$HOME/Downloads/daedalus-scanner-kit\" && sh " + installer + " " + shellQuote(location.origin) + " " + shellQuote(command.dataset.scannerName));
    });
  }

  var issueScannerEnrollment = document.getElementById("issue-scanner-enrollment");
  if (issueScannerEnrollment) {
    issueScannerEnrollment.addEventListener("click", async function () {
      var nameInput = document.getElementById("enrollment-scanner-name");
      var networksInput = document.getElementById("enrollment-network-scopes");
      var scannerName = nameInput.value.trim();
      var authorizedNetworks = networksInput.value.split(/[\n,;]+/).map(function (value) { return value.trim(); }).filter(Boolean);
      var codeOutput = document.getElementById("enrollment-code");
      var commandOutput = document.getElementById("enrollment-command");
      if (!scannerName || authorizedNetworks.length === 0) {
        text(codeOutput, "Enter a scanner name and at least one authorized CIDR first.");
        return;
      }
      issueScannerEnrollment.disabled = true;
      delete codeOutput.dataset.code;
      delete commandOutput.dataset.scannerName;
      document.getElementById("copy-code").disabled = true;
      document.getElementById("copy-enrollment").disabled = true;
      text(commandOutput, "Create an enrollment code to prepare the command.");
      text(codeOutput, "Preparing one-time code…");
      try {
        var response = await fetch("/api/enrollment-tokens", {
          method: "POST",
          credentials: "same-origin",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name: scannerName, authorized_networks: authorizedNetworks })
        });
        var body = await response.json();
        if (!response.ok) throw new Error(body.detail || "Unable to issue an enrollment code");
        var selectedPlatform = document.getElementById("enrollment-platform").value;
        var installerName = scannerInstaller(selectedPlatform);
        var command = "cd \"$HOME/Downloads/daedalus-scanner-kit\" && sh " + installerName + " " +
          shellQuote(location.origin) + " " + shellQuote(scannerName);
        if (typeof body.code !== "string" || !body.code.trim()) throw new Error("No enrollment code was returned. Try again.");
        codeOutput.dataset.code = body.code;
        text(codeOutput, body.code + "  (expires in 15 minutes)");
        document.getElementById("copy-code").disabled = false;
        document.getElementById("copy-enrollment").disabled = false;
        commandOutput.dataset.scannerName = scannerName;
        text(commandOutput, command);
      } catch (error) {
        text(codeOutput, error.message);
      } finally {
        issueScannerEnrollment.disabled = false;
      }
    });
  }

  var closeEnrollment = document.getElementById("close-enrollment");
  if (closeEnrollment) {
    closeEnrollment.addEventListener("click", function () {
      document.getElementById("enrollment-card").classList.add("hidden");
    });
  }
  var copyEnrollment = document.getElementById("copy-enrollment");
  if (copyEnrollment) {
    copyEnrollment.addEventListener("click", async function () {
      var command = document.getElementById("enrollment-command");
      if (!command.dataset.scannerName) return;
      var value = command.textContent;
      try {
        await navigator.clipboard.writeText(value);
        text(copyEnrollment, "Copied");
        window.setTimeout(function () { text(copyEnrollment, "Copy"); }, 1400);
      } catch (_error) {
        text(copyEnrollment, "Select command");
      }
    });
  }
  var copyCode = document.getElementById("copy-code");
  if (copyCode) {
    copyCode.addEventListener("click", async function () {
      var value = document.getElementById("enrollment-code").dataset.code;
      if (!value) return;
      try {
        await navigator.clipboard.writeText(value);
        text(copyCode, "Copied");
        window.setTimeout(function () { text(copyCode, "Copy code"); }, 1400);
      } catch (_error) {
        text(copyCode, "Select code");
      }
    });
  }

  function liveReconnectDelay(attempt) {
    return Math.min(1000 * Math.pow(2, Math.max(0, attempt)), 30000);
  }

  if (orgId) {
    var scheme = location.protocol === "https:" ? "wss://" : "ws://";
    var liveUrl = scheme + location.host + "/ws/live?organization_id=" + encodeURIComponent(orgId);
    var socket = null;
    var reconnectTimer = null;
    var heartbeatTimer = null;
    var reconnectAttempt = 0;
    var liveLabel = document.getElementById("live-label");
    var connectionPill = document.querySelector(".connection-pill");
    function connectLiveSocket() {
      if (socket && (socket.readyState === WebSocket.CONNECTING || socket.readyState === WebSocket.OPEN)) return;
      var currentSocket = new WebSocket(liveUrl);
      socket = currentSocket;
      currentSocket.addEventListener("open", function () {
        if (socket !== currentSocket) return;
        reconnectAttempt = 0;
        text(liveLabel, "Live updates connected");
        connectionPill.classList.add("connected");
      });
      currentSocket.addEventListener("message", function (event) {
        var message = {};
        try { message = JSON.parse(event.data); } catch (_error) { /* ignore malformed live payload */ }
        handleMembershipLiveMessage(message);
        if (message.type === "external_check_finished") {
          loadExternalCheck(message.check_type);
          loadNotifications();
          if (role === "admin") loadAuditLog();
          notifyExternalCheck(message);
        }
        if (message.type === "external_check_schedule_updated") {
          var schedule = message.schedule || {};
          if (activeTab === schedule.check_type) loadExternalCheck(schedule.check_type);
          if (role === "admin") loadAuditLog();
        }
        if (message.type === "meraki_report_finished") {
          loadReports();
          loadNotifications();
          if (role === "admin") loadAuditLog();
          var merakiToast = document.getElementById("check-toast");
          if (merakiToast) {
            var merakiNotice = message.baseline ? "Meraki report saved as the comparison baseline." : "Meraki report finished: " + (message.changed_control_count || 0) + " control change(s), " + (message.coverage_change_count || 0) + " coverage change(s), " + (message.inventory_change_count || 0) + " inventory change(s).";
            text(merakiToast, merakiNotice);
            merakiToast.classList.remove("hidden");
            window.clearTimeout(merakiToast.hideTimer);
            merakiToast.hideTimer = window.setTimeout(function () { merakiToast.classList.add("hidden"); }, 9000);
          }
        }
        if (message.type === "cis_report_received") {
          if (activeTab === "cis") loadCIS();
          loadNotifications();
          if (role === "admin") loadAuditLog();
          notifyCISReport(message);
        }
        if (message.type === "workspace_notification_created") {
          loadNotifications();
          if (message.report_id != null) loadReports();
          if (role === "admin") loadAuditLog();
        }
        if (message.type === "scanner_comparison_detected" && message.meaningful_change_count > 0 && !notifiedScannerComparisons.has(message.comparison_id)) {
          notifiedScannerComparisons.add(message.comparison_id);
          loadNotifications();
          var scannerToast = document.getElementById("check-toast");
          if (scannerToast) {
            text(scannerToast, "Scanner " + message.agent_id + ": " + message.meaningful_change_count + " observed changes. Review Saved scan comparisons for the recorded evidence.");
            scannerToast.classList.remove("hidden");
            window.clearTimeout(scannerToast.hideTimer);
            scannerToast.hideTimer = window.setTimeout(function () { scannerToast.classList.add("hidden"); }, 9000);
          }
        }
        if (message.type === "scan_event" && message.event_name === "app_update_available") {
          notifyScannerUpdate(message.payload || {});
        }
        refresh();
      });
      currentSocket.addEventListener("close", function () {
        if (socket !== currentSocket) return;
        socket = null;
        if (heartbeatTimer !== null) window.clearInterval(heartbeatTimer);
        heartbeatTimer = null;
        text(liveLabel, "Reconnecting to live updates");
        connectionPill.classList.remove("connected");
        if (reconnectTimer !== null) window.clearTimeout(reconnectTimer);
        var delay = liveReconnectDelay(reconnectAttempt);
        reconnectAttempt += 1;
        reconnectTimer = window.setTimeout(function () {
          reconnectTimer = null;
          connectLiveSocket();
        }, delay);
      });
      heartbeatTimer = window.setInterval(function () {
        if (socket === currentSocket && currentSocket.readyState === WebSocket.OPEN) currentSocket.send("ping");
      }, 20000);
    }
    connectLiveSocket();
    document.addEventListener("visibilitychange", function () {
      if (document.hidden || (socket && socket.readyState !== WebSocket.CLOSED)) return;
      if (reconnectTimer !== null) window.clearTimeout(reconnectTimer);
      reconnectTimer = null;
      connectLiveSocket();
    });
  }

  function showError(target, message) {
    text(target, message || "Something went wrong. Please try again.");
  }

  async function postJson(url, payload) {
    return requestJson(url, "POST", payload);
  }

  async function requestJson(url, method, payload) {
    var options = { method: method, credentials: "same-origin" };
    if (payload !== undefined) {
      options.headers = { "Content-Type": "application/json" };
      options.body = JSON.stringify(payload);
    }
    var response = await fetch(url, options);
    var body = await response.json();
    if (!response.ok) throw new Error(body.detail || "Request could not be completed");
    return body;
  }

  var reportPollTimer = null;
  var merakiDashboardDetailCache = new Map();
  var openMerakiDashboardDetails = new Set();

  function matchingReportJobs(reports, reportType) {
    if (!reportType) return reports;
    var reportTypes = Array.isArray(reportType) ? reportType : [reportType];
    return reports.filter(function (job) { return reportTypes.includes(job.report_type); });
  }

  function addMerakiDetailList(container, title, values, formatRow) {
    var section = document.createElement("section");
    section.className = "meraki-detail-section";
    var heading = document.createElement("h4");
    heading.textContent = title;
    section.append(heading);
    if (!values || !values.length) {
      var empty = document.createElement("p");
      empty.className = "muted";
      empty.textContent = "No " + title.toLowerCase() + " recorded.";
      section.append(empty);
    } else {
      var list = document.createElement("ul");
      values.forEach(function (value) {
        var item = document.createElement("li");
        item.textContent = formatRow(value);
        list.append(item);
      });
      section.append(list);
    }
    container.append(section);
  }

  function renderMerakiDashboardDetails(container, details) {
    container.replaceChildren();
    var heading = document.createElement("p");
    heading.className = "meraki-detail-capture-time";
    heading.textContent = "Captured " + dateLabel(details.collected_at) + (details.organization && details.organization.name ? " · " + details.organization.name : "");
    container.append(heading);

    var summary = details.summary || {};
    var metrics = [
      ["Networks", summary.network_count], ["Assigned devices", summary.device_count],
      ["Security controls read", summary.security_controls_collected],
      ["Controls unavailable", summary.security_controls_unavailable],
      ["Controls unsupported", summary.security_controls_unsupported],
      ["Switches", summary.switch_device_count], ["Wireless devices", summary.wireless_device_count],
      ["RF profiles", summary.rf_profile_count]
    ];
    var metricGrid = document.createElement("dl");
    metricGrid.className = "meraki-detail-metrics";
    metrics.forEach(function (entry) {
      if (entry[1] === undefined || entry[1] === null) return;
      var cell = document.createElement("div");
      var label = document.createElement("dt"); label.textContent = entry[0];
      var value = document.createElement("dd"); value.textContent = String(entry[1]);
      cell.append(label, value); metricGrid.append(cell);
    });
    container.append(metricGrid);

    var clientUsage = details.client_usage || {};
    addMerakiDetailList(container, "Aggregate client usage", [clientUsage], function (usage) {
      var totals = usage.usage || {};
      var values = ["Collection: " + (usage.status || "unknown")];
      if (usage.clients_with_usage_count !== null && usage.clients_with_usage_count !== undefined) values.push(usage.clients_with_usage_count + " clients with usage");
      if (totals.total !== undefined) values.push("Total " + totals.total + " " + (usage.usage_unit || "units"));
      if (totals.downstream !== undefined || totals.upstream !== undefined) values.push("Downstream " + (totals.downstream ?? "—") + " · Upstream " + (totals.upstream ?? "—"));
      if (usage.requested_timespan_seconds) values.push("Prior " + Math.round(usage.requested_timespan_seconds / 3600) + " hours");
      return values.join(" · ");
    });

    var findings = details.findings || [];
    addMerakiDetailList(container, "Findings", findings, function (finding) {
      return [finding.status, finding.title, finding.detail].filter(Boolean).join(" · ");
    });
    addMerakiDetailList(container, "Collection warnings", details.warnings || [], function (warning) { return warning; });
    addMerakiDetailList(container, "Networks", details.networks || [], function (network) {
      return [network.name || "Unnamed network", (network.product_types || []).join(", "), network.time_zone].filter(Boolean).join(" · ");
    });
    addMerakiDetailList(container, "Assigned devices", details.devices || [], function (device) {
      return [device.name || "Unnamed device", device.model, device.status, device.product_type, device.firmware, device.network_id ? "Network " + device.network_id : ""].filter(Boolean).join(" · ");
    });
    addMerakiDetailList(container, "Managed topology", details.topology || [], function (topology) {
      return [topology.network_name || "Network", topology.status || "unknown", topology.node_count + " managed nodes", topology.link_count + " links", topology.omitted_node_count + " discovered nodes omitted", topology.omitted_link_count + " links omitted", topology.reported_error_count + " reported errors", topology.scope].filter(Boolean).join(" · ");
    });

    var controls = details.controls || [];
    var section = document.createElement("section");
    section.className = "meraki-detail-section";
    var controlsHeading = document.createElement("h4"); controlsHeading.textContent = "Configuration controls"; section.append(controlsHeading);
    if (!controls.length) {
      var emptyControls = document.createElement("p"); emptyControls.className = "muted"; emptyControls.textContent = "No control observations recorded."; section.append(emptyControls);
    }
    controls.forEach(function (control) {
      var item = document.createElement("details"); item.className = "meraki-control-evidence";
      var summaryLine = document.createElement("summary");
      summaryLine.textContent = [control.network_name || "Organization", control.control || "Control", control.status || "unknown"].join(" · ");
      var evidence = document.createElement("pre"); evidence.textContent = control.evidence_preview || "No evidence returned.";
      item.append(summaryLine, evidence);
      if (control.evidence_truncated) {
        var boundedNote = document.createElement("small"); boundedNote.textContent = "Preview truncated. Download the JSON evidence for the complete captured data."; item.append(boundedNote);
      }
      section.append(item);
    });
    container.append(section);

    var truncated = Object.keys(details.truncated || {}).filter(function (key) { return details.truncated[key] > 0; });
    if (truncated.length) {
      var bounded = document.createElement("p"); bounded.className = "meraki-detail-limit-note";
      bounded.textContent = "Some sections are bounded for display. Download complete JSON evidence for full inventory and control data.";
      container.append(bounded);
    }
  }

  function fetchMerakiDashboardDetails(reportId) {
    var cached = merakiDashboardDetailCache.get(reportId);
    if (!cached) {
      cached = fetch("/api/meraki/reports/" + encodeURIComponent(reportId) + "/details", {credentials: "same-origin"})
        .then(async function (response) {
          var body = await response.json();
          if (!response.ok) throw new Error(body.detail || "Could not load Meraki report details");
          return body;
        });
      merakiDashboardDetailCache.set(reportId, cached);
    }
    return cached;
  }

  async function loadMerakiSummaryObservations(reportId, container) {
    container.textContent = "Loading saved review observations…";
    try {
      var details = await fetchMerakiDashboardDetails(reportId);
      if (container.isConnected === false) return;
      container.replaceChildren();
      if (!Array.isArray(details.findings)) {
        appendEmpty(container, "Saved observation evidence is unavailable for this report.");
        return;
      }
      var review = details.findings.filter(function (item) { return item && item.status === "Review"; });
      if (!review.length) {
        appendEmpty(container, "No saved observations are labeled Review.");
        return;
      }
      var heading = document.createElement("h3"); heading.textContent = "Review observations";
      container.append(heading);
      review.slice(0, 5).forEach(function (item) {
        var row = document.createElement("article"); row.className = "audit-policy-card";
        var title = document.createElement("strong"); title.textContent = item.title || "Observation requires review";
        var detail = document.createElement("p"); detail.textContent = item.detail || "Open the saved report for supporting evidence.";
        row.append(title, detail); container.append(row);
      });
      if (review.length > 5) appendEmpty(container, "Additional review observations are available in the saved report.");
    } catch (error) {
      merakiDashboardDetailCache.delete(reportId);
      if (container.isConnected !== false) container.textContent = "Saved review observations could not be loaded. Open the report details or retry refresh.";
    }
  }

  async function loadMerakiDashboardDetails(reportId, container) {
    container.textContent = "Loading saved report details…";
    try {
      renderMerakiDashboardDetails(container, await fetchMerakiDashboardDetails(reportId));
    } catch (error) {
      merakiDashboardDetailCache.delete(reportId);
      container.textContent = error.message;
    }
  }

  function reportJobStatusSummary(reports) {
    var ready = reports.filter(function (job) { return job.status === "completed" && job.download_url; }).length;
    var running = reports.filter(function (job) { return job.status === "queued" || job.status === "running"; }).length;
    var failed = reports.filter(function (job) { return job.status === "failed"; }).length;
    var other = reports.length - ready - running - failed;
    var parts = [ready + " PDF(s) ready"];
    if (running) parts.push(running + " in progress");
    if (failed) parts.push(failed + " failed");
    if (other) parts.push(other + " without a ready download");
    return parts.join(" · ") + ".";
  }

  function renderReportJobs(reports, listId, statusId, reportType) {
    var list = document.getElementById(listId);
    var status = document.getElementById(statusId);
    if (!list) return;
    reports = matchingReportJobs(reports, reportType);
    if (reportType === "meraki_security") {
      var overview = document.getElementById("meraki-current-summary");
      if (overview) {
        overview.replaceChildren();
        var completed = reports.find(function (job) { return job.status === "completed"; });
        if (!completed) appendEmpty(overview, "No completed network assessment yet. Connect an organization below to establish a baseline.");
        else {
          var captured = document.createElement("p"); captured.className = "muted";
          captured.textContent = "Latest completed report · " + dateLabel(completed.completed_at || completed.created_at);
          var totals = completed.meraki_summary || {};
          var grid = document.createElement("div"); grid.className = "audit-metric-grid";
          [["Review observations", "review_observation_count"], ["Controls unavailable", "security_controls_unavailable"], ["Networks", "network_count"], ["Devices", "device_count"]].forEach(function (metric) {
            grid.append(makeAuditMetric(metric[0], totals[metric[1]] == null ? "Not captured" : String(totals[metric[1]]), (metric[1] === "security_controls_unavailable" && totals.security_controls_collected != null ? String(totals.security_controls_collected) + " controls read · latest saved report" : "Latest saved report"), (metric[1] === "review_observation_count" || metric[1] === "security_controls_unavailable") && (totals[metric[1]] == null || totals[metric[1]] > 0) ? "attention" : "neutral"));
          });
          overview.append(captured, grid);
          var observations = document.createElement("div"); observations.className = "check-summary";
          overview.append(observations);
          loadMerakiSummaryObservations(completed.id, observations);
        }
      }
    }
    list.replaceChildren();
    if (!reports.length) {
      var reportTypes = Array.isArray(reportType) ? reportType : [reportType];
      var emptyMessage = Array.isArray(reportType) ? "No reports in these topics have been generated for this workspace yet." : reportType === "meraki_security"
        ? "No Meraki reports have been generated for this workspace yet."
        : (reportType === "cis_endpoint"
          ? "No CIS endpoint PDFs have been generated for this workspace yet."
          : (reportType === "scanner_results"
            ? "No NmapUI scan PDFs have been generated for this workspace yet."
            : (reportTypes.includes("scanner_results")
              ? "No external posture or NmapUI scan reports have been generated for this workspace yet."
              : "No external posture reports have been generated for this workspace yet.")));
      appendEmpty(list, emptyMessage);
      if (status) text(status, "Reports are scoped to this workspace.");
      return;
    }

    if (status) text(status, reportJobStatusSummary(reports));

    reports.forEach(function (job) {
      var card = document.createElement("article");
      card.className = "report-job-card";
      var main = document.createElement("div");
      main.className = "report-job-main";
      var heading = document.createElement("strong");
      var reportLabel = job.report_type === "meraki_security" ? "Meraki security report"
        : (job.report_type === "cis_endpoint" ? "CIS endpoint report" : (job.report_type === "scanner_results" ? "Internal scanner report" : "External posture report"));
      heading.textContent = reportLabel + " · " + job.domain;
      var metadata = document.createElement("small");
      var details = "Requested by " + (job.actor || "workspace member") + " · " + dateLabel(job.created_at);
      if (job.size_bytes) details += " · " + formatBytes(job.size_bytes);
      metadata.textContent = details;
      var stage = document.createElement("span");
      stage.className = "report-job-stage" + (job.status === "failed" ? " report-job-failed" : "");
      stage.textContent = job.status === "failed" ? (job.error_summary || job.stage) : job.stage;
      main.append(heading, metadata, stage);
      if (job.meraki_comparison) {
        var comparison = document.createElement("small");
        comparison.textContent = job.meraki_comparison.baseline ? "Comparison baseline for this Cisco organization." : "Compared with report " + job.meraki_comparison.previous_report_id + ": " + (job.meraki_comparison.changed_control_count || 0) + " control change(s), " + (job.meraki_comparison.coverage_change_count || 0) + " coverage change(s), " + (job.meraki_comparison.inventory_change_count || 0) + " inventory change(s), " + (job.meraki_comparison.inventory_coverage_change_count || 0) + " inventory coverage change(s).";
        main.append(comparison);
      }

      if (job.status === "queued" || job.status === "running") {
        var track = document.createElement("div");
        track.className = "report-progress-track";
        track.setAttribute("role", "progressbar");
        track.setAttribute("aria-label", "PDF report generation progress");
        track.setAttribute("aria-valuemin", "0");
        track.setAttribute("aria-valuemax", "100");
        track.setAttribute("aria-valuenow", String(job.progress || 0));
        var bar = document.createElement("div");
        bar.className = "report-progress-bar";
        bar.style.width = Math.max(0, Math.min(100, Number(job.progress) || 0)) + "%";
        track.append(bar);
        main.append(track);
      }

      var actions = document.createElement("div");
      actions.className = "report-job-actions";
      var badge = document.createElement("span");
      badge.className = "check-status" + (job.status === "failed" ? " status-failed" : "");
      badge.textContent = job.status.replaceAll("_", " ");
      actions.append(badge);
      if (job.status === "completed" && job.download_url) {
        var download = document.createElement("a");
        download.className = "button button-small";
        download.href = job.download_url;
        download.download = job.file_name || "daedalus-report.pdf";
        download.textContent = "Download PDF";
        actions.append(download);
      }
      if (job.meraki_changes_url) {
        var changes = document.createElement("a");
        changes.className = "button button-small button-quiet";
        changes.href = job.meraki_changes_url;
        changes.textContent = "Download change evidence";
        actions.append(changes);
      }
      if (job.meraki_snapshot_url) {
        var snapshot = document.createElement("a");
        snapshot.className = "button button-small button-quiet";
        snapshot.href = job.meraki_snapshot_url;
        snapshot.textContent = "Download complete JSON";
        actions.append(snapshot);
      }
      card.append(main, actions);
      if (job.meraki_snapshot_url) {
        var details = document.createElement("details");
        details.className = "meraki-report-details";
        details.open = openMerakiDashboardDetails.has(job.id);
        var summary = document.createElement("summary");
        summary.textContent = "View saved report details";
        var detailContent = document.createElement("div");
        detailContent.className = "meraki-report-detail-content";
        detailContent.textContent = "Open to inspect this saved snapshot.";
        details.append(summary, detailContent);
        details.addEventListener("toggle", function () {
          if (details.open) {
            openMerakiDashboardDetails.add(job.id);
            if (!detailContent.dataset.loaded) {
              detailContent.dataset.loaded = "true";
              loadMerakiDashboardDetails(job.id, detailContent);
            }
          } else {
            openMerakiDashboardDetails.delete(job.id);
          }
        });
        card.append(details);
        if (details.open) {
          detailContent.dataset.loaded = "true";
          loadMerakiDashboardDetails(job.id, detailContent);
        }
      }
      list.append(card);
    });
  }

  function formatBytes(value) {
    var size = Number(value) || 0;
    if (size < 1024) return size + " B";
    if (size < 1024 * 1024) return (size / 1024).toFixed(1) + " KB";
    return (size / (1024 * 1024)).toFixed(1) + " MB";
  }

  async function loadReports() {
    if (!orgId) return;
    window.clearTimeout(reportPollTimer);
    try {
      var response = await fetch("/api/reports", { credentials: "same-origin" });
      var body = await response.json();
      if (!response.ok) throw new Error(body.detail || "Could not load workspace reports");
      var reports = body.reports || [];
      renderReportJobs(reports, "report-job-list", "report-library-status", "external_posture");
      renderReportJobs(reports, "scanner-report-job-list", "scanner-report-library-status", "scanner_results");
      renderReportJobs(reports, "posture-report-job-list", "posture-report-library-status", ["meraki_security", "cis_endpoint"]);
      renderReportJobs(reports, "meraki-report-job-list", "meraki-report-library-status", "meraki_security");
      renderReportJobs(reports, "cis-pdf-job-list", "cis-pdf-library-status", "cis_endpoint");
      if ((activeTab === "reports" || activeTab === "meraki" || activeTab === "cis") && reports.some(function (job) {
        return job.status === "queued" || job.status === "running";
      })) {
        reportPollTimer = window.setTimeout(loadReports, 900);
      }
    } catch (error) {
      ["report-job-list", "scanner-report-job-list", "posture-report-job-list", "meraki-report-job-list", "cis-pdf-job-list"].forEach(function (id) {
        var list = document.getElementById(id);
        if (list) {
          list.replaceChildren();
          appendEmpty(list, error.message);
        }
      });
      text(document.getElementById("report-library-status"), "Could not load reports.");
      text(document.getElementById("scanner-report-library-status"), "Could not load reports.");
      text(document.getElementById("posture-report-library-status"), "Could not load reports.");
      text(document.getElementById("meraki-report-library-status"), "Could not load reports.");
      text(document.getElementById("cis-pdf-library-status"), "Could not load reports.");
    }
  }

  var merakiOrgOptions = [];

  function preferredMerakiOrganizationId(organizations, preferredId) {
    organizations = organizations || [];
    if (preferredId && organizations.some(function (item) { return item.id === preferredId; })) return preferredId;
    var authorized = organizations.find(function (item) { return item.authorized; });
    return authorized ? authorized.id : (organizations[0] ? organizations[0].id : "");
  }

  function renderMerakiOrganizations(organizations, preferredId) {
    var select = document.getElementById("meraki-org-select");
    if (!select) return;
    merakiOrgOptions = organizations || [];
    select.replaceChildren();
    if (!merakiOrgOptions.length) {
      var empty = document.createElement("option");
      empty.value = "";
      empty.textContent = "No organizations returned for this key";
      select.append(empty);
      select.disabled = true;
      updateMerakiScopeControls();
      return;
    }
    merakiOrgOptions.forEach(function (organization) {
      var option = document.createElement("option");
      option.value = organization.id;
      option.textContent = organization.name + " · " + organization.id + (organization.authorized ? " · authorized" : " · approval required");
      select.append(option);
    });
    select.value = preferredMerakiOrganizationId(merakiOrgOptions, preferredId);
    select.disabled = false;
    updateMerakiScopeControls();
  }

  function updateMerakiScopeControls() {
    var select = document.getElementById("meraki-org-select");
    if (!select) return;
    var selected = merakiOrgOptions.find(function (item) { return item.id === select.value; });
    var authorized = !!(selected && selected.authorized);
    var state = document.getElementById("meraki-org-scope-state");
    var authorize = document.getElementById("meraki-authorize-org");
    var revoke = document.getElementById("meraki-revoke-org");
    var generate = document.getElementById("meraki-generate-report");
    if (state) {
      text(state, !selected ? "Load organizations to manage workspace access." : authorized ? "Authorized for this workspace" + (selected.granted_at ? " · since " + dateLabel(selected.granted_at) : "") : "Not authorized for this workspace. Reports are disabled until approved.");
      state.classList.toggle("is-authorized", authorized);
    }
    if (authorize) authorize.disabled = role !== "admin" || !selected || authorized;
    if (revoke) revoke.disabled = role !== "admin" || !selected || !authorized;
    if (generate) generate.disabled = role !== "admin" || !selected || !authorized;
  }

  async function loadMerakiStatus() {
    var state = document.getElementById("meraki-connection-state");
    var remove = document.getElementById("meraki-remove-key");
    if (!state) return;
    try {
      var response = await fetch("/api/meraki/status", { credentials: "same-origin" });
      var body = await response.json();
      if (!response.ok) throw new Error(body.detail || "Could not read Meraki connection status");
      if (!body.configured) {
        text(state, "Not connected");
        state.className = "meraki-connection-state is-disconnected";
      } else {
        text(state, "Connected" + (body.key_hint ? " · key ending " + body.key_hint : "") + (body.last_verified_at ? " · verified " + dateLabel(body.last_verified_at) : ""));
        state.className = "meraki-connection-state is-connected";
      }
      if (remove) remove.disabled = !body.configured;
    } catch (error) {
      text(state, error.message);
      state.className = "meraki-connection-state is-disconnected";
    }
  }

  async function loadMerakiOrganizations(preferredId) {
    var feedback = document.getElementById("meraki-feedback");
    var loadButton = document.getElementById("meraki-load-organizations");
    if (!loadButton) return;
    loadButton.disabled = true;
    text(loadButton, "Loading…");
    try {
      var body = await postJson("/api/meraki/organizations");
      renderMerakiOrganizations(body.organizations || [], preferredId);
      var authorizedCount = (body.organizations || []).filter(function (item) { return item.authorized; }).length;
      text(feedback, "Loaded " + (body.organizations || []).length + " organization(s); " + authorizedCount + " authorized for this workspace.");
      await loadMerakiStatus();
    } catch (error) {
      text(feedback, error.message);
    } finally {
      text(loadButton, "Load organizations");
      loadButton.disabled = role !== "admin" || !document.getElementById("meraki-remove-key") || document.getElementById("meraki-remove-key").disabled;
    }
  }

  async function loadMeraki() {
    await Promise.all([loadMerakiStatus(), loadReports()]);
    var loadButton = document.getElementById("meraki-load-organizations");
    if (loadButton) {
      var removeButton = document.getElementById("meraki-remove-key");
      loadButton.disabled = role !== "admin" || !removeButton || removeButton.disabled;
    }
  }

  var merakiKeyForm = document.getElementById("meraki-key-form");
  if (merakiKeyForm) {
    merakiKeyForm.addEventListener("submit", async function (event) {
      event.preventDefault();
      var input = document.getElementById("meraki-api-key");
      var submit = merakiKeyForm.querySelector("[type='submit']");
      var feedback = document.getElementById("meraki-feedback");
      var apiKey = input ? input.value : "";
      submit.disabled = true;
      text(submit, "Verifying…");
      try {
        var body = await requestJson("/api/meraki/credential", "PUT", { api_key: apiKey });
        if (input) input.value = "";
        await loadMerakiOrganizations();
        text(feedback, "Key verified and encrypted. " + (body.organizations || []).length + " organization(s) are available; authorize each one for this workspace before reporting.");
        var loadButton = document.getElementById("meraki-load-organizations");
        if (loadButton) loadButton.disabled = false;
        await loadMerakiStatus();
      } catch (error) {
        text(feedback, error.message);
      } finally {
        text(submit, "Verify and save key");
        submit.disabled = false;
      }
    });
  }

  var merakiLoadButton = document.getElementById("meraki-load-organizations");
  if (merakiLoadButton) merakiLoadButton.addEventListener("click", loadMerakiOrganizations);

  var merakiOrgSelect = document.getElementById("meraki-org-select");
  if (merakiOrgSelect) merakiOrgSelect.addEventListener("change", updateMerakiScopeControls);

  var merakiAuthorizeButton = document.getElementById("meraki-authorize-org");
  if (merakiAuthorizeButton) {
    merakiAuthorizeButton.addEventListener("click", async function () {
      var select = document.getElementById("meraki-org-select");
      var feedback = document.getElementById("meraki-feedback");
      if (!select || !select.value) return;
      var selectedId = select.value;
      merakiAuthorizeButton.disabled = true;
      text(merakiAuthorizeButton, "Authorizing…");
      try {
        await postJson("/api/meraki/organization-scope", { meraki_organization_id: selectedId });
        await loadMerakiOrganizations(selectedId);
        text(feedback, "Meraki organization authorized for this workspace. The action was recorded in the audit log.");
      } catch (error) {
        text(feedback, error.message);
      } finally {
        text(merakiAuthorizeButton, "Authorize for workspace");
        updateMerakiScopeControls();
      }
    });
  }

  var merakiRevokeButton = document.getElementById("meraki-revoke-org");
  if (merakiRevokeButton) {
    merakiRevokeButton.addEventListener("click", async function () {
      var select = document.getElementById("meraki-org-select");
      var feedback = document.getElementById("meraki-feedback");
      if (!select || !select.value) return;
      var selectedId = select.value;
      merakiRevokeButton.disabled = true;
      text(merakiRevokeButton, "Revoking…");
      try {
        await requestJson("/api/meraki/organization-scope", "DELETE", { meraki_organization_id: selectedId });
        await loadMerakiOrganizations(selectedId);
        text(feedback, "Meraki organization access revoked for this workspace. The action was recorded in the audit log.");
      } catch (error) {
        text(feedback, error.message);
      } finally {
        text(merakiRevokeButton, "Revoke access");
        updateMerakiScopeControls();
      }
    });
  }

  var merakiRemoveButton = document.getElementById("meraki-remove-key");
  if (merakiRemoveButton) {
    merakiRemoveButton.addEventListener("click", async function () {
      merakiRemoveButton.disabled = true;
      text(merakiRemoveButton, "Removing…");
      try {
        await requestJson("/api/meraki/credential", "DELETE");
        renderMerakiOrganizations([]);
        text(document.getElementById("meraki-feedback"), "Saved Meraki key removed from this workspace.");
        await loadMerakiStatus();
        if (merakiLoadButton) merakiLoadButton.disabled = true;
      } catch (error) {
        text(document.getElementById("meraki-feedback"), error.message);
        merakiRemoveButton.disabled = false;
      } finally {
        text(merakiRemoveButton, "Remove saved key");
      }
    });
  }

  var merakiGenerateButton = document.getElementById("meraki-generate-report");
  if (merakiGenerateButton) {
    merakiGenerateButton.addEventListener("click", async function () {
      var select = document.getElementById("meraki-org-select");
      var feedback = document.getElementById("meraki-feedback");
      if (!select || !select.value) return;
      merakiGenerateButton.disabled = true;
      text(merakiGenerateButton, "Queueing report…");
      try {
        await postJson("/api/meraki/reports", { organization_id: select.value });
        text(feedback, "Meraki report queued. Collection progress and the finished PDF will appear below.");
        await loadReports();
      } catch (error) {
        text(feedback, error.message);
      } finally {
        text(merakiGenerateButton, "Generate security report");
        merakiGenerateButton.disabled = !select.value;
      }
    });
  }

  function makeCISResultRow(result) {
    var row = document.createElement("article");
    row.className = "cis-check-result";
    var main = document.createElement("div");
    var title = document.createElement("strong");
    title.textContent = result.id + " · " + result.description;
    var category = document.createElement("small");
    category.textContent = result.category + (Array.isArray(result.benchmark_ids) && result.benchmark_ids.length
      ? " · CIS " + result.benchmark_ids.join(", ")
      : "");
    main.append(title, category);
    var status = document.createElement("span");
    status.className = "cis-result-status is-" + result.status;
    status.textContent = result.status;
    row.append(main, status);
    if (result.details) {
      var detail = document.createElement("p");
      detail.textContent = result.details;
      row.append(detail);
    }
    return row;
  }

  function renderCISResultGroups(host, results) {
    var groups = [
      {title: "Checks requiring attention", accepts: function (status) { return status === "fail"; }},
      {title: "Unassessed checks", accepts: function (status) { return status !== "pass" && status !== "fail"; }},
      {title: "Passing checks", accepts: function (status) { return status === "pass"; }}
    ];
    groups.forEach(function (group) {
      var selected = results.filter(function (result) { return group.accepts(result.status); });
      if (!selected.length) return;
      var section = document.createElement("section");
      section.className = "cis-evidence-group";
      var heading = document.createElement("h4");
      heading.textContent = group.title + " · " + selected.length;
      section.append(heading);
      var categories = new Map();
      selected.forEach(function (result) {
        var category = result.category || "Other checks";
        if (!categories.has(category)) categories.set(category, []);
        categories.get(category).push(result);
      });
      categories.forEach(function (checks, category) {
        var evidence = document.createElement("details");
        evidence.className = "topic-secondary";
        var summary = document.createElement("summary");
        var labels = {macos: "macOS", chrome: "Chrome", safari: "Safari"};
        summary.textContent = (labels[category] || category) + " · " + checks.length + " checks";
        evidence.append(summary);
        checks.forEach(function (result) { evidence.append(makeCISResultRow(result)); });
        section.append(evidence);
      });
      host.append(section);
    });
    if (!results.length) appendEmpty(host, "No individual check evidence was returned.");
  }

  function renderCISProfiles(profiles) {
    var list = document.getElementById("cis-profile-list");
    var clientProfilePicker = document.getElementById("cis-client-profile");
    if (list) list.dataset.profileCount = String(profiles.length);
    if (clientProfilePicker) {
      var priorSelection = clientProfilePicker.value;
      var compatibleProfiles = new Map();
      profiles.forEach(function (profile) {
        var platform = String(profile.platform || "").toLowerCase();
        if ((platform === "macos" || platform === "multi") && !compatibleProfiles.has(profile.slug)) {
          compatibleProfiles.set(profile.slug, profile);
        }
      });
      clientProfilePicker.replaceChildren();
      if (!compatibleProfiles.size) {
        var emptyOption = document.createElement("option");
        emptyOption.value = "";
        emptyOption.textContent = "No compatible profile published";
        clientProfilePicker.append(emptyOption);
      }
      compatibleProfiles.forEach(function (profile) {
        var option = document.createElement("option");
        option.value = profile.slug;
        var benchmark = profile.benchmark || {};
        option.textContent = profile.name + " · v" + profile.version + (benchmark.level ? " · Level " + benchmark.level : "");
        clientProfilePicker.append(option);
      });
      var defaultSlug = compatibleProfiles.has("cis-macos-26-tahoe-level-1")
        ? "cis-macos-26-tahoe-level-1"
        : (compatibleProfiles.size ? compatibleProfiles.keys().next().value : "");
      clientProfilePicker.value = compatibleProfiles.has(priorSelection) ? priorSelection : defaultSlug;
      clientProfilePicker.disabled = compatibleProfiles.size === 0;
    }
    if (!list) return;
    list.replaceChildren();
    if (!profiles.length) {
      appendEmpty(list, "No profile is published yet. Install the CSP starter profile or publish a new version.");
      return;
    }
    profiles.forEach(function (profile) {
      var card = document.createElement("article");
      card.className = "cis-profile-card";
      var main = document.createElement("div");
      var title = document.createElement("h4");
      title.textContent = profile.name + " · v" + profile.version;
      var description = document.createElement("p");
      description.textContent = profile.description || "Published workspace audit profile.";
      var metadata = document.createElement("small");
      var benchmark = profile.benchmark || {};
      var benchmarkLabel = benchmark.name
        ? benchmark.name + (benchmark.level ? " · Level " + benchmark.level : "")
        : profile.platform;
      metadata.textContent = benchmarkLabel + " · " + profile.check_count + " checks · SHA-256 " + String(profile.checksum || "").slice(0, 12) + " · published " + dateLabel(profile.published_at);
      main.append(title, description, metadata);
      var actions = document.createElement("div");
      actions.className = "cis-profile-actions";
      var download = document.createElement("a");
      download.className = "button button-small";
      download.href = profile.download_url;
      download.download = profile.slug + "-" + profile.version + ".json";
      download.textContent = "Download JSON";
      actions.append(download);
      if (profile.yaml_download_url) {
        var checklist = document.createElement("a");
        checklist.className = "button button-small button-quiet";
        checklist.href = profile.yaml_download_url;
        checklist.download = "checklist-" + profile.slug + "-" + profile.version + ".yaml";
        checklist.textContent = "Download client checklist";
        actions.append(checklist);
      }
      card.append(main, actions);
      list.append(card);
    });
  }

  function renderCISCoverage(status) {
    var host = document.getElementById("cis-assessment-coverage");
    if (!host) return;
    host.replaceChildren();
    var counts = status.assessment_counts || {};
    var keys = ["current", "stale", "unknown", "missing"];
    var complete = keys.every(function (key) { return Number.isInteger(counts[key]) && counts[key] >= 0; }) && keys.reduce(function (total, key) { return total + counts[key]; }, 0) === status.device_count;
    var labels = ["Recent assessments", "Overdue assessments", "Times needing review", "Without assessment"];
    keys.forEach(function (key, index) {
      host.append(makeAuditMetric(labels[index], complete ? String(counts[key]) : "Unknown", "Latest collected evidence per enrolled endpoint", key !== "current" && (!complete || counts[key] > 0) ? "attention" : "neutral"));
    });
  }

  function cisDeviceAssessmentLabel(device) {
    var summary = device.latest_assessment_summary;
    if (!summary) return "Assessment results unavailable";
    var counts = ["total", "pass", "fail", "manual", "error"];
    if (!counts.every(function (key) { return Number.isInteger(summary[key]) && summary[key] >= 0; })
        || summary.total !== summary.pass + summary.fail + summary.manual + summary.error
        || summary.total === 0 || typeof summary.score !== "number" || !Number.isFinite(summary.score)
        || summary.score < 0 || summary.score > 100) return "Assessment results need review";
    return "Latest assessment: " + summary.score.toFixed(1) + "% pass rate · "
      + (summary.pass + summary.fail) + " of " + summary.total + " checks assessed · "
      + summary.fail + " failed · " + summary.manual + " manual · " + summary.error + " errors";
  }

  function renderCISDevices(devices) {
    var list = document.getElementById("cis-device-list");
    if (!list) return;
    list.replaceChildren();
    if (!devices.length) {
      appendEmpty(list, "No endpoint has checked in yet. Download a client config and run the CSP menu-bar client.");
      return;
    }
    devices.forEach(function (device) {
      var card = document.createElement("article");
      card.className = "cis-device-card";
      var main = document.createElement("div");
      var name = document.createElement("strong");
      name.textContent = device.name || "CIS endpoint";
      var details = document.createElement("small");
      details.textContent = (device.platform || "unknown") + (device.os_version ? " · " + device.os_version : "") + " · last report received " + dateLabel(device.last_seen_at);
      main.append(name, details);
      var state = document.createElement("span");
      var clientState = device.client_state || "unknown";
      state.className = "cis-device-state is-" + clientState;
      state.textContent = clientState === "online" ? "Client checking in" : clientState === "offline" ? "Client check-in overdue" : "Client presence unknown";
      var heartbeat = document.createElement("small");
      heartbeat.textContent = device.last_client_heartbeat_at ? "Client check-in " + dateLabel(device.last_client_heartbeat_at) : "This device has not sent a separate client check-in.";
      main.append(heartbeat);
      var assessment = document.createElement("small");
      var assessmentLabels = {current: "Recent assessment", stale: "Assessment overdue", missing: "No saved assessment", unknown: "Assessment time needs review"};
      assessment.textContent = (assessmentLabels[device.assessment_state] || "Assessment recency unknown") + (device.last_collected_at ? " · collected " + dateLabel(device.last_collected_at) : "");
      main.append(assessment);
      var results = document.createElement("small");
      results.textContent = cisDeviceAssessmentLabel(device);
      main.append(results);
      card.append(main, state);
      list.append(card);
    });
  }

  function cisAssessmentScope(latest) {
    if (!latest) return "Waiting for the first saved endpoint assessment.";
    var profile = latest.profile_slug ? latest.profile_slug + (latest.profile_version ? " v" + latest.profile_version : "") : "Profile not identified";
    return "Latest saved assessment: " + (latest.device_name || "Unnamed endpoint") + " · " + profile + " · collected " + dateLabel(latest.collected_at) + ". Check counts and pass rate below describe this report.";
  }

  function cisPriorityMetrics(latest, enrolledDeviceCount) {
    var summary = latest && latest.summary ? latest.summary : {};
    function count(key) {
      var value = summary[key];
      return Number.isInteger(value) && value >= 0 ? String(value) : "Unknown";
    }
    return [
      [latest ? count("fail") : "—", "Failed checks"],
      [latest ? count("manual") : "—", "Need manual review"],
      [latest ? count("error") : "—", "Collection errors"],
      [latest && typeof summary.score === "number" && Number.isFinite(summary.score) ? summary.score.toFixed(1) + "%" : "—", "Latest report pass rate"],
      [String(enrolledDeviceCount), "Enrolled devices"]
    ];
  }

  function groupEarlierCISHistory(list, label, wasOpen) {
    var earlier = Array.from(list.children).slice(10);
    if (!earlier.length) return;
    var group = document.createElement("details");
    group.className = "cis-history-group";
    group.open = Boolean(wasOpen);
    var summary = document.createElement("summary");
    summary.textContent = earlier.length + " earlier " + label;
    var entries = document.createElement("div");
    entries.className = "cis-history-entries";
    earlier.forEach(function (entry) { entries.append(entry); });
    group.append(summary, entries);
    list.append(group);
  }

  function renderCISReports(reports, enrolledDeviceCount) {
    var list = document.getElementById("cis-report-list");
    var metrics = document.getElementById("cis-summary-metrics");
    text(document.getElementById("cis-assessment-scope"), cisAssessmentScope(reports[0]));
    if (metrics) {
      var latest = reports[0];
      metrics.replaceChildren();
      cisPriorityMetrics(latest, enrolledDeviceCount).forEach(function (metric, index) {
        var card = document.createElement("div");
        card.className = "cis-mini-metric";
        var value = document.createElement("strong");
        value.textContent = metric[0];
        var label = document.createElement("span");
        label.textContent = metric[1];
        if (latest) card.title = "Latest report collected " + dateLabel(latest.collected_at);
        card.append(value, label);
        metrics.append(card);
      });
    }
    if (!list) return;
    var earlierOpen = Boolean(list.querySelector(".cis-history-group[open]"));
    list.replaceChildren();
    if (!reports.length) {
      appendEmpty(list, "Waiting for the first endpoint report. Download a client configuration and run the CSP CIS client.");
      return;
    }
    reports.forEach(function (report) {
      var card = document.createElement("details");
      card.className = "cis-report-card";
      card.dataset.reportId = report.id;
      var summary = document.createElement("summary");
      var top = document.createElement("div");
      top.className = "cis-report-topline";
      var device = document.createElement("strong");
      device.textContent = report.device_name;
      var score = document.createElement("span");
      var assessmentComplete = report.summary.manual === 0 && report.summary.error === 0;
      score.className = "cis-score-badge" + (assessmentComplete && Number(report.summary.score) === 100 ? " is-good" : " is-review");
      score.textContent = Number(report.summary.score).toFixed(1) + "% pass rate";
      top.append(device, score);
      var metadata = document.createElement("small");
      metadata.textContent = report.platform + (report.os_version ? " · " + report.os_version : "") + (report.profile_slug ? " · " + report.profile_slug + " v" + report.profile_version : " · profile not identified") + " · collected " + dateLabel(report.collected_at);
      var counts = document.createElement("span");
      counts.className = "cis-report-counts";
      counts.textContent = report.summary.total + " checks · " + report.summary.pass + " pass · " + report.summary.fail + " fail · " + report.summary.manual + " manual · " + report.summary.error + " error";
      var coverage = document.createElement("span");
      coverage.className = "cis-report-coverage";
      var assessedCount = Number(report.summary.pass) + Number(report.summary.fail);
      coverage.textContent = assessedCount + " of " + report.summary.total + " checks assessed. " + (assessmentComplete ? "All checks have a pass or fail result." : "Manual and error results remain unassessed and are included in the pass-rate denominator.");
      var progress = document.createElement("div");
      progress.className = "cis-score-track";
      var fill = document.createElement("div");
      fill.className = "cis-score-fill";
      fill.style.width = Math.max(0, Math.min(100, Number(report.summary.score) || 0)) + "%";
      progress.append(fill);
      summary.append(top, metadata, counts, coverage, progress);
      var resultList = document.createElement("div");
      resultList.className = "cis-result-list";
      resultList.dataset.loaded = "false";
      resultList.append(document.createTextNode("Open this report to load individual check results."));
      card.append(summary, resultList);
      card.addEventListener("toggle", async function () {
        if (!card.open || resultList.dataset.loaded === "true") return;
        resultList.dataset.loaded = "loading";
        resultList.replaceChildren();
        appendEmpty(resultList, "Loading check results…");
        try {
          var response = await fetch("/api/cis/reports/" + encodeURIComponent(report.id), { credentials: "same-origin" });
          var body = await response.json();
          if (!response.ok) throw new Error(body.detail || "Could not load CIS results");
          resultList.replaceChildren();
          var pdfToolbar = document.createElement("div");
          pdfToolbar.className = "cis-pdf-toolbar";
          var pdfButton = document.createElement("button");
          pdfButton.type = "button";
          pdfButton.className = "button button-small button-secondary";
          pdfButton.dataset.cisPdfReport = String(report.id);
          pdfButton.textContent = "Generate PDF report";
          var pdfFeedback = document.createElement("span");
          pdfFeedback.className = "cis-pdf-feedback";
          pdfToolbar.append(pdfButton, pdfFeedback);
          resultList.append(pdfToolbar);
          renderCISResultGroups(resultList, body.results || []);
          resultList.dataset.loaded = "true";
        } catch (error) {
          resultList.replaceChildren();
          appendEmpty(resultList, error.message);
          resultList.dataset.loaded = "false";
        }
      });
      list.append(card);
    });
    groupEarlierCISHistory(list, "reports", earlierOpen);
  }

  function renderCISChanges(changes) {
    var list = document.getElementById("cis-change-list");
    if (!list) return;
    var earlierOpen = Boolean(list.querySelector(".cis-history-group[open]"));
    list.replaceChildren();
    if (!changes.length) {
      appendEmpty(list, "No check status changes have been detected yet.");
      return;
    }
    changes.forEach(function (change) {
      var row = document.createElement("article");
      row.className = "cis-change-row";
      var main = document.createElement("div");
      var title = document.createElement("strong");
      title.textContent = change.device_name + " · " + change.check_id;
      var detail = document.createElement("small");
      detail.textContent = "Report " + change.report_id + " · " + dateLabel(change.detected_at);
      main.append(title, detail);
      var state = document.createElement("span");
      state.className = "cis-change-transition";
      state.textContent = change.previous_status + " → " + change.current_status;
      row.append(main, state);
      list.append(row);
    });
    groupEarlierCISHistory(list, "changes", earlierOpen);
  }

  async function loadCIS() {
    if (!orgId) return;
    try {
      var responses = await Promise.all([
        fetch("/api/cis/status", { credentials: "same-origin" }),
        fetch("/api/cis/profiles", { credentials: "same-origin" }),
        fetch("/api/cis/reports", { credentials: "same-origin" }),
        fetch("/api/cis/changes", { credentials: "same-origin" })
      ]);
      var bodies = await Promise.all(responses.map(function (response) { return response.json(); }));
      var failed = responses.findIndex(function (response) { return !response.ok; });
      if (failed >= 0) throw new Error(bodies[failed].detail || "Could not load CIS workspace data");
      var status = bodies[0];
      renderCISProfiles(bodies[1].profiles || []);
      renderCISCoverage(status);
      renderCISDevices(status.devices || []);
      renderCISReports(bodies[2].reports || [], status.device_count || 0);
      renderCISChanges(bodies[3].changes || []);
      var keyStatus = document.getElementById("cis-key-status");
      if (status.key_configured) {
        text(keyStatus, "Upload key ready" + (status.key_hint ? " · ending " + status.key_hint : "") + ". Client configuration is scoped to this workspace.");
        if (keyStatus) keyStatus.className = "cis-feedback is-ready";
      } else {
        text(keyStatus, "No client upload key has been issued.");
        if (keyStatus) keyStatus.className = "cis-feedback";
      }
      var revoke = document.getElementById("cis-revoke-key");
      if (revoke) revoke.disabled = !status.key_configured;
      var issue = document.getElementById("cis-issue-key");
      if (issue) {
        issue.dataset.keyConfigured = status.key_configured ? "true" : "false";
        text(issue, status.key_configured ? "Rotate key and download new config" : "Issue client key and download config");
      }
      var starter = document.getElementById("cis-install-starter");
      if (starter) starter.disabled = (bodies[1].profiles || []).some(function (profile) {
        return profile.slug === "csp-macos-browser-baseline" && profile.version === "1.0.0";
      });
      var tahoe = document.getElementById("cis-install-macos26");
      if (tahoe) {
        var publishedSlugs = new Set((bodies[1].profiles || []).map(function (profile) { return profile.slug; }));
        tahoe.disabled = publishedSlugs.has("cis-macos-26-tahoe-level-1") && publishedSlugs.has("cis-macos-26-tahoe-level-2");
      }
    } catch (error) {
      text(document.getElementById("cis-assessment-scope"), "Could not refresh the latest endpoint assessment. Previously displayed headline counts may be out of date.");
      ["cis-assessment-coverage", "cis-profile-list", "cis-device-list", "cis-report-list", "cis-change-list"].forEach(function (id) {
        var list = document.getElementById(id);
        if (list) { list.replaceChildren(); appendEmpty(list, error.message); }
      });
      text(document.getElementById("cis-key-status"), error.message);
    }
  }

  var cisInstallMacOS26 = document.getElementById("cis-install-macos26");
  if (cisInstallMacOS26) {
    cisInstallMacOS26.addEventListener("click", async function () {
      cisInstallMacOS26.disabled = true;
      text(cisInstallMacOS26, "Publishing macOS 26 profiles…");
      try {
        var result = await postJson("/api/cis/profiles/install-macos26");
        await loadCIS();
        var count = result.installed_count || 0;
        text(document.getElementById("cis-key-status"), count
          ? "Published " + count + " macOS 26 Tahoe CIS profile(s). Choose a level in Client profile before downloading a config."
          : "The macOS 26 Tahoe Level 1 and Level 2 profiles are already published.");
      } catch (error) {
        text(document.getElementById("cis-key-status"), error.message);
      } finally {
        text(cisInstallMacOS26, "Install macOS 26 Level 1 + 2 profiles");
        cisInstallMacOS26.disabled = false;
        await loadCIS();
      }
    });
  }

  function notifyCISReport(message) {
    if (!message || message.report_id == null) return;
    var toast = document.getElementById("check-toast");
    if (!toast) return;
    var notice = "CIS report received from " + (message.device_name || "an endpoint") + ".";
    if (message.changed_check_count) notice += " " + message.changed_check_count + " check status change(s) detected.";
    text(toast, notice);
    toast.classList.remove("hidden");
    window.clearTimeout(toast.hideTimer);
    toast.hideTimer = window.setTimeout(function () { toast.classList.add("hidden"); }, 9000);
  }

  var cisInstallStarter = document.getElementById("cis-install-starter");
  if (cisInstallStarter) {
    cisInstallStarter.addEventListener("click", async function () {
      cisInstallStarter.disabled = true;
      text(cisInstallStarter, "Installing profile…");
      try { await postJson("/api/cis/profiles/install-starter"); await loadCIS(); }
      catch (error) { text(document.getElementById("cis-key-status"), error.message); }
      finally { text(cisInstallStarter, "Install CSP starter profile"); cisInstallStarter.disabled = false; }
    });
  }

  var cisIssueKey = document.getElementById("cis-issue-key");
  if (cisIssueKey) {
    cisIssueKey.addEventListener("click", async function () {
      cisIssueKey.disabled = true;
      text(cisIssueKey, "Preparing secure config…");
      try {
        var body = await postJson("/api/cis/api-key");
        var profilePicker = document.getElementById("cis-client-profile");
        var profileSlug = profilePicker ? profilePicker.value : "";
        var config = buildCISClientConfig(body, profileSlug);
        var blobUrl = URL.createObjectURL(new Blob([config], { type: "application/yaml" }));
        var link = document.createElement("a");
        link.href = blobUrl;
        link.download = "daedalus-cis-" + body.domain + "-config.yaml";
        document.body.append(link);
        link.click();
        link.remove();
        window.setTimeout(function () { URL.revokeObjectURL(blobUrl); }, 1000);
        text(document.getElementById("cis-key-status"), body.rotated
          ? "Upload key rotated. The prior configuration is no longer valid; download and replace it on all clients."
          : "Upload key issued and client configuration downloaded. The key is shown only in that file.");
        await loadCIS();
      } catch (error) {
        text(document.getElementById("cis-key-status"), error.message);
      } finally {
        if (cisIssueKey.dataset.keyConfigured !== "true") text(cisIssueKey, "Issue client key and download config");
        else text(cisIssueKey, "Rotate key and download new config");
        cisIssueKey.disabled = false;
      }
    });
  }

  var cisRevokeKey = document.getElementById("cis-revoke-key");
  if (cisRevokeKey) {
    cisRevokeKey.addEventListener("click", async function () {
      cisRevokeKey.disabled = true;
      try {
        await requestJson("/api/cis/api-key", "DELETE");
        text(document.getElementById("cis-key-status"), "Client upload key revoked. Existing client configurations can no longer send reports.");
        await loadCIS();
      } catch (error) {
        text(document.getElementById("cis-key-status"), error.message);
        cisRevokeKey.disabled = false;
      }
    });
  }

  document.addEventListener("click", function (event) {
    var button = event.target.closest("[data-disable-scanner]");
    if (!button) return;
    event.preventDefault();
    requestInlineConfirmation(button, "Revoke portal access for " + (button.dataset.scannerName || "this scanner") + "? Future check-ins and uploads will be rejected, and queued commands cancelled. An active local scan may continue. Saved history will remain. Reconnecting requires a new enrollment.", "Revoke access", async function () {
      var feedback = button.parentElement.querySelector(".scanner-revoke-feedback");
      try {
        var result = await postJson("/api/agents/" + encodeURIComponent(button.dataset.disableScanner) + "/disable");
        text(feedback, "Access revoked. " + result.cancelled_queued_command_count + " queued commands cancelled; " + result.unconfirmed_active_command_count + " delivered commands remain unconfirmed.");
        var revokeToast = document.getElementById("check-toast");
        if (revokeToast) {
          text(revokeToast, "Scanner access revoked. " + result.unconfirmed_active_command_count + " delivered commands remain unconfirmed; active local work may continue.");
          revokeToast.classList.remove("hidden");
          window.clearTimeout(revokeToast.hideTimer);
          revokeToast.hideTimer = window.setTimeout(function () { revokeToast.classList.add("hidden"); }, 9000);
        }
        await refresh(true);
        if (role === "admin") loadAuditLog();
      } catch (error) {
        text(feedback, error.message);
        throw error;
      }
    });
  });

  document.addEventListener("click", async function (event) {
    var button = event.target.closest("[data-scanner-pdf-event], [data-scanner-pdf-run]");
    if (!button) return;
    event.preventDefault();
    var feedback = button.closest(".agent-actions").querySelector(".scanner-pdf-feedback");
    button.disabled = true;
    text(button, "Queueing PDF…");
    try {
      var endpoint = button.dataset.scannerPdfRun
        ? "/api/agents/" + encodeURIComponent(button.dataset.scannerAgent) + "/runs/" + encodeURIComponent(button.dataset.scannerPdfRun) + "/pdf"
        : "/api/agents/events/" + encodeURIComponent(button.dataset.scannerPdfEvent) + "/pdf";
      await postJson(endpoint);
      text(feedback, "Queued. See Reports for generation progress and download.");
      await loadReports();
    } catch (error) {
      text(feedback, error.message);
    } finally {
      text(button, button.dataset.scannerPdfRun ? "Generate run PDF" : "Generate PDF report");
      button.disabled = false;
    }
  });

  document.addEventListener("click", async function (event) {
    var button = event.target.closest("[data-cis-pdf-report]");
    if (!button) return;
    event.preventDefault();
    event.stopPropagation();
    var toolbar = button.closest(".cis-pdf-toolbar");
    var feedback = toolbar ? toolbar.querySelector(".cis-pdf-feedback") : null;
    button.disabled = true;
    text(button, "Queueing PDF…");
    try {
      await postJson("/api/cis/reports/" + encodeURIComponent(button.dataset.cisPdfReport) + "/pdf");
      text(feedback, "Queued. Progress and the finished PDF appear below.");
      await loadReports();
    } catch (error) {
      text(feedback, error.message);
    } finally {
      text(button, "Generate PDF report");
      button.disabled = false;
    }
  });

  var cisProfileForm = document.getElementById("cis-profile-form");
  if (cisProfileForm) {
    cisProfileForm.addEventListener("submit", async function (event) {
      event.preventDefault();
      var submit = cisProfileForm.querySelector("[type='submit']");
      var file = cisProfileForm.elements.profile_file.files[0];
      if (!file) return;
      submit.disabled = true;
      text(submit, "Validating profile…");
      try {
        var profile = JSON.parse(await file.text());
        profile.name = cisProfileForm.elements.name.value;
        profile.version = cisProfileForm.elements.version.value;
        profile.platform = cisProfileForm.elements.platform.value;
        profile.description = cisProfileForm.elements.description.value;
        await postJson("/api/cis/profiles", profile);
        cisProfileForm.reset();
        text(document.getElementById("cis-key-status"), "Profile published as a new immutable version.");
        await loadCIS();
      } catch (error) {
        text(document.getElementById("cis-key-status"), error instanceof SyntaxError ? "Choose a valid profile JSON file." : error.message);
      } finally {
        text(submit, "Validate and publish new version");
        submit.disabled = false;
      }
    });
  }

  var generateReport = document.querySelector("[data-generate-report]");
  if (generateReport) {
    generateReport.addEventListener("click", async function () {
      var original = generateReport.textContent;
      generateReport.disabled = true;
      text(generateReport, "Queueing PDF…");
      text(document.getElementById("report-library-status"), "Capturing the latest saved DNS and website evidence…");
      try {
        await postJson("/api/reports/external-posture");
        await loadReports();
      } catch (error) {
        text(document.getElementById("report-library-status"), error.message);
      } finally {
        text(generateReport, original);
        generateReport.disabled = false;
      }
    });
  }

  function dateLabel(value) {
    if (!value) return "Not recorded";
    var date = new Date(value);
    return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString(undefined, {
      month: "short", day: "numeric", year: "numeric", hour: "numeric", minute: "2-digit",
      second: "2-digit", timeZoneName: "short"
    });
  }

  function displayCheckValue(value, fieldPath) {
    if (typeof fieldPath === "string" && fieldPath.startsWith("resolver_errors.")) {
      if (value === null) return "Lookup available";
      if (value === "unavailable") return "Lookup unavailable";
    }
    if (value === undefined) return "Not captured";
    if (value === null) return "No value returned";
    if (typeof value === "string") return value || "Empty value";
    if (Array.isArray(value) && !value.length) return "No values returned";
    return JSON.stringify(value, null, 2);
  }

  function appendEmpty(container, message) {
    if (!container) return;
    var empty = document.createElement("div");
    empty.className = "empty-events";
    empty.textContent = message;
    container.append(empty);
  }

  function makeCheckCard(title, value) {
    var card = document.createElement("article");
    card.className = "check-record-card";
    var heading = document.createElement("h3");
    heading.textContent = title;
    var formatted = displayCheckValue(value);
    if (formatted === "Not published") {
      var empty = document.createElement("p");
      empty.className = "check-empty-value";
      empty.textContent = formatted;
      card.append(heading, empty);
    } else {
      var body = document.createElement("pre");
      body.textContent = formatted;
      card.append(heading, body);
    }
    return card;
  }

  function makeAuditMetric(label, value, detail, state) {
    var card = document.createElement("article");
    card.className = "audit-metric-card";
    var heading = document.createElement("span");
    heading.className = "audit-metric-label";
    heading.textContent = label;
    var result = document.createElement("strong");
    result.textContent = value;
    var caption = document.createElement("small");
    caption.textContent = detail || "";
    if (state) card.classList.add("audit-metric-" + state);
    card.append(heading, result, caption);
    return card;
  }

  function makeAuditTable(title, description, rows, countLabel) {
    var section = document.createElement("section");
    section.className = "audit-table-card";
    var heading = document.createElement("div");
    heading.className = "audit-table-heading";
    var copy = document.createElement("div");
    var titleNode = document.createElement("h3");
    titleNode.textContent = title;
    var descriptionNode = document.createElement("p");
    descriptionNode.textContent = description;
    copy.append(titleNode, descriptionNode);
    var count = document.createElement("span");
    count.className = "audit-table-count";
    count.textContent = rows.filter(function (row) { return row.present; }).length + " " + (countLabel || "published");
    heading.append(copy, count);

    var scroller = document.createElement("div");
    scroller.className = "audit-table-scroll";
    scroller.tabIndex = 0;
    scroller.setAttribute("role", "region");
    scroller.setAttribute("aria-label", title + "; scroll horizontally to view all columns");
    var table = document.createElement("table");
    table.className = "audit-record-table";
    var thead = document.createElement("thead");
    var headerRow = document.createElement("tr");
    ["Type", "Name", "Value", "Status"].forEach(function (label) {
      var cell = document.createElement("th");
      cell.scope = "col";
      cell.textContent = label;
      headerRow.append(cell);
    });
    thead.append(headerRow);
    var tbody = document.createElement("tbody");
    rows.forEach(function (row) {
      var tableRow = document.createElement("tr");
      [row.type, row.name].forEach(function (value) {
        var cell = document.createElement("td");
        cell.textContent = value;
        tableRow.append(cell);
      });
      var valueCell = document.createElement("td");
      valueCell.className = "audit-record-value";
      valueCell.textContent = row.value;
      tableRow.append(valueCell);
      var statusCell = document.createElement("td");
      var status = document.createElement("span");
      var checked = row.present !== null;
      status.className = "audit-state-badge " + (row.statusTone || (row.present ? "is-present" : (checked ? "is-absent" : "is-neutral")));
      status.textContent = row.statusText || (row.present ? "Published" : (checked ? "Not published" : "Not checked"));
      statusCell.append(status);
      tableRow.append(statusCell);
      tbody.append(tableRow);
    });
    table.append(thead, tbody);
    scroller.append(table);
    section.append(heading, scroller);
    return section;
  }

  function rowsForRecord(type, name, values, lookupError) {
    if (lookupError) {
      return [{ type: type, name: name, value: "Lookup failed (" + lookupError + ")", present: null, statusText: "Lookup failed" }];
    }
    var items = Array.isArray(values) ? values : (values == null ? [] : [values]);
    if (!items.length) return [{ type: type, name: name, value: "Not published", present: false }];
    return items.map(function (value) {
      return { type: type, name: name, value: displayCheckValue(value), present: true };
    });
  }

  function uncheckedRecordRow(type, name) {
    return { type: type, name: name, value: "Not captured in this snapshot", present: null, statusText: "Not checked" };
  }

  function makePolicyCard(name, value) {
    var card = document.createElement("article");
    card.className = "audit-policy-card";
    var top = document.createElement("div");
    top.className = "audit-policy-top";
    var heading = document.createElement("h3");
    heading.textContent = name;
    var present = typeof value === "string" && value.trim().length > 0;
    var state = document.createElement("span");
    state.className = "audit-state-badge " + (present ? "is-present" : "is-absent");
    state.textContent = present ? "Present" : "Not set";
    top.append(heading, state);
    var detail = document.createElement("p");
    detail.textContent = present ? value : "This response did not include this header.";
    card.append(top, detail);
    return card;
  }

  function emailAuthenticationMetrics(assessment) {
    assessment = assessment && typeof assessment === "object" ? assessment : {};
    var spf = assessment.spf && typeof assessment.spf === "object" ? assessment.spf : {};
    var dmarc = assessment.dmarc && typeof assessment.dmarc === "object" ? assessment.dmarc : {};
    var dmarcDetail = dmarc.summary || "No DMARC interpretation is available in this snapshot.";
    if (dmarc.status === "published") {
      var alignment = dmarc.alignment && typeof dmarc.alignment === "object" ? dmarc.alignment : {};
      dmarcDetail += " Subdomains: existing " + (dmarc.effective_subdomain_policy || dmarc.subdomain_policy || "unknown")
        + "; nonexistent " + (dmarc.effective_nonexistent_subdomain_policy || dmarc.nonexistent_subdomain_policy || "unknown")
        + ". Alignment: SPF " + (alignment.aspf || "relaxed") + "; DKIM " + (alignment.adkim || "relaxed") + ".";
    }
    return [
      {
        label: "SPF policy",
        value: spf.label || "Not assessed",
        detail: spf.summary || "Policy interpretation is not available in this snapshot.",
        state: spf.tone || "neutral"
      },
      {
        label: "DMARC policy",
        value: dmarc.label || "Not assessed",
        detail: dmarcDetail,
        state: dmarc.tone || "neutral"
      }
    ];
  }

  function websiteCertificateAssessment(certificate, now) {
    var value = certificate && certificate.valid_until;
    var match = typeof value === "string" ? value.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,6})?(Z|[+-]\d{2}:\d{2})$/) : null;
    var unknown = {state: "unknown", value: "Unknown", detail: "Expiry unavailable or timestamp unsupported", days: null, expiry: null};
    if (!match) return unknown;
    var calendar = new Date(0); calendar.setUTCFullYear(Number(match[1]), Number(match[2]) - 1, Number(match[3])); calendar.setUTCHours(0, 0, 0, 0);
    if (calendar.getUTCFullYear() !== Number(match[1]) || calendar.getUTCMonth() !== Number(match[2]) - 1 || calendar.getUTCDate() !== Number(match[3]) || Number(match[4]) > 23 || Number(match[5]) > 59 || Number(match[6]) > 59) return unknown;
    if (match[7] !== "Z" && (Number(match[7].slice(1, 3)) > 23 || Number(match[7].slice(4)) > 59)) return unknown;
    var expiry = Date.parse(value), reference = now === undefined ? Date.now() : now;
    if (!Number.isFinite(expiry) || !Number.isFinite(reference)) return unknown;
    var remaining = expiry - reference, days = Math.ceil(remaining / 86400000);
    var state = remaining <= 0 ? "expired" : remaining < 30 * 86400000 ? "expiring" : "recorded";
    return {state: state, value: state === "expired" ? "Expired" : days + " days", detail: "Saved certificate expires " + new Date(expiry).toISOString(), days: days, expiry: expiry};
  }

  function mailRouteMetric(records, errors) {
    if (errors.MX) return {value: "Lookup failed", detail: errors.MX, state: "neutral"};
    if (!Array.isArray(records.MX)) return {value: "Unknown", detail: "MX evidence not captured", state: "neutral"};
    if (!records.MX.every(function (record) { return typeof record === "string" && record.trim().length > 0; })) {
      return {value: "Unknown", detail: "Saved MX evidence is incomplete or malformed", state: "neutral"};
    }
    var nullRecords = records.MX.filter(function (record) { return typeof record === "string" && /^\s*0\s+\.\s*$/.test(record); });
    if (nullRecords.length) {
      return records.MX.length === 1
        ? {value: "No mail", detail: "Null MX explicitly declares no incoming mail service", state: "neutral"}
        : {value: "Review", detail: "Null MX appears alongside other MX records", state: "attention"};
    }
    if (!records.MX.length) return {value: "0", detail: "No MX published; address-record fallback was not evaluated", state: "neutral"};
    return {value: String(records.MX.length), detail: "MX records published; delivery was not tested", state: "neutral"};
  }

  function renderTopicPriorities(type, snapshot) {
    var container = document.getElementById(type + "-priorities");
    if (!container) return;
    container.replaceChildren();
    if (!snapshot) { appendEmpty(container, "No saved assessment yet. Run a check to establish a baseline."); return; }
    var items = [];
    function finding(title, detail) { items.push({title: title, detail: detail}); }
    if (type === "dns") {
      var errors = snapshot.resolver_errors || {};
      emailAuthenticationMetrics(snapshot.email_authentication_assessment).forEach(function (metric) {
        if (metric.state !== "good") finding(metric.label + ": " + metric.value, metric.detail);
      });
      if (Object.keys(errors).length) finding("DNS lookup coverage", "Some DNS lookups failed. Those records remain unknown; review the lookup evidence below.");
      if (!items.length) finding("Email protection evidence recorded", "No concern was identified in the saved SPF and DMARC assessment. Review domain resolution and selector evidence below.");
    } else {
      var code = Number(snapshot.http_status || 0);
      if (!code || code >= 400) finding("Website availability", "Website response needs review: " + (code || "no HTTP response") + ".");
      var certificateAssessment = websiteCertificateAssessment(snapshot.tls);
      if (certificateAssessment.state === "unknown") finding("Certificate expiry unknown", "Certificate expiry evidence is unavailable or has an unsupported timestamp.");
      else if (certificateAssessment.state === "expired") finding("Certificate expired", "The observed TLS certificate has expired.");
      else if (certificateAssessment.state === "expiring") finding("Certificate renewal approaching", "The observed TLS certificate expires within 30 days (about " + certificateAssessment.days + " days remaining).");
      var policies = snapshot.security_headers || {};
      var missing = Object.keys(policies).filter(function (name) { return !policies[name]; });
      if (missing.length) finding("Browser protection", "Browser policy headers absent from the response: " + missing.join(", ") + ". Review which policies are appropriate for this site.");
      if (!Object.keys(policies).length) finding("Browser protection unknown", "Browser policy header evidence is unavailable.");
      if (!items.length) finding("Saved website evidence recorded", "No response, certificate-expiry, or missing-header concern was identified in this saved snapshot. Deeper audit coverage is separate.");
    }
    var group = document.createElement("div");
    group.className = "assessment-findings";
    items.forEach(function (item) {
      var row = document.createElement("article");
      row.className = "assessment-finding";
      var heading = document.createElement("h4");
      heading.textContent = item.title;
      var detail = document.createElement("p");
      detail.textContent = item.detail;
      row.append(heading, detail);
      group.append(row);
    });
    container.append(group);
    if (type === "dns") {
      var limit = document.createElement("p");
      limit.className = "check-scope-note";
      limit.textContent = "DKIM coverage is limited to the common selectors checked. A missing selector does not establish that mail is unsigned.";
      container.append(limit);
    }
  }

  function renderDnsSnapshot(snapshot) {
    var grid = document.getElementById("dns-record-grid");
    if (!grid) return;
    grid.replaceChildren();
    if (!snapshot || !snapshot.records) {
      appendEmpty(grid, "No successful DNS result is stored yet.");
      return;
    }
    var records = snapshot.records;
    var errors = snapshot.resolver_errors || {};
    var inventoryRows = [];
    ["A", "AAAA", "CNAME", "NS", "SOA", "TXT", "CAA", "DS", "DNSKEY"].forEach(function (key) {
      if (!Object.prototype.hasOwnProperty.call(records, key)) { inventoryRows.push(uncheckedRecordRow(key, "@")); return; }
      var values = records[key] || [];
      if (key === "TXT") {
        values = values.filter(function (value) {
          return !String(value).trim().toLowerCase().startsWith("v=spf1");
        });
      }
      inventoryRows = inventoryRows.concat(rowsForRecord(key, "@", values, errors[key]));
    });
    ["A", "AAAA", "CNAME"].forEach(function (type) {
      var key = "WWW_" + type;
      if (Object.prototype.hasOwnProperty.call(records, key)) {
        inventoryRows = inventoryRows.concat(rowsForRecord(type, "www", records[key] || [], errors["www " + type]));
      } else {
        inventoryRows.push(uncheckedRecordRow(type, "www"));
      }
    });

    var authRows = [];
    authRows = authRows.concat(rowsForRecord("MX", "@", records.MX || [], errors.MX));
    authRows = authRows.concat(rowsForRecord("SPF", "@", records.SPF || [], errors.TXT));
    authRows = authRows.concat(rowsForRecord("DMARC", "_dmarc", records.DMARC || [], errors.DMARC));
    var dkimRecords = records.DKIM || {};
    Object.keys(dkimRecords).sort().forEach(function (selector) {
      authRows = authRows.concat(rowsForRecord(
        "DKIM",
        selector + "._domainkey",
        dkimRecords[selector] || [],
        errors["DKIM " + selector]
      ));
    });

    var summary = document.createElement("div");
    summary.className = "audit-metric-grid dns-audit-metrics";
    var selectorNames = Object.keys(dkimRecords);
    var failedSelectors = selectorNames.filter(function (selector) { return Boolean(errors["DKIM " + selector]); });
    var checkedSelectors = selectorNames.length - failedSelectors.length;
    var publishedSelectors = selectorNames.filter(function (selector) {
      return !errors["DKIM " + selector] && Array.isArray(dkimRecords[selector]) && dkimRecords[selector].length > 0;
    }).length;
    var selectorMetricValue = selectorNames.length
      ? (checkedSelectors ? publishedSelectors + "/" + checkedSelectors : "Lookup failed")
      : "No data";
    var selectorMetricDetail = !selectorNames.length
      ? "No selector data in this snapshot"
      : (failedSelectors.length ? failedSelectors.length + " selector lookup(s) failed" : "of the selectors checked");
    var mailRoutes = mailRouteMetric(records, errors);
    var emailMetrics = emailAuthenticationMetrics(snapshot.email_authentication_assessment);
    summary.append(
      makeAuditMetric("Mail routes", mailRoutes.value, mailRoutes.detail, mailRoutes.state),
      makeAuditMetric(emailMetrics[0].label, emailMetrics[0].value, emailMetrics[0].detail, emailMetrics[0].state),
      makeAuditMetric(emailMetrics[1].label, emailMetrics[1].value, emailMetrics[1].detail, emailMetrics[1].state),
      makeAuditMetric("DKIM selectors", selectorMetricValue, selectorMetricDetail, publishedSelectors ? "good" : "attention")
    );
    var networkHeading = document.createElement("h3");
    networkHeading.className = "topic-group-heading";
    networkHeading.textContent = "Domain resolution & trust";
    var networkMetrics = document.createElement("div");
    networkMetrics.className = "audit-metric-grid";
    function resolutionMetric(label, keys) {
      var captured = keys.every(function (key) { return Object.prototype.hasOwnProperty.call(records, key); });
      var unavailable = keys.some(function (key) { return Boolean(errors[key.replace("WWW_", "www ")]); });
      var published = keys.some(function (key) { return Array.isArray(records[key]) && records[key].length > 0; });
      return makeAuditMetric(label, unavailable ? "Unknown" : !captured ? "Not assessed" : published ? "Records observed" : "No records observed",
        unavailable ? "A lookup failed; review the saved evidence" : "Address and alias records in this snapshot",
        unavailable || !captured || !published ? "attention" : "good");
    }
    var dnssec = snapshot.dnssec_observations || {};
    var signingLabels = {lookup_incomplete: "Unknown", records_observed: "Records observed", no_records_observed: "No records observed"};
    networkMetrics.append(
      resolutionMetric("Root domain", ["A", "AAAA", "CNAME"]),
      resolutionMetric("www domain", ["WWW_A", "WWW_AAAA", "WWW_CNAME"]),
      makeAuditMetric("Signing evidence", signingLabels[dnssec.assessment] || "Not assessed", "DNSSEC chain has not been validated locally", "neutral"),
      makeAuditMetric("Lookup coverage", String(Object.keys(errors).length) + " unavailable", "Failed lookups remain unknown", Object.keys(errors).length ? "attention" : "neutral")
    );
    var mailHeading = document.createElement("h3");
    mailHeading.className = "topic-group-heading";
    mailHeading.textContent = "Email routing & protection";
    function evidenceGroup(id, heading, metrics, label, table) {
      var group = document.createElement("section");
      group.className = "dns-evidence-group";
      heading.id = id;
      group.setAttribute("aria-labelledby", id);
      var details = document.createElement("details");
      details.className = "topic-secondary";
      var disclosure = document.createElement("summary"); disclosure.textContent = label;
      details.append(disclosure, table);
      group.append(heading, metrics, details);
      return group;
    }
    grid.append(
      evidenceGroup("dns-resolution-group", networkHeading, networkMetrics, "Domain record evidence",
        makeAuditTable("DNS record inventory", "@ is the root of " + (snapshot.domain || "the workspace domain") + "; www records are checked separately.", inventoryRows)),
      evidenceGroup("dns-email-group", mailHeading, summary, "Email record evidence",
        makeAuditTable("Email routing and authentication", "MX, SPF, DMARC, and the common DKIM selectors checked by Daedalus. Names are relative to the domain.", authRows))
    );
    var diagnostics = document.createElement("details");
    diagnostics.className = "topic-secondary";
    var diagnosticHeading = document.createElement("summary"); diagnosticHeading.textContent = "Resolver diagnostics & lookup coverage";
    diagnostics.append(diagnosticHeading);
    if (snapshot.query_observations) {
      var lookupDetails = document.createElement("details");
      lookupDetails.className = "agent-command-history";
      var lookupHeading = document.createElement("summary");
      lookupHeading.textContent = "DNS lookup evidence and remaining TTL";
      lookupDetails.append(lookupHeading);
      var resolverContext = snapshot.resolver_context;
      if (resolverContext && Array.isArray(resolverContext.nameservers)) {
        var resolverNote = document.createElement("p");
        resolverNote.className = "muted";
        resolverNote.textContent = "Audit resolver: " + (resolverContext.mode === "explicit" ? "operator configured" : "system configured") + " · " + (resolverContext.nameservers.join(", ") || "address not captured");
        lookupDetails.append(resolverNote);
      }
      var lookupRows = Object.keys(snapshot.query_observations).sort().map(function (key) {
        var observation = snapshot.query_observations[key];
        var ttl = typeof observation.observed_ttl_seconds === "number" ? observation.observed_ttl_seconds + " seconds" : "Unknown";
        var ad = observation.resolver_ad === true ? "Asserted" : observation.resolver_ad === false ? "Not asserted" : "Unknown";
        return {type: observation.record_type, name: observation.query_name, value: "Remaining TTL: " + ttl + "; canonical name: " + (observation.canonical_name || "Unknown") + "; upstream AD: " + ad, present: null, statusText: String(observation.status || "unknown").replace(/_/g, " ")};
      });
      lookupDetails.append(makeAuditTable("Per-query observations", "TTL is the remaining resolver cache lifetime, not necessarily the configured authoritative TTL. TTL-only changes do not trigger alerts. AD is an upstream assertion, not local chain validation.", lookupRows));
      diagnostics.append(lookupDetails);
    }
    if (snapshot.dnssec_observations) {
      var dnssecNote = document.createElement("p");
      dnssecNote.className = "audit-inline-warning";
      var assessmentLabels = {lookup_incomplete: "Lookup incomplete", records_observed: "Signing records observed", no_records_observed: "No signing records observed"};
      dnssecNote.textContent = "DNSSEC: " + (assessmentLabels[snapshot.dnssec_observations.assessment] || "Unknown") + ". Upstream resolver flags are observations; the DNSSEC chain was not validated locally.";
      diagnostics.append(dnssecNote);
    }
    if (Object.keys(errors).length) {
      var warning = document.createElement("p");
      warning.className = "audit-inline-warning";
      var failedLookups = Object.keys(errors).sort().map(function (name) { return name + " (" + errors[name] + ")"; });
      var visibleFailures = failedLookups.slice(0, 6).join(", ");
      if (failedLookups.length > 6) visibleFailures += ", and " + (failedLookups.length - 6) + " more";
      warning.textContent = "Could not verify: " + visibleFailures + ". These results are unknown, not missing records.";
      diagnostics.append(warning);
    }
    if (diagnostics.children.length > 1) grid.append(diagnostics);
  }

  var vendorReviewContext = null, vendorReviewSequence = 0, vendorReviewPending = null;
  var vendorReviewHistory = [], vendorReviewBefore = null, vendorReviewSaving = false, vendorReviewLoadFailed = false;
  var vendorReviewLabels = {reviewed: "Reviewed", needs_action: "Needs action", monitor: "Monitor"};

  function renderVendorDecisionList(host, rows) {
    if (!host) return;
    host.replaceChildren();
    if (!rows.length) { appendEmpty(host, "No review decisions recorded for this inventory."); return; }
    rows.forEach(function (row) {
      var item = document.createElement("article"); item.className = "cis-report-card";
      var title = document.createElement("strong");
      title.textContent = (row.origin || {}).host + " · " + (vendorReviewLabels[row.status] || "Unknown decision");
      var note = document.createElement("p"); note.textContent = row.note;
      var when = document.createElement("small"); when.textContent = (row.reviewer || "Former member") + " · " + dateLabel(row.created_at);
      item.append(title, note, when); host.append(item);
    });
  }

  async function fetchVendorReviews(older) {
    if (!vendorReviewContext) return;
    var runId = vendorReviewContext.runId, sequence = ++vendorReviewSequence;
    try {
      var response = await fetch("/api/vendor-reviews?run_id=" + runId + (older && vendorReviewBefore ? "&before=" + vendorReviewBefore : ""), {credentials: "same-origin"});
      var body = await response.json();
      if (!response.ok) throw new Error(body.detail || "Review decisions unavailable.");
      if (sequence !== vendorReviewSequence || !vendorReviewContext || vendorReviewContext.runId !== runId) return;
      if (vendorReviewLoadFailed) { text(document.getElementById("vendor-review-feedback"), "Review decisions refreshed."); vendorReviewLoadFailed = false; }
      renderVendorDecisionList(document.getElementById("vendor-review-decisions"), body.reviews || []);
      var expanded = vendorReviewHistory.length > 100;
      var merged = new Map(vendorReviewHistory.map(function (row) { return [row.id, row]; }));
      (body.history || []).forEach(function (row) { merged.set(row.id, row); });
      vendorReviewHistory = Array.from(merged.values()).sort(function (a,b) { return b.id-a.id; });
      if (older || !expanded) vendorReviewBefore = body.history_has_more ? body.history_next_before : null;
      renderVendorDecisionList(document.getElementById("vendor-review-history"), vendorReviewHistory);
      var more = document.getElementById("vendor-review-older"); if (more) more.classList.toggle("hidden", !vendorReviewBefore);
    } catch (error) {
      if (sequence === vendorReviewSequence) { vendorReviewLoadFailed = true; text(document.getElementById("vendor-review-feedback"), error.message); }
    }
  }

  function loadVendorReviewContext(runId, resources) {
    var note = document.getElementById("vendor-review-note");
    var keepDraft = vendorReviewContext && vendorReviewContext.runId !== runId && (vendorReviewSaving || (note && note.value.trim()));
    if (keepDraft) {
      text(document.getElementById("vendor-review-scope"), "New inventory available. This draft remains attached to saved website run #" + vendorReviewContext.runId + ". Finish or clear the rationale before switching.");
      return;
    }
    if (!vendorReviewContext || vendorReviewContext.runId !== runId) {
      vendorReviewContext = runId && Array.isArray(resources) ? {runId: runId, resources: resources} : null;
      vendorReviewHistory = []; vendorReviewBefore = null; vendorReviewPending = null; ++vendorReviewSequence;
      var select = document.getElementById("vendor-review-origin");
      if (select) {
        select.replaceChildren();
        (resources || []).forEach(function (origin, index) {
          var option = document.createElement("option"); option.value = String(index);
          option.textContent = origin.host + " · " + origin.scheme + (origin.port ? ":" + origin.port : ""); select.append(option);
        });
      }
    }
    text(document.getElementById("vendor-review-scope"), vendorReviewContext ? "Decisions apply to saved website run #" + runId + ". Reviewed records a human decision; provider security remains unassessed." : "No saved inventory available for review.");
    var save = document.getElementById("vendor-review-save"); if (save) save.disabled = vendorReviewSaving || !vendorReviewContext || !resources.length;
    if (vendorReviewContext) fetchVendorReviews(false);
    else {
      renderVendorDecisionList(document.getElementById("vendor-review-decisions"), []);
      renderVendorDecisionList(document.getElementById("vendor-review-history"), []);
      var more = document.getElementById("vendor-review-older"); if (more) more.classList.toggle("hidden", true);
    }
  }

  var vendorReviewForm = document.getElementById("vendor-review-form");
  if (vendorReviewForm) vendorReviewForm.addEventListener("submit", async function (event) {
    event.preventDefault(); if (!vendorReviewContext || vendorReviewSaving) return;
    var note = document.getElementById("vendor-review-note"), origin = document.getElementById("vendor-review-origin"), status = document.getElementById("vendor-review-status");
    var values = {run_id: vendorReviewContext.runId, resource_index: Number(origin.value), status: status.value, note: note.value.trim()};
    var signature = JSON.stringify(values);
    if (!vendorReviewPending || vendorReviewPending.signature !== signature) vendorReviewPending = {signature: signature, payload: Object.assign({request_id: crypto.randomUUID()}, values)};
    vendorReviewSaving = true; document.getElementById("vendor-review-save").disabled = true;
    try {
      var response = await fetch("/api/vendor-reviews", {method: "POST", credentials: "same-origin", headers: {"Content-Type": "application/json"}, body: JSON.stringify(vendorReviewPending.payload)});
      var body = await response.json(); if (!response.ok) throw new Error(typeof body.detail === "string" ? body.detail : "Review could not be saved.");
      text(document.getElementById("vendor-review-feedback"), "Review recorded for website run #" + values.run_id + ".");
      if (note.value.trim() === values.note && Number(origin.value) === values.resource_index && status.value === values.status) note.value = "";
      vendorReviewPending = null; await fetchVendorReviews(false);
    } catch (error) { text(document.getElementById("vendor-review-feedback"), error.message); }
    finally { vendorReviewSaving = false; document.getElementById("vendor-review-save").disabled = false; }
  });
  var vendorReviewOlder = document.getElementById("vendor-review-older");
  if (vendorReviewOlder) vendorReviewOlder.addEventListener("click", function () { fetchVendorReviews(true); });

  function groupExternalDependencies(resources) {
    var groups = new Map();
    (Array.isArray(resources) ? resources : []).forEach(function (resource) {
      var category = resource.category || "Unclassified";
      if (!groups.has(category)) groups.set(category, []);
      groups.get(category).push(resource);
    });
    return Array.from(groups, function (entry) { return {category: entry[0], resources: entry[1]}; });
  }

  function dependencyOriginEvidence(snapshot, resource) {
    var block = snapshot.dependency_origin_observations;
    if (!block || block.schema_version !== 1 || !Array.isArray(block.origins)) return "Origin attributes not recorded";
    var matches = block.origins.filter(function (origin) {
      return origin && origin.host === resource.host && origin.scheme === resource.scheme && origin.port === resource.port;
    });
    var keys = ["http_reference_count", "script_reference_count", "stylesheet_reference_count", "integrity_declared_reference_count", "integrity_missing_reference_count"];
    if (matches.length !== 1 || !keys.every(function (key) { return Number.isSafeInteger(matches[0][key]) && matches[0][key] >= 0; })) return "Origin attributes unavailable";
    var origin = matches[0];
    return origin.http_reference_count + " HTTP · " + origin.script_reference_count + " script(s) · " + origin.stylesheet_reference_count + " stylesheet(s) · integrity: " + origin.integrity_declared_reference_count + " declared, " + origin.integrity_missing_reference_count + " not declared";
  }

  function renderWebsiteSnapshot(snapshot) {
    var summary = document.getElementById("web-summary-grid");
    var headers = document.getElementById("web-header-grid");
    var vendors = document.getElementById("web-vendor-grid");
    if (!summary || !headers) return;
    summary.replaceChildren();
    headers.replaceChildren();
    if (!snapshot) {
      appendEmpty(summary, "No successful website result is stored yet.");
      appendEmpty(headers, "Security header results will appear after a successful check.");
      if (vendors) appendEmpty(vendors, "External dependency results will appear after a website check.");
      return;
    }
    var policies = snapshot.security_headers || {};
    var headerNames = Object.keys(policies);
    var presentHeaders = headerNames.filter(function (name) {
      return typeof policies[name] === "string" && policies[name].trim().length > 0;
    }).length;
    var responseCode = Number(snapshot.http_status || 0);
    var responseOkay = responseCode >= 200 && responseCode < 400;
    var certificate = snapshot.tls || {};
    var certificateAssessment = websiteCertificateAssessment(certificate);
    var certTone = certificateAssessment.state === "recorded" ? "good" : "attention";
    var headerTone = headerNames.length > 0 && presentHeaders === headerNames.length ? "good" : "attention";

    var hero = document.createElement("section");
    hero.className = "site-snapshot-hero";
    var heroCopy = document.createElement("div");
    var eyebrow = document.createElement("p");
    eyebrow.className = "eyebrow";
    eyebrow.textContent = "LATEST HTTPS SNAPSHOT";
    var siteName = document.createElement("h3");
    var observedUrl = snapshot.final_url || snapshot.requested_url || "";
    try { siteName.textContent = new URL(observedUrl).hostname || observedUrl; }
    catch (_error) { siteName.textContent = observedUrl || "Website endpoint"; }
    var siteTitle = document.createElement("p");
    siteTitle.className = "site-snapshot-title";
    siteTitle.textContent = snapshot.title || "No page title was returned.";
    heroCopy.append(eyebrow, siteName, siteTitle);
    var responseBadge = document.createElement("span");
    responseBadge.className = "audit-state-badge " + (responseOkay ? "is-present" : "is-absent");
    responseBadge.textContent = responseCode ? (responseOkay ? "HTTPS responds · " : "Review response · ") + responseCode : "No HTTP response";
    hero.append(heroCopy, responseBadge);

    var metrics = document.createElement("div");
    metrics.className = "audit-metric-grid site-audit-metrics";
    metrics.append(
      makeAuditMetric("HTTP response", responseCode ? String(responseCode) : "No response", snapshot.http_reason || "Root page request", responseOkay ? "good" : "attention"),
      makeAuditMetric("TLS certificate", certificateAssessment.value, certificateAssessment.detail, certTone),
      makeAuditMetric("Security headers", headerNames.length ? presentHeaders + "/" + headerNames.length : "No data", headerNames.length ? "selected headers present" : "Header data unavailable", headerTone),
      makeAuditMetric("Content type", snapshot.content_type || "Not returned", snapshot.redirects && snapshot.redirects.length ? snapshot.redirects.length + " same-domain redirect(s)" : "No redirect recorded", "neutral")
    );
    summary.append(hero, metrics);

    var details = document.createElement("div");
    details.className = "site-detail-grid";
    details.append(makeCheckCard("Request details", {
      requested_url: snapshot.requested_url,
      final_url: snapshot.final_url,
      public_destination_addresses: snapshot.destination_addresses || [],
      redirects: snapshot.redirects || []
    }));
    if (snapshot.tls) {
      details.append(makeCheckCard("TLS certificate", {
        negotiated_protocol: snapshot.tls.negotiated_protocol || "Not collected",
        negotiated_cipher: snapshot.tls.negotiated_cipher || "Not collected",
        supported_protocols_tested: false,
        issuer: snapshot.tls.issuer,
        subject: snapshot.tls.subject,
        valid_from: snapshot.tls.valid_from,
        valid_until: snapshot.tls.valid_until,
        dns_names: snapshot.tls.dns_names,
        sha256_fingerprint: snapshot.tls.sha256_fingerprint
      }));
    }
    if (snapshot.cookie_observations) details.append(makeCheckCard("Cookie attributes · final response only", snapshot.cookie_observations));
    if (snapshot.header_observations) details.append(makeCheckCard("Header observations · recognized tokens only", snapshot.header_observations));
    if (snapshot.page_content) {
      details.append(makeCheckCard("Fetched page evidence · dynamic content may change legitimately", snapshot.page_content));
    }
    var evidence = document.createElement("details"); evidence.className = "topic-secondary";
    var evidenceHeading = document.createElement("summary"); evidenceHeading.textContent = "Certificate, cookies & response evidence";
    evidence.append(evidenceHeading, details); summary.append(evidence);
    headerNames.forEach(function (name) {
      headers.append(makePolicyCard(name, policies[name]));
    });
    if (!headerNames.length) appendEmpty(headers, "No security header data was returned.");

    if (vendors) {
      vendors.replaceChildren();
      var dependency = snapshot.dependency_observations;
      if (dependency && dependency.schema_version === 1) {
        var dependencyMetrics = document.createElement("div"); dependencyMetrics.className = "audit-metric-grid";
        [["HTTP references", "http_reference_count"], ["External scripts", "script_reference_count"], ["External stylesheets", "stylesheet_reference_count"], ["Script/style integrity not declared", "integrity_missing_reference_count"]].forEach(function (metric) {
          var count = dependency[metric[1]];
          dependencyMetrics.append(makeAuditMetric(metric[0], Number.isInteger(count) && count >= 0 ? String(count) : "Unknown", "Returned root-page attributes", (metric[1] === "http_reference_count" || metric[1] === "integrity_missing_reference_count") && count > 0 ? "attention" : "neutral"));
        });
        var dependencyScope = document.createElement("p"); dependencyScope.className = "muted";
        dependencyScope.textContent = "Integrity attributes are counted, not validated. Missing metadata needs context; this does not prove a vulnerable dependency. Linked content and vendor security were not assessed.";
        vendors.append(dependencyMetrics, dependencyScope);
      }

      if (!Array.isArray(snapshot.external_resources)) {
        appendEmpty(vendors, "This saved run predates linked vendor inventory. Run a new website check to build the first inventory.");
      } else if (!snapshot.external_resources.length) {
        appendEmpty(vendors, snapshot.page_html_truncated
          ? "No third-party resource links were found in the captured portion of the root page."
          : "No third-party resource links were found in the returned root page.");
      } else {
        groupExternalDependencies(snapshot.external_resources).forEach(function (group) {
          var dependencyRows = group.resources.map(function (resource) {
            var host = resource.host || "Unknown host";
            if (resource.port) host += ":" + resource.port;
            var insecure = resource.scheme === "http";
            return {
              type: resource.vendor || "Unclassified external host",
              name: host,
              value: (resource.category || "Other") + " · " + (resource.resource_types || []).join(", ") + " · " + (resource.reference_count || 1) + " reference(s) · " + dependencyOriginEvidence(snapshot, resource),
              present: true,
              statusTone: insecure ? "is-absent" : "is-neutral",
              statusText: insecure ? "HTTP reference" : "HTTPS reference"
            };
          });
          vendors.append(makeAuditTable(
            group.category + " · " + group.resources.length + " linked origin(s)",
            "Categories are hostname observations, not vendor security assessments. HTTPS references remain unassessed.",
            dependencyRows,
            "linked"
          ));
        });
        if (snapshot.external_resources_truncated) {
          var truncationNote = document.createElement("p");
          truncationNote.className = "audit-inline-warning";
          truncationNote.textContent = "Showing " + snapshot.external_resources.length + " of " + (snapshot.external_origin_count || "many") + " linked origins; the stored list was capped for this run.";
          vendors.append(truncationNote);
        }
      }
      if (snapshot.page_html_truncated) {
        var pageNote = document.createElement("p");
        pageNote.className = "audit-inline-warning";
        pageNote.textContent = "The response exceeded 256 KiB; dependency inventory covers only the first 256 KiB of HTML.";
        vendors.append(pageNote);
      }
    }
  }

  function dnsChangeUncertainty(change, snapshot) {
    if (!change || !snapshot || !String(change.field_path || "").startsWith("records.")) return "";
    var field = String(change.field_path).slice("records.".length);
    var queryName = field.startsWith("WWW_")
      ? "www " + field.slice(4).replaceAll("_", " ")
      : field.startsWith("DKIM.")
        ? "DKIM " + field.slice(5)
        : field.replaceAll("_", " ");
    var errors = snapshot.resolver_errors || {};
    var matchingKey = Object.keys(errors).find(function (key) {
      return key.toLowerCase() === queryName.toLowerCase();
    });
    if (!matchingKey) return "";
    return "Current lookup failed (" + errors[matchingKey] + "); this historical value cannot confirm a record addition or removal.";
  }

  function renderCheckHistory(type, body) {
    var status = document.getElementById(type + "-check-status");
    var lastRun = document.getElementById(type + "-check-last-run");
    var runList = document.getElementById(type + "-check-runs");
    var changeList = document.getElementById(type + "-check-changes");
    var historyState = externalCheckHistory[type];
    var runs = body.runs || [];
    var latestRun = runs[0];
    if (status) {
      status.className = "check-status";
      if (latestRun && latestRun.status === "running") {
        text(status, "Check running");
      } else if (latestRun && latestRun.status === "failed") {
        status.classList.add("status-failed");
        text(status, "Last run failed");
      } else if (latestRun) {
        status.classList.add("status-completed");
        text(status, latestRun.status === "completed_with_warnings" ? "Completed with DNS warnings" : "Check complete");
      } else {
        text(status, "No check run yet");
      }
    }
    if (lastRun) {
      if (!latestRun) {
        text(lastRun, "Run a check to establish the first baseline.");
      } else {
        var when = latestRun.completed_at || latestRun.started_at;
        text(lastRun, (latestRun.status === "running" ? "Started " : "Last checked ") + dateLabel(when) +
          (latestRun.actor ? " by " + latestRun.actor : "") +
          (latestRun.duration_ms != null ? " · " + (latestRun.duration_ms / 1000).toFixed(1) + " sec" : "") +
          (latestRun.error_summary ? " · " + latestRun.error_summary : ""));
      }
    }
    if (runList) {
      runList.replaceChildren();
      runs.forEach(function (run) {
        var row = document.createElement("article");
        row.className = "check-run-row";
        var main = document.createElement("div");
        main.className = "check-run-main";
        var heading = document.createElement("strong");
        heading.textContent = run.domain + " · run #" + run.id;
        var details = document.createElement("small");
        details.textContent = (run.actor || "system") + " · " +
          (run.duration_ms == null ? "in progress" : (run.duration_ms / 1000).toFixed(1) + " sec") +
          " · " + run.change_count + " change(s)" +
          (run.error_summary ? " · " + run.error_summary : "");
        main.append(heading, details);
        var time = document.createElement("time");
        time.dateTime = run.completed_at || run.started_at || "";
        time.textContent = dateLabel(run.completed_at || run.started_at);
        var state = document.createElement("span");
        state.className = "check-run-status" + (run.status === "failed" ? " failed" : "");
        state.textContent = run.status.replaceAll("_", " ");
        main.append(state);
        row.append(main, time);
        runList.append(row);
      });
      if (!runs.length) appendEmpty(runList, "No check history yet.");
    }
    var olderRunsButton = document.querySelector('[data-load-older-checks="' + type + '"][data-page-kind="runs"]');
    if (olderRunsButton) {
      olderRunsButton.classList.toggle("hidden", !body.runs_has_more);
      olderRunsButton.disabled = Boolean(historyState && historyState.loading === "runs");
      olderRunsButton.textContent = historyState && historyState.loading === "runs" ? "Loading older runs…" : "Load older check runs";
    }
    if (changeList) {
      changeList.replaceChildren();
      (body.changes || []).forEach(function (change) {
        var row = document.createElement("article");
        row.className = "check-change-row";
        var main = document.createElement("div");
        main.className = "check-change-main";
        var field = document.createElement("strong");
        field.textContent = change.field_label || change.field_path;
        var actor = document.createElement("small");
        actor.textContent = "Run #" + change.run_id + " · detected by " + (change.actor || "system");
        var values = document.createElement("div");
        values.className = "check-change-values";
        [["Previous", change.previous_value], ["Current", change.current_value]].forEach(function (pair) {
          var box = document.createElement("div");
          var label = document.createElement("span");
          label.textContent = pair[0];
          var pre = document.createElement("pre");
          pre.textContent = displayCheckValue(pair[1], change.field_path);
          box.append(label, pre);
          values.append(box);
        });
        main.append(field, actor, values);
        var uncertainty = type === "dns" ? dnsChangeUncertainty(change, body.latest_snapshot) : "";
        if (uncertainty) {
          var uncertaintyNote = document.createElement("p");
          uncertaintyNote.className = "audit-inline-warning check-change-warning";
          uncertaintyNote.textContent = uncertainty;
          main.append(uncertaintyNote);
        }
        var time = document.createElement("time");
        time.dateTime = change.detected_at || "";
        time.textContent = dateLabel(change.detected_at);
        row.append(main, time);
        changeList.append(row);
      });
      if (!(body.changes || []).length) appendEmpty(changeList, "No confirmed changes are recorded in the saved assessment history. The first successful assessment establishes the baseline; unavailable checks cannot establish changes.");
    }
    var olderChangesButton = document.querySelector('[data-load-older-checks="' + type + '"][data-page-kind="changes"]');
    if (olderChangesButton) {
      olderChangesButton.classList.toggle("hidden", !body.changes_has_more);
      olderChangesButton.disabled = Boolean(historyState && historyState.loading === "changes");
      olderChangesButton.textContent = historyState && historyState.loading === "changes" ? "Loading older changes…" : "Load older changes";
    }
    renderTopicPriorities(type, body.latest_snapshot);
    if (type === "dns") renderDnsSnapshot(body.latest_snapshot);
    if (type === "web") { renderWebsiteSnapshot(body.latest_snapshot); loadVendorReviewContext(body.latest_snapshot_run_id, (body.latest_snapshot || {}).external_resources); }
    renderExternalCheckSchedule(type, body.schedule);
  }

  function renderExternalCheckSchedule(type, schedule) {
    schedule = schedule || { enabled: false, interval_hours: 24 };
    var status = document.getElementById(type + "-schedule-status");
    var nextRun = document.getElementById(type + "-schedule-next-run");
    var checkbox = document.querySelector('[data-schedule-enabled="' + type + '"]');
    var interval = document.querySelector('[data-schedule-interval="' + type + '"]');
    var cadence = Number(schedule.interval_hours) === 168 ? "weekly" : "daily";
    if (status) {
      status.className = "check-status" + (schedule.enabled ? " status-completed" : "");
      text(status, schedule.enabled ? "Recurring " + cadence + " checks are active" : "Recurring checks are off");
    }
    if (nextRun) {
      var message = schedule.enabled
        ? "Next run " + dateLabel(schedule.next_run_at)
        : "Schedules start one full interval after they are saved.";
      if (schedule.last_completed_at) {
        message += " · Last attempt " + dateLabel(schedule.last_completed_at) +
          (schedule.last_run_status ? " (" + schedule.last_run_status.replaceAll("_", " ") + ")" : "");
      }
      text(nextRun, message);
    }
    if (checkbox) checkbox.checked = Boolean(schedule.enabled);
    if (interval) {
      interval.value = String(schedule.interval_hours || 24);
      interval.disabled = !checkbox || checkbox.disabled || !checkbox.checked;
    }
  }

  function renderWebsiteAuditOutcome(id, label, run) {
    var node = document.getElementById(id);
    if (!node) return;
    if (!run) { text(node, label + ": no assessment saved yet."); return; }
    if (run.status === "failed" || run.status === "running" || run.status === "queued" || run.status === "cancelled") {
      text(node, label + ": latest attempt " + run.status + ". Review the audit details below."); return;
    }
    var snapshot = run.snapshot || {};
    var findings = Array.isArray(snapshot.findings) ? snapshot.findings.length : 0;
    text(node, label + ": " + findings + " observation(s) in the latest run · " + dateLabel(run.completed_at || run.started_at)
      + (snapshot.coverage_complete === true ? ". Fixed-path coverage completed; observations need review." : ". Coverage incomplete; absence does not establish resolution."));
  }

  function renderExposureReview(run) {
    var host = document.getElementById("web-exposure-review");
    if (!host) return;
    host.replaceChildren();
    if (!run) { appendEmpty(host, "No saved exposure assessment yet."); return; }
    if (run.status !== "completed" && run.status !== "completed_with_warnings") {
      appendEmpty(host, "Latest exposure attempt " + String(run.status || "has unknown status") + ". No completed assessment is inferred from this attempt.");
      return;
    }
    var snapshot = run.snapshot || {};
    var findings = Array.isArray(snapshot.findings) ? snapshot.findings : [];
    var caption = document.createElement("p");
    caption.className = "muted";
    caption.textContent = "Latest exposure assessment · " + dateLabel(run.completed_at || run.started_at)
      + " · run #" + run.id + ". Signature observations require application review.";
    host.append(caption);
    findings.slice(0, 20).forEach(function (finding) {
      var row = document.createElement("article"); row.className = "assessment-finding";
      var title = document.createElement("h4"); title.textContent = String(finding.signature_id || "Unclassified signature");
      var detail = document.createElement("p");
      detail.textContent = String(finding.path || "Path unavailable") + " · HTTP "
        + (finding.http_status == null ? "unknown" : finding.http_status) + " · signature requires review";
      row.append(title, detail); host.append(row);
    });
    if (findings.length > 20) {
      var more = document.createElement("p"); more.textContent = (findings.length - 20) + " further observations are retained in exposure history."; host.append(more);
    }
    var scope = document.createElement("p"); scope.className = "check-scope-note";
    scope.textContent = (findings.length ? "" : "No configured signature was observed. ")
      + (snapshot.coverage_complete === true ? "Fixed-path coverage completed; this does not establish that the website is free of vulnerabilities."
        : "Coverage incomplete or ambiguous; absence does not establish resolution.");
    host.append(scope);
  }

  function renderActiveExposure(body) {
    var status = document.getElementById("web-active-status");
    var list = document.getElementById("web-active-runs");
    var changesList = document.getElementById("web-active-changes");
    if (!list) return;
    var runs = body.runs || [];
    renderWebsiteAuditOutcome("web-exposure-outcome", "Public exposure paths", runs[0]);
    renderExposureReview(runs[0]);
    if (status) {
      var latest = runs[0];
      status.className = "check-status" + (latest && latest.status === "failed" ? " status-failed" : "");
      status.textContent = !latest ? "No active check run yet" : latest.status.replaceAll("_", " ") + " · " + (latest.change_count || 0) + " finding change(s)";
    }
    list.replaceChildren();
    if (!runs.length) { appendEmpty(list, "No active check history yet."); return; }
    runs.forEach(function (run) {
      var row = document.createElement("article"); row.className = "check-run-row";
      var main = document.createElement("div"); main.className = "check-run-main";
      var title = document.createElement("strong"); title.textContent = run.domain + " · run #" + run.id;
      var meta = document.createElement("small"); meta.textContent = (run.actor || "workspace administrator") + " · " + dateLabel(run.completed_at || run.started_at) + " · " + run.status.replaceAll("_", " ");
      main.append(title, meta);
      var snapshot = run.snapshot || {};
      var coverage = document.createElement("small"); coverage.textContent = snapshot.coverage_complete === true ? "All fixed probes assessed against a usable missing-page baseline." : "Coverage incomplete or ambiguous; absence cannot resolve earlier findings.";
      main.append(coverage);
      (snapshot.findings || []).forEach(function (finding) {
        var item = document.createElement("p"); item.className = "check-scope-note";
        item.textContent = finding.signature_id + " · " + finding.path + " · HTTP " + (finding.http_status == null ? "unknown" : finding.http_status) + " · signature requires review";
        main.append(item);
      });
      if (!(snapshot.findings || []).length) { var none = document.createElement("p"); none.className = "muted"; none.textContent = "No configured exposure signature was observed in this run. This is not a vulnerability-free assessment."; main.append(none); }
      row.append(main); list.append(row);
    });
    if (changesList) {
      changesList.replaceChildren();
      (body.changes || []).forEach(function (change) {
        var row = document.createElement("article"); row.className = "check-change-row";
        var main = document.createElement("div"); main.className = "check-change-main";
        var field = document.createElement("strong"); field.textContent = change.field_label || change.field_path || "Finding change";
        var actor = document.createElement("small"); actor.textContent = "Run #" + change.run_id + " · detected by " + (change.actor || "system");
        var values = document.createElement("div"); values.className = "check-change-values";
        [["Previous", change.previous_value], ["Current", change.current_value]].forEach(function (pair) {
          var box = document.createElement("div"); var label = document.createElement("span"); label.textContent = pair[0];
          var value = document.createElement("pre"); value.textContent = displayCheckValue(pair[1]); box.append(label, value); values.append(box);
        });
        var time = document.createElement("time"); time.dateTime = change.detected_at || ""; time.textContent = dateLabel(change.detected_at);
        main.append(field, actor, values); row.append(main, time); changesList.append(row);
      });
      if (!(body.changes || []).length) appendEmpty(changesList, "No finding changes have been detected yet; the first complete run is the baseline.");
    }
    var olderRuns = document.querySelector('[data-load-older-active="runs"]');
    var olderChanges = document.querySelector('[data-load-older-active="changes"]');
    if (olderRuns) {
      olderRuns.classList.toggle("hidden", !body.runs_has_more);
      olderRuns.disabled = activeExposureHistory.loading === "runs";
      olderRuns.textContent = activeExposureHistory.loading === "runs" ? "Loading older runs…" : "Load older exposure runs";
    }
    if (olderChanges) {
      olderChanges.classList.toggle("hidden", !body.changes_has_more);
      olderChanges.disabled = activeExposureHistory.loading === "changes";
      olderChanges.textContent = activeExposureHistory.loading === "changes" ? "Loading older changes…" : "Load older finding changes";
    }
  }

  async function loadActiveExposure(olderKind) {
    if (!orgId) return;
    if (olderKind && (!activeExposureHistory[olderKind + "HasMore"] || activeExposureHistory.loading)) return;
    if (!olderKind) activeExposureHistory = { runs: [], changes: [], runsCursor: null, changesCursor: null, runsHasMore: false, changesHasMore: false, loading: null };
    activeExposureHistory.loading = olderKind || null;
    var requestState = activeExposureHistory;
    try {
      var params = new URLSearchParams();
      if (olderKind === "runs") params.set("runs_before", activeExposureHistory.runsCursor);
      if (olderKind === "changes") params.set("changes_before", activeExposureHistory.changesCursor);
      var suffix = params.toString() ? "?" + params.toString() : "";
      var response = await fetch("/api/external-checks/web-active" + suffix, { credentials: "same-origin" });
      var body = await response.json();
      if (requestState !== activeExposureHistory) return;
      if (!response.ok) throw new Error(body.detail || "Could not load active check history");
      if (!olderKind) {
        activeExposureHistory.runs = body.runs || [];
        activeExposureHistory.changes = body.changes || [];
        activeExposureHistory.runsCursor = body.runs_next_before;
        activeExposureHistory.changesCursor = body.changes_next_before;
        activeExposureHistory.runsHasMore = body.runs_has_more;
        activeExposureHistory.changesHasMore = body.changes_has_more;
      } else if (olderKind === "runs") {
        activeExposureHistory.runs = activeExposureHistory.runs.concat(body.runs || []);
        activeExposureHistory.runsCursor = body.runs_next_before;
        activeExposureHistory.runsHasMore = body.runs_has_more;
      } else {
        activeExposureHistory.changes = activeExposureHistory.changes.concat(body.changes || []);
        activeExposureHistory.changesCursor = body.changes_next_before;
        activeExposureHistory.changesHasMore = body.changes_has_more;
      }
      activeExposureHistory.loading = null;
      renderActiveExposure(Object.assign({}, body, {
        runs: activeExposureHistory.runs,
        changes: activeExposureHistory.changes,
        runs_has_more: activeExposureHistory.runsHasMore,
        changes_has_more: activeExposureHistory.changesHasMore
      }));
    } catch (error) {
      if (requestState !== activeExposureHistory) return;
      activeExposureHistory.loading = null;
      if (olderKind) {
        var retryButton = document.querySelector('[data-load-older-active="' + olderKind + '"]');
        if (retryButton) {
          retryButton.disabled = false;
          retryButton.textContent = olderKind === "runs" ? "Load older exposure runs" : "Load older finding changes";
        }
      }
      if (!olderKind) {
        var review = document.getElementById("web-exposure-review");
        if (review) { review.replaceChildren(); appendEmpty(review, "Current exposure evidence could not be refreshed. Review is unavailable until the request succeeds."); }
        text(document.getElementById("web-exposure-outcome"), "Public exposure paths: current evidence unavailable.");
      }
      text(document.getElementById("web-active-feedback"), error.message);
    }
  }

  document.querySelectorAll("[data-load-older-active]").forEach(function (button) {
    button.addEventListener("click", function () { loadActiveExposure(button.dataset.loadOlderActive); });
  });

  var activeExposureButton = document.querySelector("[data-run-active-exposure]");
  function niktoObservationGroup(finding) {
    var id = String(finding.test_id || "");
    if (id === "013587") return "Policy review";
    if (id === "999100" || id === "999962") return "Infrastructure information";
    return "Needs application context";
  }

  function renderNiktoReview(runs) {
    var host = document.getElementById("web-audit-review");
    if (!host) return;
    host.replaceChildren();
    var completed = runs.find(function (run) { return run.status === "completed" || run.status === "completed_with_warnings"; });
    if (!completed) { appendEmpty(host, "No completed deeper audit is available yet."); return; }
    var caption = document.createElement("p"); caption.className = "muted";
    caption.textContent = "Latest completed audit · " + dateLabel(completed.completed_at || completed.started_at)
      + " · run #" + completed.id + ". Groups help review observations; they are not vulnerability severity ratings.";
    host.append(caption);
    var findings = (completed.snapshot || {}).findings || [];
    if (!findings.length) { appendEmpty(host, "No observations retained in this completed audit. Incomplete coverage cannot establish that the site is free of vulnerabilities."); return; }
    ["Policy review", "Needs application context", "Infrastructure information"].forEach(function (group) {
      var items = findings.filter(function (finding) { return niktoObservationGroup(finding) === group; });
      if (!items.length) return;
      var section = document.createElement(group === "Infrastructure information" ? "details" : "section");
      section.className = "topic-observation-group";
      var heading = document.createElement(group === "Infrastructure information" ? "summary" : "h4");
      heading.textContent = group + " · " + items.length;
      section.append(heading);
      items.slice(0, 8).forEach(function (finding) {
        var row = document.createElement("p");
        row.textContent = (finding.description || "Observation requires review") + " · " + finding.method + " " + finding.path;
        section.append(row);
      });
      if (items.length > 8) { var more = document.createElement("p"); more.textContent = (items.length - 8) + " more observations are retained in audit history below."; section.append(more); }
      if (group === "Needs application context") {
        var note = document.createElement("small"); note.textContent = "These detector observations need supporting application evidence before they can be treated as vulnerabilities."; section.append(note);
      }
      host.append(section);
    });
  }

  async function loadNikto(older) {
    var host = document.getElementById("web-nikto-runs");
    if (!host || !orgId || (older && !niktoHistory.hasMore)) return;
    var sequence = ++niktoHistory.sequence;
    try {
      var response = await fetch("/api/external-checks/web-nikto" + (older ? "?runs_before=" + encodeURIComponent(niktoHistory.cursor) : ""), { credentials: "same-origin" });
      var body = await response.json();
      if (!response.ok) throw new Error(body.detail || "Could not load Nikto history");
      if (sequence !== niktoHistory.sequence) return;
      niktoHistory.runs = older ? niktoHistory.runs.concat(body.runs || []) : (body.runs || []);
      renderWebsiteAuditOutcome("web-nikto-outcome", "Deeper website audit", niktoHistory.runs[0]);
      renderNiktoReview(niktoHistory.runs);
      niktoHistory.cursor = body.runs_next_before;
      niktoHistory.hasMore = body.runs_has_more;
      host.replaceChildren();
      niktoHistory.runs.forEach(function (run) {
        var card = document.createElement("article"); card.className = "external-schedule-card";
        var title = document.createElement("h4"); title.textContent = "Run #" + run.id + " · " + String(run.status).replace(/_/g, " ") + " · " + dateLabel(run.completed_at || run.started_at);
        var note = document.createElement("p"); note.className = "muted";
        note.textContent = run.error_summary || "Coverage remains unconfirmed. Comparisons record new observations; absent findings do not prove resolution.";
        card.append(title, note);
        if (role === "admin" && run.status === "queued") {
          var cancel = document.createElement("button"); cancel.type = "button";
          cancel.className = "button button-small button-secondary"; cancel.textContent = "Cancel queued audit";
          cancel.addEventListener("click", async function () {
            cancel.disabled = true;
            try {
              await postJson("/api/external-checks/web-nikto/runs/" + run.id + "/cancel");
              text(document.getElementById("web-nikto-feedback"), "Queued audit #" + run.id + " cancelled.");
              await loadNikto(); await loadAuditLog();
            } catch (error) {
              text(document.getElementById("web-nikto-feedback"), error.message);
              cancel.disabled = false;
            }
          });
          card.append(cancel);
        }
        if (run.queued_at) {
          var timing = document.createElement("p"); timing.className = "muted";
          timing.textContent = "Queued " + dateLabel(run.queued_at) + (run.collection_started_at ? " · Collection started " + dateLabel(run.collection_started_at) : " · Collection start not recorded");
          card.append(timing);
        }
        var findings = (run.snapshot || {}).findings || [];
        var details = document.createElement("details");
        var summary = document.createElement("summary"); summary.textContent = findings.length + " retained observation(s) · " + (run.change_count || 0) + " new compared observation(s)";
        details.append(summary);
        details.addEventListener("toggle", function () {
          if (!details.open || details.dataset.loaded) return;
          details.dataset.loaded = "true";
          findings.forEach(function (finding) {
            var entry = document.createElement("p"); entry.textContent = "Nikto test " + finding.test_id + " · " + finding.method + " " + finding.path + (finding.description ? " · " + finding.description : "");
            details.append(entry);
          });
        });
        card.append(details); host.append(card);
      });
      text(document.getElementById("web-nikto-status"), niktoHistory.runs.length ? "Latest: " + String(niktoHistory.runs[0].status).replace(/_/g, " ") : "No Nikto run yet");
      document.getElementById("older-nikto").classList.toggle("hidden", !niktoHistory.hasMore);
      var button = document.getElementById("run-nikto");
      if (button) button.disabled = !controlsEnabled || niktoHistory.busy || niktoHistory.runs.some(function (run) { return run.status === "queued" || run.status === "running"; });
    } catch (error) {
      if (sequence !== niktoHistory.sequence) return;
      if (!older) {
        var review = document.getElementById("web-audit-review");
        if (review) { review.replaceChildren(); appendEmpty(review, "Current deeper audit evidence could not be refreshed. Review is unavailable until the request succeeds."); }
        text(document.getElementById("web-nikto-outcome"), "Deeper website audit: current evidence unavailable.");
      }
      text(document.getElementById("web-nikto-feedback"), error.message);
    }
  }
  var niktoButton = document.getElementById("run-nikto");
  if (niktoButton) niktoButton.addEventListener("click", async function () {
    niktoHistory.busy = true; niktoButton.disabled = true;
    text(document.getElementById("web-nikto-feedback"), "Submitting website audit. The saved queue continues after you leave this page; collection may take ten minutes.");
    window.setTimeout(function () { loadNikto(); }, 500);
    try {
      var result = await postJson("/api/external-checks/web-nikto/run");
      text(document.getElementById("web-nikto-feedback"), "Run #" + result.id + " saved: " + String(result.status).replace(/_/g, " "));
      await loadAuditLog();
    } catch (error) { text(document.getElementById("web-nikto-feedback"), error.message); }
    finally { niktoHistory.busy = false; await loadNikto(); }
  });
  var olderNikto = document.getElementById("older-nikto");
  if (olderNikto) olderNikto.addEventListener("click", function () { loadNikto(true); });
  if (activeExposureButton) activeExposureButton.addEventListener("click", async function () {
    var original = activeExposureButton.textContent;
    activeExposureButton.disabled = true; text(activeExposureButton, "Checking fixed paths…");
    text(document.getElementById("web-active-feedback"), "The bounded request set can take up to 40 seconds.");
    try {
      var result = await postJson("/api/external-checks/web-active/run");
      text(document.getElementById("web-active-feedback"), "Run #" + result.id + " saved. Load its evidence and coverage state.");
      await loadActiveExposure(); await loadAuditLog();
    } catch (error) { text(document.getElementById("web-active-feedback"), error.message); }
    finally { text(activeExposureButton, original); activeExposureButton.disabled = !controlsEnabled; }
  });

  async function loadExternalCheck(type, olderKind) {
    if (!orgId || !["dns", "web"].includes(type)) return;
    var state = externalCheckHistory[type] || { runs: [], changes: [], runsCursor: null, changesCursor: null, runsHasMore: false, changesHasMore: false, loading: null };
    if (olderKind && (!state[olderKind + "HasMore"] || state.loading)) return;
    if (!olderKind) state = { runs: [], changes: [], runsCursor: null, changesCursor: null, runsHasMore: false, changesHasMore: false, loading: null };
    state.loading = olderKind || null;
    externalCheckHistory[type] = state;
    try {
      var params = new URLSearchParams();
      if (olderKind === "runs") params.set("runs_before", state.runsCursor);
      if (olderKind === "changes") params.set("changes_before", state.changesCursor);
      var suffix = params.toString() ? "?" + params.toString() : "";
      var response = await fetch("/api/external-checks/" + type + suffix, { credentials: "same-origin" });
      var body = await response.json();
      if (state !== externalCheckHistory[type]) return;
      if (!response.ok) throw new Error(body.detail || "Could not load check history");
      if (!olderKind) {
        state.runs = body.runs || [];
        state.changes = body.changes || [];
        state.runsCursor = body.runs_next_before;
        state.changesCursor = body.changes_next_before;
        state.runsHasMore = body.runs_has_more;
        state.changesHasMore = body.changes_has_more;
      } else if (olderKind === "runs") {
        state.runs = state.runs.concat(body.runs || []);
        state.runsCursor = body.runs_next_before;
        state.runsHasMore = body.runs_has_more;
      } else {
        state.changes = state.changes.concat(body.changes || []);
        state.changesCursor = body.changes_next_before;
        state.changesHasMore = body.changes_has_more;
      }
      state.loading = null;
      renderCheckHistory(type, Object.assign({}, body, {
        runs: state.runs,
        changes: state.changes,
        runs_has_more: state.runsHasMore,
        changes_has_more: state.changesHasMore
      }));
    } catch (error) {
      if (state !== externalCheckHistory[type]) return;
      state.loading = null;
      if (olderKind) {
        var retryButton = document.querySelector('[data-load-older-checks="' + type + '"][data-page-kind="' + olderKind + '"]');
        if (retryButton) {
          retryButton.disabled = false;
          retryButton.textContent = olderKind === "runs" ? "Load older check runs" : "Load older changes";
        }
      }
      if (!olderKind) {
        var priorities = document.getElementById(type + "-priorities");
        if (priorities) { priorities.replaceChildren(); appendEmpty(priorities, "Current assessment evidence could not be refreshed. Review is unavailable until the request succeeds."); }
      }
      var target = document.getElementById(type + "-check-runs");
      if (target) {
        target.replaceChildren();
        appendEmpty(target, error.message);
      }
    }
  }

  document.querySelectorAll("[data-load-older-checks]").forEach(function (button) {
    button.addEventListener("click", function () {
      loadExternalCheck(button.dataset.loadOlderChecks, button.dataset.pageKind);
    });
  });

  function notifyExternalCheck(message) {
    if (message && message.source === "schedule" && message.notice_suppressed) return;
    if (!message || message.run_id == null || notifiedCheckRuns[message.run_id]) return;
    notifiedCheckRuns[message.run_id] = true;
    var toast = document.getElementById("check-toast");
    if (!toast) return;
    var moduleName = message.check_type === "dns" ? "DNS" : "Website";
    var textMessage;
    if (message.status === "failed") {
      textMessage = moduleName + " check failed for " + message.domain + ". Open its tab to review the recorded error.";
    } else if (message.status === "completed_with_warnings") {
      textMessage = moduleName + " check completed with warnings for " + message.domain + ". " +
        (message.initial_baseline === true ? "Initial baseline saved; no previous assessment was available for comparison." : message.change_count ? message.change_count + " change(s) were detected." : "No confirmed changes were detected.") +
        " Some checks may be unknown; review the latest run.";
    } else if (message.initial_baseline === true) {
      textMessage = moduleName + " baseline saved for " + message.domain + ". Future checks can compare against this assessment.";
    } else if (message.change_count) {
      textMessage = moduleName + " check found " + message.change_count + " change(s) for " + message.domain + ". Review the change history.";
    } else {
      textMessage = moduleName + " check completed for " + message.domain + " with no detected changes.";
    }
    text(toast, textMessage);
    toast.classList.remove("hidden");
    window.clearTimeout(toast.hideTimer);
    toast.hideTimer = window.setTimeout(function () { toast.classList.add("hidden"); }, 9000);
  }

  function notifyScannerUpdate(payload) {
    var toast = document.getElementById("check-toast");
    if (!toast) return;
    var message = payload.available
      ? "NmapUI " + (payload.latest_version || "update") + " is available on this scanner. Review the scanner event stream."
      : "NmapUI checked its release channel; no update is currently available.";
    text(toast, message);
    toast.classList.remove("hidden");
    window.clearTimeout(toast.hideTimer);
    toast.hideTimer = window.setTimeout(function () { toast.classList.add("hidden"); }, 9000);
  }

  document.querySelectorAll("[data-run-external-check]").forEach(function (button) {
    button.addEventListener("click", async function () {
      var type = button.dataset.runExternalCheck;
      var original = button.textContent;
      button.disabled = true;
      text(button, "Checking…");
      try {
        var run = await postJson("/api/external-checks/" + type + "/run");
        await loadExternalCheck(type);
        notifyExternalCheck({
          run_id: run.id,
          check_type: type,
          domain: run.domain,
          status: run.status,
          change_count: run.change_count,
          initial_baseline: run.initial_baseline,
          fields: run.changed_fields,
          actor: run.actor,
          completed_at: run.completed_at
        });
        await loadAuditLog();
      } catch (error) {
        text(document.getElementById(type + "-check-last-run"), error.message);
      } finally {
        text(button, original);
        button.disabled = false;
      }
    });
  });

  document.querySelectorAll("[data-schedule-enabled]").forEach(function (checkbox) {
    checkbox.addEventListener("change", function () {
      var type = checkbox.dataset.scheduleEnabled;
      var interval = document.querySelector('[data-schedule-interval="' + type + '"]');
      if (interval) interval.disabled = checkbox.disabled || !checkbox.checked;
    });
  });

  document.querySelectorAll("[data-save-schedule]").forEach(function (button) {
    button.addEventListener("click", async function () {
      var type = button.dataset.saveSchedule;
      var checkbox = document.querySelector('[data-schedule-enabled="' + type + '"]');
      var interval = document.querySelector('[data-schedule-interval="' + type + '"]');
      if (!checkbox || !interval) return;
      button.disabled = true;
      var original = button.textContent;
      text(button, "Saving…");
      try {
        var saved = await requestJson("/api/external-checks/" + type + "/schedule", "PUT", {
          enabled: checkbox.checked,
          interval_hours: Number(interval.value)
        });
        renderExternalCheckSchedule(type, saved);
        await loadAuditLog();
      } catch (error) {
        var status = document.getElementById(type + "-schedule-status");
        if (status) {
          status.className = "check-status status-failed";
          text(status, error.message);
        }
      } finally {
        text(button, original);
        button.disabled = false;
      }
    });
  });

  var workspaceDialog = document.getElementById("workspace-dialog");
  document.querySelectorAll("[data-open-workspace-dialog]").forEach(function (button) {
    button.addEventListener("click", function () {
      if (workspaceDialog && !workspaceDialog.open) workspaceDialog.showModal();
    });
  });
  document.querySelectorAll("[data-close-workspace-dialog]").forEach(function (button) {
    button.addEventListener("click", function () {
      if (workspaceDialog) workspaceDialog.close();
    });
  });
  if (workspaceDialog) {
    workspaceDialog.addEventListener("click", function (event) {
      if (event.target === workspaceDialog) workspaceDialog.close();
    });
  }

  function renderWorkspaceList(workspaces) {
    ["dialog-workspace-list", "account-workspace-list"].forEach(function (id) {
      var list = document.getElementById(id);
      if (!list) return;
      list.replaceChildren();
      workspaces.forEach(function (workspace) {
        var row = document.createElement("div");
        row.className = "workspace-request-row";
        var details = document.createElement("div");
        var name = document.createElement("strong");
        name.textContent = workspace.name;
        var domain = document.createElement("small");
        domain.textContent = workspace.domain;
        details.append(name, domain);
        var state = document.createElement("span");
        state.className = "workspace-state";
        state.textContent = workspace.status === "approved" ? workspace.role : workspace.status;
        row.append(details, state);
        if (workspace.status === "approved") {
          var select = document.createElement("button");
          select.type = "button";
          select.className = "button button-small button-quiet";
          select.dataset.selectWorkspace = workspace.id;
          select.textContent = "Open";
          row.append(select);
        }
        list.append(row);
      });
    });
    var workspaceSelect = document.getElementById("workspace-select");
    if (workspaceSelect) {
      workspaceSelect.replaceChildren();
      workspaces.filter(function (workspace) { return workspace.status === "approved"; }).forEach(function (workspace) {
        var option = document.createElement("option");
        option.value = workspace.id;
        option.textContent = workspace.name + " · " + workspace.role;
        option.selected = String(workspace.id) === String(orgId);
        workspaceSelect.append(option);
      });
    }
  }

  async function loadWorkspaces() {
    try {
      var response = await fetch("/api/my-workspaces", { credentials: "same-origin" });
      if (!response.ok) return;
      var workspaces = (await response.json()).workspaces;
      renderWorkspaceList(workspaces);
      syncPendingMembershipFeeds(workspaces);
    } catch (_error) {
      // The account workspace list can retry when the page is refreshed.
    }
  }

  var createWorkspaceForm = document.getElementById("create-workspace-form");
  if (createWorkspaceForm) {
    createWorkspaceForm.addEventListener("submit", async function (event) {
      event.preventDefault();
      var feedback = document.getElementById("workspace-feedback");
      var challenge = document.getElementById("created-challenge");
      challenge.classList.add("hidden");
      text(feedback, "Creating workspace…");
      var form = new FormData(createWorkspaceForm);
      try {
        var body = await postJson("/api/workspaces", {
          name: form.get("name"),
          domain: form.get("domain")
        });
        text(document.getElementById("created-record-name"), body.txt.record_name);
        text(document.getElementById("created-record-value"), body.txt.record_value);
        text(document.getElementById("created-probation"), "Add this record within 30 days. Challenge expires " + new Date(body.txt.expires_at).toLocaleString() + ".");
        text(feedback, body.name + " is ready. Save the DNS record now; Daedalus will switch into this workspace when you continue.");
        challenge.classList.remove("hidden");
        createWorkspaceForm.reset();
      } catch (error) {
        showError(feedback, error.message);
      }
    });
  }

  var openCreatedWorkspace = document.getElementById("open-created-workspace");
  if (openCreatedWorkspace) {
    openCreatedWorkspace.addEventListener("click", function () { window.location.reload(); });
  }

  var requestAccessForm = document.getElementById("request-access-form");
  if (requestAccessForm) {
    requestAccessForm.addEventListener("submit", async function (event) {
      event.preventDefault();
      var feedback = document.getElementById("workspace-feedback");
      text(feedback, "Sending access request…");
      try {
        var form = new FormData(requestAccessForm);
        var body = await postJson("/api/membership-requests", { domain: form.get("domain") });
        clearMembershipNotice();
        var message = body.status === "approved"
          ? "You already have access to " + body.organization + "."
          : "Request sent to " + body.organization + " admin for approval.";
        text(feedback, message);
        requestAccessForm.reset();
        await loadWorkspaces();
      } catch (error) {
        showError(feedback, error.message);
      }
    });
  }

  async function selectWorkspace(id) {
    try {
      await postJson("/api/workspaces/select", { organization_id: Number(id) });
      window.location.reload();
    } catch (error) {
      var feedback = document.getElementById("workspace-feedback");
      showError(feedback, error.message);
    }
  }

  document.addEventListener("click", function (event) {
    var selectButton = event.target.closest("[data-select-workspace]");
    if (selectButton) selectWorkspace(selectButton.dataset.selectWorkspace);
  });
  var workspaceSelect = document.getElementById("workspace-select");
  if (workspaceSelect) {
    workspaceSelect.addEventListener("change", function () {
      selectWorkspace(workspaceSelect.value);
    });
  }

  var issueChallengeButton = document.getElementById("issue-domain-challenge");
  var verifyDomainButton = document.getElementById("verify-domain");
  var verificationFeedback = document.getElementById("verification-feedback");
  if (issueChallengeButton && orgId) {
    issueChallengeButton.addEventListener("click", async function () {
      text(verificationFeedback, "Preparing a DNS TXT record…");
      try {
        var body = await postJson("/api/workspaces/" + orgId + "/domain-challenge");
        if (body.verified) return window.location.reload();
        text(document.getElementById("challenge-record-name"), body.txt.record_name);
        text(document.getElementById("challenge-record-value"), body.txt.record_value);
        text(document.getElementById("challenge-expires"), "Challenge expires " + new Date(body.txt.expires_at).toLocaleString() + ".");
        document.getElementById("dns-challenge").classList.remove("hidden");
        text(verificationFeedback, "Publish the record, wait for DNS to update, then check it here.");
      } catch (error) {
        showError(verificationFeedback, error.message);
      }
    });
  }
  if (verifyDomainButton && orgId) {
    verifyDomainButton.addEventListener("click", async function () {
      text(verificationFeedback, "Checking the public DNS TXT record…");
      try {
        var body = await postJson("/api/workspaces/" + orgId + "/verify-domain");
        if (body.verified) {
          text(verificationFeedback, "Domain verified. Reloading workspace…");
          window.location.reload();
        } else {
          text(verificationFeedback, body.detail || "The TXT record is not visible yet. Try again after DNS updates.");
        }
      } catch (error) {
        showError(verificationFeedback, error.message);
      }
    });
  }

  var grantOverrideForm = document.getElementById("grant-override-form");
  if (grantOverrideForm && orgId) {
    grantOverrideForm.addEventListener("submit", async function (event) {
      event.preventDefault();
      var feedback = document.getElementById("override-feedback");
      var reason = new FormData(grantOverrideForm).get("reason");
      text(feedback, "Recording the 14-day override…");
      try {
        var body = await postJson("/api/workspaces/" + orgId + "/probation-overrides", { reason: reason });
        text(feedback, "Controls are open through " + new Date(body.expires_at).toLocaleString() + ". The grant is in the workspace audit log.");
        window.location.reload();
      } catch (error) {
        showError(feedback, error.message);
      }
    });
  }

  document.querySelectorAll("[data-revoke-override]").forEach(function (button) {
    button.addEventListener("click", async function () {
      button.disabled = true;
      try {
        await postJson("/api/workspaces/" + orgId + "/probation-overrides/" + button.dataset.revokeOverride + "/revoke");
        window.location.reload();
      } catch (error) {
        button.disabled = false;
        text(document.getElementById("override-feedback"), error.message);
      }
    });
  });

  async function loadMemberships() {
    var list = document.getElementById("membership-list");
    if (!list || !orgId) return;
    try {
      var response = await fetch("/api/memberships", { credentials: "same-origin" });
      var body = await response.json();
      if (!response.ok) throw new Error(body.detail || "Could not load workspace members");
      list.replaceChildren();
      if (role !== "admin") {
        text(document.getElementById("member-access-note"), "Your access is scoped to this workspace and uses the user role. Only workspace admins can approve access requests or revoke access.");
        document.getElementById("member-access-note").classList.remove("hidden");
      }
      body.members.forEach(function (member) {
        var row = document.createElement("article");
        row.className = "membership-row";
        var person = document.createElement("div");
        person.className = "membership-person";
        var name = document.createElement("strong");
        name.textContent = member.name || member.email;
        var email = document.createElement("small");
        email.textContent = member.email;
        person.append(name, email);
        var meta = document.createElement("div");
        meta.className = "membership-meta";
        meta.textContent = member.role + " · " + member.status;
        row.append(person, meta);
        if (role === "admin" && member.status === "pending") {
          var actions = document.createElement("div");
          actions.className = "membership-actions";
          [true, false].forEach(function (approve) {
            var button = document.createElement("button");
            button.type = "button";
            button.className = approve ? "button button-small" : "button button-small button-quiet";
            button.dataset.membershipDecision = String(approve);
            button.dataset.membershipId = member.id;
            button.disabled = !controlsEnabled;
            button.textContent = approve ? "Approve as user" : "Deny";
            actions.append(button);
          });
          row.append(actions);
        } else if (role === "admin" && member.status === "approved") {
          var actions = document.createElement("div");
          actions.className = "membership-actions";
          var roleButton = null;
          if (member.role === "user") {
            roleButton = document.createElement("button");
            roleButton.dataset.membershipRole = "admin";
            roleButton.textContent = "Promote to admin";
          } else if (member.role === "admin" && body.approved_admin_count > 1) {
            roleButton = document.createElement("button");
            roleButton.dataset.membershipRole = "user";
            roleButton.textContent = member.is_self ? "Transfer admin and switch to user" : "Change to user";
          }
          if (roleButton) {
            roleButton.type = "button";
            roleButton.className = "button button-small button-quiet";
            roleButton.dataset.membershipId = member.id;
            roleButton.dataset.membershipEmail = member.email;
            roleButton.dataset.membershipSelf = String(member.is_self);
            roleButton.disabled = !controlsEnabled;
            actions.append(roleButton);
          }
          if (member.role === "user") {
            var revoke = document.createElement("button");
            revoke.type = "button";
            revoke.className = "button button-small button-quiet membership-revoke";
            revoke.dataset.membershipRevoke = member.id;
            revoke.dataset.membershipEmail = member.email;
            revoke.textContent = "Remove access";
            actions.append(revoke);
          }
          if (actions.childElementCount) row.append(actions);
        }
        list.append(row);
      });
      if (!body.members.length) {
        var empty = document.createElement("div");
        empty.className = "empty-events";
        empty.textContent = "No members have been added to this workspace yet.";
        list.append(empty);
      }
    } catch (error) {
      list.replaceChildren();
      var message = document.createElement("div");
      message.className = "empty-events";
      message.textContent = error.message;
      list.append(message);
    }
  }

  async function loadAuditLog() {
    var list = document.getElementById("audit-log-list");
    if (!list || !orgId || role !== "admin") return;
    try {
      var response = await fetch("/api/audit-log", { credentials: "same-origin" });
      var body = await response.json();
      if (!response.ok) throw new Error(body.detail || "Could not load workspace audit history");
      list.replaceChildren();
      body.events.forEach(function (entry) {
        var row = document.createElement("article");
        row.className = "audit-log-row";
        var main = document.createElement("div");
        var title = document.createElement("strong");
        title.textContent = entry.action.replaceAll("_", " ").replaceAll(".", " · ");
        var actor = document.createElement("small");
        actor.textContent = "by " + entry.actor;
        main.append(title, actor);
        var time = document.createElement("time");
        time.textContent = dateLabel(entry.created_at);
        var details = document.createElement("pre");
        details.textContent = JSON.stringify(entry.details || {}, null, 2);
        row.append(main, time, details);
        list.append(row);
      });
      if (!body.events.length) {
        var empty = document.createElement("div");
        empty.className = "empty-events";
        empty.textContent = "No workspace admin actions have been recorded yet.";
        list.append(empty);
      }
    } catch (error) {
      list.replaceChildren();
      var message = document.createElement("div");
      message.className = "empty-events";
      message.textContent = error.message;
      list.append(message);
    }
  }

  function notificationReviewLabel(tab) {
    var labels = {
      dns: "Review DNS",
      web: "Review website",
      meraki: "Review Meraki",
      cis: "Review CIS",
      scanners: "Review scanners",
      members: "Review access"
    };
    return labels[tab] || "Review website";
  }

  function notificationEmptyMessage() {
    return "No security changes, warnings, or audit notices have been recorded for this workspace.";
  }

  function readableNotificationSummary(summary) {
    return String(summary || "")
      .replace(/(?:page_content\.[a-z0-9_]+)(?:,\s*page_content\.[a-z0-9_]+)*/gi, "page content")
      .replace(/\brecords\.([A-Z][A-Z0-9_]*)\b/g, function (_match, field) {
        return "DNS record " + field.replace(/^WWW_/, "www ").replaceAll("_", " ");
      })
      .replace(/(\d+) material change\(s\) detected/g, function (_match, count) {
        return count + " material " + (Number(count) === 1 ? "change" : "changes") + " detected";
      });
  }

  async function loadNotifications() {
    if (!orgId) return;
    var list = document.getElementById("notification-list");
    var status = document.getElementById("notification-inbox-status");
    try {
      var response = await fetch("/api/notifications", { credentials: "same-origin" });
      var body = await response.json();
      if (!response.ok) throw new Error(body.detail || "Could not load notifications");
      var badge = document.getElementById("notification-badge");
      if (badge) {
        badge.textContent = body.unread_count > 99 ? "99+" : String(body.unread_count);
        badge.classList.toggle("hidden", body.unread_count < 1);
      }
      text(status, body.unread_count ? body.unread_count + " unread notification(s)" : "You are all caught up.");
      if (!list) return;
      list.replaceChildren();
      body.notifications.forEach(function (notice) {
        var row = document.createElement("article");
        row.className = "notification-row" + (notice.read_at ? " is-read" : " is-unread");
        var main = document.createElement("div");
        main.className = "notification-main";
        var title = document.createElement("strong");
        title.textContent = notice.title;
        var summary = document.createElement("p");
        summary.textContent = readableNotificationSummary(notice.summary);
        var time = document.createElement("time");
        time.dateTime = notice.detected_at;
        time.textContent = "Detected " + dateLabel(notice.detected_at);
        var reason = document.createElement("small");
        reason.textContent = notice.reason.replaceAll("_", " ");
        main.append(title, summary, reason);
        var actions = document.createElement("div");
        actions.className = "notification-actions";
        actions.append(time);
        var open = document.createElement("button");
        open.type = "button";
        open.className = "button button-secondary";
        open.textContent = notificationReviewLabel(notice.tab);
        open.dataset.notificationOpen = String(notice.id);
        open.dataset.notificationTab = notice.tab;
        open.dataset.notificationRead = notice.read_at ? "true" : "false";
        actions.append(open);
        row.append(main, actions);
        list.append(row);
      });
      if (!body.notifications.length) {
        var empty = document.createElement("div");
        empty.className = "empty-events";
        empty.textContent = notificationEmptyMessage();
        list.append(empty);
      }
    } catch (error) {
      text(status, error.message);
      if (list) { list.replaceChildren(); appendEmpty(list, error.message); }
    }
  }

  document.addEventListener("click", async function (event) {
    var notificationOpen = event.target.closest("[data-notification-open]");
    if (notificationOpen) {
      var notificationId = notificationOpen.dataset.notificationOpen;
      try {
        if (notificationOpen.dataset.notificationRead !== "true") {
          var readResponse = await fetch("/api/notifications/" + encodeURIComponent(notificationId) + "/read", {
            method: "POST", credentials: "same-origin"
          });
          var readBody = await readResponse.json();
          if (!readResponse.ok) throw new Error(readBody.detail || "Could not mark notification read");
        }
        await loadNotifications();
        activateTab(notificationOpen.dataset.notificationTab, true);
      } catch (error) {
        text(document.getElementById("notification-inbox-status"), error.message);
      }
      return;
    }
    var decision = event.target.closest("[data-membership-decision]");
    if (!decision) return;
    decision.disabled = true;
    try {
      await postJson("/api/memberships/" + decision.dataset.membershipId + "/decision", {
        approve: decision.dataset.membershipDecision === "true"
      });
      await Promise.all([loadMemberships(), loadAuditLog()]);
    } catch (error) {
      text(document.getElementById("member-access-note"), error.message);
      document.getElementById("member-access-note").classList.remove("hidden");
      decision.disabled = false;
    }
  });

  document.addEventListener("click", function (event) {
    var roleButton = event.target.closest("[data-membership-role]");
    if (!roleButton) return;
    var targetRole = roleButton.dataset.membershipRole;
    var selfChange = roleButton.dataset.membershipSelf === "true";
    var actionDescription = targetRole === "admin" ? "promote " : "change to user: ";
    var confirmation = selfChange
      ? "Transfer admin control to another approved member and switch your account to the user role?"
      : "Confirm " + actionDescription + roleButton.dataset.membershipEmail + "?";
    requestInlineConfirmation(roleButton, confirmation, selfChange ? "Transfer admin" : (targetRole === "admin" ? "Promote to admin" : "Change to user"), async function () {
      try {
        await postJson("/api/memberships/" + roleButton.dataset.membershipId + "/role", { role: targetRole });
        if (selfChange) {
          window.location.reload();
          return;
        }
        text(document.getElementById("member-access-note"), "Administrator access updated. The change is recorded in the workspace audit log.");
        document.getElementById("member-access-note").classList.remove("hidden");
        await Promise.all([loadMemberships(), loadAuditLog()]);
      } catch (error) {
        text(document.getElementById("member-access-note"), error.message);
        document.getElementById("member-access-note").classList.remove("hidden");
        throw error;
      }
    });
  });

  document.addEventListener("click", function (event) {
    var revoke = event.target.closest("[data-membership-revoke]");
    if (!revoke) return;
    requestInlineConfirmation(revoke, "Remove " + revoke.dataset.membershipEmail + " from this workspace? They will need admin approval to rejoin.", "Remove access", async function () {
      try {
        await postJson("/api/memberships/" + revoke.dataset.membershipRevoke + "/revoke");
        text(document.getElementById("member-access-note"), "Workspace access was removed. The action is recorded in the audit log.");
        document.getElementById("member-access-note").classList.remove("hidden");
        await Promise.all([loadMemberships(), loadAuditLog()]);
      } catch (error) {
        text(document.getElementById("member-access-note"), error.message);
        document.getElementById("member-access-note").classList.remove("hidden");
        throw error;
      }
    });
  });

  if (orgId) {
    refresh();
    // Heartbeat status expires on the server even when the live stream is quiet.
    window.setInterval(function () { if (!document.hidden) { refresh(); if (activeTab === "web") { loadActiveExposure(); loadNikto(); } } }, 15000);
    document.addEventListener("visibilitychange", function () { if (!document.hidden) { refresh(); if (activeTab === "web") { loadActiveExposure(); loadNikto(); } } });
  }
  loadWorkspaces();
  loadMemberships();
  loadAuditLog();
  loadNotifications();
})();
