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
  function fetch(url, options) {
    // Bind API requests to the workspace rendered in this document.
    if (orgId && typeof url === "string" && url.startsWith("/api/")) {
      var headers = new Headers(options && options.headers);
      headers.set("X-Daedalus-Workspace", orgId);
      options = Object.assign({}, options, {headers: headers});
    }
    return window.fetch(url, options);
  }
  var postureRequestSequence = 0;
  var workspacePostureRead = {body: null, signature: null, error: null, loading: false, controller: null, mutationBusy: false,
    publicCheckRetryTypes: null, publicCheckFeedback: ""};
  var portfolioRead = {body: null, signature: null, error: null, loading: false, controller: null, sequence: 0};
  var workspaceSelectionBusy = false;
  var reportHistories = Object.create(null);
  var notificationHistory = null;
  var role = shell ? shell.dataset.role : null;
  var verificationStatus = shell ? shell.dataset.verificationStatus : null;
  var controlsEnabled = shell ? shell.dataset.controlsEnabled === "true" : false;
  var notifiedCheckRuns = Object.create(null);
  var externalCheckHistory = Object.create(null);
  var savedCheckHistories = Object.create(null);
  var activeExposureHistory = { runs: [], changes: [], runsCursor: null, changesCursor: null, runsHasMore: false, changesHasMore: false, loading: null };
  var cisWorkspaceRead = { bodies: null, sequence: 0, loading: false, error: null, invalidated: false, mutationBusy: false, controller: null };
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
  var probationApproval = null;
  var scannerComparisonCache = new Map();
  var titleMap = {
    overview: "Workspace overview",
    portfolio: "All customers",
    scanners: "Internal network",
    meraki: "Meraki security report",
    "google-admin": "Google Admin security",
    dns: "DNS & email health",
    web: "Website health",
    cis: "Endpoint compliance",
    reports: "Report library",
    members: "Members & access",
    notifications: "Security notifications"
  };
  var activeTab = null;
  var auditReview = null;
  var workspaceRequests = null;
  var customerCreation = null;
  var membershipReview = window.DaedalusMembershipReview ? window.DaedalusMembershipReview.create({
    organizationId: orgId,
    fetch: function (url, options) { return fetch(url, options); },
    confirm: requestInlineConfirmation,
    onRoleObserved: function (canManage) {if ((role === "admin") !== canManage) window.location.reload();},
    onSaved: function () { return loadAuditLog(); },
    onSelfRoleChange: function () { window.location.reload(); }
  }) : null;
  window.daedalusMembers = membershipReview;


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
    if (name === "portfolio") loadPortfolio();
    if (name === "meraki") loadMeraki();
    if (name === "google-admin") { if (window.daedalusGoogleAdmin) window.daedalusGoogleAdmin.load(); loadReports(); }
    if (name === "cis") { loadCIS(); loadReports(); }
    if (name === "dns" || name === "web") loadExternalCheck(name);
    if (name === "web") { loadActiveExposure(); loadNikto(); }
    if (name === "reports") loadReports();
    if (name === "notifications") loadNotifications();
    if (name === "members") {loadMemberships();loadAuditLog();}
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
            if (workspaceDialog && !workspaceDialog.open) {workspaceDialog.showModal();loadWorkspaces();}
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
      makeAuditMetric("Online scanners", counts.online + "/" + counts.enabled, "Enabled scanners with a current bridge heartbeat", counts.enabled && counts.online === counts.enabled ? "good" : "attention"),
      makeAuditMetric("Scan engine ready", String(counts.ready), "Online scanners with confirmed NmapUI readiness", counts.ready ? "good" : "attention"),
      makeAuditMetric("Approved scope", counts.scoped + "/" + counts.enabled, "Scanners assigned one or more private network ranges", counts.enabled && counts.scoped === counts.enabled ? "good" : "attention")
    );
    var note = document.createElement("p"); note.className = "muted";
    note.textContent = !counts.enabled ? (document.getElementById("add-scanner")
          ? "No enabled scanner is enrolled. Add a scanner for each network location you want to assess."
          : "No enabled scanner is enrolled. Ask a workspace admin to add a scanner for each network location.")
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
    var evidenceHosts = observation.xml_coverage_host_count;
    if (Number.isInteger(evidenceHosts) && evidenceHosts >= 0 && evidenceHosts <= observation.host_count) {
      metrics.append(makeAuditMetric("Coverage evidence", evidenceHosts + "/" + observation.host_count,
        "Observed hosts whose original scan evidence identifies the target and tested ports",
        evidenceHosts > 0 && evidenceHosts === observation.host_count ? "neutral" : "attention"));
    }
    var tested = [];
    ["tcp", "udp", "sctp"].forEach(function (protocol) {
      var count = observation.xml_scanned_port_counts && observation.xml_scanned_port_counts[protocol];
      if (Number.isSafeInteger(count) && count > 0) tested.push(protocol.toUpperCase() + " " + count.toLocaleString("en-US"));
    });
    var note = document.createElement("p"); note.className = "check-scope-note";
    note.textContent = "Results collected " + dateLabel(observation.collected_at) + ". " +
      (Array.isArray(observation.covered_targets) ? "Targets in saved coverage evidence: " + observation.covered_targets.join(", ") +
        (Number.isInteger(observation.additional_covered_targets) && observation.additional_covered_targets > 0 ? " (" + observation.additional_covered_targets + " more targets in the saved run)" : "") + ". " : "Target coverage was not explicitly reported. ") +
      (tested.length ? "Ports tested across hosts with matching original evidence: " + tested.join(" · ") + ". " : "") +
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
    appendScannerActivity(card, agent);
    appendScannerDelivery(card, agent);

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
    if (agent.enabled !== false && agent.bridge_online === true &&
        (agent.connection_scope === "outside" || agent.connection_scope === "partial")) {
      var connectionNotice = document.createElement("p");
      connectionNotice.className = "scanner-connection-notice";
      connectionNotice.textContent = (agent.connection_scope === "outside"
        ? "Current connection is outside the approved scan scope. "
        : "Current connection is only partly covered by the approved scan scope. ") +
        "Confirm a route to the approved target, reconnect to its network, or ask an admin to review scope. Detected networks do not grant scan permission.";
      card.append(connectionNotice);
    }
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

  function appendScannerActivity(card, agent) {
    card.scannerActivityAgent = agent;
    var section = document.createElement("section"); section.className = "scanner-current-activity";
    var heading = document.createElement("h4"); heading.textContent = "Current scanner activity";
    var summary = document.createElement("p"); summary.className = "scanner-activity-summary";
    var activity = agent.nmapui_activity;
    var observed = activity && Date.parse(activity.observed_at);
    var valid = agent.enabled !== false && agent.status !== "disabled" && agent.bridge_online === true && agent.nmapui_ready !== false && activity &&
      activity.schema_version === 1 && ["idle", "maintenance", "running"].includes(activity.state) &&
      Number.isFinite(observed) && observed <= Date.now() + 5000 && Date.now() - observed <= 45000 &&
      Number.isInteger(activity.active_job_count) && activity.active_job_count >= 0 && activity.active_job_count <= 128 &&
      Array.isArray(activity.jobs) && activity.jobs.length === Math.min(activity.active_job_count, 8) &&
      activity.truncated === (activity.active_job_count > 8) &&
      (activity.state === "running") === (activity.active_job_count > 0) && activity.jobs.every(function (job) {
        return job && ["scan", "report", "other"].includes(job.job_type) && ["running", "cancelling"].includes(job.status) &&
          (job.target === null || (typeof job.target === "string" && job.target.length > 0 && job.target.length <= 255 && !/[\x00-\x1f\x7f]/.test(job.target))) &&
          (job.progress === null || (typeof job.progress === "number" && Number.isFinite(job.progress) && job.progress >= 0 && job.progress <= 100));
      });
    summary.textContent = !valid ? (agent.enabled === false || agent.status === "disabled"
      ? "Activity unavailable · scanner access revoked"
      : agent.bridge_online !== true ? "Current activity unknown · scanner bridge offline"
      : "Current activity unknown · a fresh runtime observation is unavailable")
      : activity.state === "maintenance" ? "Maintenance · new scans and reports are paused"
      : activity.state === "idle" ? "Idle · no active jobs observed"
      : activity.active_job_count + " active " + (activity.active_job_count === 1 ? "job" : "jobs");
    section.append(heading, summary);
    if (valid && activity.state === "running") {
      activity.jobs.forEach(function (job) {
        var row = document.createElement("div"); row.className = "scanner-active-job";
        var label = document.createElement("p");
        label.textContent = ({scan: "Scan", report: "Report", other: "Scanner job"}[job.job_type]) +
          " · " + (job.status === "cancelling" ? "Cancellation requested" : "Running") +
          " · " + (job.target || "Target not reported") +
          (job.progress === null ? " · Progress not reported" : " · " + job.progress + "% reported");
        row.append(label);
        if (job.progress !== null) {
          var track = document.createElement("div"); track.className = "report-progress-track";
          track.setAttribute("role", "progressbar"); track.setAttribute("aria-label", "Reported " + job.job_type + " progress");
          track.setAttribute("aria-valuemin", "0"); track.setAttribute("aria-valuemax", "100"); track.setAttribute("aria-valuenow", String(job.progress));
          var fill = document.createElement("span"); fill.className = "report-progress-bar"; fill.style.width = job.progress + "%";
          track.append(fill); row.append(track);
        }
        section.append(row);
      });
      if (activity.truncated) {
        var more = document.createElement("p"); more.textContent = "Showing 8 of " + activity.active_job_count + " active jobs. Open the local scanner for all activity.";
        section.append(more);
      }
    }
    var note = document.createElement("p"); note.className = "check-scope-note";
    note.textContent = (valid ? "Runtime observed " + new Date(observed).toLocaleString() + ". " : "") +
      "Current activity is separate from saved results. An idle observation does not confirm that an earlier scan completed.";
    section.append(note); card.append(section);
    return section;
  }

  function appendScannerDelivery(card, agent) {
    var section = document.createElement("section"); section.className = "scanner-upload-delivery";
    var heading = document.createElement("h4"); heading.textContent = "Results delivery";
    var summary = document.createElement("p");
    var delivery = agent.upload_delivery;
    var observed = delivery && typeof delivery.observed_at === "string" && Date.parse(delivery.observed_at);
    var fields = ["schema_version", "state", "pending_events", "review_events", "preservation_failed", "last_acknowledged_at", "observed_at"];
    var fresh = agent.enabled !== false && agent.status !== "disabled" && agent.bridge_online === true &&
      delivery && Object.keys(delivery).length === fields.length && fields.every(function (field) { return Object.prototype.hasOwnProperty.call(delivery, field); }) &&
      delivery.schema_version === 1 && Number.isFinite(observed) &&
      observed <= Date.now() && Date.now() - observed <= 45000;
    var valid = fresh && delivery.state === "observed" &&
      Number.isInteger(delivery.pending_events) && delivery.pending_events >= 0 && delivery.pending_events <= 10000 &&
      Number.isInteger(delivery.review_events) && delivery.review_events >= 0 && delivery.review_events <= 10000 &&
      typeof delivery.preservation_failed === "boolean" &&
      (delivery.last_acknowledged_at === null || (typeof delivery.last_acknowledged_at === "string" && Number.isFinite(Date.parse(delivery.last_acknowledged_at))));
    summary.textContent = !valid ? "Current upload queue unknown · a fresh observation is unavailable"
      : delivery.pending_events + " upload(s) queued · " + delivery.review_events + " retained for review";
    var unknownFailure = fresh && delivery.state === "unknown" && delivery.pending_events === null && delivery.review_events === null && delivery.last_acknowledged_at === null && delivery.preservation_failed === true;
    if (unknownFailure) summary.textContent = "Upload queue unknown · a local event save did not finish";
    if (valid && delivery.preservation_failed) summary.textContent += " · a local event save did not finish";
    if (unknownFailure || (valid && (delivery.review_events > 0 || delivery.preservation_failed))) section.classList.add("upload-needs-review");
    var note = document.createElement("p"); note.className = "check-scope-note";
    note.textContent = (valid ? "Queue observed " + new Date(observed).toLocaleString() + ". " : "") + "An empty queue does not prove scan completeness. Review the saved run and its coverage.";
    var ack = valid && delivery.last_acknowledged_at && Date.parse(delivery.last_acknowledged_at);
    if (Number.isFinite(ack) && ack <= Date.now()) note.textContent += " Last upload acknowledged " + new Date(ack).toLocaleString() + ".";
    if (valid && delivery.pending_events > 0) note.textContent += " Keep the bridge running; queued evidence is retried automatically.";
    if (unknownFailure || (valid && (delivery.review_events > 0 || delivery.preservation_failed))) note.textContent += " Keep local evidence and review the scanner's logs and available storage before relying on this run.";
    section.append(heading, summary, note); card.append(section); return section;
  }

  function refreshScannerActivities(agents) {
    var list = document.getElementById("agent-list");
    if (!list) return;
    Array.from(list.children).forEach(function (card) {
      var agent = Array.isArray(agents) ? agents.find(function (candidate) { return String(candidate.id) === card.dataset.agentId; }) : card.scannerActivityAgent;
      if (!agent) return;
      var prior = card.querySelector(".scanner-current-activity");
      var updated = appendScannerActivity(card, agent);
      if (prior) prior.replaceWith(updated);
      var priorDelivery = card.querySelector(".scanner-upload-delivery");
      var updatedDelivery = appendScannerDelivery(card, agent);
      if (priorDelivery) priorDelivery.replaceWith(updatedDelivery);
    });
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

  function pauseRestrictedWorkspaceControls() {
    if (controlsEnabled) return;
    document.querySelectorAll('#add-scanner, [data-open-enrollment], #issue-scanner-enrollment, [data-command="start_scan"], [data-save-scanner-scope], [data-run-active-exposure], #run-nikto, [data-membership-decision="true"], [data-pending-approval="true"], [data-membership-role]').forEach(function (button) {
      button.disabled = true;
    });
  }

  function workspaceAccessPresentation(organization, now) {
    var verified = organization.verification_status === "verified";
    var available = organization.controls_enabled === true;
    var moment = Number.isFinite(now) ? now : Date.now();
    function deadline(value) {
      var parsed = value ? new Date(value).getTime() : NaN;
      return Number.isFinite(parsed) ? new Date(parsed).toLocaleString() : "date unavailable";
    }
    var verificationTime = organization.verification_expires_at ? new Date(organization.verification_expires_at).getTime() : NaN;
    var onboarding = organization.onboarding;
    return {
      ownership: verified ? "Verified" : "Awaiting TXT verification",
      controls: available ? "Controls available" : "Controls paused",
      capabilities: available ? "Available to workspace admins" : "Paused pending verification or approval",
      explanation: verified ? "Domain ownership is verified." : available ? "Temporary approval provides access while domain ownership is pending." : "Public DNS and website checks and saved reports remain available.",
      verification: verified ? "" : Number.isFinite(verificationTime) ? "Ownership verification window " + (verificationTime <= moment ? "ended " : "ends ") + deadline(organization.verification_expires_at) + "." : "Ownership verification deadline is unavailable.",
      onboarding: onboarding && onboarding.status === "onboarding" ? (onboarding.review_required === true ? "Onboarding approval is overdue. Review was due " : "Onboarding review due ") + deadline(onboarding.review_due_at) + "." : "",
      override: organization.probation_override_expires_at ? "Temporary admin approval ends " + deadline(organization.probation_override_expires_at) + "." : ""
    };
  }

  function renderWorkspaceAccess(organization) {
    var summary = workspaceAccessPresentation(organization);
    var fields = {
      "access-ownership-state": summary.ownership,
      "access-controls-state": summary.controls,
      "access-capabilities": summary.capabilities,
      "access-control-explanation": summary.explanation,
      "access-verification-deadline": summary.verification,
      "access-onboarding-status": summary.onboarding,
      "access-override-status": summary.override
    };
    Object.keys(fields).forEach(function (id) {
      var node = document.getElementById(id);
      if (!node) return;
      if (node.textContent !== fields[id]) text(node, fields[id]);
      node.hidden = !fields[id];
    });
    var state = document.getElementById("access-controls-state");
    if (state) state.classList.toggle("is-paused", organization.controls_enabled !== true);
    var ownership = document.getElementById("domain-verification-details");
    if (ownership) ownership.hidden = organization.verification_status === "verified";
    var approval = document.getElementById("probation-override-card");
    var refreshActions = document.getElementById("access-actions-refresh");
    if (typeof probationApproval !== "undefined" && probationApproval) {
      probationApproval.observe(organization);
      if (refreshActions) refreshActions.hidden = true;
    } else if (approval && approval.dataset) {
      var approvalChanged = (approval.dataset.overrideExpires || "") !== (organization.probation_override_expires_at || "");
      var unnecessaryGrant = organization.verification_status === "verified" && !organization.probation_override_expires_at;
      approval.hidden = approvalChanged || unnecessaryGrant;
      if (refreshActions) refreshActions.hidden = !approvalChanged || unnecessaryGrant;
    }
  }

  function updateWorkspaceControls(organization) {
    var controlsJustClosed = controlsEnabled && organization.controls_enabled !== true;
    controlsEnabled = organization.controls_enabled === true;
    if (!controlsEnabled && membershipReview) membershipReview.pauseApproval();
    var controlsNotice = document.getElementById("workspace-controls-notice");
    if (controlsNotice && controlsJustClosed) {
      controlsNotice.textContent = "Temporary workspace access has closed. Scanner enrollment, new scans and active website audits are paused. Review domain verification, onboarding approval or the temporary override. Saved results remain available.";
      controlsNotice.classList.remove("hidden");
    } else if (controlsNotice && controlsEnabled) controlsNotice.classList.add("hidden");
    renderWorkspaceAccess(organization);
    pauseRestrictedWorkspaceControls();
    // Static controls also recover after a remote approval. Request state is
    // separate from authorization so an in-flight action stays disabled.
    ["add-scanner", "issue-scanner-enrollment"].forEach(function (id) {
      var button = document.getElementById(id);
      if (button) button.disabled = !controlsEnabled || button.dataset.requestBusy === "true";
    });
    var exposure = document.querySelector("[data-run-active-exposure]");
    if (exposure) exposure.disabled = !controlsEnabled || exposure.dataset.requestBusy === "true";
    var nikto = document.getElementById("run-nikto");
    if (nikto) nikto.disabled = !controlsEnabled || Boolean(niktoHistory && (niktoHistory.busy || niktoHistory.runs.some(function (run) { return run.status === "queued" || run.status === "running"; })));
    var scannerPauseNote = document.getElementById("scanner-access-paused");
    if (scannerPauseNote) scannerPauseNote.hidden = controlsEnabled;
  }

  function render(data) {
    verificationStatus = data.organization.verification_status;
    updateWorkspaceControls(data.organization);
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
          empty.textContent = document.getElementById("add-scanner")
            ? controlsEnabled ? "No scanner connected yet. Use Add scanner to enroll a scanner for this network." : "No scanner connected yet. Review Overview → Workspace access before enrolling a scanner."
            : "No scanner connected yet. Ask a workspace admin to enroll a scanner for this network.";
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
    pauseRestrictedWorkspaceControls();
  }

  document.querySelectorAll(".workspace-icon[data-icon-src]").forEach(function (holder) {
    var image = new Image();
    image.alt = "";
    image.onload = function () { holder.textContent = ""; holder.classList.add("has-image"); holder.append(image); };
    image.src = holder.dataset.iconSrc;
  });

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

  function workspaceEvidenceTime(value, now) {
    if (typeof value !== "string" || !/T.*(?:Z|[+-]\d{2}:\d{2})$/.test(value)) return null;
    var timestamp = new Date(value).getTime();
    return Number.isFinite(timestamp) && timestamp <= now ? timestamp : null;
  }

  function workspaceAreaPresentation(area, now) {
    area = area && typeof area === "object" ? area : {};
    now = Number.isFinite(now) ? now : Date.now();
    var known = ["recorded", "attention", "unavailable", "not_assessed", "running"];
    var state = known.indexOf(area.state) >= 0 ? area.state : "unknown";
    var timestamp = workspaceEvidenceTime(area.updated_at, now);
    var hasEvidence = timestamp !== null && state !== "not_assessed" && state !== "unknown";
    var labels = {recorded: "Evidence saved", attention: "Review evidence", unavailable: "Latest attempt failed",
      not_assessed: "Not assessed", running: "Check running", unknown: "Assessment status unknown"};
    var level = state === "unavailable" ? "bad" : state === "attention" || state === "unknown" ? "warn"
      : state === "not_assessed" || state === "running" ? "idle" : "ok";
    var verdict = labels[state];
    var unknownTime = state !== "not_assessed" && (area.updated_at != null || state === "recorded") && timestamp === null;
    if (state === "recorded" && timestamp === null) { level = "warn"; verdict = "Evidence time unknown"; }
    else if (state === "recorded" && now - timestamp > 48 * 3600 * 1000) { level = "warn"; verdict = "Evidence needs refresh"; }
    var when = hasEvidence ? "Saved evidence " + dateLabel(area.updated_at)
      : state === "unknown" ? "Saved evidence source unknown"
      : unknownTime ? "Saved evidence time needs review" : "No saved assessment time";
    if (hasEvidence && (state === "unavailable" || state === "running")) when += " · earlier evidence retained";
    var schedule = area.schedule;
    var interval = schedule && Number.isInteger(schedule.interval_hours) && schedule.interval_hours > 0 ? schedule.interval_hours : null;
    var scheduleLabel = !schedule ? "" : schedule.enabled === false ? "Automatic checks off"
      : schedule.enabled === true && interval !== null ? "Automatic checks every " + interval + " hours" : "Schedule unknown";
    var reviewLabel = state === "not_assessed" ? "Review setup" : state === "running" ? "Review progress"
      : state === "unavailable" ? "Review attempt" : state === "unknown" ? "Review status" : "Review findings";
    return {area: area, state: state, level: level, verdict: verdict, when: when, hasEvidence: hasEvidence,
      unknownTime: unknownTime, scheduleLabel: scheduleLabel, interval: interval,
      enableSchedule: !!schedule && schedule.enabled === false && (interval === 24 || interval === 168) && (area.key === "dns" || area.key === "web"),
      reviewLabel: reviewLabel};
  }

  function workspaceStatusSummary(areas, now) {
    var rows = (Array.isArray(areas) ? areas : []).map(function (area) { return workspaceAreaPresentation(area, now); });
    var order = {bad: 0, warn: 1, idle: 2, ok: 3};
    rows.sort(function (left, right) { return order[left.level] - order[right.level]; });
    var review = rows.filter(function (row) { return row.level === "bad" || row.level === "warn"; }).length;
    var missing = rows.filter(function (row) { return row.state === "not_assessed"; }).length;
    var running = rows.filter(function (row) { return row.state === "running"; }).length;
    var unknown = rows.filter(function (row) { return row.state === "unknown" || row.unknownTime; }).length;
    var saved = rows.filter(function (row) { return row.hasEvidence; }).length;
    var headline = !rows.length ? "Assessment coverage unavailable"
      : review ? review + (review === 1 ? " area needs review" : " areas need review")
      : missing ? missing + (missing === 1 ? " area not assessed" : " areas not assessed")
      : running ? "Checks are running" : "Saved evidence available";
    var details = [saved + " of " + rows.length + " areas have dated saved evidence"];
    if (missing) details.push(missing + " not assessed");
    if (running) details.push(running + " in progress");
    if (unknown) details.push(unknown + " with unknown status or time");
    return {rows: rows, review: review, missing: missing, running: running, unknown: unknown, saved: saved,
      headline: headline, detail: details.join(" · "), level: rows.length ? rows[0].level : "warn"};
  }

  function areaLevel(area) {
    return workspaceAreaPresentation(area).level;
  }

  function updatePortfolioReadState() {
    var read = portfolioRead;
    var refresh = document.getElementById("portfolio-refresh");
    if (refresh) {
      if (!refresh.dataset.bound) { refresh.dataset.bound = "true"; refresh.addEventListener("click", function () { return loadPortfolio(); }); }
      refresh.textContent = read.error ? "Retry customer status" : "Refresh customer status";
      refresh.setAttribute("aria-busy", String(read.loading));
      refresh.setAttribute("aria-disabled", String(workspaceSelectionBusy));
    }
    var observed = document.getElementById("portfolio-observed");
    if (observed) observed.textContent = read.body ? (read.error ? "Last observed " : "Customer status read ") + dateLabel(read.body.assessed_at)
      + ". Each assessment retains its own evidence date." : "No customer status read yet.";
    var note = document.getElementById("portfolio-read-note");
    if (note) {
      note.hidden = !read.error && (!read.loading || !!read.body);
      note.textContent = read.error ? read.error + (read.body ? " Saved customer evidence remains visible. Availability and access are last observed; refresh before switching customers."
        : " Retry to load the customers you can access.") : read.loading && !read.body ? "Reading customer status…" : "";
    }
    var board = document.getElementById("portfolio-status-board");
    if (board) board.dataset.readStale = read.error ? "true" : "false";
    var host = document.getElementById("portfolio-board");
    if (host) host.querySelectorAll("[data-select-workspace]").forEach(function (button) {
      button.setAttribute("aria-disabled", String(!read.body || !!read.error || read.loading || workspaceSelectionBusy
        || !read.body.can_switch_workspaces && String(button.dataset.selectWorkspace) !== String(orgId)));
    });
  }

  function validPortfolioBody(body) {
    if (!body || String(body.organization_id) !== String(orgId) || typeof body.can_switch_workspaces !== "boolean"
      || typeof body.assessed_at !== "string" || !/T.*(?:Z|[+-]\d{2}:\d{2})$/.test(body.assessed_at)
      || !Number.isFinite(Date.parse(body.assessed_at)) || Date.parse(body.assessed_at) > Date.now() + 60000
      || !Array.isArray(body.workspaces)) return false;
    var ids = new Set();
    return body.workspaces.every(function (workspace) {
      if (!workspace || !Number.isSafeInteger(workspace.id) || workspace.id <= 0 || ids.has(workspace.id)
        || typeof workspace.name !== "string" || !workspace.name || typeof workspace.domain !== "string" || !workspace.domain
        || ["admin", "member"].indexOf(workspace.role) < 0 || typeof workspace.verification_status !== "string"
        || !validWorkspaceAreaRows(workspace.areas)) return false;
      ids.add(workspace.id); return true;
    });
  }

  async function loadPortfolio(background) {
    var host = document.getElementById("portfolio-board");
    if (!host || !orgId || workspaceSelectionBusy || background && portfolioRead.loading) return;
    var sequence = ++portfolioRead.sequence;
    if (portfolioRead.controller) portfolioRead.controller.abort();
    var controller = new AbortController(); portfolioRead.controller = controller; portfolioRead.loading = true;
    updatePortfolioReadState();
    var deadline = window.setTimeout(function () { controller.abort(); }, 20000);
    try {
      var response = await fetch("/api/portfolio", { credentials: "same-origin", cache: "no-store", signal: controller.signal });
      var body = await response.json();
      if (controller.signal.aborted || !response.ok || !validPortfolioBody(body)) throw new Error("Customer status could not be refreshed.");
      if (sequence !== portfolioRead.sequence) return;
      var signature = JSON.stringify([body.can_switch_workspaces, body.workspaces, body.workspaces.map(function (workspace) {
        return workspaceStatusSummary(workspace.areas).rows.map(function (row) { return [row.level, row.verdict]; });
      })]);
      portfolioRead.body = body; portfolioRead.error = null;
      if (signature === portfolioRead.signature) return;
      portfolioRead.signature = signature;
      var focusedId = host.contains(document.activeElement) && document.activeElement.dataset ? document.activeElement.dataset.selectWorkspace : null;
      var order = {bad: 0, warn: 1, idle: 2, ok: 3};
      var rows = body.workspaces.map(function (workspace) {
        return {workspace: workspace, assessment: workspaceStatusSummary(workspace.areas)};
      });
      rows.sort(function (x, y) { return order[x.assessment.level] - order[y.assessment.level] || y.assessment.review - x.assessment.review || y.assessment.missing - x.assessment.missing || String(x.workspace.name).localeCompare(String(y.workspace.name)); });
      var needing = rows.filter(function (row) { return row.assessment.review > 0 || !row.assessment.rows.length; }).length;
      var incomplete = rows.filter(function (row) { return row.assessment.missing > 0; }).length;
      var running = rows.filter(function (row) { return row.assessment.running > 0; }).length;
      host.replaceChildren();
      var banner = document.createElement("div");
      banner.className = "status-banner is-" + (rows.some(function (row) { return row.assessment.level === "bad"; }) ? "bad" : needing ? "warn" : incomplete || running || !rows.length ? "idle" : "ok");
      var headline = document.createElement("strong");
      headline.textContent = !rows.length ? "No customers available" : needing ? needing + " of " + rows.length + " customers need review"
        : incomplete ? incomplete + " of " + rows.length + " customers have unassessed areas"
        : running ? "Customer checks are running" : "Saved customer evidence available";
      var coverage = document.createElement("span");
      coverage.textContent = rows.length + " accessible customers · " + incomplete + " with unassessed areas · " + running + " with checks in progress. Saved evidence is not a security verdict.";
      banner.append(headline, coverage);
      host.append(banner);
      var list = document.createElement("ul"); list.className = "status-list";
      rows.forEach(function (row) {
        var li = document.createElement("li"); li.className = "status-row portfolio-row is-" + row.assessment.level;
        var dot = document.createElement("span"); dot.className = "status-dot"; dot.setAttribute("aria-hidden", "true");
        var name = document.createElement("button"); name.type = "button"; name.className = "status-name";
        name.textContent = row.workspace.name; name.dataset.selectWorkspace = row.workspace.id;
        name.dataset.workspaceReviewTab = "overview";
        name.setAttribute("aria-label", "Review " + row.workspace.name);
        var domain = document.createElement("span"); domain.className = "status-when portfolio-domain"; domain.textContent = row.workspace.domain;
        var access = document.createElement("span"); access.className = "status-why";
        var ownership = {verified: "Domain ownership verified", pending: "TXT verification pending", expired: "Domain verification expired"};
        access.textContent = (ownership[row.workspace.verification_status] || "Domain ownership status unknown")
          + " · " + (row.workspace.role === "admin" ? "Workspace admin" : "Workspace member");
        var chips = document.createElement("span"); chips.className = "portfolio-chips";
        row.assessment.rows.forEach(function (area) {
          var chip = document.createElement("span"); chip.className = "portfolio-chip is-" + area.level;
          chip.textContent = (area.area.title || "Unknown area") + ": " + area.verdict;
          chip.title = area.when + (area.area.summary ? " · " + area.area.summary : "");
          chips.append(chip);
        });
        var verdict = document.createElement("span"); verdict.className = "status-verdict";
        verdict.textContent = row.assessment.headline;
        var coverage = document.createElement("span"); coverage.className = "status-why";
        var datedAreas = row.assessment.rows.filter(function (area) { return area.hasEvidence; });
        datedAreas.sort(function (left, right) { return new Date(right.area.updated_at).getTime() - new Date(left.area.updated_at).getTime(); });
        coverage.textContent = row.assessment.detail + (datedAreas.length ? " · Latest saved evidence " + dateLabel(datedAreas[0].area.updated_at) : " · No dated saved evidence");
        li.append(dot, name, domain, verdict, chips, coverage, access);
        list.append(li);
      });
      host.append(list);
      if (focusedId && /^\d+$/.test(String(focusedId))) {
        var focused = host.querySelector('[data-select-workspace="' + focusedId + '"]') || document.getElementById("portfolio-refresh");
        if (focused) focused.focus({preventScroll: true});
      }
    } catch (_error) { if (sequence === portfolioRead.sequence) {
      portfolioRead.error = controller.signal.aborted ? "Customer status read timed out." : "Customer status could not be refreshed.";
      if (!portfolioRead.body) { host.replaceChildren(); appendEmpty(host, "Customer status is unavailable."); }
    } } finally {
      window.clearTimeout(deadline);
      if (sequence === portfolioRead.sequence) { portfolioRead.loading = false; portfolioRead.controller = null; updatePortfolioReadState(); }
    }
  }

  function renderStatusBoard(areas) {
    var host = document.getElementById("workspace-priorities");
    if (!host) return;
    var focusKey = host.contains(document.activeElement) && document.activeElement.dataset ? document.activeElement.dataset.statusKey : null;
    var assessment = workspaceStatusSummary(areas);
    var renderedSignature = workspacePostureRead.signature;
    host.replaceChildren();
    var banner = document.createElement("div");
    banner.className = "status-banner is-" + assessment.level;
    var headline = document.createElement("strong"); headline.textContent = assessment.headline;
    var sub = document.createElement("span"); sub.textContent = assessment.detail + ". Saved evidence is not a security verdict.";
    banner.append(headline, sub);
    if (role === "admin" && workspacePostureRead.body && workspacePostureRead.body.can_manage === true) {
      var runAll = document.createElement("button"); runAll.type = "button"; runAll.className = "button button-primary status-run-all";
      runAll.textContent = workspacePostureRead.publicCheckRetryTypes ? "Retry " + workspacePostureRead.publicCheckRetryTypes.map(function (type) { return type === "dns" ? "DNS & email" : "website"; }).join(" & ") : "Check DNS & website now";
      runAll.dataset.statusKey = "public-refresh";
      runAll.dataset.overviewMutation = "true";
      var pendingTypes = workspacePostureRead.publicCheckRetryTypes || ["dns", "web"];
      var feedback = document.createElement("span"); feedback.className = "status-refresh-feedback";
      feedback.setAttribute("role", "status");
      feedback.textContent = workspacePostureRead.publicCheckFeedback || "";
      runAll.addEventListener("click", async function () {
        if (!overviewMutationAllowed(renderedSignature)) return;
        workspacePostureRead.mutationBusy = true; updateOverviewReadState();
        runAll.setAttribute("aria-busy", "true"); runAll.textContent = "Requesting checks…";
        var outcomes = await Promise.all(pendingTypes.map(async function (type) {
          try {
            var response = await fetch("/api/external-checks/" + type + "/run", {method: "POST", credentials: "same-origin"});
            return {type: type, accepted: response.ok};
          } catch (_error) { return {type: type, accepted: false}; }
        }));
        pendingTypes = outcomes.filter(function (outcome) { return !outcome.accepted; }).map(function (outcome) { return outcome.type; });
        workspacePostureRead.mutationBusy = false;
        runAll.setAttribute("aria-busy", "false"); updateOverviewReadState();
        if (pendingTypes.length) {
          workspacePostureRead.publicCheckRetryTypes = pendingTypes;
          var failed = pendingTypes.map(function (type) { return type === "dns" ? "DNS & email" : "website"; });
          var accepted = outcomes.filter(function (outcome) { return outcome.accepted; }).map(function (outcome) { return outcome.type === "dns" ? "DNS & email" : "website"; });
          feedback.textContent = (accepted.length ? accepted.join(" and ") + " check requested. " : "") + "Could not request " + failed.join(" and ") + " checks. Review those areas or try again.";
          workspacePostureRead.publicCheckFeedback = feedback.textContent;
          runAll.disabled = false; runAll.textContent = "Retry " + failed.join(" & ");
        } else {
          pendingTypes = ["dns", "web"];
          workspacePostureRead.publicCheckRetryTypes = null;
          workspacePostureRead.publicCheckFeedback = "DNS & website checks requested.";
          workspacePostureRead.signature = null;
          feedback.textContent = "DNS & website checks requested. Refreshing workspace status…";
          runAll.textContent = "Check DNS & website now";
          await loadWorkspacePosture();
        }
      });
      banner.append(runAll, feedback);
    }
    host.append(banner);
    var list = document.createElement("ul"); list.className = "status-list";
    assessment.rows.forEach(function (row) {
      var li = document.createElement("li"); li.className = "status-row is-" + row.level;
      var dot = document.createElement("span"); dot.className = "status-dot"; dot.setAttribute("aria-hidden", "true");
      var key = typeof row.area.key === "string" && /^[a-z-]+$/.test(row.area.key) ? row.area.key : null;
      var name = document.createElement("button"); name.type = "button"; name.className = "status-name";
      name.textContent = row.area.title || "Unknown area"; name.disabled = !key;
      if (key) { name.dataset.statusKey = key + "-name"; name.addEventListener("click", function () { activateTab(key, true); }); }
      var verdict = document.createElement("span"); verdict.className = "status-verdict"; verdict.textContent = row.verdict;
      var when = document.createElement("span"); when.className = "status-when"; when.textContent = row.when;
      var action = document.createElement("span"); action.className = "status-action-slot";
      var review = document.createElement("button"); review.type = "button"; review.className = "button button-quiet status-action";
      review.textContent = row.reviewLabel; review.disabled = !key;
      review.setAttribute("aria-label", row.reviewLabel + ": " + (row.area.title || "Unknown area"));
      if (key) { review.dataset.statusKey = key + "-review"; review.addEventListener("click", function () { activateTab(key, true); }); }
      action.append(review);
      if (row.enableSchedule && role === "admin" && workspacePostureRead.body && workspacePostureRead.body.can_manage === true) {
        var turnOn = document.createElement("button"); turnOn.type = "button"; turnOn.className = "button button-quiet status-action";
        turnOn.textContent = "Enable automatic checks"; turnOn.dataset.statusKey = key + "-schedule";
        turnOn.dataset.overviewMutation = "true";
        turnOn.setAttribute("aria-label", "Enable " + row.area.title + " checks every " + row.interval + " hours");
        turnOn.addEventListener("click", async function () {
          if (!overviewMutationAllowed(renderedSignature)) return;
          workspacePostureRead.mutationBusy = true; updateOverviewReadState();
          turnOn.setAttribute("aria-busy", "true"); turnOn.textContent = "Enabling…";
          try {
            var response = await fetch("/api/external-checks/" + key + "/schedule", {method: "PUT", credentials: "same-origin",
              headers: {"Content-Type": "application/json"}, body: JSON.stringify({enabled: true, interval_hours: row.interval})});
            if (!response.ok) throw new Error();
            workspacePostureRead.mutationBusy = false;
            workspacePostureRead.signature = null;
            turnOn.textContent = "Automatic checks enabled";
            await loadWorkspacePosture();
          } catch (_error) { turnOn.textContent = "Retry automatic checks"; }
          finally { workspacePostureRead.mutationBusy = false; turnOn.setAttribute("aria-busy", "false"); updateOverviewReadState(); }
        });
        action.append(turnOn);
      }
      li.append(dot, name, verdict, when, action);
      var why = document.createElement("span"); why.className = "status-why";
      why.textContent = (row.area.summary || "Assessment summary unavailable.") + (row.scheduleLabel ? " · " + row.scheduleLabel : "");
      li.append(why);
      if (row.area.audit_summary) {
        var audit = document.createElement("span"); audit.className = "status-why";
        var auditTime = workspaceEvidenceTime(row.area.audit_updated_at, Date.now());
        audit.textContent = row.area.audit_summary + " · " + (auditTime !== null ? "Audit evidence " + dateLabel(row.area.audit_updated_at) : "Audit evidence time unknown");
        li.append(audit);
      }
      list.append(li);
    });
    host.append(list);
    if (focusKey && /^[a-z-]+$/.test(focusKey)) {
      var focused = host.querySelector('[data-status-key="' + focusKey + '"]');
      if (focused) focused.focus({preventScroll: true});
    }
  }

  function overviewMutationAllowed(signature) {
    return !!workspacePostureRead.body && workspacePostureRead.body.can_manage === true && role === "admin"
      && !workspacePostureRead.error && !workspacePostureRead.loading && !workspacePostureRead.mutationBusy
      && workspacePostureRead.signature === signature;
  }

  function updateOverviewReadState() {
    var read = workspacePostureRead;
    var button = document.getElementById("overview-refresh");
    var note = document.getElementById("overview-read-note");
    var observed = document.getElementById("overview-observed");
    if (button) {
      if (!button.dataset.bound) { button.dataset.bound = "true"; button.addEventListener("click", function () { return loadWorkspacePosture(); }); }
      button.textContent = read.error ? "Retry workspace status" : "Refresh workspace status";
      button.setAttribute("aria-busy", String(read.loading));
      button.setAttribute("aria-disabled", String(read.mutationBusy));
    }
    if (observed) observed.textContent = read.body ? (read.error ? "Last observed " : "Status read ") + dateLabel(read.body.assessed_at)
      + ". Assessment dates below describe the saved evidence." : "No workspace status read yet.";
    if (note) {
      note.hidden = !read.error && (!read.loading || !!read.body);
      note.textContent = read.error ? read.error + (read.body ? " Saved evidence remains available; scanner availability and schedules are last observed. Refresh before requesting checks or enabling schedules."
        : " Retry to load this workspace’s evidence and controls.") : read.loading && !read.body ? "Reading workspace status…" : "";
    }
    ["overview-status-board", "workspace-posture"].forEach(function (id) {
      var node = document.getElementById(id);
      if (node) node.dataset.readStale = read.error ? "true" : "false";
    });
    var priorities = document.getElementById("workspace-priorities");
    if (priorities) priorities.querySelectorAll("[data-overview-mutation]").forEach(function (control) {
      control.setAttribute("aria-disabled", String(!overviewMutationAllowed(read.signature)));
    });
  }

  function validWorkspacePosture(body) {
    if (!body || String(body.organization_id) !== String(orgId) || typeof body.can_manage !== "boolean"
      || typeof body.domain !== "string" || !body.domain || typeof body.assessed_at !== "string"
      || !/T.*(?:Z|[+-]\d{2}:\d{2})$/.test(body.assessed_at)
      || !Number.isFinite(Date.parse(body.assessed_at)) || Date.parse(body.assessed_at) > Date.now() + 60000
      || !Array.isArray(body.areas) || !body.areas.length) return false;
    return validWorkspaceAreaRows(body.areas);
  }

  function validWorkspaceAreaRows(areas) {
    if (!Array.isArray(areas) || !areas.length) return false;
    var seen = new Set();
    return areas.every(function (area) {
      if (!area || ["dns", "web", "scanners", "cis", "meraki", "google-admin"].indexOf(area.key) < 0 || seen.has(area.key)
        || typeof area.title !== "string" || typeof area.summary !== "string" || typeof area.state !== "string") return false;
      seen.add(area.key); return true;
    });
  }

  async function loadWorkspacePosture(background) {
    var host = document.getElementById("workspace-posture");
    if (!host || !orgId || workspacePostureRead.mutationBusy || background && workspacePostureRead.loading) return;
    var sequence = ++postureRequestSequence;
    if (workspacePostureRead.controller) workspacePostureRead.controller.abort();
    var controller = new AbortController();
    workspacePostureRead.controller = controller; workspacePostureRead.loading = true;
    updateOverviewReadState();
    var deadline = window.setTimeout(function () { controller.abort(); }, 20000);
    try {
      var response = await fetch("/api/workspace-posture", { credentials: "same-origin", cache: "no-store", signal: controller.signal });
      var body = await response.json();
      if (controller.signal.aborted) throw new Error("Workspace status read timed out.");
      if (!response.ok || !validWorkspacePosture(body)) throw new Error("Workspace status could not be refreshed.");
      if (sequence !== postureRequestSequence) return;
      var signature = JSON.stringify([body.can_manage, body.areas, body.areas.map(function (area) {
        var presentation = workspaceAreaPresentation(area); return [presentation.level, presentation.verdict];
      })]);
      workspacePostureRead.body = body; workspacePostureRead.error = null;
      if (signature === workspacePostureRead.signature) return;
      workspacePostureRead.signature = signature;
      var focusedKey = host.contains(document.activeElement) ? document.activeElement.dataset.postureKey : null;
      host.replaceChildren();
      var assessment = workspaceAssessmentSummary(body.areas);
      renderStatusBoard(body.areas);
      assessment.areas.forEach(function (area) {
        var presentation = workspaceAreaPresentation(area);
        var card = document.createElement("button"); card.type = "button"; card.className = "posture-card"; card.dataset.postureKey = area.key;
        var heading = document.createElement("strong"); heading.textContent = area.title;
        var state = document.createElement("span"); state.className = "posture-state is-" + (presentation.level === "warn" ? "attention" : presentation.level === "bad" ? "unavailable" : presentation.state); state.textContent = presentation.verdict;
        var summary = document.createElement("p"); summary.textContent = area.summary;
        var date = document.createElement("small"); date.textContent = presentation.when;
        var link = document.createElement("span"); link.className = "module-link"; link.textContent = "Review this area →";
        card.append(heading, state, summary, date);
        if (area.audit_summary) {
          var audit = document.createElement("p"); audit.textContent = area.audit_summary;
          var captured = document.createElement("small"); captured.textContent = workspaceEvidenceTime(area.audit_updated_at, Date.now()) !== null ? "Audit evidence " + dateLabel(area.audit_updated_at) : "Audit evidence time unknown";
          card.append(audit, captured);
        }
        card.append(link);
        card.addEventListener("click", function () { activateTab(area.key, true); });
        host.append(card);
      });
      if (focusedKey) { var focused = host.querySelector('[data-posture-key="' + focusedKey + '"]'); if (focused) focused.focus({preventScroll:true}); }
    } catch (_error) { if (sequence === postureRequestSequence) {
      workspacePostureRead.error = controller.signal.aborted ? "Workspace status read timed out." : "Workspace status could not be refreshed.";
      var priorities = document.getElementById("workspace-priorities");
      if (!workspacePostureRead.body) {
        host.replaceChildren(); appendEmpty(host, "Saved evidence has not been loaded.");
        if (priorities) { priorities.replaceChildren(); appendEmpty(priorities, "Workspace status is unavailable."); }
      }
    } } finally {
      window.clearTimeout(deadline);
      if (sequence === postureRequestSequence) { workspacePostureRead.loading = false; workspacePostureRead.controller = null; updateOverviewReadState(); }
    }
  }

  async function loadPendingApprovals() {
    if (membershipReview) return membershipReview.load(true);
  }

  function refresh(force) {
    // Expire old runtime facts even if the network request fails or a user is
    // editing controls. Saved evidence and focused controls remain untouched.
    refreshScannerActivities();
    if (dashboardRefreshPromise) {
      if (force) return dashboardRefreshPromise.then(function () { return refresh(true); });
      return dashboardRefreshPromise;
    }
    dashboardRefreshPromise = (async function () {
      try {
        var response = await fetch("/api/dashboard", { credentials: "same-origin" });
        if (!response.ok) return;
        var data = await response.json();
        updateWorkspaceControls(data.organization);
        refreshScannerActivities(data.agents);
        if (!force && document.querySelector(".inline-confirmation")) return;
        render(data);
        if (activeTab === "overview") { await loadWorkspacePosture(true); await loadPendingApprovals(); }
        if (activeTab === "portfolio") await loadPortfolio(true);
        if (activeTab === "members") await loadMemberships(true);
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
        button.disabled = action === "start_scan" && !controlsEnabled;
      }, 1800);
    } catch (error) {
      button.textContent = error.message;
      window.setTimeout(function () {
        button.textContent = original;
        button.disabled = action === "start_scan" && !controlsEnabled;
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
      button.disabled = !controlsEnabled;
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
      issueScannerEnrollment.dataset.requestBusy = "true";
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
        delete issueScannerEnrollment.dataset.requestBusy;
        issueScannerEnrollment.disabled = !controlsEnabled;
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
          if (activeTab === "cis") loadCIS(true); if (activeTab === "meraki") loadMerakiStatus(true);
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

  function renderMerakiPowerUsage(container, rows, additional) {
    if (!Array.isArray(rows) || !rows.length) return;
    var validMeasure = function (value) { return typeof value === "number" && Number.isFinite(value) && value >= 0; };
    var format = function (value, unit) { return validMeasure(value) ? new Intl.NumberFormat("en-US", {maximumFractionDigits: 3}).format(value) + (unit ? " " + unit : "") : "Unavailable"; };
    var section = document.createElement("section"); section.className = "meraki-detail-section meraki-power-section";
    var heading = document.createElement("h4"); heading.textContent = "Switch PoE usage";
    var note = document.createElement("p"); note.className = "muted";
    note.textContent = "Measured energy over the requested prior 24 hours. Missing ports remain unmeasured. Average usage does not establish peak demand or replacement PoE capacity.";
    section.append(heading, note);
    var measured = rows.filter(function (row) {
      var data = row.data || {};
      return row.status === "complete" && data.requested_timespan_seconds === 86400 && validMeasure(data.measured_energy_wh);
    });
    var energy = measured.reduce(function (total, row) { return total + row.data.measured_energy_wh; }, 0);
    var complete = measured.filter(function (row) { return row.data.energy_coverage === "complete"; }).length;
    var metrics = document.createElement("dl"); metrics.className = "meraki-detail-metrics";
    [["Switches shown", rows.length], ["Complete energy coverage", complete + "/" + rows.length],
     ["Measured energy · shown switches", measured.length ? format(energy, "Wh") : "Unavailable"]].forEach(function (entry) {
      var cell = document.createElement("div"), label = document.createElement("dt"), value = document.createElement("dd");
      label.textContent = entry[0]; value.textContent = String(entry[1]); cell.append(label, value); metrics.append(cell);
    });
    section.append(metrics);
    var scroller = document.createElement("div"); scroller.className = "audit-table-scroll meraki-power-scroll";
    scroller.tabIndex = 0; scroller.setAttribute("role", "region"); scroller.setAttribute("aria-label", "Switch PoE usage table");
    var table = document.createElement("table"); table.className = "audit-record-table meraki-power-table";
    var caption = document.createElement("caption"); caption.textContent = "Per-switch measured energy and coverage"; table.append(caption);
    var labels = ["Switch / network", "Collection / energy coverage", "Ports measured", "Measured energy", "Measured average"];
    var head = document.createElement("thead"), header = document.createElement("tr");
    labels.forEach(function (label) { var cell = document.createElement("th"); cell.scope = "col"; cell.textContent = label; header.append(cell); });
    head.append(header); table.append(head);
    var body = document.createElement("tbody");
    rows.forEach(function (row) {
      var data = row.data || {}, line = document.createElement("tr");
      var scoped = row.status === "complete" && data.requested_timespan_seconds === 86400;
      var counts = Number.isInteger(data.measured_port_count) && Number.isInteger(data.port_count) && data.measured_port_count >= 0 && data.port_count >= data.measured_port_count;
      var values = [(row.device_serial || "Switch") + " / " + (row.network_name || "Network"),
                    (row.status || "unknown") + " / " + (data.energy_coverage || "unavailable"),
                    counts ? data.measured_port_count + " / " + data.port_count : "Unavailable",
                    scoped ? format(data.measured_energy_wh, "Wh") : "Unavailable",
                    scoped ? format(data.measured_average_watts, "W") : "Unavailable"];
      values.forEach(function (value, index) {
        var cell = document.createElement(index === 0 ? "th" : "td");
        if (index === 0) cell.scope = "row";
        cell.dataset.label = labels[index]; cell.textContent = value; line.append(cell);
      });
      body.append(line);
    });
    table.append(body); scroller.append(table); section.append(scroller);
    if (additional > 0) {
      var more = document.createElement("p"); more.className = "muted";
      more.textContent = additional + " more switches in the saved JSON evidence. Summary covers shown switches.";
      section.append(more);
    }
    container.append(section);
  }

  function renderMerakiActionPlan(container, plan) {
    if (!plan || plan.schema_version !== 1 || !Array.isArray(plan.rows)) return;
    var section = document.createElement("section"); section.className = "meraki-detail-section";
    var heading = document.createElement("h4"); heading.textContent = "Recommendations & implementation plan";
    var scope = document.createElement("p"); scope.className = "muted"; scope.textContent = plan.scope; section.append(heading, scope);
    var labels = {review: "Review observation", planning: "Design / planning review", evidence_gap: "Evidence gap"};
    (plan.phases || []).forEach(function (phase, index) {
      var group = document.createElement("details"), summary = document.createElement("summary"), rows = plan.rows.filter(function (row) {return row.phase === index;});
      summary.textContent = phase + " · " + rows.length + " review actions"; group.append(summary);
      if (!rows.length) {var empty = document.createElement("p"); empty.textContent = "No actions derived for this window; this does not certify a healthy network."; group.append(empty);}
      rows.forEach(function (row) {var article = document.createElement("article"); article.className = "audit-policy-card";var title = document.createElement("strong"); title.textContent = row.title + " · " + (labels[row.status] || "Evidence gap");article.append(title);
        [["Observation", row.observation], ["Suggested owner", row.suggested_owner], ["Next action", row.action], ["Validation", row.verification], ["Saved evidence", (row.evidence_references || []).join("; ")]].forEach(function (item) {var p = document.createElement("p"); p.textContent = item[0] + ": " + (item[1] || "Unavailable");article.append(p);});group.append(article);}); section.append(group);
    }); container.append(section);
  }

  function renderMerakiClientDistributions(container, observations, additionalNetworks) {
    if (!Array.isArray(observations) || !observations.length) return;
    var section = document.createElement("section"); section.className = "meraki-detail-section";
    var heading = document.createElement("h4"); heading.textContent = "Wireless client analysis"; section.append(heading);
    observations.forEach(function (observation) {
      var group = document.createElement("details"), summary = document.createElement("summary"), data = observation.data;
      summary.textContent = (observation.network_name || "Network") + " · " + (observation.status || "unknown") + " · " + (data && Number.isSafeInteger(data.wireless_client_count) ? data.wireless_client_count + " wireless records" : "Count unavailable"); group.append(summary);
      if (!data) {var unavailable = document.createElement("p"); unavailable.textContent = "Wireless client distributions unavailable for this saved collection."; group.append(unavailable); section.append(group); return;}
      var scope = document.createElement("p"); scope.className = "muted"; scope.textContent = data.scope; group.append(scope);
      var excluded = document.createElement("p"); excluded.textContent = (data.excluded_connection_count ?? "Unknown") + " returned records excluded because their recent connection was not explicitly Wireless. RSSI: not provided by this endpoint."; group.append(excluded);
      [["ssid", "SSID"], ["os", "OS / device-type prediction"], ["vlan", "VLAN"], ["status", "Reported status"]].forEach(function (dimension) {
        var distribution = (data.distributions || {})[dimension[0]] || {};
        var title = document.createElement("h5"); title.textContent = dimension[1]; group.append(title);
        if (distribution.status !== "complete") {var invalid = document.createElement("p"); invalid.textContent = "Distribution evidence unavailable or invalid."; group.append(invalid); return;}
        var table = document.createElement("table"); table.className = "data-table";
        var caption = document.createElement("caption"); caption.textContent = "Wireless records by " + dimension[1]; table.append(caption);
        var header = document.createElement("thead"), headerRow = document.createElement("tr");
        ["Group", "Record count"].forEach(function (label) {var th = document.createElement("th"); th.scope = "col"; th.textContent = label; headerRow.append(th);}); header.append(headerRow); table.append(header);
        var body = document.createElement("tbody"); (distribution.rows || []).forEach(function (row) {var tr = document.createElement("tr"); [row.label, row.count].forEach(function (value) {var td = document.createElement("td"); td.textContent = String(value); tr.append(td);}); body.append(tr);}); table.append(body);
        var scroll = document.createElement("div"); scroll.className = "table-scroll"; scroll.tabIndex = 0; scroll.setAttribute("role", "region"); scroll.setAttribute("aria-label", caption.textContent); scroll.append(table); group.append(scroll);
        var note = document.createElement("p"); note.className = "muted"; note.textContent = distribution.unknown_count + " records with missing/unsupported labels · " + distribution.additional_group_count + " additional groups (" + distribution.additional_client_count + " records) in complete JSON evidence."; group.append(note);
      }); section.append(group);
    });
    if (additionalNetworks) {var more = document.createElement("p"); more.textContent = additionalNetworks + " more networks in complete saved evidence."; section.append(more);} container.append(section);
  }

  function renderMerakiCis8(container, evidence) {
    if (!evidence || evidence.schema_version !== 1 || !Array.isArray(evidence.rows)) return;
    var section = document.createElement("section");section.className = "meraki-detail-section";
    var title = document.createElement("h4");title.textContent = "CIS Controls v8 evidence review";
    var note = document.createElement("p");note.className = "muted";note.textContent = evidence.scope || "Saved network evidence requires human control assessment.";section.append(title, note);
    var labels = {partial: "Partial evidence", review: "Review observations", not_assessed: "Not assessed"};
    evidence.rows.slice(0, 18).forEach(function (row) {
      var group = document.createElement("details"), summary = document.createElement("summary");summary.textContent = "CIS " + row.control_id + " · " + row.title + " · " + (labels[row.status] || "Not assessed");group.append(summary);
      var observed = document.createElement("p");observed.textContent = row.observation || "Evidence unavailable.";
      var action = document.createElement("p");action.textContent = "Next review: " + (row.next_action || "Review external control evidence.");group.append(observed, action);
      var refs = document.createElement("p");refs.className = "muted";refs.textContent = "Saved evidence references: " + ((row.evidence_references || []).length ? row.evidence_references.join("; ") : "No assessed Meraki evidence for this control");group.append(refs);section.append(group);
    });
    var source = document.createElement("a");source.href = "https://www.cisecurity.org/controls/cis-controls-navigator/v8";source.target = "_blank";source.rel = "noopener noreferrer";source.textContent = "CIS Controls v8 reference (opens in a new tab)";section.append(source);container.append(section);
  }

  function renderMerakiNetworkDiagram(container, network) {
    var diagram = network.diagram;
    if (!diagram || diagram.status !== "available" || !Array.isArray(diagram.nodes)) return;
    var figure = document.createElement("figure"), caption = document.createElement("figcaption");caption.textContent = "Network diagram · " + (network.network_name || "Network");figure.append(caption);
    var scroll = document.createElement("div");scroll.className = "meraki-topology-canvas";scroll.tabIndex = 0;scroll.setAttribute("role", "region");scroll.setAttribute("aria-label", "Scrollable network diagram for " + (network.network_name || "Network"));
    var svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");svg.setAttribute("viewBox", "0 0 " + diagram.width + " " + diagram.height);svg.setAttribute("width", diagram.width);svg.setAttribute("height", diagram.height);svg.setAttribute("role", "img");svg.setAttribute("aria-label", "Named assigned devices and observed undirected relationships");
    var title = document.createElementNS("http://www.w3.org/2000/svg", "title");title.textContent = "Observed network relationships for " + (network.network_name || "Network");svg.append(title);
    var byId = new Map();diagram.nodes.forEach(function (node) {byId.set(node.device_serial, node);});
    (diagram.links || []).forEach(function (link) {var a = byId.get(link.device_serials[0]), b = byId.get(link.device_serials[1]);if (!a || !b) return;var line = document.createElementNS("http://www.w3.org/2000/svg", "line");line.setAttribute("x1", a.x + a.width / 2);line.setAttribute("y1", a.y + a.height / 2);line.setAttribute("x2", b.x + b.width / 2);line.setAttribute("y2", b.y + b.height / 2);line.setAttribute("stroke", "#8a9269");line.setAttribute("stroke-width", "2");svg.append(line);});
    diagram.nodes.forEach(function (node) {var group = document.createElementNS("http://www.w3.org/2000/svg", "g"), title = document.createElementNS("http://www.w3.org/2000/svg", "title");title.textContent = node.number + ": " + node.name + " / " + node.model + (node.reported_root === true ? " · API root flag" : "");group.append(title);
      var rect = document.createElementNS("http://www.w3.org/2000/svg", "rect");[["x", node.x], ["y", node.y], ["width", node.width], ["height", node.height], ["rx", 8], ["fill", node.reported_root === true ? "#464a34" : "#f0eee5"], ["stroke", "#6e754b"]].forEach(function (a) {rect.setAttribute(a[0], a[1]);});group.append(rect);
      ["#" + node.number + " · " + (node.model || "Device"), node.name.slice(0, 26), node.name.slice(26, 52)].forEach(function (value, index) {if (!value) return;var text = document.createElementNS("http://www.w3.org/2000/svg", "text");text.setAttribute("x", node.x + 10);text.setAttribute("y", node.y + 18 + index * 20);text.setAttribute("font-size", "12");text.setAttribute("fill", node.reported_root === true ? "#faf8f1" : "#29271f");text.textContent = value;group.append(text);});svg.append(group);
    });scroll.append(svg);figure.append(scroll);var note = document.createElement("p");note.className = "muted";note.textContent = diagram.scope + " " + (diagram.additional_nodes || 0) + " additional devices and " + (diagram.additional_links || 0) + " additional relationship pairs are outside the diagram preview.";figure.append(note);container.append(figure);
  }

  function renderMerakiTopology(container, evidence) {
    if (!evidence || !Array.isArray(evidence.networks) || !evidence.networks.length) return;
    var section = document.createElement("section"); section.className = "meraki-detail-section";
    var heading = document.createElement("h4"); heading.textContent = "Observed network relationships";
    var note = document.createElement("p"); note.className = "muted"; note.textContent = evidence.scope || "Saved assigned-device relationships; missing links remain unknown."; section.append(heading, note);
    var count = function (v) {return Number.isSafeInteger(v) && v >= 0 ? String(v) : "Unavailable";};
    evidence.networks.forEach(function (network) {
      var group = document.createElement("details"), summary = document.createElement("summary");
      summary.textContent = (network.network_name || "Network") + " · " + (network.status || "unknown") + " · " + count(network.node_count) + " observed assigned devices · " + count(network.link_count) + " relationship pairs"; group.append(summary);
      var coverage = document.createElement("p"); coverage.textContent = count(network.isolated_node_count) + " devices without observed links · " + count(network.root_node_count) + " reported root flags · " + count(network.omitted_node_count) + " nodes and " + count(network.omitted_link_count) + " links omitted at collection · " + count(network.reported_error_count) + " API errors"; group.append(coverage);
      if (network.status === "complete") {
        if (network.diagram) renderMerakiNetworkDiagram(group, network);
        var list = document.createElement("ul"); (network.nodes || []).forEach(function (node, index) {var item = document.createElement("li"); item.textContent = (network.diagram && network.diagram.status === "available" ? "#" + (index + 1) + " · " : "") + node.name + " · " + (node.model || "Model unavailable") + (node.reported_root === true ? " · API root flag" : ""); list.append(item);});group.append(list);
        if ((network.links || []).length) {
          var scroll = document.createElement("div"); scroll.className = "table-scroll"; scroll.tabIndex = 0; scroll.setAttribute("aria-label", "Observed relationships for " + (network.network_name || "Network"));
          var table = document.createElement("table"), caption = document.createElement("caption");caption.textContent = "Saved undirected managed-device relationships";table.append(caption);
          var head = document.createElement("thead"), tr = document.createElement("tr");["Assigned device", "Observed neighbor", "Reported relationship count"].forEach(function (text) {var th = document.createElement("th");th.textContent = text;th.setAttribute("scope", "col");tr.append(th);});head.append(tr);table.append(head);
          var body = document.createElement("tbody");network.links.forEach(function (link) {var tr = document.createElement("tr");[(link.endpoint_names || [])[0], (link.endpoint_names || [])[1], count(link.link_count)].forEach(function (value) {var td = document.createElement("td");td.textContent = value || "Unavailable";tr.append(td);});body.append(tr);});table.append(body);scroll.append(table);group.append(scroll);
        } else {var empty = document.createElement("p");empty.textContent = "No relationships shown. Missing links do not establish disconnection; review coverage and complete saved JSON.";group.append(empty);}
      }
      if (network.additional_nodes || network.additional_links) {var more = document.createElement("p");more.textContent = count(network.additional_nodes) + " more assigned devices and " + count(network.additional_links) + " more relationship pairs in complete saved JSON.";group.append(more);}
      section.append(group);
    });
    if (evidence.additional_networks) {var more = document.createElement("p");more.textContent = evidence.additional_networks + " more networks in complete saved JSON.";section.append(more);}
    container.append(section);
  }

  function renderMerakiRefreshPlan(container, plan) {
    if (!plan || plan.schema_version !== 1 || plan.currency !== "USD" || !Array.isArray(plan.scenarios)) return;
    var section = document.createElement("section"); section.className = "meraki-detail-section";
    var title = document.createElement("h4"); title.textContent = "Equipment refresh reserve";
    var note = document.createElement("p"); note.className = "muted"; note.textContent = plan.scope || "Nominal equipment reserve; replacement cycles are planning assumptions."; section.append(title, note);
    plan.scenarios.slice(0, 2).forEach(function (row) {
      var text = document.createElement("p"), amount = Number.isSafeInteger(row.annual_reserve_cents) && row.annual_reserve_cents >= 0 ? new Intl.NumberFormat("en-US", {style: "currency", currency: "USD"}).format(row.annual_reserve_cents / 100) : "Unavailable";
      text.textContent = (row.name || "Scenario") + ": " + amount + " per year · assumed " + (Number.isSafeInteger(row.replacement_cycle_years) ? row.replacement_cycle_years : "unknown") + "-year cycle · " + (row.complete_inventory_pricing === true ? "All assigned inventory priced" : "Partial pricing; reserve covers priced inventory only") + (Number.isSafeInteger(row.unpriced_device_count) && row.unpriced_device_count > 0 ? " · " + row.unpriced_device_count + " unpriced devices" : ""); section.append(text);
    });
    container.append(section);
  }

  function renderMerakiProviderLifecycle(container, evidence, overview) {
    if (!evidence) return;
    var section = document.createElement("section"); section.className = "meraki-detail-section";
    var title = document.createElement("h4"); title.textContent = "Meraki inventory support review"; section.append(title);
    if (evidence.status !== "available") {var unavailable = document.createElement("p"); unavailable.textContent = "Provider lifecycle evidence unavailable or invalid; dates and support remain unverified."; section.append(unavailable); container.append(section); return;}
    var counts = evidence.summary || {}, summary = document.createElement("p");
    summary.textContent = counts.provider_end_of_support + " devices reported end of support · " + counts.provider_near_end_of_support + " reported near end of support · " + counts.unknown_support_date + " unknown support dates · " + counts.date_conflicts + " with differing published dates · " + counts.no_notice_cross_check + " without a published notice cross-check · " + counts.missing_devices + " missing inventory records · As of " + (evidence.as_of || "unknown date"); section.append(summary);
    var note = document.createElement("p"); note.className = "muted"; note.textContent = evidence.scope; section.append(note);
    if (!overview) {
      var scroll = document.createElement("div"); scroll.className = "table-scroll"; scroll.tabIndex = 0; scroll.setAttribute("role", "region"); scroll.setAttribute("aria-label", "Meraki inventory support dates");
      var table = document.createElement("table"), caption = document.createElement("caption"); caption.textContent = "Frozen API milestones and version-" + evidence.schema_version + " published-date comparison"; table.append(caption);
      var head = document.createElement("thead"), tr = document.createElement("tr");
      ["Network / model / quantity", "Provider status", "API sale / support", "Published sale / support", "Review"].forEach(function (label) {var th = document.createElement("th"); th.textContent = label; th.setAttribute("scope", "col"); tr.append(th);}); head.append(tr); table.append(head);
      var body = document.createElement("tbody"), labels = {endOfSupport: "End of support", nearEndOfSupport: "Near end of support", endOfSale: "End of sale", unknown: "Unknown"};
      (evidence.rows || []).forEach(function (row) {
        var tr = document.createElement("tr");
        [row.network_name + " / " + row.model + " × " + row.quantity, labels[row.provider_status] || "Unknown", (row.end_of_sale_date || "Unknown") + " / " + (row.end_of_support_date || "Unknown"), (row.published_end_of_sale_date || "Not in notice catalog") + " / " + (row.published_end_of_support_date || "Not in notice catalog"), (row.reported ? "Assigned inventory record observed. " : "Inventory record missing. ") + ((row.date_conflicts || []).length ? "API and published dates differ; verify with vendor. " : "") + (Number.isInteger(row.days_until_support_date) ? (evidence.schema_version === 2 && row.days_until_support_date < 0 ? "API support date passed " + (-row.days_until_support_date) + " days ago." : row.days_until_support_date + " days to API support date.") : "Support date unverified.")].forEach(function (value) {var td = document.createElement("td"); td.textContent = value; tr.append(td);});
        if (evidence.schema_version === 2 && ["https://documentation.meraki.com/Platform_Management/Product_Information/End-of-Life_Notices/Meraki_End-of-Life_(EOL)_Products_and_Dates", "https://www.cisco.com/c/en/us/products/collateral/wireless/catalyst-9100ax-access-points/meraki-wi-fi-6-indoor-access-points-eol.html"].indexOf(row.published_source_url) !== -1) {var published = document.createElement("a"); published.href = row.published_source_url; published.textContent = row.published_end_of_support_date ? "Published vendor dates" : "Review vendor index"; published.target = "_blank"; published.rel = "noopener noreferrer"; tr.children[4].append(published);}
        body.append(tr);
      }); table.append(body); scroll.append(table); section.append(scroll);
      if (evidence.additional_rows) {var more = document.createElement("p"); more.textContent = evidence.additional_rows + " more rows in the evidence download and PDF."; section.append(more);}
    }
    var link = document.createElement("a"); link.href = "https://developer.cisco.com/meraki/api-v1/get-organization-inventory-devices/"; link.textContent = "Meraki inventory API documentation"; link.target = "_blank"; link.rel = "noopener noreferrer"; section.append(link); container.append(section);
  }

  function renderMerakiLifecycle(container, evidence, overview) {
    if (!evidence) return;
    var section = document.createElement("section"); section.className = "meraki-detail-section";
    var heading = document.createElement("h4"); heading.textContent = "Hardware support milestones"; section.append(heading);
    if (evidence.status !== "available") {var missing = document.createElement("p"); missing.textContent = "Lifecycle evidence unavailable or invalid; support dates remain unverified."; section.append(missing); container.append(section); return;}
    var counts = evidence.summary || {}, summary = document.createElement("p");
    summary.textContent = counts.within_180_days + " devices with support dates within 180 days · " + counts.date_passed + " with dates passed · " + counts.unknown + " with unknown support dates · As of " + (evidence.as_of || "unknown date"); section.append(summary);
    var note = document.createElement("p"); note.className = "muted"; note.textContent = evidence.scope; section.append(note);
    if (overview) {container.append(section); return;}
    var scroll = document.createElement("div"); scroll.className = "table-scroll"; scroll.tabIndex = 0; scroll.setAttribute("role", "region"); scroll.setAttribute("aria-label", "Hardware lifecycle dates");
    var table = document.createElement("table"), caption = document.createElement("caption"); caption.textContent = "Vendor notices observed " + evidence.notice_observed_on; table.append(caption);
    var head = document.createElement("thead"), tr = document.createElement("tr");
    ["Network / model / quantity", "End of sale", "End of support", "Review / source"].forEach(function (label) {var th = document.createElement("th"); th.textContent = label; th.setAttribute("scope", "col"); tr.append(th);}); head.append(tr); table.append(head);
    var body = document.createElement("tbody"), labels = {date_passed: "Support date passed", within_180_days: "Support date within 180 days", later: "Support date later than 180 days", unknown: "Support date unknown"};
    (evidence.rows || []).forEach(function (row) {
      var tr = document.createElement("tr");
      [row.network_name + " / " + row.model + " × " + row.quantity, row.end_of_sale_date || "Unknown", row.end_of_support_date || "Unknown"].forEach(function (value) {var td = document.createElement("td"); td.textContent = value; tr.append(td);});
      var td = document.createElement("td"), text = document.createElement("p"); text.textContent = labels[row.support_status] + (Number.isInteger(row.days_until_support_date) ? " · " + (evidence.schema_version === 2 && row.days_until_support_date < 0 ? (-row.days_until_support_date) + " days ago" : row.days_until_support_date + " days") : "") + ". " + row.note; td.append(text);
      if (["https://documentation.meraki.com/Platform_Management/Product_Information/End-of-Life_Notices/Meraki_End-of-Life_(EOL)_Products_and_Dates", "https://documentation.meraki.com/Platform_Management/Product_Information/End-of-Life_(EOL)_Products_and_Dates", "https://www.cisco.com/c/en/us/products/collateral/wireless/catalyst-9100ax-access-points/meraki-wi-fi-6-indoor-access-points-eol.html"].indexOf(row.source_url) !== -1) {var link = document.createElement("a"); link.href = row.source_url; link.textContent = row.notice_status === "published" && row.source_url.indexOf("End-of-Life_Notices/") === -1 ? "Official vendor notice" : "Official vendor lifecycle index"; link.target = "_blank"; link.rel = "noopener noreferrer"; td.append(link);}
      tr.append(td); body.append(tr);
    }); table.append(body); scroll.append(table); section.append(scroll);
    if (evidence.additional_rows) {var more = document.createElement("p"); more.textContent = evidence.additional_rows + " more model/network rows in the evidence download and PDF."; section.append(more);}
    container.append(section);
  }

  function renderMerakiPaths(container, evidence, overview) {
    if (!evidence) return;
    var section = document.createElement("section"); section.className = "meraki-detail-section";
    var heading = document.createElement(overview ? "h3" : "h4"); heading.textContent = "Network traffic and connection review";
    var note = document.createElement("p"); note.className = "muted"; note.textContent = evidence.scope;
    section.append(heading, note);
    if (evidence.status !== "available" || !evidence.summary) {
      var unavailable = document.createElement("p"); unavailable.textContent = "Saved layer-review evidence is invalid or unavailable."; section.append(unavailable); container.append(section); return;
    }
    var number = function (value) {return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value.toLocaleString("en-US", {maximumFractionDigits: 3}) : "Unavailable";};
    var summary = evidence.summary, counts = document.createElement("p");
    counts.textContent = summary.mapped_ap_count + "/" + summary.assigned_ap_count + " APs uniquely mapped · " + summary.unmapped_ap_count + " unmapped · " + summary.ambiguous_ap_count + " ambiguous · " + summary.review_band_count + " RF bands meeting review thresholds · " + summary.ap_telemetry_unavailable_count + " APs with incomplete telemetry";
    section.append(counts);
    if (overview) {container.append(section); return;}
    var apTable = function (parent, aps, title) {
      if (!aps.length) return;
      var scroll = document.createElement("div"); scroll.className = "table-scroll"; scroll.tabIndex = 0; scroll.setAttribute("role", "region"); scroll.setAttribute("aria-label", "AP evidence for " + title);
      var table = document.createElement("table"), caption = document.createElement("caption"); caption.textContent = "Assigned APs · " + title; table.append(caption);
      var head = document.createElement("thead"), tr = document.createElement("tr");
      ["AP / model / state", "Local switch port / link", "Channel percentages", "Connection outcomes"].forEach(function (label) {var th = document.createElement("th"); th.textContent = label; th.setAttribute("scope", "col"); tr.append(th);}); head.append(tr); table.append(head);
      var body = document.createElement("tbody");
      aps.forEach(function (ap) {
        var tr = document.createElement("tr"), link = ap.port_evidence || {};
        var bands = ap.bands.map(function (band) {return band.band + " GHz: total " + number(band.percentages.total) + "% / WiFi " + number(band.percentages.wifi) + "% / non-WiFi " + number(band.percentages.nonWifi) + "%";}).join("; ") || "Unavailable";
        var counters = [["success", "Success"], ["assoc", "Assoc"], ["auth", "Auth"], ["dhcp", "DHCP"], ["dns", "DNS"]].map(function (field) {return field[1] + ": " + number(ap.connection_counters[field[0]]);}).join(" · ");
        var local = ap.local_port ? "Port " + ap.local_port + " · " + (link.state || "state unavailable") + " · " + (link.speed || "speed unavailable") + " · " + (link.duplex || "duplex unavailable") : "No unique switch mapping";
        [ap.name + " / " + ap.model + " / " + ap.status, local, bands + " · collection " + ap.channel_status + " · requested " + number(ap.channel_timespan_seconds) + " seconds", counters + " · collection " + ap.connection_status + " · requested " + number(ap.connection_timespan_seconds) + " seconds"].forEach(function (value) {var td = document.createElement("td"); td.textContent = value; tr.append(td);}); body.append(tr);
      }); table.append(body); scroll.append(table); parent.append(scroll);
    };
    evidence.networks.forEach(function (network, index) {
      var group = document.createElement("details"), title = document.createElement("summary"); group.open = index === 0;
      title.textContent = network.name + " · " + network.summary.mapped_ap_count + "/" + network.summary.assigned_ap_count + " APs mapped · " + network.summary.review_band_count + " RF review bands"; group.append(title);
      var records = document.createElement("p"); records.textContent = "Wireless client records: " + number(network.wireless_client_count) + " · requested " + number(network.wireless_client_timespan_seconds) + " seconds · " + network.rf_profile_count + " collected RF profiles. RF thresholds: total ≥50%, non-WiFi ≥20%; review observations require investigation. No combined connection failure rate is inferred."; group.append(records);
      var edgeHeading = document.createElement("h5"); edgeHeading.textContent = "WAN / edge"; group.append(edgeHeading);
      if (!network.edges.length) {var noEdge = document.createElement("p"); noEdge.textContent = "No assigned WAN appliance in this network; Internet reachability remains unverified."; group.append(noEdge);}
      network.edges.forEach(function (edge) {var row = document.createElement("p"); row.textContent = edge.name + " / " + edge.model + " / " + edge.status + " · " + (edge.interfaces.map(function (iface) {return iface.interface + ": " + iface.state;}).join(" · ") || "Interface states unavailable"); group.append(row);});
      network.wan_usage.forEach(function (iface) {var row = document.createElement("p"); row.textContent = iface.interface + " measured-window averages: " + number(iface.download.average_mbps) + " Mbps down / " + number(iface.upload.average_mbps) + " Mbps up · highest interval averages: " + number(iface.download.peak_interval_average_mbps) + " Mbps down / " + number(iface.upload.peak_interval_average_mbps) + " Mbps up. These do not establish instantaneous peaks or circuit capacity."; group.append(row);});
      var switchesHeading = document.createElement("h5"); switchesHeading.textContent = "Switches and mapped APs"; group.append(switchesHeading);
      network.switches.forEach(function (sw) {
        var switchGroup = document.createElement("details"), switchTitle = document.createElement("summary"); switchTitle.textContent = sw.name + " / " + sw.model + " / " + sw.status + " · " + sw.aps.length + " shown mapped APs · " + number(sw.review_port_count) + " ports for review"; switchGroup.append(switchTitle);
        var metrics = document.createElement("p"); metrics.textContent = number(sw.connected_port_count) + "/" + number(sw.reported_port_count) + " connected ports · collection " + sw.port_status + " · discovery " + sw.discovery_status + " · measured average PoE " + number(sw.power.measured_average_watts) + " W · coverage " + sw.power.energy_coverage + " · requested " + number(sw.power.requested_timespan_seconds) + " seconds. Partial averages do not establish capacity headroom."; switchGroup.append(metrics);
        if (!sw.aps.length) {var empty = document.createElement("p"); empty.textContent = "No AP with a unique saved mapping to this switch."; switchGroup.append(empty);}
        apTable(switchGroup, sw.aps, sw.name);
        if (sw.additional_aps) {var more = document.createElement("p"); more.textContent = sw.additional_aps + " more APs in complete saved JSON evidence."; switchGroup.append(more);}
        group.append(switchGroup);
      });
      apTable(group, network.unmapped_aps, network.name + " · unmapped APs"); apTable(group, network.ambiguous_aps, network.name + " · ambiguous mappings");
      [["edges", "WAN appliances"], ["switches", "switches"], ["unmapped_aps", "unmapped APs"], ["ambiguous_aps", "APs with ambiguous mappings"]].forEach(function (field) {if (network["additional_" + field[0]]) {var more = document.createElement("p"); more.textContent = network["additional_" + field[0]] + " more " + field[1] + " in complete saved JSON evidence."; group.append(more);}});
      section.append(group);
    });
    if (evidence.additional_networks) {var more = document.createElement("p"); more.textContent = evidence.additional_networks + " more networks in complete saved JSON evidence."; section.append(more);}
    container.append(section);
  }

  function renderMerakiNeighbors(container, evidence) {
    if (!evidence || !Array.isArray(evidence.switches) || !evidence.switches.length) return;
    var section = document.createElement("section"); section.className = "meraki-detail-section";
    var heading = document.createElement("h4"); heading.textContent = "Switch port relationships";
    var note = document.createElement("p"); note.className = "muted"; note.textContent = evidence.scope;
    section.append(heading, note);
    evidence.switches.forEach(function (sw) {
      var group = document.createElement("details"), title = document.createElement("summary"), data = sw.data;
      title.textContent = (sw.device_name || "Switch") + " · " + (sw.network_name || "Network") + " · " + (sw.status || "unknown") + (data ? " · " + data.matched_port_count + " matched / " + data.reported_port_count + " reported ports" : " · relationships unavailable"); group.append(title);
      if (data) {
        var counts = document.createElement("p"); counts.textContent = data.unmatched_port_count + " unmatched · " + data.ambiguous_port_count + " ambiguous"; group.append(counts);
        if (data.rows.length) {
          var scroll = document.createElement("div"); scroll.className = "table-scroll"; scroll.tabIndex = 0; scroll.setAttribute("role", "region"); scroll.setAttribute("aria-label", "Port relationships for " + (sw.device_name || "Switch"));
          var table = document.createElement("table"), caption = document.createElement("caption"); caption.textContent = "Saved LLDP/CDP discovery · assigned inventory only"; table.append(caption);
          var head = document.createElement("thead"), tr = document.createElement("tr");
          ["Local port", "Assigned neighbor", "Model", "Remote port", "Evidence"].forEach(function (label) {var th = document.createElement("th"); th.textContent = label; th.setAttribute("scope", "col"); tr.append(th);}); head.append(tr); table.append(head);
          var body = document.createElement("tbody"); data.rows.forEach(function (row) {
            var tr = document.createElement("tr");
            [row.local_port, row.status === "matched" ? row.neighbor_name : row.status === "ambiguous" ? "Ambiguous discovery" : "Not matched to assigned inventory", row.neighbor_model || "Unavailable", row.neighbor_ports && Object.keys(row.neighbor_ports).length ? Object.entries(row.neighbor_ports).map(function (entry) {return entry[0].toUpperCase() + ": " + entry[1];}).join(" · ") : row.remote_port_conflict ? "Different protocol port IDs" : row.neighbor_port || "Unavailable", row.protocols.length ? row.protocols.join(", ") : row.status].forEach(function (value) {var td = document.createElement("td"); td.textContent = value; tr.append(td);}); body.append(tr);
          }); table.append(body); scroll.append(table); group.append(scroll);
        } else {var empty = document.createElement("p"); empty.textContent = "No discovery ports returned; this does not establish an empty network."; group.append(empty);}
        if (data.additional_rows) {var more = document.createElement("p"); more.textContent = data.additional_rows + " more ports in complete saved JSON evidence."; group.append(more);}
      }
      section.append(group);
    });
    if (evidence.additional_switches) {var more = document.createElement("p"); more.textContent = evidence.additional_switches + " more switches in complete saved JSON evidence."; section.append(more);}
    container.append(section);
  }

  function renderMerakiSwitchPorts(container, evidence) {
    if (!evidence || !Array.isArray(evidence.switches) || !evidence.switches.length) return;
    var section = document.createElement("section"); section.className = "meraki-detail-section";
    var heading = document.createElement("h4"); heading.textContent = "Switch health and port evidence";
    var note = document.createElement("p"); note.className = "muted";
    note.textContent = "Reported link states and prior 24-hour counters. Review prompts require investigation; averages do not establish a bottleneck, peak load or replacement capacity.";
    section.append(heading, note);
    var value = function (number) { return typeof number === "number" && Number.isFinite(number) && number >= 0 ? number.toLocaleString("en-US", {maximumFractionDigits: 3}) : "Unavailable"; };
    evidence.switches.forEach(function (sw) {
      var group = document.createElement("details"), title = document.createElement("summary"), data = sw.data || {};
      title.textContent = (sw.device_name || sw.device_serial || "Switch") + " · " + (sw.network_name || "Network") + " · " + (sw.status || "unknown") + " · " + value(data.review_port_count) + " ports for review";
      group.append(title);
      var coverage = document.createElement("p"); coverage.textContent = "Configuration: " + (sw.configuration_status || "unknown") + " · " + value(data.connected_port_count) + " connected / " + value(data.reported_port_count) + " reported ports · " + value(data.missing_status_port_count) + " configured ports missing status · " + value(data.unknown_state_port_count) + " unknown states · " + value(data.diagnostic_coverage_port_count) + " ports with diagnostic coverage"; group.append(coverage);
      if (Array.isArray(data.rows) && data.rows.length) {
        var scroll = document.createElement("div"); scroll.className = "table-scroll"; scroll.tabIndex = 0; scroll.setAttribute("aria-label", "Switch port observations for " + (sw.device_name || sw.device_serial || "Switch"));
        var table = document.createElement("table"), caption = document.createElement("caption"); caption.textContent = "Saved port evidence · review prompts first"; table.append(caption);
        var head = document.createElement("thead"), tr = document.createElement("tr");
        ["Port", "State / speed", "Uplink", "Mode / VLAN", "Traffic total Kbps", "Usage total KB", "Energy Wh", "Review prompts"].forEach(function (label) {var th = document.createElement("th"); th.textContent = label; th.setAttribute("scope", "col"); tr.append(th);}); head.append(tr); table.append(head);
        var body = document.createElement("tbody"); data.rows.forEach(function (row) {
          var tr = document.createElement("tr"), prompts = Array.isArray(row.review_prompts) ? row.review_prompts : [];
          [row.port_id, (row.state || "Unknown") + " / " + (row.speed || "Unavailable"), row.is_uplink === true ? "Yes" : row.is_uplink === false ? "No" : "Unknown", (row.mode || "Unknown") + " / " + value(row.vlan), value((row.traffic_kbps || {}).total), value((row.usage_kb || {}).total), value(row.power_usage_wh), prompts.length ? prompts.join("; ") : "No captured review prompt"].forEach(function (text) {var td = document.createElement("td"); td.textContent = text; tr.append(td);}); body.append(tr);
        }); table.append(body); scroll.append(table); group.append(scroll);
      }
      if (data.additional_rows) {var more = document.createElement("p"); more.textContent = data.additional_rows + " more ports in complete saved JSON evidence."; group.append(more);}
      section.append(group);
    });
    if (evidence.additional_switches) {var more = document.createElement("p"); more.textContent = evidence.additional_switches + " more switches in complete saved JSON evidence."; section.append(more);}
    container.append(section);
  }

  function renderMerakiSwitchOverview(container, details) {
    var evidence = details.switch_ports || {}, switches = evidence.switches || [];
    if (!switches.length) return;
    var section = document.createElement("section"); section.className = "meraki-detail-section";
    var heading = document.createElement("h3"); heading.textContent = "Switch health";
    var note = document.createElement("p"); note.textContent = "Saved port evidence for " + switches.length + " shown switches" + (evidence.additional_switches ? "; " + evidence.additional_switches + " additional switches in complete JSON" : "") + ". Review prompts are observations for investigation.";
    section.append(heading, note);
    switches.slice(0, 5).forEach(function (sw) {var row = document.createElement("p"), data = sw.data || {}, count = function (v) {return Number.isSafeInteger(v) && v >= 0 ? String(v) : "Unavailable";}; row.textContent = (sw.device_name || sw.device_serial || "Switch") + ": " + count(data.review_port_count) + " ports for review · " + count(data.connected_port_count) + "/" + count(data.reported_port_count) + " connected · collection " + (sw.status || "unknown"); section.append(row);});
    if (switches.length > 5) {var more = document.createElement("p"); more.textContent = switches.length - 5 + " more shown switches in saved report details."; section.append(more);}
    var discovery = details.switch_neighbors;
    if (discovery && Array.isArray(discovery.switches)) {
      var mapped = 0, unknown = 0, ambiguous = 0, collected = 0;
      discovery.switches.forEach(function (sw) {if (sw.data) {collected++; mapped += sw.data.matched_port_count; unknown += sw.data.unmatched_port_count; ambiguous += sw.data.ambiguous_port_count;}});
      var relationships = document.createElement("p"); relationships.textContent = "Port discovery: " + mapped + " matched to assigned inventory · " + unknown + " unmatched · " + ambiguous + " ambiguous · " + collected + "/" + discovery.switches.length + " shown switches collected" + (discovery.additional_switches ? " · " + discovery.additional_switches + " additional switches in JSON" : ""); section.append(relationships);
    }
    var action = document.createElement("button"); action.type = "button"; action.className = "button button-small button-quiet"; action.textContent = "Review switch port evidence";
    action.addEventListener("click", function () {if (!Number.isSafeInteger(details.report_id)) return; var saved = document.querySelector('#tab-meraki details[data-report-id="' + details.report_id + '"]'); if (!saved) return; saved.open = true; var summary = saved.querySelector("summary"); if (summary) {summary.focus(); summary.scrollIntoView({block: "center", behavior: "smooth"});}});
    section.append(action); container.append(section);
  }

  function renderMerakiWanUsage(container, observations) {
    (observations || []).forEach(function (observation) {
      var data = observation.data || {}, section = document.createElement("section"); section.className = "meraki-detail-section";
      var heading = document.createElement("h4"); heading.textContent = "WAN usage · " + (observation.network_name || "Network");
      var note = document.createElement("p"); note.className = "muted";
      note.textContent = "Collection: " + (observation.status || "unknown") + ". Prior seven-day request at hourly resolution. Rates cover measured seconds only; the highest interval average is not an instantaneous peak or subscribed circuit capacity.";
      section.append(heading, note);
      if (observation.status === "complete") {
        var coverage = document.createElement("p"); coverage.textContent = (data.interval_count ?? "—") + " intervals reported · " + (data.first_interval_start || "start unavailable") + " to " + (data.last_interval_end || "end unavailable"); section.append(coverage);
        if (!(data.interfaces || []).length) {var empty = document.createElement("p"); empty.textContent = "No interface counters reported. Usage remains unavailable."; section.append(empty);}
        else {
          var scroll = document.createElement("div"); scroll.className = "table-scroll"; scroll.tabIndex = 0; scroll.setAttribute("aria-label", "WAN usage measurements");
          var table = document.createElement("table"), caption = document.createElement("caption"); caption.textContent = "Saved WAN usage by interface and direction"; table.append(caption);
          var head = document.createElement("thead"), tr = document.createElement("tr");
          ["Interface", "Direction", "Observed GiB", "Measured hours", "Measured intervals", "Average Mbps", "Highest interval average Mbps"].forEach(function (label) {var th = document.createElement("th"); th.textContent = label; th.setAttribute("scope", "col"); tr.append(th);}); head.append(tr); table.append(head);
          var body = document.createElement("tbody");
          var format = function (value, scale) {return typeof value === "number" && Number.isFinite(value) && value >= 0 ? (value / (scale || 1)).toLocaleString("en-US", {maximumFractionDigits: 3}) : "Unavailable";};
          (data.interfaces || []).forEach(function (iface) {[["sent", "Upload"], ["received", "Download"]].forEach(function (direction) {
            var measured = (iface.directions || {})[direction[0]] || {}, tr = document.createElement("tr");
            var count = Number.isSafeInteger(measured.measured_interval_count) && measured.measured_interval_count >= 0 ? measured.measured_interval_count + "/" + iface.reported_interval_count : "Unavailable";
            [iface.interface, direction[1], format(measured.observed_bytes, 1073741824), format(measured.observed_seconds, 3600), count, format(measured.average_mbps), format(measured.peak_interval_average_mbps)].forEach(function (value) {var td = document.createElement("td"); td.textContent = value; tr.append(td);}); body.append(tr);
          });}); table.append(body); scroll.append(table); section.append(scroll);
        }
      }
      if (data.additional_interfaces) {var more = document.createElement("p"); more.textContent = data.additional_interfaces + " more interfaces in complete saved evidence."; section.append(more);}
      container.append(section);
    });
  }

  function renderMerakiWanuplinks(container, evidence) {
    if (!evidence || !evidence.status) return;
    var data = evidence.data || {}, section = document.createElement("section"); section.className = "meraki-detail-section";
    var heading = document.createElement("h4"); heading.textContent = "WAN / Internet uplinks";
    var note = document.createElement("p"); note.className = "muted";
    note.textContent = "Collection: " + evidence.status + ". Current reported interface states; no circuit capacity or throughput measurement. A ready or disconnected secondary interface does not establish an outage.";
    section.append(heading, note);
    if (evidence.status === "complete") {
      var summary = document.createElement("p"); summary.textContent = (data.reported_device_count ?? "—") + "/" + (data.expected_device_count ?? "—") + " assigned appliances reported · " + (data.interface_count ?? "—") + " interfaces · " + (data.missing_device_count ?? "—") + " appliances missing"; section.append(summary);
      var scroll = document.createElement("div"); scroll.className = "table-scroll"; scroll.tabIndex = 0; scroll.setAttribute("aria-label", "WAN interface observations");
      var table = document.createElement("table"), caption = document.createElement("caption"); caption.textContent = "Saved WAN interface states"; table.append(caption);
      var head = document.createElement("thead"), tr = document.createElement("tr");
      ["Appliance", "Network", "Interface", "Reported state", "Device last reported"].forEach(function (label) {var th = document.createElement("th"); th.textContent = label; th.setAttribute("scope", "col"); tr.append(th);}); head.append(tr); table.append(head);
      var body = document.createElement("tbody");
      (evidence.rows || []).forEach(function (row) {var tr = document.createElement("tr"); [row.device_name || row.device_serial, row.network_name || row.network_id, row.interface, row.state || "unknown", row.last_reported_at || "Unavailable"].forEach(function (value) {var td = document.createElement("td"); td.textContent = value; tr.append(td);}); body.append(tr);});
      table.append(body); scroll.append(table); section.append(scroll);
      if (evidence.additional_rows) {var more = document.createElement("p"); more.textContent = evidence.additional_rows + " more interfaces in the complete saved evidence."; section.append(more);}
    }
    container.append(section);
  }

  function renderMerakiChannelUtilization(container, evidence) {
    if (!evidence || !evidence.status) return;
    var data = evidence.data || {};
    var section = document.createElement("section"); section.className = "meraki-detail-section";
    var heading = document.createElement("h4"); heading.textContent = "Wireless channel utilization";
    var note = document.createElement("p"); note.className = "muted";
    note.textContent = "Collection: " + evidence.status + ". Prior 24-hour per-band averages; missing measurements stay unavailable. Review prompts: total ≥50% or non-Wi-Fi ≥20%. These readings do not establish interference causes, peak load or replacement capacity.";
    section.append(heading, note);
    if (evidence.status === "complete") {
      var summary = document.createElement("p");
      summary.textContent = (data.reported_device_count ?? "—") + "/" + (data.expected_device_count ?? "—") + " assigned APs measured · " + (data.measured_band_count ?? "—") + " bands with observations · " + (data.review_band_count ?? "—") + " bands meet a review threshold";
      section.append(summary);
      var scroll = document.createElement("div"); scroll.className = "table-scroll"; scroll.tabIndex = 0; scroll.setAttribute("aria-label", "Wireless channel utilization measurements");
      var table = document.createElement("table"); var caption = document.createElement("caption"); caption.textContent = "Saved channel averages by access point and band"; table.append(caption);
      var head = document.createElement("thead"), header = document.createElement("tr");
      ["Access point", "Band (GHz)", "Wi-Fi", "Non-Wi-Fi", "Total", "Review"].forEach(function (label) {var cell = document.createElement("th"); cell.textContent = label; cell.setAttribute("scope", "col"); header.append(cell);}); head.append(header); table.append(head);
      var body = document.createElement("tbody");
      var format = function (value) {return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 100 ? value.toLocaleString("en-US", {maximumFractionDigits: 2}) + "%" : "Unavailable";};
      (evidence.rows || []).forEach(function (row) {
        var tr = document.createElement("tr"), values = row.percentages || {};
        [row.device_serial, row.band, format(values.wifi), format(values.nonWifi), format(values.total), row.review_threshold_met === true ? "Review channel" : "No reported threshold met"].forEach(function (value) {var cell = document.createElement("td"); cell.textContent = value; tr.append(cell);}); body.append(tr);
      });
      table.append(body); scroll.append(table); section.append(scroll);
      if (evidence.additional_rows) {var more = document.createElement("p"); more.textContent = evidence.additional_rows + " more rows in the complete saved evidence."; section.append(more);}
    }
    container.append(section);
  }

  function renderMerakiWirelessConnections(container, rows) {
    addMerakiDetailList(container, "Wireless connection outcomes", rows, function (row) {
      var data = row.data || {}, totals = data.observed_counter_totals || {};
      var values = [row.network_name || "Network", "Collection: " + (row.status || "unknown")];
      if (row.status === "complete") {
        values.push("Prior " + Math.round(data.requested_timespan_seconds / 3600) + " hours");
        values.push((data.reported_device_count ?? "—") + "/" + (data.expected_device_count ?? "—") + " assigned APs reported · " + (data.counter_coverage || "unknown") + " counter coverage");
        [["success", "Successful connections"], ["assoc", "Association failures"], ["auth", "Authentication failures"], ["dhcp", "DHCP failures"], ["dns", "DNS failures"]].forEach(function (field) {
          if (Number.isSafeInteger(totals[field[0]]) && totals[field[0]] >= 0) values.push(field[1] + ": " + totals[field[0]].toLocaleString("en-US"));
        });
        values.push("Failure-stage counters are observations, not a combined failure rate or security score.");
      }
      return values.join(" · ");
    });

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
    if (details.path_analysis) renderMerakiPaths(container, details.path_analysis, false);

    if (details.unifi_plan && details.unifi_plan.provider_lifecycle) renderMerakiProviderLifecycle(container, details.unifi_plan.provider_lifecycle, false);
    if (details.unifi_plan && details.unifi_plan.lifecycle) renderMerakiLifecycle(container, details.unifi_plan.lifecycle, false);
    var plan = details.unifi_plan;
    if (plan && Array.isArray(plan.scenarios)) {
      var planning = document.createElement("section"); planning.className = "meraki-detail-section";
      var planningHeading = document.createElement("h4"); planningHeading.textContent = "UniFi purchase planning";
      var dated = document.createElement("p"); dated.textContent = "USD · Prices and availability observed " + plan.price_observed_on;
      planning.append(planningHeading, dated);
      (plan.assumptions || []).forEach(function (note) {
        var paragraph = document.createElement("p"); paragraph.className = "muted"; paragraph.textContent = note; planning.append(paragraph);
      });
      var money = function (cents) { return new Intl.NumberFormat("en-US", {style: "currency", currency: "USD"}).format(cents / 100); };
      plan.scenarios.forEach(function (scenario) {
        var group = document.createElement("details");
        var title = document.createElement("summary");
        title.textContent = scenario.name + " · " + money(scenario.hardware_subtotal_cents) + " hardware subtotal" + (scenario.complete_inventory_pricing ? "" : " · Partial inventory pricing");
        group.append(title);
        (scenario.rows || []).concat(scenario.additional_items || []).forEach(function (row) {
          var line = document.createElement("p");
          line.textContent = row.quantity + " × " + row.meraki_model + " → " + row.candidate_model + " · " + money(row.unit_with_surcharge_cents) + " each including surcharge · " + money(row.subtotal_cents) + " · " + row.availability_observed + ". ";
          if (/^https:\/\/store\.ui\.com\/us\/en\/products\/[a-z0-9-]+$/.test(row.purchase_url || "")) {
            var link = document.createElement("a"); link.href = row.purchase_url; link.target = "_blank"; link.rel = "noopener noreferrer"; link.textContent = "View product"; link.setAttribute("aria-label", "View " + row.candidate_model + " (opens in a new tab)"); line.append(link);
          }
          var review = document.createElement("p"); review.className = "muted"; review.textContent = row.review;
          group.append(line, review);
        });
        (scenario.unmatched || []).forEach(function (row) {
          var missing = document.createElement("p"); missing.textContent = row.quantity + " × " + row.meraki_model + ": candidate and price need review."; group.append(missing);
        });
        if (scenario.additional_unmatched_models) {
          var more = document.createElement("p"); more.textContent = scenario.additional_unmatched_models + " more unpriced models. Download complete JSON evidence for the full list."; group.append(more);
        }
        planning.append(group);
      });
      container.append(planning);
    }

    renderMerakiActionPlan(container, details.action_plan);
    renderMerakiClientDistributions(container, details.wireless_clients, details.wireless_clients_additional_networks);
    renderMerakiCis8(container, details.cis8_assessment);
    renderMerakiNeighbors(container, details.switch_neighbors);
    renderMerakiTopology(container, details.topology_graph);
    renderMerakiRefreshPlan(container, details.unifi_plan && details.unifi_plan.refresh_plan);
    renderMerakiSwitchPorts(container, details.switch_ports);
    renderMerakiPowerUsage(container, details.switch_power, (details.truncated || {}).switch_power);

    renderMerakiWanuplinks(container, details.wan_uplinks);
    renderMerakiWanUsage(container, details.wan_usage);
    if (details.wan_usage_additional_networks) {var moreWan = document.createElement("p"); moreWan.textContent = details.wan_usage_additional_networks + " more WAN networks in complete saved evidence."; container.append(moreWan);}
    renderMerakiChannelUtilization(container, details.channel_utilization);
    renderMerakiWirelessConnections(container, details.wireless_connections || []);

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
    if (!Number.isSafeInteger(reportId) || reportId <= 0) return Promise.reject(new Error("Invalid saved report."));
    var cached = merakiDashboardDetailCache.get(reportId);
    if (!cached) {
      var controller = new AbortController();
      var deadline = window.setTimeout(function () { controller.abort(); }, 20000);
      cached = fetch("/api/meraki/reports/" + encodeURIComponent(reportId) + "/details", {credentials: "same-origin", cache: "no-store", signal: controller.signal})
        .then(async function (response) {
          var body = await response.json();
          if (!response.ok) throw new Error("Saved report details could not be read.");
          if (!body || typeof body !== "object" || Array.isArray(body) || body.report_id !== reportId || body.organization_id !== Number(orgId)
              || !body.summary || typeof body.summary !== "object" || Array.isArray(body.summary)
              || !Array.isArray(body.findings)) throw new Error("Saved report details could not be validated.");
          return body;
        }).catch(function (error) {
          if (merakiDashboardDetailCache.get(reportId) === cached) merakiDashboardDetailCache.delete(reportId);
          throw error;
        }).finally(function () { window.clearTimeout(deadline); });
      merakiDashboardDetailCache.set(reportId, cached);
    }
    return cached;
  }

  async function readMerakiEvidence(reportId, container, renderer, label) {
    if (container.dataset.loading || (container.dataset.loaded && container.dataset.loadedReportId === String(reportId))) return false;
    delete container.dataset.loaded;
    container.dataset.loading = "true";
    container.setAttribute("aria-busy", "true");
    var retryControl = container.querySelector("[data-meraki-evidence-retry]");
    if (retryControl) retryControl.setAttribute("aria-disabled", "true");
    else container.textContent = "Loading " + label + "…";
    try {
      var details = await fetchMerakiDashboardDetails(reportId);
      if (container.isConnected === false) return false;
      var restoreFocus = container.contains(document.activeElement);
      renderer(container, details);
      container.dataset.loaded = "true";
      container.dataset.loadedReportId = String(reportId);
      if (restoreFocus) {
        var summary = container.parentElement && container.parentElement.querySelector("summary");
        if (summary) summary.focus();
        else { container.tabIndex = -1; container.focus(); }
      }
      return true;
    } catch (_error) {
      if (container.isConnected === false) return false;
      var restoreFocus = container.contains(document.activeElement);
      container.replaceChildren();
      var warning = document.createElement("p");
      warning.className = "check-scope-note";
      warning.setAttribute("role", "status");
      warning.textContent = "Saved " + label + " could not be loaded. Retrying reads the saved snapshot and does not run an audit.";
      var retry = document.createElement("button");
      retry.type = "button"; retry.className = "button button-small button-quiet";
      retry.textContent = "Retry " + label;
      retry.dataset.merakiEvidenceRetry = "true";
      retry.addEventListener("click", function () { return readMerakiEvidence(reportId, container, renderer, label); });
      container.append(warning, retry);
      if (restoreFocus) retry.focus();
      return false;
    } finally {
      delete container.dataset.loading;
      container.setAttribute("aria-busy", "false");
    }
  }

  function renderMerakiActionOverview(container, details) {
    var plan = details.action_plan;
    if (!plan || plan.schema_version !== 1 || !Array.isArray(plan.rows)) return;
    var section = document.createElement("section");section.className = "meraki-detail-section";var heading = document.createElement("h3");heading.textContent = "Recommended next actions";section.append(heading);
    plan.rows.slice(0, 3).forEach(function (row) {var title = document.createElement("strong");title.textContent = row.title;var p = document.createElement("p");p.textContent = row.action;section.append(title, p);});
    var note = document.createElement("p");note.className = "muted";note.textContent = "Suggested review windows require an approved owner and change plan. No automatic remediation or purchasing.";section.append(note);
    var action = document.createElement("button");action.type = "button";action.className = "button button-small button-quiet";action.textContent = "Review implementation plan";
    action.addEventListener("click", function () {if (!Number.isSafeInteger(details.report_id)) return;var saved = document.querySelector('#tab-meraki details[data-report-id="' + details.report_id + '"]');if (!saved) return;saved.open = true;var summary = saved.querySelector("summary");if (summary) {summary.focus();summary.scrollIntoView({block: "center", behavior: "smooth"});}});section.append(action);container.append(section);
  }

  function renderMerakiClientOverview(container, details) {
    var observations = details.wireless_clients;
    if (!Array.isArray(observations) || !observations.length) return;
    var section = document.createElement("section"); section.className = "meraki-detail-section";
    var heading = document.createElement("h3"); heading.textContent = "Wireless client observations"; section.append(heading);
    observations.slice(0, 5).forEach(function (row) {var p = document.createElement("p"); var n = row.data && row.data.wireless_client_count; p.textContent = (row.network_name || "Network") + ": " + (Number.isSafeInteger(n) ? n + " wireless records" : "count unavailable") + " · collection " + (row.status || "unknown"); section.append(p);});
    var note = document.createElement("p"); note.className = "muted"; note.textContent = "Prior one-hour request; last-reported SSID, OS/device type and VLAN distributions. Counts do not establish concurrent clients or distinct people. RSSI unavailable."; section.append(note);
    var action = document.createElement("button"); action.type = "button"; action.className = "button button-small button-quiet"; action.textContent = "Review wireless client distributions";
    action.addEventListener("click", function () {if (!Number.isSafeInteger(details.report_id)) return;var saved = document.querySelector('#tab-meraki details[data-report-id="' + details.report_id + '"]'); if (!saved) return;saved.open = true;var summary = saved.querySelector("summary");if (summary) {summary.focus();summary.scrollIntoView({block: "center", behavior: "smooth"});}}); section.append(action); container.append(section);
  }

  function renderMerakiCis8Overview(container, details) {
    var evidence = details.cis8_assessment;
    if (!evidence || evidence.schema_version !== 1 || !Array.isArray(evidence.rows)) return;
    var section = document.createElement("section");section.className = "meraki-detail-section";
    var heading = document.createElement("h3");heading.textContent = "CIS Controls evidence coverage";
    var grid = document.createElement("div");grid.className = "audit-metric-grid";
    [["Partial evidence", "partial"], ["Review observations", "review"], ["Not assessed", "not_assessed"]].forEach(function (label) {var card = document.createElement("article");card.className = "audit-policy-card";var title = document.createElement("strong");title.textContent = label[0];var count = document.createElement("p");var v = (evidence.summary || {})[label[1]];count.textContent = Number.isSafeInteger(v) && v >= 0 ? String(v) : "Unavailable";card.append(title, count);grid.append(card);});
    var note = document.createElement("p");note.className = "muted";note.textContent = "Control-level network evidence index. All controls require human assessment; no safeguard compliance or overall score is asserted. Endpoint benchmark results are separate.";
    section.append(heading, grid, note);
    var action = document.createElement("button");action.type = "button";action.className = "button button-small button-quiet";action.textContent = "Review CIS control evidence";
    action.addEventListener("click", function () {if (!Number.isSafeInteger(details.report_id)) return;var saved = document.querySelector('#tab-meraki details[data-report-id="' + details.report_id + '"]');if (!saved) return;saved.open = true;var summary = saved.querySelector("summary");if (summary) {summary.focus();summary.scrollIntoView({block: "center", behavior: "smooth"});}});section.append(action);container.append(section);
  }

  function renderMerakiTopologyOverview(container, details) {
    var evidence = details.topology_graph;
    if (!evidence || !Array.isArray(evidence.networks) || !evidence.networks.length) return;
    var section = document.createElement("section");section.className = "meraki-detail-section";
    var title = document.createElement("h3");title.textContent = "Network relationships";section.append(title);
    evidence.networks.slice(0, 3).forEach(function (network) {var row = document.createElement("p"), count = function (v) {return Number.isSafeInteger(v) && v >= 0 ? String(v) : "Unavailable";};row.textContent = (network.network_name || "Network") + ": " + count(network.node_count) + " observed assigned devices · " + count(network.link_count) + " relationship pairs · collection " + (network.status || "unknown");section.append(row);});
    if (evidence.networks.length > 3 || evidence.additional_networks) {var more = document.createElement("p");more.textContent = "Additional networks are available in saved report details and complete JSON.";section.append(more);}
    var note = document.createElement("p");note.className = "muted";note.textContent = "Observed managed-device relationships; missing links do not establish disconnection or a complete network map.";section.append(note);
    var action = document.createElement("button");action.type = "button";action.className = "button button-small button-quiet";action.textContent = "Review network relationships";
    action.addEventListener("click", function () {if (!Number.isSafeInteger(details.report_id)) return;var saved = document.querySelector('#tab-meraki details[data-report-id="' + details.report_id + '"]');if (!saved) return;saved.open = true;var summary = saved.querySelector("summary");if (summary) {summary.focus();summary.scrollIntoView({block: "center", behavior: "smooth"});}});section.append(action);container.append(section);
  }

  function renderMerakiWanOverview(container, details) {
    var state = details.wan_uplinks || {}, usage = Array.isArray(details.wan_usage) ? details.wan_usage : [];
    if (!state.status && !usage.length) return;
    var section = document.createElement("section"); section.className = "meraki-detail-section";
    var heading = document.createElement("h3"); heading.textContent = "WAN / Internet observations";
    var note = document.createElement("p"); note.className = "muted";
    note.textContent = "Saved link states and prior seven-day usage request. Rates average measured intervals; they do not establish subscribed capacity, instantaneous peaks or service availability.";
    section.append(heading, note);
    if (state.status) {var line = document.createElement("p"), data = state.data || {};
      line.textContent = "Link-state collection: " + state.status;
      if (state.status === "complete") line.textContent += " · " + (data.reported_device_count ?? "—") + "/" + (data.expected_device_count ?? "—") + " assigned appliances reported · " + (data.state_counts?.active ?? 0) + " active interfaces · " + (data.missing_device_count ?? "—") + " appliances missing";
      section.append(line);
    }
    var grid = document.createElement("div"); grid.className = "audit-metric-grid"; var shown = 0, total = 0;
    var format = function (value) {return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value.toLocaleString("en-US", {maximumFractionDigits: 3}) : "Unavailable";};
    usage.forEach(function (observation) {var interfaces = (observation.data || {}).interfaces || [];total += Math.max(1, interfaces.length);
      if (shown >= 3) return;
      if (!interfaces.length) {var empty = document.createElement("article"); empty.className = "audit-policy-card"; var title = document.createElement("strong"); title.textContent = observation.network_name || "Network";var status = document.createElement("p"); status.textContent = "Usage unavailable · collection " + (observation.status || "unknown");empty.append(title, status);grid.append(empty);shown++;return;}
      interfaces.forEach(function (iface) {if (shown >= 3) return;var card = document.createElement("article");card.className = "audit-policy-card";
        var title = document.createElement("strong");title.textContent = (observation.network_name || "Network") + " / " + iface.interface;card.append(title);
        [["received", "Download"], ["sent", "Upload"]].forEach(function (direction) {var measured = (iface.directions || {})[direction[0]] || {}, line = document.createElement("p");
          line.textContent = direction[1] + " average: " + format(measured.average_mbps) + " Mbps · highest interval average: " + format(measured.peak_interval_average_mbps) + " Mbps · measured " + format(typeof measured.observed_seconds === "number" ? measured.observed_seconds / 3600 : null) + " hours";card.append(line);});
        grid.append(card);shown++;
      });
    });section.append(grid);
    var remaining = Math.max(0, total - shown) + (details.wan_usage_additional_networks || 0);
    if (remaining) {var more = document.createElement("p");more.textContent = "Additional WAN evidence is available in saved report details.";section.append(more);}
    var action = document.createElement("button");action.type = "button";action.className = "button button-small button-quiet";action.textContent = "Review WAN evidence";
    action.addEventListener("click", function () {if (!Number.isSafeInteger(details.report_id)) return;var saved = document.querySelector('#tab-meraki details[data-report-id="' + details.report_id + '"]');if (!saved) return;saved.open = true;var summary = saved.querySelector("summary");if (summary) {summary.focus();summary.scrollIntoView({block:"center",behavior:"smooth"});}});section.append(action);container.append(section);
  }

  function renderMerakiPlanningOverview(container, details) {
    var plan = details.unifi_plan;
    if (!plan || plan.schema_version !== 1 || plan.currency !== "USD" || !Array.isArray(plan.scenarios)) return;
    var scenarios = plan.scenarios.slice(0, 2).filter(function (row) { return row && Number.isSafeInteger(row.hardware_subtotal_cents) && row.hardware_subtotal_cents >= 0; });
    if (!scenarios.length) return;
    var section = document.createElement("section"); section.className = "meraki-detail-section";
    var title = document.createElement("h3"); title.textContent = "UniFi replacement planning";
    var note = document.createElement("p"); note.className = "muted";
    note.textContent = "Saved USD equipment budgets · prices observed " + (plan.price_observed_on || "date unavailable") + ". Includes vendor surcharge; excludes tax, shipping, accessories and installation. Candidates require design review.";
    var grid = document.createElement("div"); grid.className = "audit-metric-grid";
    scenarios.forEach(function (row) {
      var card = document.createElement("article"); card.className = "audit-policy-card";
      var name = document.createElement("strong"); name.textContent = row.name || "Purchase scenario";
      var amount = document.createElement("p"); amount.textContent = new Intl.NumberFormat("en-US", {style: "currency", currency: "USD", maximumFractionDigits: 2}).format(row.hardware_subtotal_cents / 100);
      var coverage = document.createElement("p"); coverage.className = "muted";
      coverage.textContent = row.complete_inventory_pricing === true ? "All assigned inventory priced" : "Partial inventory pricing; review unpriced models";
      card.append(name, amount, coverage);
      var refresh = plan.refresh_plan;
      var reserve = refresh && refresh.schema_version === 1 && refresh.currency === "USD" && Array.isArray(refresh.scenarios) ? refresh.scenarios.find(function (item) {return item.name === row.name;}) : null;
      if (reserve && Number.isSafeInteger(reserve.annual_reserve_cents) && reserve.annual_reserve_cents >= 0 && Number.isSafeInteger(reserve.replacement_cycle_years)) {
        var annual = document.createElement("p"); annual.className = "muted";
        annual.textContent = new Intl.NumberFormat("en-US", {style: "currency", currency: "USD"}).format(reserve.annual_reserve_cents / 100) + "/year nominal equipment reserve · assumed " + reserve.replacement_cycle_years + "-year cycle" + (reserve.complete_inventory_pricing === true ? "" : " · priced inventory only"); card.append(annual);
      }
      grid.append(card);
    });
    section.append(title, note, grid);
    var action = document.createElement("button"); action.type = "button"; action.className = "button button-small button-quiet";
    action.textContent = "Review quantities and vendor links";
    action.addEventListener("click", function () {
      if (!Number.isSafeInteger(details.report_id)) return;
      var saved = document.querySelector('#tab-meraki details[data-report-id="' + details.report_id + '"]');
      if (!saved) return;
      saved.open = true; var summary = saved.querySelector("summary");
      if (summary) { summary.focus(); summary.scrollIntoView({block: "center", behavior: "smooth"}); }
    });
    section.append(action); container.append(section);
  }

  function renderMerakiSummaryObservations(container, details) {
    container.replaceChildren();
    var review = details.findings.filter(function (item) { return item && item.status === "Review"; });
    if (!review.length) appendEmpty(container, "No saved observations are labeled Review.");
    else {
      var heading = document.createElement("h3"); heading.textContent = "Review observations";
      container.append(heading);
      review.slice(0, 5).forEach(function (item) {
        var row = document.createElement("article"); row.className = "audit-policy-card";
        var title = document.createElement("strong"); title.textContent = item.title || "Observation requires review";
        var detail = document.createElement("p"); detail.textContent = item.detail || "Open the saved report for supporting evidence.";
        row.append(title, detail); container.append(row);
      });
      if (review.length > 5) appendEmpty(container, "Additional review observations are available in the saved report.");
    }
    renderMerakiActionOverview(container, details);
    renderMerakiClientOverview(container, details);
    renderMerakiCis8Overview(container, details);
    renderMerakiTopologyOverview(container, details);
    if (details.unifi_plan && details.unifi_plan.provider_lifecycle) renderMerakiProviderLifecycle(container, details.unifi_plan.provider_lifecycle, true);
    if (details.unifi_plan && details.unifi_plan.lifecycle) renderMerakiLifecycle(container, details.unifi_plan.lifecycle, true);
    if (details.path_analysis) renderMerakiPaths(container, details.path_analysis, true);
    renderMerakiSwitchOverview(container, details);
    renderMerakiWanOverview(container, details);
    renderMerakiPlanningOverview(container, details);
  }

  async function loadMerakiSummaryObservations(reportId, container) {
    return readMerakiEvidence(reportId, container, renderMerakiSummaryObservations, "review observations");
  }

  async function loadMerakiDashboardDetails(reportId, container) {
    return readMerakiEvidence(reportId, container, renderMerakiDashboardDetails, "report details");
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

  function renderReportJobs(reports, listId, statusId, reportType, latestCompleted) {
    var list = document.getElementById(listId);
    var status = document.getElementById(statusId);
    if (!list) return;
    reports = matchingReportJobs(reports, reportType);
    var focused = list.contains(document.activeElement) ? document.activeElement : null;
    var focusedCard = focused && focused.closest(".report-job-card");
    var focusId = focusedCard && focusedCard.dataset.reportId;
    var focusAction = focused && focused.dataset.reportAction;
    var existing = new Map();
    Array.from(list.querySelectorAll(".report-job-card")).forEach(function (card) { existing.set(card.dataset.reportId, card); });
    var cards = [];
    function restoreReviewFocus() {
      if (!focused) return;
      if (list.contains(focused)) {
        if (document.activeElement !== focused) focused.focus({preventScroll: true});
        return;
      }
      var replacement = cards.find(function (card) { return card.dataset.reportId === focusId; });
      if (replacement) {
        var control = focusAction && replacement.querySelector('[data-report-action="' + focusAction + '"]');
        if (!control) control = replacement.querySelector("summary");
        if (control) control.focus({preventScroll: true});
        else { replacement.tabIndex = -1; replacement.focus({preventScroll: true}); }
      } else {
        var controls = document.getElementById(listId + "-history-controls");
        var refresh = controls && controls.querySelector("[data-history-refresh]");
        if (refresh) refresh.focus({preventScroll: true});
        else { list.tabIndex = -1; list.focus({preventScroll: true}); }
      }
    }
    if (reportType === "meraki_security") {
      var overview = document.getElementById("meraki-current-summary");
      if (overview) {
        var completed = latestCompleted || reports.find(function (job) { return job.status === "completed"; });
        var overviewSignature = JSON.stringify(completed ? [completed.id, completed.completed_at, completed.created_at, completed.meraki_summary] : null);
        if (overview.dataset.reportSignature !== overviewSignature) {
          var overviewFocused = overview.contains(document.activeElement);
          overview.replaceChildren();
          overview.dataset.reportSignature = overviewSignature;
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
          if (overviewFocused) { overview.tabIndex = -1; overview.focus({preventScroll: true}); }
        }
      }
    }
    if (!reports.length) {
      list.replaceChildren();
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
      if (status && status.textContent !== "Reports are scoped to this workspace.") text(status, "Reports are scoped to this workspace.");
      restoreReviewFocus();
      return;
    }

    var statusSummary = reportJobStatusSummary(reports);
    if (status && status.textContent !== statusSummary) text(status, statusSummary);

    reports.forEach(function (job) {
      var prior = existing.get(String(job.id));
      var signature = JSON.stringify([job, !!(driveState && driveState.connected), !!(driveState && driveState.is_admin)]);
      if (prior && prior.dataset.reportSignature === signature) { cards.push(prior); return; }
      var card = document.createElement("article");
      card.className = "report-job-card";
      card.dataset.reportId = String(job.id);
      card.dataset.reportSignature = signature;
      card.dataset.detailSource = job.meraki_snapshot_url || "";
      var main = document.createElement("div");
      main.className = "report-job-main";
      var heading = document.createElement("strong");
      var reportLabel = job.report_type === "google_admin_security" ? "Google Admin security audit" : job.report_type === "meraki_security" ? "Meraki security report"
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
        download.dataset.reportAction = "download";
        download.className = "button button-small";
        download.href = job.download_url;
        download.download = job.file_name || "daedalus-report.pdf";
        download.textContent = "Download PDF";
        actions.append(download);
        if (driveState && driveState.connected) {
          if (job.drive_link) {
            var openDrive = document.createElement("a");
            openDrive.dataset.reportAction = "drive-link";
            openDrive.className = "button button-small button-quiet"; openDrive.href = job.drive_link;
            openDrive.target = "_blank"; openDrive.rel = "noopener noreferrer"; openDrive.textContent = "In Drive ↗";
            actions.append(openDrive);
          } else if (driveState.is_admin) {
            var saveDrive = document.createElement("button");
            saveDrive.dataset.reportAction = "save-drive";
            saveDrive.type = "button"; saveDrive.className = "button button-small button-quiet"; saveDrive.textContent = "Save to Drive";
            saveDrive.addEventListener("click", async function () {
              saveDrive.disabled = true; saveDrive.textContent = "Saving…";
              try { await postJson("/api/reports/" + job.id + "/drive"); } catch (error) { saveDrive.textContent = "Retry"; saveDrive.title = error.message; saveDrive.disabled = false; return; }
              saveDrive.textContent = "Saved to Drive";
              await loadReports();
            });
            actions.append(saveDrive);
          }
        }
      }
      if (job.google_admin_snapshot_url) {
        var googleEvidence = document.createElement("a"); googleEvidence.className = "button button-small button-quiet";
        googleEvidence.dataset.reportAction = "google-evidence";
        googleEvidence.href = job.google_admin_snapshot_url; googleEvidence.textContent = "Download audit evidence";
        actions.append(googleEvidence);
      }
      if (job.meraki_changes_url) {
        var changes = document.createElement("a");
        changes.dataset.reportAction = "changes";
        changes.className = "button button-small button-quiet";
        changes.href = job.meraki_changes_url;
        changes.textContent = "Download change evidence";
        actions.append(changes);
      }
      if (job.meraki_snapshot_url) {
        var snapshot = document.createElement("a");
        snapshot.dataset.reportAction = "snapshot";
        snapshot.className = "button button-small button-quiet";
        snapshot.href = job.meraki_snapshot_url;
        snapshot.textContent = "Download complete JSON";
        actions.append(snapshot);
      }
      card.append(main, actions);
      if (job.meraki_snapshot_url) {
        var retainedDetails = prior && prior.dataset.detailSource === job.meraki_snapshot_url && prior.querySelector(".meraki-report-details");
        if (retainedDetails) card.append(retainedDetails);
        else {
          var details = document.createElement("details");
          details.className = "meraki-report-details";
          details.dataset.reportId = String(job.id);
          details.open = openMerakiDashboardDetails.has(job.id);
          var summary = document.createElement("summary");
          summary.textContent = "View saved report details";
          summary.dataset.reportAction = "details";
          var detailContent = document.createElement("div");
          detailContent.className = "meraki-report-detail-content";
          detailContent.textContent = "Open to inspect this saved snapshot.";
          details.append(summary, detailContent);
          details.addEventListener("toggle", function () {
            if (details.open) {
              openMerakiDashboardDetails.add(job.id);
              if (!detailContent.dataset.loaded) {
                loadMerakiDashboardDetails(job.id, detailContent);
              }
            } else {
              openMerakiDashboardDetails.delete(job.id);
            }
          });
          card.append(details);
          if (details.open) {
            loadMerakiDashboardDetails(job.id, detailContent);
          }
        }
      }
      cards.push(card);
    });
    var keptCards = new Set(cards);
    Array.from(list.children).forEach(function (child) { if (!keptCards.has(child)) child.remove(); });
    cards.forEach(function (card, index) { if (list.children[index] !== card) list.insertBefore(card, list.children[index] || null); });
    restoreReviewFocus();
  }

  function formatBytes(value) {
    var size = Number(value) || 0;
    if (size < 1024) return size + " B";
    if (size < 1024 * 1024) return (size / 1024).toFixed(1) + " KB";
    return (size / (1024 * 1024)).toFixed(1) + " MB";
  }

  var driveState = null;

  async function loadDriveStatus() {
    var card = document.getElementById("drive-card");
    if (!card) return;
    try {
      var response = await fetch("/api/drive", { credentials: "same-origin" });
      driveState = response.ok ? await response.json() : null;
    } catch (_error) { driveState = null; }
    card.replaceChildren();
    if (!driveState || !driveState.configured) { card.classList.add("hidden"); return; }
    card.classList.remove("hidden");
    var title = document.createElement("strong"); var detail = document.createElement("span"); detail.className = "muted";
    var actions = document.createElement("span"); actions.className = "drive-actions";
    if (!driveState.connected) {
      title.textContent = "Keep every report in Google Drive";
      detail.textContent = "Connect once and new report PDFs are saved to a folder in your Drive. Daedalus can only see files it creates.";
      if (driveState.is_admin) {
        var connect = document.createElement("a"); connect.className = "button button-primary"; connect.href = "/auth/drive/connect"; connect.textContent = "Connect Google Drive";
        actions.append(connect);
      } else { detail.textContent += " A workspace admin can connect it."; }
    } else {
      title.textContent = "Saving reports to Google Drive";
      detail.textContent = "Folder: " + driveState.folder_name + (driveState.last_upload_at ? " · last saved " + dateLabel(driveState.last_upload_at) : "") + (driveState.auto_upload ? " · new reports save automatically" : " · automatic saving is off");
      if (driveState.last_error) { var problem = document.createElement("small"); problem.className = "status-failed"; problem.textContent = "Last problem: " + driveState.last_error; detail.append(document.createElement("br"), problem); }
      if (driveState.is_admin) {
        var toggle = document.createElement("button"); toggle.type = "button"; toggle.className = "button button-quiet";
        toggle.textContent = driveState.auto_upload ? "Turn off automatic saving" : "Turn on automatic saving";
        toggle.addEventListener("click", async function () { toggle.disabled = true; try { await postJson("/api/drive/settings", { auto_upload: !driveState.auto_upload }); } catch (_e) { /* status reload shows state */ } await loadDriveStatus(); });
        var disconnect = document.createElement("button"); disconnect.type = "button"; disconnect.className = "button button-quiet";
        disconnect.textContent = "Disconnect";
        disconnect.addEventListener("click", async function () { disconnect.disabled = true; await fetch("/api/drive", { method: "DELETE", credentials: "same-origin" }); await loadDriveStatus(); await loadReports(); });
        actions.append(toggle, disconnect);
      }
    }
    var copy = document.createElement("span"); copy.className = "drive-copy"; copy.append(title, document.createElement("br"), detail);
    card.append(copy, actions);
  }

  window.addEventListener("google-admin-changed", function () { loadReports(); loadWorkspacePosture(); });

  var reportHistoryGroups = [
    { topic: "external_posture", tab: "reports", views: [["report-job-list", "report-library-status"]] },
    { topic: "scanner_results", tab: "reports", views: [["scanner-report-job-list", "scanner-report-library-status"]] },
    { topic: "meraki_security,cis_endpoint", tab: "reports", views: [["posture-report-job-list", "posture-report-library-status"]] },
    { topic: "meraki_security", tab: "meraki", views: [["meraki-report-job-list", "meraki-report-library-status"]] },
    { topic: "cis_endpoint", tab: "cis", views: [["cis-pdf-job-list", "cis-pdf-library-status"]] },
    { topic: "google_admin_security", tab: "google-admin", views: [["google-admin-report-job-list", "google-admin-report-library-status"], ["google-admin-library-list", "google-admin-library-status"]] }
  ];

  function renderHistoryControls(list, pager, label) {
    var controls = document.getElementById(list.id + "-history-controls");
    if (!controls) {
      controls = document.createElement("div"); controls.id = list.id + "-history-controls"; controls.className = "history-toolbar";
      var older = document.createElement("button"); older.type = "button"; older.className = "button button-secondary";
      older.textContent = "Load older " + label; older.dataset.historyOlder = "true";
      older.addEventListener("click", function () { pager.older(); });
      var retry = document.createElement("button"); retry.type = "button"; retry.className = "button button-quiet";
      retry.textContent = "Refresh " + label; retry.dataset.historyRefresh = "true";
      retry.addEventListener("click", function () { if (!pager.state.busy) loadReports(); });
      controls.append(older, retry); list.after(controls);
    }
    var state = pager.state;
    var olderButton = controls.querySelector("[data-history-older]");
    olderButton.classList.toggle("hidden", !state.body || !state.body.has_more);
    olderButton.disabled = false;
    olderButton.setAttribute("aria-disabled", String(state.busy));
    var refreshButton = controls.querySelector("[data-history-refresh]");
    refreshButton.disabled = false;
    refreshButton.setAttribute("aria-disabled", String(state.busy));
    if (olderButton.classList.contains("hidden") && document.activeElement === olderButton) refreshButton.focus({ preventScroll: true });
  }

  function reportHistory(group) {
    if (reportHistories[group.topic]) return reportHistories[group.topic];
    var pager = window.daedalusHistory.create({ url: "/api/reports", field: "reports", fetch: function (url, options) { return fetch(url, options); }, changed: function (state, committed) {
      group.views.forEach(function (view) {
        var list = document.getElementById(view[0]);
        if (!list) return;
        if (committed && state.loaded) {
          var focused = list.contains(document.activeElement) ? document.activeElement : null;
          var card = focused && focused.closest("[data-report-id]");
          var focusId = card && card.dataset.reportId;
          var focusText = focused && focused.textContent;
          renderReportJobs(state.rows, view[0], view[1], group.topic.includes(",") ? group.topic.split(",") : group.topic, state.body && state.body.latest_completed);
          if (focusId && !list.contains(focused)) {
            var replacement = Array.from(list.querySelectorAll("[data-report-id] button, [data-report-id] a, [data-report-id] summary")).find(function (item) {
              return item.closest("[data-report-id]").dataset.reportId === focusId && item.textContent === focusText;
            });
            if (replacement) replacement.focus({ preventScroll: true });
          }
        }
        var summary = state.loaded ? "Showing " + state.rows.length + " of " + state.body.total_count + " reports. " + reportJobStatusSummary(state.rows) : "Loading report history…";
        if (state.error) summary = state.error + (state.loaded ? " Previously loaded reports remain below; refresh to update them." : " Use Refresh reports to retry.");
        else if (state.busy) summary += " Updating…";
        text(document.getElementById(view[1]), summary);
        if (state.error && !state.loaded) { list.replaceChildren(); appendEmpty(list, "Report history is unavailable. Refresh to retry."); }
        renderHistoryControls(list, pager, "reports");
      });
    } });
    reportHistories[group.topic] = pager;
    return pager;
  }

  async function loadReports() {
    if (!orgId) return;
    window.clearTimeout(reportPollTimer);
    if (!driveState) await loadDriveStatus();
    var groups = reportHistoryGroups.filter(function (group) {
      return group.tab === activeTab || (activeTab === "reports" && group.topic === "google_admin_security");
    });
    await Promise.all(groups.map(function (group) { return reportHistory(group).refresh({ report_type: group.topic }); }));
    if (groups.some(function (group) { return reportHistory(group).state.rows.some(function (job) {
      return job.status === "queued" || job.status === "running";
    }); })) reportPollTimer = window.setTimeout(loadReports, 900);
  }

  var merakiOrgOptions = [];
  var merakiWorkspaceRead = {body: null, loading: false, error: null, invalidated: false, busy: false, sequence: 0, controller: null, providerOptions: null, providerCredential: null};

  function preferredMerakiOrganizationId(organizations, preferredId) {
    organizations = organizations || [];
    if (preferredId && organizations.some(function (item) { return item.id === preferredId; })) return preferredId;
    var authorized = organizations.find(function (item) { return item.authorized; });
    return authorized ? authorized.id : (organizations[0] ? organizations[0].id : "");
  }

  function validateMerakiOrganizations(organizations, provider) {
    if (!Array.isArray(organizations)) throw new Error("Saved Meraki organizations could not be validated.");
    var ids = new Set();
    organizations.forEach(function (item) {
      if (!item || typeof item.id !== "string" || !item.id || item.id.length > 128 || typeof item.name !== "string" || item.name.length > 200 || ids.has(item.id)
          || (!provider && (typeof item.authorized !== "boolean" || (item.authorized && (typeof item.granted_at !== "string" || !Number.isFinite(Date.parse(item.granted_at))))))) throw new Error("Saved Meraki organizations could not be validated.");
      ids.add(item.id);
    });
  }

  function validateMerakiStatus(body) {
    if (!body || body.organization_id !== Number(orgId) || typeof body.configured !== "boolean" || typeof body.can_manage !== "boolean"
        || typeof body.observed_at !== "string" || !Number.isFinite(Date.parse(body.observed_at)) || !/^[a-f0-9]{64}$/.test(body.state_reference || "")
        || (body.configured ? !/^[a-f0-9]{64}$/.test(body.credential_reference || "") : body.credential_reference !== null)
        || (body.key_hint !== null && (typeof body.key_hint !== "string" || body.key_hint.length !== 4))
        || (body.last_verified_at !== null && (typeof body.last_verified_at !== "string" || !Number.isFinite(Date.parse(body.last_verified_at))))) throw new Error("Saved Meraki connection data could not be validated.");
    validateMerakiOrganizations(body.organizations, false);
    if (body.organizations.some(function (item) { return !item.authorized; }) || (!body.configured && body.organizations.length)) throw new Error("Saved Meraki approvals could not be validated.");
    if (body.active_report !== null && (!body.active_report || !Number.isSafeInteger(body.active_report.id) || body.active_report.id <= 0 || !["queued", "running"].includes(body.active_report.status)
        || typeof body.active_report.stage !== "string" || !Number.isFinite(body.active_report.progress) || body.active_report.progress < 0 || body.active_report.progress > 100)) throw new Error("Meraki report progress could not be validated.");
    return body;
  }

  function renderMerakiOrganizations(organizations, preferredId) {
    var select = document.getElementById("meraki-org-select");
    if (!select) return;
    var wanted = typeof preferredId === "string" ? preferredId : select.value;
    merakiOrgOptions = organizations;
    var signature = JSON.stringify([organizations, wanted && !organizations.some(function (item) { return item.id === wanted; }) ? wanted : null]);
    if (select.dataset.optionsSignature !== signature) {
      select.replaceChildren();
      if (!organizations.length) {
        var empty = document.createElement("option"); empty.value = "";
        empty.textContent = merakiWorkspaceRead.body && merakiWorkspaceRead.body.configured ? "No saved approvals. Refresh Cisco organizations to choose." : "Connect a key to choose an organization";
        select.append(empty);
      }
      if (wanted && !organizations.some(function (item) { return item.id === wanted; })) {
        var retired = document.createElement("option"); retired.value = wanted; retired.disabled = true;
        retired.textContent = "Previous selection is unavailable — choose an organization"; select.append(retired);
      }
      organizations.forEach(function (item) {
        var option = document.createElement("option"); option.value = item.id;
        option.textContent = item.name + " · " + item.id + (item.authorized ? " · approved" : " · approval required") + (item.available === false ? " · absent from last Cisco list" : ""); select.append(option);
      });
      select.value = wanted || preferredMerakiOrganizationId(organizations);
      select.dataset.optionsSignature = signature;
    }
    select.disabled = false;
    updateMerakiScopeControls();
  }

  function merakiActionAllowed(action) {
    var read = merakiWorkspaceRead, body = read.body;
    if (!body || read.loading || read.error || read.invalidated || read.busy || role !== "admin" || !body.can_manage) return false;
    if (action === "save") return !body.active_report;
    if (!body.configured) return false;
    if (action === "load") return true;
    if (action === "remove") return !body.active_report;
    var select = document.getElementById("meraki-org-select");
    var selected = select && merakiOrgOptions.find(function (item) { return item.id === select.value; });
    if (!selected) return false;
    if (action === "authorize") return !selected.authorized && selected.available !== false;
    if (action === "revoke") return selected.authorized && !body.active_report;
    if (action === "collect") return selected.authorized && selected.available !== false && !body.active_report;
    return false;
  }

  function updateMerakiScopeControls() {
    var body = merakiWorkspaceRead.body, select = document.getElementById("meraki-org-select");
    var selected = select && merakiOrgOptions.find(function (item) { return item.id === select.value; });
    var stale = merakiWorkspaceRead.error || merakiWorkspaceRead.invalidated;
    var state = document.getElementById("meraki-org-scope-state");
    if (state) {
      var label = !selected ? "Choose an organization; refresh Cisco organizations for available choices." : selected.authorized ? "Approved for this workspace" + (selected.granted_at ? " · since " + dateLabel(selected.granted_at) : "") : "Not approved for this workspace.";
      if (selected && selected.available === false) label += " · Not returned by the last Cisco lookup. Refresh Cisco organizations to check again.";
      if (stale && selected) label = "Last observed: " + label;
      if (body && body.active_report) label += " · Report " + body.active_report.id + " " + body.active_report.status + ": " + body.active_report.stage;
      if (state.textContent !== label) text(state, label);
      state.classList.toggle("is-authorized", !!(selected && selected.authorized && !stale));
    }
    [["meraki-remove-key", "remove"], ["meraki-load-organizations", "load"], ["meraki-authorize-org", "authorize"], ["meraki-revoke-org", "revoke"], ["meraki-generate-report", "collect"]].forEach(function (pair) {
      var button = document.getElementById(pair[0]);
      if (button) { button.disabled = false; button.setAttribute("aria-disabled", String(!merakiActionAllowed(pair[1]))); }
    });
    var form = document.getElementById("meraki-key-form"), submit = form && form.querySelector("[type='submit']");
    if (submit) { submit.disabled = false; submit.setAttribute("aria-disabled", String(!merakiActionAllowed("save"))); }
    var refresh = document.getElementById("meraki-refresh-connection");
    if (refresh) { refresh.disabled = false; refresh.setAttribute("aria-disabled", String(merakiWorkspaceRead.loading || merakiWorkspaceRead.busy)); refresh.setAttribute("aria-busy", String(merakiWorkspaceRead.loading)); }
  }

  function renderMerakiConnection() {
    var read = merakiWorkspaceRead, body = read.body, state = document.getElementById("meraki-connection-state");
    if (state) {
      var label = !body ? "Saved connection unavailable" : body.configured ? "Saved key" + (body.key_hint ? " · ending " + body.key_hint : "") + (body.last_verified_at ? " · Cisco verification " + dateLabel(body.last_verified_at) : "") : "No saved Meraki key";
      if (body && (read.error || read.invalidated)) label = "Last observed: " + label;
      if (state.textContent !== label) text(state, label);
      state.className = "meraki-connection-state";
    }
    var warning = document.getElementById("meraki-connection-refresh-status");
    var message = read.error ? read.error + (body ? " Last successful saved connection read: " + dateLabel(body.observed_at) + "." : "") + " Refresh saved connection data to retry." : read.busy ? "Updating connection or assessment setup…" : read.invalidated ? "Refresh saved connection data before another setup action." : "";
    if (warning && warning.textContent !== message) text(warning, message);
    var observation = document.getElementById("meraki-connection-observation");
    if (observation && body) observation.textContent = "Saved connection read " + dateLabel(body.observed_at) + ". This does not query Cisco or refresh assessment evidence.";
    updateMerakiScopeControls();
  }

  async function loadMerakiStatus(background) {
    var read = merakiWorkspaceRead;
    if (!orgId || read.busy || (background && read.loading)) return false;
    if (read.controller) read.controller.abort();
    var sequence = ++read.sequence, controller = new AbortController(), timedOut = false;
    read.controller = controller; read.loading = true; updateMerakiScopeControls();
    var deadline = window.setTimeout(function () { timedOut = true; controller.abort(); }, 20000);
    try {
      var response = await fetch("/api/meraki/status", {credentials: "same-origin", cache: "no-store", signal: controller.signal});
      var body = await response.json();
      if (!response.ok) throw new Error("Saved Meraki connection data could not be read.");
      validateMerakiStatus(body);
      if (sequence !== read.sequence) return false;
      var options = body.organizations.map(function (item) { return Object.assign({available: null}, item); });
      if (body.credential_reference && read.providerCredential === body.credential_reference && read.providerOptions) {
        var approved = new Map(body.organizations.map(function (item) { return [item.id, item]; }));
        options = read.providerOptions.map(function (item) { return Object.assign({available: true}, approved.get(item.id) || {id: item.id, name: item.name, authorized: false, granted_at: null}); });
        body.organizations.forEach(function (item) { if (!options.some(function (choice) { return choice.id === item.id; })) options.push(Object.assign({available: false}, item)); });
      } else { read.providerOptions = null; read.providerCredential = null; }
      read.body = body; read.error = null; read.invalidated = false;
      renderMerakiOrganizations(options);
      return true;
    } catch (_error) {
      if (sequence !== read.sequence) return false;
      read.error = timedOut ? "Saved Meraki connection read timed out." : "Saved Meraki connection data is unavailable or could not be validated.";
      return false;
    } finally {
      window.clearTimeout(deadline);
      if (sequence === read.sequence) { read.loading = false; read.controller = null; renderMerakiConnection(); }
    }
  }

  async function merakiRequest(path, method, payload) {
    var options = {method: method, credentials: "same-origin", cache: "no-store", headers: {"X-Daedalus-Meraki-State": merakiWorkspaceRead.body.state_reference}};
    if (payload !== undefined) { options.headers["Content-Type"] = "application/json"; options.body = JSON.stringify(payload); }
    var response = await fetch(path, options), body = await response.json();
    if (!response.ok) throw new Error(typeof body.detail === "string" ? body.detail : "Meraki action could not be completed.");
    return body;
  }

  function acceptMerakiProviderChoices(body) {
    if (!body || body.organization_id !== Number(orgId) || !/^[a-f0-9]{64}$/.test(body.credential_reference || "")) throw new Error("Cisco organization choices could not be validated. Refresh saved connection data.");
    validateMerakiOrganizations(body.organizations, true);
    merakiWorkspaceRead.providerOptions = body.organizations;
    merakiWorkspaceRead.providerCredential = body.credential_reference;
  }

  async function performMerakiAction(action, path, method, payload, success) {
    if (!merakiActionAllowed(action)) return false;
    var read = merakiWorkspaceRead, feedback = document.getElementById("meraki-feedback");
    read.busy = true; read.invalidated = true; renderMerakiConnection();
    try {
      var body = await merakiRequest(path, method, payload);
      if (action === "load" || action === "save") acceptMerakiProviderChoices(body);
      if (success) success(body);
      return true;
    } catch (error) {
      if (feedback) text(feedback, error.message);
      return false;
    } finally {
      read.busy = false;
      await loadMerakiStatus();
      if (action === "collect") await loadReports();
    }
  }

  async function loadMerakiOrganizations() {
    return performMerakiAction("load", "/api/meraki/organizations", "POST", undefined, function (body) {
      text(document.getElementById("meraki-feedback"), "Cisco returned " + body.organizations.length + " organization(s). Saved approvals apply only to this workspace.");
    });
  }

  async function loadMeraki() { await Promise.all([loadMerakiStatus(), loadReports()]); }

  var merakiKeyForm = document.getElementById("meraki-key-form");
  if (merakiKeyForm) merakiKeyForm.addEventListener("submit", async function (event) {
    event.preventDefault();
    var input = document.getElementById("meraki-api-key"), apiKey = input ? input.value : "";
    await performMerakiAction("save", "/api/meraki/credential", "PUT", {api_key: apiKey}, function () {
      if (input && input.value === apiKey) input.value = "";
      text(document.getElementById("meraki-feedback"), "Key verified and saved. Choose an organization and approve it for this workspace before requesting an assessment.");
    });
  });
  var merakiLoadButton = document.getElementById("meraki-load-organizations");
  if (merakiLoadButton) merakiLoadButton.addEventListener("click", loadMerakiOrganizations);
  var merakiOrgSelect = document.getElementById("meraki-org-select");
  if (merakiOrgSelect) merakiOrgSelect.addEventListener("change", updateMerakiScopeControls);
  var merakiRefreshConnection = document.getElementById("meraki-refresh-connection");
  if (merakiRefreshConnection) merakiRefreshConnection.addEventListener("click", function () { if (!merakiWorkspaceRead.loading && !merakiWorkspaceRead.busy) return loadMerakiStatus(); });
  [["meraki-authorize-org", "authorize", "POST"], ["meraki-revoke-org", "revoke", "DELETE"], ["meraki-generate-report", "collect", "POST"]].forEach(function (item) {
    var button = document.getElementById(item[0]);
    if (button) button.addEventListener("click", function () {
      var selectedId = merakiOrgSelect && merakiOrgSelect.value;
      if (!selectedId) return false;
      return performMerakiAction(item[1], item[1] === "collect" ? "/api/meraki/reports" : "/api/meraki/organization-scope", item[2], item[1] === "collect" ? {organization_id: selectedId} : {meraki_organization_id: selectedId}, function () {
        text(document.getElementById("meraki-feedback"), item[1] === "collect" ? "Assessment queued for " + selectedId + ". Review collection progress and its PDF in Saved network assessments." : "Organization " + selectedId + (item[1] === "authorize" ? " approved" : " access revoked") + " for this workspace. The action was recorded in its audit log.");
      });
    });
  });
  var merakiRemoveButton = document.getElementById("meraki-remove-key");
  if (merakiRemoveButton) merakiRemoveButton.addEventListener("click", function () {
    return performMerakiAction("remove", "/api/meraki/credential", "DELETE", undefined, function () { text(document.getElementById("meraki-feedback"), "Saved Meraki key removed from this workspace."); });
  });

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
      appendEmpty(list, document.getElementById("cis-profile-form")
        ? "No profile is published yet. Install the CSP starter profile or publish a new version."
        : "No profile is published yet. Ask a workspace admin to publish a profile.");
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
      state.dataset.cisClientState = clientState;
      state.dataset.cisClientLabel = clientState === "online" ? "Client checking in" : clientState === "offline" ? "Client check-in overdue" : "Client presence unknown";
      state.textContent = state.dataset.cisClientLabel;
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
    var focused = document.activeElement;
    var hadFocus = list.contains(focused);
    var savedCards = new Map(Array.from(list.querySelectorAll("[data-report-id]")).map(function (card) {
      return [String(card.dataset.reportId), card];
    }));
    list.replaceChildren();
    if (!reports.length) {
      appendEmpty(list, "Waiting for the first endpoint report. Download a client configuration and run the CSP CIS client.");
      if (hadFocus) {
        var retry = document.getElementById("cis-refresh");
        if (retry) retry.focus();
      }
      return;
    }
    reports.forEach(function (report) {
      var signature = JSON.stringify(report);
      var saved = savedCards.get(String(report.id));
      if (saved && saved.dataset.reportSignature === signature) {
        list.append(saved);
        return;
      }
      var card = document.createElement("details");
      card.className = "cis-report-card";
      card.dataset.reportId = report.id;
      card.dataset.reportSignature = signature;
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
        if (!card.open || resultList.dataset.loaded === "true" || resultList.dataset.loaded === "loading") return;
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
    var earlierReview = Array.from(list.children).slice(10).some(function (card) { return card.open || card.contains(focused); });
    groupEarlierCISHistory(list, "reports", earlierOpen || earlierReview);
    if (hadFocus) {
      if (list.contains(focused)) focused.focus();
      else {
        var refresh = document.getElementById("cis-refresh");
        if (refresh) refresh.focus();
      }
    }
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

  function validateCISWorkspace(bodies) {
    function object(value) { return value && typeof value === "object" && !Array.isArray(value); }
    function count(value) { return Number.isSafeInteger(value) && value >= 0; }
    function rows(value, maximum) {
      return Array.isArray(value) && value.length <= maximum && value.every(function (row) {
        return object(row) && Number.isSafeInteger(row.id) && row.id > 0;
      }) && new Set(value.map(function (row) { return row.id; })).size === value.length;
    }
    if (!Array.isArray(bodies) || bodies.length !== 4 || bodies.some(function (body) {
      return !object(body) || body.organization_id !== Number(orgId);
    })) throw new Error("The endpoint workspace changed. Reload this page before reviewing it.");
    var status = bodies[0];
    if (typeof status.key_configured !== "boolean" || typeof status.can_manage !== "boolean" ||
        !count(status.device_count) || !rows(status.devices, 250) || status.devices.length > status.device_count ||
        typeof status.devices_truncated !== "boolean" || status.devices_truncated !== (status.device_count > status.devices.length) ||
        typeof status.observed_at !== "string" || !Number.isFinite(Date.parse(status.observed_at)) ||
        !rows(bodies[1].profiles, 100) || !rows(bodies[2].reports, 50) || !rows(bodies[3].changes, 100)) {
      throw new Error("Saved endpoint data is incomplete. Please retry.");
    }
    var counts = status.assessment_counts;
    if (!object(counts) || !["current", "stale", "unknown", "missing"].every(function (key) { return count(counts[key]); }) ||
        counts.current + counts.stale + counts.unknown + counts.missing !== status.device_count ||
        bodies[1].profiles.some(function (profile) { return typeof profile.slug !== "string" || !profile.slug || typeof profile.platform !== "string"; }) ||
        bodies[2].reports.some(function (report) {
          var summary = report.summary;
          return !object(summary) || !["total", "pass", "fail", "manual", "error"].every(function (key) { return count(summary[key]); }) ||
            summary.total !== summary.pass + summary.fail + summary.manual + summary.error ||
            typeof summary.score !== "number" || !Number.isFinite(summary.score) || summary.score < 0 || summary.score > 100;
        })) throw new Error("Saved endpoint assessment metadata is incomplete. Please retry.");
  }

  function canManageCIS() {
    return Boolean(role === "admin" && cisWorkspaceRead.bodies && cisWorkspaceRead.bodies[0].can_manage &&
      !cisWorkspaceRead.loading && !cisWorkspaceRead.error && !cisWorkspaceRead.invalidated && !cisWorkspaceRead.mutationBusy);
  }

  function updateCISReadControls() {
    function available(button, enabled) {
      if (!button) return;
      button.disabled = false;
      button.setAttribute("aria-disabled", String(!enabled));
    }
    var status = cisWorkspaceRead.bodies && cisWorkspaceRead.bodies[0];
    var profiles = cisWorkspaceRead.bodies ? cisWorkspaceRead.bodies[1].profiles : [];
    var manage = Boolean(canManageCIS());
    var refresh = document.getElementById("cis-refresh");
    if (refresh) {
      refresh.setAttribute("aria-busy", String(cisWorkspaceRead.loading));
      refresh.setAttribute("aria-disabled", String(cisWorkspaceRead.loading || cisWorkspaceRead.mutationBusy));
    }
    var note = "";
    if (cisWorkspaceRead.error || cisWorkspaceRead.invalidated) {
      note = status ? (cisWorkspaceRead.error ? "Could not refresh. " : "Workspace setup is being updated. ") + "Previously loaded endpoint evidence remains visible. Assessment coverage, check-in status and setup may be out of date. Last successful workspace read: " + dateLabel(status.observed_at) + "."
        : "Endpoint data is unavailable. Refresh saved endpoint data to retry.";
      if (cisWorkspaceRead.error) note += " " + cisWorkspaceRead.error;
      if (cisWorkspaceRead.invalidated) note += " A setup action may have changed the workspace; refresh before making another setup change.";
    } else if (cisWorkspaceRead.loading && !status) note = "Loading saved endpoint data…";
    var refreshStatus = document.getElementById("cis-refresh-status");
    if (refreshStatus && refreshStatus.textContent !== note) text(refreshStatus, note);
    var revoke = document.getElementById("cis-revoke-key");
    available(revoke, manage && status.key_configured);
    var issue = document.getElementById("cis-issue-key");
    available(issue, manage);
    var starter = document.getElementById("cis-install-starter");
    available(starter, manage && !profiles.some(function (profile) { return profile.slug === "csp-macos-browser-baseline" && profile.version === "1.0.0"; }));
    var tahoe = document.getElementById("cis-install-macos26");
    if (tahoe) {
      var slugs = new Set(profiles.map(function (profile) { return profile.slug; }));
      available(tahoe, manage && !(slugs.has("cis-macos-26-tahoe-level-1") && slugs.has("cis-macos-26-tahoe-level-2")));
    }
    var form = document.getElementById("cis-profile-form");
    var submit = form && form.querySelector("[type='submit']");
    available(submit, manage);
    // Cached presence is a dated observation, not proof of a currently connected client.
    var devices = document.getElementById("cis-device-list");
    if (devices) Array.from(devices.querySelectorAll("[data-cis-client-state]")).forEach(function (badge) {
      var stale = Boolean(cisWorkspaceRead.error || cisWorkspaceRead.invalidated);
      badge.className = "cis-device-state is-" + (stale ? "unknown" : badge.dataset.cisClientState);
      badge.textContent = (stale ? "Last observed: " : "") + badge.dataset.cisClientLabel;
    });
  }

  function renderCISWorkspace(bodies) {
    var status = bodies[0];
    var previous = cisWorkspaceRead.bodies;
    function changed(index, field) {
      return !previous || JSON.stringify(field ? previous[index][field] : previous[index]) !== JSON.stringify(field ? bodies[index][field] : bodies[index]);
    }
    if (changed(1, "profiles")) renderCISProfiles(bodies[1].profiles);
    if (changed(0, "assessment_counts")) renderCISCoverage(status);
    if (changed(0, "devices")) renderCISDevices(status.devices);
    if (changed(2, "reports") || !previous || previous[0].device_count !== status.device_count) renderCISReports(bodies[2].reports, status.device_count);
    if (changed(3, "changes")) renderCISChanges(bodies[3].changes);
    text(document.getElementById("cis-device-list-scope"), status.devices_truncated
      ? "Showing the 250 most recently reporting endpoints of " + status.device_count + " enrolled devices. Assessment coverage includes all enrolled devices."
      : status.device_count + " enrolled endpoint(s). Check-in states observed " + dateLabel(status.observed_at) + ".");
    var keyStatus = document.getElementById("cis-key-status");
    text(keyStatus, (status.key_configured ? "Upload key configured" + (status.key_hint ? " · ending " + status.key_hint : "") + "." : "No client upload key has been issued.") + " Last observed " + dateLabel(status.observed_at) + ".");
    if (keyStatus) keyStatus.className = "cis-feedback";
    var issue = document.getElementById("cis-issue-key");
    if (issue && !cisWorkspaceRead.mutationBusy) {
      issue.dataset.keyConfigured = String(status.key_configured);
      text(issue, status.key_configured ? "Rotate key and download new config" : "Issue client key and download config");
    }
  }

  async function loadCIS(background) {
    if (!orgId || cisWorkspaceRead.mutationBusy || (background && cisWorkspaceRead.loading)) return false;
    if (cisWorkspaceRead.controller) cisWorkspaceRead.controller.abort();
    var controller = new AbortController();
    cisWorkspaceRead.controller = controller;
    var sequence = ++cisWorkspaceRead.sequence;
    var timedOut = false;
    var deadline = window.setTimeout(function () { timedOut = true; controller.abort(); }, 20000);
    cisWorkspaceRead.loading = true;
    updateCISReadControls();
    try {
      var responses = await Promise.all(["status", "profiles", "reports", "changes"].map(function (path) {
        return fetch("/api/cis/" + path, { credentials: "same-origin", cache: "no-store", signal: controller.signal });
      }));
      var bodies = await Promise.all(responses.map(function (response) { return response.json(); }));
      if (sequence !== cisWorkspaceRead.sequence) return false;
      if (timedOut) throw new Error("The refresh timed out. Please retry.");
      var failed = responses.findIndex(function (response) { return !response.ok; });
      if (failed >= 0) throw new Error(bodies[failed] && typeof bodies[failed].detail === "string" ? bodies[failed].detail : "Could not load endpoint workspace data.");
      validateCISWorkspace(bodies);
      renderCISWorkspace(bodies);
      cisWorkspaceRead.bodies = bodies;
      cisWorkspaceRead.error = null;
      cisWorkspaceRead.invalidated = false;
      return true;
    } catch (error) {
      if (sequence !== cisWorkspaceRead.sequence) return false;
      controller.abort();
      cisWorkspaceRead.error = timedOut ? "The refresh timed out. Please retry." : error.message;
      if (!cisWorkspaceRead.bodies) {
        text(document.getElementById("cis-assessment-scope"), "Saved endpoint assessment unavailable.");
        ["cis-assessment-coverage", "cis-profile-list", "cis-device-list", "cis-report-list", "cis-change-list"].forEach(function (id) {
          var list = document.getElementById(id);
          if (list) { list.replaceChildren(); appendEmpty(list, "Saved data unavailable. Use Refresh saved endpoint data to retry."); }
        });
        text(document.getElementById("cis-key-status"), "Workspace setup status unavailable.");
      }
      return false;
    } finally {
      window.clearTimeout(deadline);
      if (sequence === cisWorkspaceRead.sequence) {
        cisWorkspaceRead.loading = false;
        cisWorkspaceRead.controller = null;
        updateCISReadControls();
      }
    }
  }

  function beginCISMutation() {
    if (!canManageCIS()) return false;
    cisWorkspaceRead.mutationBusy = true;
    cisWorkspaceRead.invalidated = true;
    updateCISReadControls();
    return true;
  }

  async function finishCISMutation() {
    cisWorkspaceRead.mutationBusy = false;
    await loadCIS();
  }

  var cisRefresh = document.getElementById("cis-refresh");
  if (cisRefresh) cisRefresh.addEventListener("click", function () {
    if (!cisWorkspaceRead.loading && !cisWorkspaceRead.mutationBusy) loadCIS();
  });

  var cisInstallMacOS26 = document.getElementById("cis-install-macos26");
  if (cisInstallMacOS26) {
    cisInstallMacOS26.addEventListener("click", async function () {
      if (cisInstallMacOS26.getAttribute("aria-disabled") === "true") return;
      if (!beginCISMutation()) return;
      text(cisInstallMacOS26, "Publishing macOS 26 profiles…");
      text(document.getElementById("cis-profile-feedback"), "");
      try {
        var result = await postJson("/api/cis/profiles/install-macos26");
        var count = result.installed_count || 0;
        text(document.getElementById("cis-profile-feedback"), count
          ? "Published " + count + " macOS 26 Tahoe CIS profile(s). Choose a level in Client profile before downloading a config."
          : "The macOS 26 Tahoe Level 1 and Level 2 profiles are already published.");
      } catch (error) {
        text(document.getElementById("cis-profile-feedback"), error.message);
      } finally {
        text(cisInstallMacOS26, "Install macOS 26 Level 1 + 2 profiles");
        await finishCISMutation();
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
      if (cisInstallStarter.getAttribute("aria-disabled") === "true") return;
      if (!beginCISMutation()) return;
      text(cisInstallStarter, "Installing profile…");
      text(document.getElementById("cis-profile-feedback"), "");
      try { await postJson("/api/cis/profiles/install-starter"); text(document.getElementById("cis-profile-feedback"), "CSP starter profile published."); }
      catch (error) { text(document.getElementById("cis-profile-feedback"), error.message); }
      finally { text(cisInstallStarter, "Install CSP starter profile"); await finishCISMutation(); }
    });
  }

  var cisIssueKey = document.getElementById("cis-issue-key");
  if (cisIssueKey) {
    cisIssueKey.addEventListener("click", async function () {
      if (!beginCISMutation()) return;
      text(cisIssueKey, "Preparing secure config…");
      var profilePicker = document.getElementById("cis-client-profile");
      var profileSlug = profilePicker ? profilePicker.value : "";
      try {
        var body = await postJson("/api/cis/api-key");
        var config = buildCISClientConfig(body, profileSlug);
        var blobUrl = URL.createObjectURL(new Blob([config], { type: "application/yaml" }));
        var link = document.createElement("a");
        link.href = blobUrl;
        link.download = "daedalus-cis-" + body.domain + "-config.yaml";
        document.body.append(link);
        link.click();
        link.remove();
        window.setTimeout(function () { URL.revokeObjectURL(blobUrl); }, 1000);
        text(document.getElementById("cis-client-feedback"), body.rotated
          ? "Upload key rotated. The prior configuration is no longer valid; download and replace it on all clients."
          : "Upload key issued and client configuration downloaded. The key is shown only in that file.");
      } catch (error) {
        text(document.getElementById("cis-client-feedback"), error.message);
      } finally {
        if (cisIssueKey.dataset.keyConfigured !== "true") text(cisIssueKey, "Issue client key and download config");
        else text(cisIssueKey, "Rotate key and download new config");
        await finishCISMutation();
      }
    });
  }

  var cisRevokeKey = document.getElementById("cis-revoke-key");
  if (cisRevokeKey) {
    cisRevokeKey.addEventListener("click", async function () {
      if (cisRevokeKey.getAttribute("aria-disabled") === "true") return;
      if (!beginCISMutation()) return;
      try {
        await requestJson("/api/cis/api-key", "DELETE");
        text(document.getElementById("cis-client-feedback"), "Client upload key revoked. Existing client configurations can no longer send reports.");
      } catch (error) {
        text(document.getElementById("cis-client-feedback"), error.message);
      } finally {
        await finishCISMutation();
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
      if (!file || !beginCISMutation()) return;
      text(submit, "Validating profile…");
      text(document.getElementById("cis-profile-feedback"), "");
      try {
        var profile = JSON.parse(await file.text());
        profile.name = cisProfileForm.elements.name.value;
        profile.version = cisProfileForm.elements.version.value;
        profile.platform = cisProfileForm.elements.platform.value;
        profile.description = cisProfileForm.elements.description.value;
        await postJson("/api/cis/profiles", profile);
        cisProfileForm.reset();
        text(document.getElementById("cis-profile-feedback"), "Profile published as a new immutable version.");
      } catch (error) {
        text(document.getElementById("cis-profile-feedback"), error instanceof SyntaxError ? "Choose a valid profile JSON file." : error.message);
      } finally {
        text(submit, "Validate and publish new version");
        await finishCISMutation();
      }
    });
  }

  var externalReportCreationBusy = false;
  async function queueExternalPostureReport(button) {
    if (externalReportCreationBusy) return;
    externalReportCreationBusy = true;
    var original = button.textContent;
    var controls = Array.from(document.querySelectorAll("[data-generate-report]"));
    var feedback = document.getElementById(button.dataset.reportFeedback || "domain-report-feedback");
    var createdMessage = null;
    controls.forEach(function (control) { control.disabled = true; });
    text(button, "Queueing PDF…");
    text(feedback, "Capturing the latest saved DNS and website evidence…");
    try {
      var job = await postJson("/api/reports/external-posture");
      var message = "Report" + (Number.isSafeInteger(job.id) && job.id > 0 ? " #" + job.id : "") + " queued. Generation progress and the finished download are in Reports.";
      createdMessage = message;
      text(feedback, message);
      text(document.getElementById("domain-report-feedback"), message);
      activateTab("reports", true);
      await loadReports();
    } catch (error) {
      var failure = createdMessage ? createdMessage + " Report history could not refresh; use Refresh reports to retry. " + error.message : error.message;
      text(feedback, failure);
      if (createdMessage) text(document.getElementById("domain-report-feedback"), failure);
    } finally {
      text(button, original);
      controls.forEach(function (control) { control.disabled = false; });
      externalReportCreationBusy = false;
    }
  }
  document.addEventListener("click", function (event) {
    var button = event.target.closest("[data-generate-report]");
    if (!button) return;
    event.preventDefault();
    queueExternalPostureReport(button);
  });

  function buildCheckActionBar(type) {
    var panel = document.getElementById("tab-" + type);
    var intro = panel && panel.querySelector(".page-intro");
    if (!intro || panel.querySelector(".check-action-bar")) return;
    var bar = document.createElement("div"); bar.className = "check-action-bar";
    var note = document.createElement("p"); note.className = "check-action-note";
    note.id = type + "-action-schedule";
    note.textContent = "Loading saved monitoring schedule…";
    var admin = role === "admin";
    var checkNow = document.createElement("button"); checkNow.type = "button"; checkNow.className = "button button-primary"; checkNow.textContent = "Check now";
    checkNow.dataset.runExternalCheck = type;
    checkNow.dataset.checkFeedback = type + "-action-feedback";
    var schedule = document.createElement("button"); schedule.type = "button"; schedule.className = "button button-quiet"; schedule.textContent = "Monitoring schedule";
    schedule.setAttribute("aria-controls", type + "-monitoring-details");
    schedule.addEventListener("click", function () {
      var details = document.getElementById(type + "-monitoring-details");
      if (!details) return;
      details.open = true;
      var summary = details.querySelector("summary");
      if (summary) { summary.focus(); summary.scrollIntoView({block: "center"}); }
    });
    var pdf = document.createElement("button"); pdf.type = "button"; pdf.className = "button button-quiet"; pdf.textContent = "Create PDF report";
    pdf.dataset.generateReport = "";
    pdf.dataset.reportFeedback = type + "-action-feedback";
    var feedback = document.createElement("p"); feedback.id = type + "-action-feedback";
    feedback.className = "check-action-feedback";
    feedback.setAttribute("role", "status");
    feedback.setAttribute("aria-live", "polite");
    if (admin) bar.append(checkNow, schedule);
    bar.append(pdf);
    intro.after(bar);
    bar.after(note, feedback);
  }
  ["dns", "web"].forEach(buildCheckActionBar);

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
    scroller.setAttribute("aria-label", title + "; record evidence");
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
      [row.type, row.name].forEach(function (value, index) {
        var cell = document.createElement("td");
        cell.textContent = value;
        cell.dataset.label = index === 0 ? "Type" : "Name";
        tableRow.append(cell);
      });
      var valueCell = document.createElement("td");
      valueCell.className = "audit-record-value";
      valueCell.dataset.label = "Value";
      valueCell.textContent = row.value;
      if (Array.isArray(row.advisoryIds)) {
        var links = document.createElement("div");
        links.className = "audit-advisory-links";
        row.advisoryIds.filter(function (id) { return typeof id === "string" && /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(id); }).slice(0, 10).forEach(function (id) {
          var link = document.createElement("a");
          link.href = "https://osv.dev/vulnerability/" + encodeURIComponent(id);
          link.textContent = id;
          link.target = "_blank";
          link.rel = "noopener noreferrer";
          link.setAttribute("aria-label", "Review OSV advisory " + id + " (opens in a new tab)");
          links.append(link);
        });
        if (links.children.length) valueCell.append(links);
      }
      tableRow.append(valueCell);
      var statusCell = document.createElement("td");
      statusCell.dataset.label = "Status";
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

  function appendCheckRow(list, level, label, detailText) {
    var marks = {ok: "✓", info: "~", warn: "!", bad: "✕"};
    var li = document.createElement("li"); li.className = "check-item is-" + level;
    var icon = document.createElement("span"); icon.className = "check-mark"; icon.textContent = marks[level] || "!"; icon.setAttribute("aria-hidden", "true");
    var name = document.createElement("strong"); name.textContent = label;
    var detail = document.createElement("span"); detail.className = "check-detail"; detail.textContent = detailText;
    li.append(icon, name, detail); list.append(li);
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
      var guidance = snapshot.email_authentication_assessment && snapshot.email_authentication_assessment.guidance;
      if (Array.isArray(guidance) && guidance.length) {
        var marks = {good: ["✓", "ok"], info: ["~", "info"], warn: ["!", "warn"], action: ["✕", "bad"]};
        var list = document.createElement("ul"); list.className = "check-list";
        guidance.forEach(function (item) {
          var mark = marks[item.level] || marks.warn;
          var li = document.createElement("li"); li.className = "check-item is-" + mark[1];
          var icon = document.createElement("span"); icon.className = "check-mark"; icon.textContent = mark[0]; icon.setAttribute("aria-hidden", "true");
          var label = document.createElement("strong"); label.textContent = item.area;
          var detail = document.createElement("span"); detail.className = "check-detail"; detail.textContent = item.text;
          li.append(icon, label, detail); list.append(li);
        });
        var failed = Object.keys(errors);
        var look = document.createElement("li"); look.className = "check-item is-" + (failed.length ? "warn" : "ok");
        var lookIcon = document.createElement("span"); lookIcon.className = "check-mark"; lookIcon.textContent = failed.length ? "!" : "✓"; lookIcon.setAttribute("aria-hidden", "true");
        var lookLabel = document.createElement("strong"); lookLabel.textContent = "DNS lookups";
        var lookDetail = document.createElement("span"); lookDetail.className = "check-detail";
        lookDetail.textContent = failed.length ? "These lookups failed and are unknown: " + failed.join(", ") + "." : "No DNS lookup errors were recorded. Empty answers can still mean no record was found.";
        look.append(lookIcon, lookLabel, lookDetail); list.append(look);
        container.append(list);
        return;
      } else {
        emailAuthenticationMetrics(snapshot.email_authentication_assessment).forEach(function (metric) {
          if (metric.state !== "good") finding(metric.label + ": " + metric.value, metric.detail);
        });
      }
      if (Object.keys(errors).length) finding("DNS lookup coverage", "Some DNS lookups failed. Those records remain unknown; review the lookup evidence below.");
      if (!items.length) finding("Email protection evidence recorded", "No concern was identified in the saved SPF and DMARC assessment. Review domain resolution and selector evidence below.");
    } else {
      var checklist = document.createElement("ul"); checklist.className = "check-list";
      var statusCode = Number(snapshot.http_status || 0);
      appendCheckRow(checklist, statusCode >= 200 && statusCode < 400 ? "ok" : "bad", "Website",
        statusCode ? (statusCode < 400 ? "Responds over HTTPS (" + statusCode + ")." : "Returned an error response (" + statusCode + ").") : "No HTTP response was received.");
      var certificateAssessment = websiteCertificateAssessment(snapshot.tls);
      appendCheckRow(checklist, certificateAssessment.state === "expired" ? "bad" : certificateAssessment.state === "expiring" || certificateAssessment.state === "unknown" ? "warn" : "ok", "Certificate",
        certificateAssessment.state === "expired" ? "The TLS certificate has expired." : certificateAssessment.state === "unknown" ? "Certificate expiry could not be read." :
        certificateAssessment.state === "expiring" ? "Renew soon: expires in about " + certificateAssessment.days + " days." : "Valid" + (certificateAssessment.days != null ? "; about " + certificateAssessment.days + " days left." : "."));
      var headerMap = snapshot.security_headers || {};
      var headerNames = Object.keys(headerMap);
      var absentHeaders = headerNames.filter(function (name) { return !headerMap[name]; });
      appendCheckRow(checklist, !headerNames.length ? "info" : absentHeaders.length ? "warn" : "ok", "Browser headers",
        !headerNames.length ? "Header evidence is unavailable." : absentHeaders.length ? absentHeaders.length + " of " + headerNames.length + " selected protections are absent: " + absentHeaders.join(", ") + "." : "All selected protections are present.");
      container.append(checklist);
      var advisory = snapshot.dependency_advisory_observations;
      if (advisory && (advisory.state === "unavailable" || advisory.state === "partial")) {
        finding("Dependency advisory coverage", "The saved OSV lookup is " + advisory.state + ". Missing matches remain unknown; inspect package evidence below.");
      }
      if (advisory && advisory.state === "not_assessed") {
        finding("Dependency versions need review", "No advisory assessment was completed for this saved page. Supported exact version declarations were unavailable or incomplete; linked libraries remain unassessed. Inspect the saved dependency inventory below.");
      }
      var matchedPackages = advisory && Array.isArray(advisory.packages) ? advisory.packages.filter(function (item) {
        return item && Array.isArray(item.advisory_ids) && item.advisory_ids.length > 0;
      }) : [];
      if (matchedPackages.length) {
        finding("Declared dependencies have advisory matches", matchedPackages.length + " declared package version(s) returned OSV advisory IDs. Review the saved matches and update applicability; URL declarations do not verify loaded bytes, execution or exploitability.");
      }
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
    ["A", "AAAA", "CNAME", "NS", "SOA", "TXT", "SRV", "CAA", "DS", "DNSKEY"].forEach(function (key) {
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
    var registration = snapshot.registration_observations;
    var registrationHeading = document.createElement("h3");
    registrationHeading.className = "topic-group-heading";
    registrationHeading.textContent = "Domain registration";
    var registrationMetrics = document.createElement("div");
    registrationMetrics.className = "audit-metric-grid dns-audit-metrics";
    var observedRegistration = registration && registration.state === "observed";
    registrationMetrics.append(makeAuditMetric("Registry lookup",
      !registration ? "Not assessed" : observedRegistration ? (registration.collection_partial ? "Partial evidence" : "Evidence saved") : "Unavailable",
      "Public RDAP evidence does not verify domain ownership", observedRegistration ? "neutral" : registration ? "attention" : "neutral"));
    var registrationRows = [];
    if (observedRegistration) {
      var registrarNames = registration.registrars || [];
      var registryNameservers = registration.nameservers || [];
      var expiryEvents = (registration.events || []).filter(function (event) { return event.action === "expiration"; });
      registrationMetrics.append(
        makeAuditMetric("Registrar", registrarNames.join(", ") || "Unknown", "Registry's public registrar metadata", "neutral"),
        makeAuditMetric("Registration expiry", expiryEvents.length === 1 ? dateLabel(expiryEvents[0].date) : expiryEvents.length ? "Multiple dates" : "Unknown", "Provider-reported date; review saved event evidence", "neutral"),
        makeAuditMetric("Registry nameservers", registryNameservers.length ? String(registryNameservers.length) : "Unknown", registryNameservers.join(", ") || "Not supplied by provider", "neutral")
      );
      ["registrars", "nameservers"].forEach(function (key) {
        registrationRows.push({type: key === "registrars" ? "Registrar" : "Nameservers", name: "RDAP", value: (registration[key] || []).join(", ") || "Not supplied by provider", present: Boolean((registration[key] || []).length), statusTone: "is-neutral", statusText: (registration[key] || []).length ? "Observed" : "Unknown"});
      });
      (registration.events || []).forEach(function (event) {
        registrationRows.push({type: event.action, name: "RDAP", value: dateLabel(event.date), present: true, statusTone: "is-neutral", statusText: "Observed"});
      });
    }
    grid.append(evidenceGroup("dns-registration-group", registrationHeading, registrationMetrics, "Registration evidence",
      makeAuditTable("Registry observations", "Saved provider metadata; unavailable fields remain unknown. Registration dates are not ownership approval.", registrationRows, "observations")));
    var transparency = snapshot.certificate_transparency;
    var transparencyHeading = document.createElement("h3");
    transparencyHeading.className = "topic-group-heading";
    transparencyHeading.textContent = "Certificate issuance history";
    var transparencyMetrics = document.createElement("div");
    transparencyMetrics.className = "audit-metric-grid dns-audit-metrics";
    var observedTransparency = transparency && transparency.state === "observed";
    var certificateEntries = observedTransparency && Array.isArray(transparency.entries) ? transparency.entries : [];
    function transparencyDiagnostic(evidence, query) {
      var prefix = query === "root" ? "Root-domain history lookup" : query === "subdomain" ? "Subdomain history lookup" : "History provider";
      var status = query ? evidence[query + "_query_http_status"] : evidence.http_status;
      var errorType = query ? evidence[query + "_query_error_type"] : evidence.error_type;
      if (Number.isInteger(status) && status >= 100 && status <= 599) return prefix + " returned HTTP " + status + ".";
      if (errorType === "TimeoutError" || evidence.error_code === "timeout") return prefix + " timed out.";
      if (!query && evidence.error_code === "invalid_response") return "History provider response could not be interpreted.";
      return prefix + " did not complete.";
    }
    var transparencyDetail = "crt.sh observations do not verify the website's live TLS certificate";
    if (transparency && !observedTransparency) transparencyDetail = transparencyDiagnostic(transparency, false);
    else if (observedTransparency && transparency.root_query_error_type) transparencyDetail = transparencyDiagnostic(transparency, "root");
    else if (observedTransparency && transparency.subdomain_query_error_type) transparencyDetail = transparencyDiagnostic(transparency, "subdomain");
    transparencyMetrics.append(makeAuditMetric("History lookup", !transparency ? "Not assessed" : observedTransparency ? transparency.collection_partial ? "Partial evidence" : "Evidence saved" : "Unavailable",
      transparencyDetail, observedTransparency ? "neutral" : transparency ? "attention" : "neutral"));
    if (observedTransparency) {
      var observedNames = new Set();
      certificateEntries.forEach(function (entry) { (entry.dns_names || []).forEach(function (name) { observedNames.add(name); }); });
      transparencyMetrics.append(
        makeAuditMetric("Saved log entries", String(certificateEntries.length), "Bounded observations; certificate and precertificate entries may overlap", "neutral"),
        makeAuditMetric("Observed DNS names", String(observedNames.size), "Domain and subdomain names; availability has not been tested", "neutral"),
        makeAuditMetric("Log proof validation", "Not performed", "Issuance history only; no log inclusion or consistency proof", "neutral")
      );
    }
    var certificateRows = certificateEntries.map(function (entry) {
      return {type: "Entry " + entry.id, name: (entry.dns_names || []).join(", "),
        value: entry.issuer + " · validity " + dateLabel(entry.not_before) + " to " + dateLabel(entry.not_after),
        present: true, statusText: "Observed", statusTone: "is-neutral"};
    });
    var certificateEvidence;
    if (observedTransparency) {
      certificateEvidence = document.createElement("div");
      var certificateTable = makeAuditTable("Certificate log observations", "Missing later entries do not establish revocation. New entries are newly observed provider records, not confirmed new issuances.", certificateRows, "observations");
      certificateTable.className = "audit-table-card certificate-history-table";
      var mobileEntries = document.createElement("div");
      mobileEntries.className = "certificate-history-mobile-list";
      var mobileScope = document.createElement("p");
      mobileScope.className = "muted";
      mobileScope.textContent = "Provider observations only. Missing later entries do not establish revocation; new entries do not confirm a new issuance.";
      mobileEntries.append(mobileScope);
      certificateEntries.forEach(function (entry) {
        var card = document.createElement("article");
        card.className = "certificate-history-entry";
        var heading = document.createElement("h4");
        heading.textContent = "Observed entry " + entry.id;
        var fields = document.createElement("dl");
        [["Issuer", entry.issuer], ["DNS names", (entry.dns_names || []).join(", ")],
          ["Validity starts", dateLabel(entry.not_before)], ["Validity ends", dateLabel(entry.not_after)]].forEach(function (field) {
          var label = document.createElement("dt"); label.textContent = field[0];
          var value = document.createElement("dd"); value.textContent = field[1];
          fields.append(label, value);
        });
        card.append(heading, fields);
        mobileEntries.append(card);
      });
      certificateEvidence.append(certificateTable, mobileEntries);
    } else {
      certificateEvidence = document.createElement("p");
      certificateEvidence.className = "muted";
      certificateEvidence.textContent = transparency ? "Certificate history is unavailable; issuance remains unknown. " + transparencyDiagnostic(transparency, false) : "No certificate history assessment is stored yet.";
    }
    grid.append(evidenceGroup("dns-certificate-history-group", transparencyHeading, transparencyMetrics, "Certificate log evidence", certificateEvidence));
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
      var when = document.createElement("small"); when.textContent = (row.reviewer || "Former member") + " · " + dateLabel(row.created_at) + " · Website run #" + row.run_id;
      item.append(title, note, when); host.append(item);
    });
  }

  async function fetchVendorReviews(older) {
    if (!vendorReviewContext) return;
    var runId = vendorReviewContext.runId, sequence = ++vendorReviewSequence;
    try {
      var response = await fetch("/api/vendor-reviews?run_id=" + runId + "&history_all=true" + (older && vendorReviewBefore ? "&before=" + vendorReviewBefore : ""), {credentials: "same-origin"});
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

  function declaredPackageEvidence(snapshot) {
    var metadata = snapshot.dependency_package_observations;
    if (!metadata || metadata.schema_version !== 1 || !Array.isArray(metadata.packages)) {
      return {rows: [], scope: "Package version declarations were not collected in this saved run."};
    }
    var rows = metadata.packages.filter(function (item) {
      return item && item.ecosystem === "npm" && typeof item.name === "string" && typeof item.version === "string";
    }).slice(0, 100).map(function (item) {
      var audit = snapshot.dependency_advisory_observations;
      var observed = audit && Array.isArray(audit.packages) ? audit.packages.find(function (p) { return p.name === item.name && p.version === item.version && p.ecosystem === item.ecosystem; }) : null;
      var ids = observed && Array.isArray(observed.advisory_ids) ? observed.advisory_ids : [];
      var status = !audit ? "Advisories not assessed" : audit.state === "unavailable" ? "Advisory lookup unavailable" : !observed ? "Advisories not assessed" : observed.state === "partial" ? "Partial advisory lookup" : ids.length ? ids.length + " OSV advisory match(es)" : "No OSV matches returned";
      var value = item.version + " · declared by " + (item.source_host || "source unknown");
      if (ids.length > 10) value += " · " + (ids.length - 10) + " more saved IDs";
      return {type: "npm", name: item.name, value: value, advisoryIds: ids, present: true, statusTone: ids.length ? "is-absent" : "is-neutral", statusText: status};
    });
    var sourceScope = metadata.scope === "exact_stable_unpkg_versions_in_root_html_attributes" ? "UNPKG" : "supported UNPKG/jsDelivr";
    return {rows: rows, scope: "Exact stable versions declared in " + sourceScope + " root-page references only. Package bytes and execution were not verified. Advisory matches describe declared versions only. " + (metadata.truncated ? "The saved package list is truncated." : "Tags, ranges and unsupported reference formats remain unidentified.")};
  }

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

      var packageEvidence = declaredPackageEvidence(snapshot);
      vendors.append(makeAuditTable("Declared package versions", packageEvidence.scope, packageEvidence.rows, "declared"));
      if (!packageEvidence.rows.length) {
        appendEmpty(vendors, "No exact supported package version is recorded. This does not establish that dependencies are safe or absent.");
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

  function externalEvidenceLabel(body) {
    var source = body.latest_snapshot_run;
    var latest = (body.runs || [])[0];
    if (!body.latest_snapshot) {
      return latest && latest.status === "running" ? "First assessment running; no saved findings yet."
        : latest && latest.status === "failed" ? "Latest attempt failed; no saved assessment is available."
        : "No saved assessment yet. Run a check to establish a baseline.";
    }
    var validSource = source && Number.isSafeInteger(source.id) && source.id > 0
      && source.id === body.latest_snapshot_run_id && ["completed", "completed_with_warnings"].includes(source.status);
    var dated = validSource && typeof source.completed_at === "string" && Number.isFinite(Date.parse(source.completed_at));
    var label = dated ? "Findings use saved evidence from " + dateLabel(source.completed_at) + " · run #" + source.id + "."
      : "Findings use saved evidence; its collection time is unavailable.";
    if (validSource && source.status === "completed_with_warnings") label += " Collection completed with warnings; some observations may be unknown.";
    if (latest && (!validSource || latest.id !== source.id)) {
      if (latest.status === "running") label += " A new check is running; these findings have not been replaced yet.";
      else if (latest.status === "failed") label += " The latest attempt failed; earlier evidence is retained.";
    }
    return label;
  }

  function externalComparisonLabel(body) {
    var source = body.latest_snapshot_run;
    if (!body.latest_snapshot || !source || !Number.isSafeInteger(source.id) || source.id <= 0
        || source.id !== body.latest_snapshot_run_id || !["completed", "completed_with_warnings"].includes(source.status)) return "No saved comparison is available yet.";
    if (!Number.isSafeInteger(source.change_count) || source.change_count < 0) return "Saved comparison count is unavailable.";
    if (source.comparison_recorded !== true) return "Run #" + source.id + " recorded " + source.change_count + " evidence difference(s). Its comparison baseline was not recorded; earlier provenance is unavailable.";
    if (source.previous_snapshot_run_id === null) return "Run #" + source.id + " establishes the first saved baseline; there is no earlier assessment to compare.";
    if (!Number.isSafeInteger(source.previous_snapshot_run_id) || source.previous_snapshot_run_id <= 0
        || source.previous_snapshot_run_id >= source.id) return "Earlier comparison evidence is unavailable.";
    return "Run #" + source.id + " recorded " + source.change_count + " evidence difference(s) against saved run #"
      + source.previous_snapshot_run_id + ". Unavailable observations can limit comparison; differences are not security incident verdicts.";
  }

  function renderCheckHistory(type, body) {
    var evidenceNode = document.getElementById(type + "-assessment-evidence");
    var evidenceLabel = externalEvidenceLabel(body);
    if (evidenceNode && evidenceNode.textContent !== evidenceLabel) text(evidenceNode, evidenceLabel);
    var status = document.getElementById(type + "-check-status");
    var lastRun = document.getElementById(type + "-check-last-run");
    var runList = document.getElementById(type + "-check-runs");
    var changeList = document.getElementById(type + "-check-changes");
    var latestChanges = document.getElementById(type + "-latest-changes");
    text(document.getElementById(type + "-comparison-summary"), externalComparisonLabel(body));
    if (latestChanges) latestChanges.replaceChildren();
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
        text(lastRun, (latestRun.status === "running" ? "Started " : latestRun.status === "failed" ? "Last attempt " : "Last checked ") + dateLabel(when) +
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
        var isLatest = body.latest_snapshot_run && change.run_id === body.latest_snapshot_run_id;
        if (isLatest && latestChanges) latestChanges.append(row);
        else changeList.append(row);
      });
      if (!changeList.children.length) appendEmpty(changeList, "No earlier changes are loaded. The first successful assessment establishes the baseline; unavailable checks cannot establish changes.");
      if (latestChanges && body.latest_snapshot_run) {
        var loadedCount = (body.changes || []).filter(function (change) { return change.run_id === body.latest_snapshot_run_id; }).length;
        var totalCount = body.latest_snapshot_run.change_count;
        if (Number.isSafeInteger(totalCount) && totalCount > loadedCount) {
          appendEmpty(latestChanges, "Showing " + loadedCount + " of " + totalCount + " recorded differences. Use Load older changes in Earlier change history to load the remaining saved rows.");
        }
      }
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

  function externalSchedulePresentation(schedule, now) {
    var unknown = {state: "unknown", label: "Monitoring schedule unknown", detail: "Refresh saved evidence to read the monitoring schedule."};
    if (!schedule || typeof schedule.enabled !== "boolean" || ![24, 168].includes(schedule.interval_hours)) return unknown;
    if (!schedule.enabled) return {state: "off", label: "Automatic checks off", detail: "Schedules start one full interval after they are saved."};
    var cadence = schedule.interval_hours === 168 ? "Weekly" : "Daily";
    var next = typeof schedule.next_run_at === "string" ? Date.parse(schedule.next_run_at) : NaN;
    var reference = now === undefined ? Date.now() : now;
    var detail = !Number.isFinite(next) ? "Expected collection time is not recorded."
      : next <= reference ? "Expected collection " + dateLabel(schedule.next_run_at) + "; no later schedule update is recorded."
      : "Next scheduled collection " + dateLabel(schedule.next_run_at) + ".";
    return {state: "saved", label: cadence + " schedule saved", detail: detail};
  }

  function renderExternalCheckSchedule(type, schedule) {
    var presentation = externalSchedulePresentation(schedule);
    var status = document.getElementById(type + "-schedule-status");
    var nextRun = document.getElementById(type + "-schedule-next-run");
    var actionSchedule = document.getElementById(type + "-action-schedule");
    var checkbox = document.querySelector('[data-schedule-enabled="' + type + '"]');
    var interval = document.querySelector('[data-schedule-interval="' + type + '"]');
    if (status) {
      status.className = "check-status";
      text(status, presentation.label);
    }
    if (nextRun) {
      var message = presentation.detail;
      if (schedule && schedule.last_completed_at) {
        message += " · Last attempt " + dateLabel(schedule.last_completed_at) +
          (schedule.last_run_status ? " (" + schedule.last_run_status.replaceAll("_", " ") + ")" : "");
      }
      text(nextRun, message);
    }
    if (actionSchedule) text(actionSchedule, presentation.label + " · " + presentation.detail);
    if (presentation.state === "unknown") return;
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

  function savedSuccessfulCheck(body) {
    return body.latest_snapshot && body.latest_snapshot_run
      ? Object.assign({}, body.latest_snapshot_run, { snapshot: body.latest_snapshot }) : null;
  }

  function updateSavedCheckStatus(type, state, focused) {
    var note = document.getElementById(type + "-history-status");
    var message = state.error
      ? (state.loaded ? "Could not refresh. Previously loaded evidence remains visible and may be out of date. " : "Saved evidence is unavailable. ") + state.error
      : state.loading && !state.loaded ? "Loading saved evidence…" : "";
    if (note && note.textContent !== message) text(note, message);
    var scheduleNote = document.getElementById(type + "-action-schedule");
    if (scheduleNote && state.error) {
      var savedSchedule = state.loaded && state.body ? externalSchedulePresentation(state.body.schedule) : null;
      text(scheduleNote, savedSchedule ? "Last observed: " + savedSchedule.label + " · " + savedSchedule.detail
        : "Monitoring schedule unavailable. Retry saved evidence to load it.");
    }
    if (state.error && !state.loaded) {
      var emptyIds = type === "web-active" ? ["web-exposure-review", "web-exposure-outcome", "web-active-runs"]
        : type === "web-nikto" ? ["web-audit-review", "web-nikto-outcome", "web-nikto-runs"]
        : [type + "-priorities", type + "-assessment-evidence", type + "-comparison-summary", type + "-check-runs"];
      emptyIds.forEach(function (id) { text(document.getElementById(id), "Saved evidence is unavailable. Use Retry saved evidence to load it."); });
    }
    var refreshButton = document.querySelector('[data-refresh-check="' + type + '"]');
    if (refreshButton) {
      refreshButton.setAttribute("aria-disabled", state.loading ? "true" : "false");
      refreshButton.setAttribute("aria-busy", state.loading ? "true" : "false");
      refreshButton.textContent = state.error ? "Retry saved evidence" : "Refresh saved evidence";
    }
    var buttons = type === "web-active" ? document.querySelectorAll("[data-load-older-active]")
      : type === "web-nikto" ? [document.getElementById("older-nikto")]
      : document.querySelectorAll('[data-load-older-checks="' + type + '"]');
    Array.from(buttons).forEach(function (button) {
      if (!button) return;
      var field = button.dataset.pageKind || button.dataset.loadOlderActive || "runs";
      var more = Boolean(state.body && state.body[field + "_has_more"]);
      if (!more && focused === button && refreshButton) refreshButton.focus({ preventScroll: true });
      button.classList.toggle("hidden", !more);
      button.disabled = false;
      button.setAttribute("aria-disabled", state.loading ? "true" : "false");
    });
  }

  function savedCheckHistory(type) {
    if (savedCheckHistories[type]) return savedCheckHistories[type];
    var state = type === "web-active" ? activeExposureHistory : type === "web-nikto" ? niktoHistory
      : (externalCheckHistory[type] || (externalCheckHistory[type] = {}));
    var pager = window.daedalusCheckHistory.create({
      fetch: function (url, options) { return fetch(url, options); },
      url: "/api/external-checks/" + type, type: type, state: state,
      changed: function (current, committed) {
        var focused = document.activeElement;
        if (committed) {
          if (type === "web-active") renderActiveExposure(current.body);
          else if (type === "web-nikto") renderNiktoHistory(current.body);
          else renderCheckHistory(type, current.body);
        }
        updateSavedCheckStatus(type, current, focused);
      }
    });
    savedCheckHistories[type] = pager;
    return pager;
  }

  document.querySelectorAll("[data-refresh-check]").forEach(function (button) {
    button.addEventListener("click", function () {
      if (!orgId) return;
      var pager = savedCheckHistory(button.dataset.refreshCheck);
      if (!pager.state.loading) pager.refresh();
    });
  });

  function renderExposureReview(run, savedRun) {
    var host = document.getElementById("web-exposure-review");
    if (!host) return;
    host.replaceChildren();
    if (!run) { appendEmpty(host, "No saved exposure assessment yet."); return; }
    if (run.status !== "completed" && run.status !== "completed_with_warnings") {
      appendEmpty(host, "Latest exposure attempt " + String(run.status || "has unknown status") + ". No completed assessment is inferred from this attempt.");
      if (!savedRun) return;
      run = savedRun;
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
    renderExposureReview(runs[0], savedSuccessfulCheck(body));
    if (status) {
      var latest = runs[0];
      status.className = "check-status" + (latest && latest.status === "failed" ? " status-failed" : "");
      status.textContent = !latest ? "No active check run yet" : latest.status.replaceAll("_", " ") + " · " + (latest.change_count || 0) + " finding change(s)";
    }
    list.replaceChildren();
    if (!runs.length) appendEmpty(list, "No active check history yet.");
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

  async function loadActiveExposure(olderKind, background) {
    if (!orgId) return;
    var pager = savedCheckHistory("web-active");
    if (background && pager.state.loading) return;
    return olderKind ? pager.older(olderKind) : pager.refresh();
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

  function renderNiktoReview(runs, savedRun) {
    var host = document.getElementById("web-audit-review");
    if (!host) return;
    host.replaceChildren();
    var completed = savedRun || runs.find(function (run) { return run.status === "completed" || run.status === "completed_with_warnings"; });
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

  function renderNiktoHistory(body) {
    var host = document.getElementById("web-nikto-runs");
    if (!host) return;
    var focused = document.activeElement && host.contains(document.activeElement) ? document.activeElement : null;
    var focusedRun = focused && focused.dataset.niktoCancel;
    var openRuns = new Set(Array.from(host.querySelectorAll("[data-saved-run-id]")).filter(function (node) { return node.open; }).map(function (node) { return node.dataset.savedRunId; }));
    renderWebsiteAuditOutcome("web-nikto-outcome", "Deeper website audit", niktoHistory.runs[0]);
    renderNiktoReview(niktoHistory.runs, savedSuccessfulCheck(body));
    host.replaceChildren();
    niktoHistory.runs.forEach(function (run) {
      var card = document.createElement("article"); card.className = "external-schedule-card";
      var title = document.createElement("h4"); title.textContent = "Run #" + run.id + " · " + String(run.status).replace(/_/g, " ") + " · " + dateLabel(run.completed_at || run.started_at);
      var note = document.createElement("p"); note.className = "muted";
      note.textContent = run.error_summary || "Coverage remains unconfirmed. Comparisons record new observations; absent findings do not prove resolution.";
      card.append(title, note);
      if (role === "admin" && run.status === "queued") {
        var cancel = document.createElement("button"); cancel.type = "button";
        cancel.dataset.niktoCancel = String(run.id);
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
      details.dataset.savedRunId = String(run.id);
      details.append(summary);
      details.addEventListener("toggle", function () {
        if (!details.open || details.dataset.loaded) return;
        details.dataset.loaded = "true";
        findings.forEach(function (finding) {
          var entry = document.createElement("p"); entry.textContent = "Nikto test " + finding.test_id + " · " + finding.method + " " + finding.path + (finding.description ? " · " + finding.description : "");
          details.append(entry);
        });
      });
      details.open = openRuns.has(String(run.id));
      card.append(details); host.append(card);
    });
    text(document.getElementById("web-nikto-status"), niktoHistory.runs.length ? "Latest: " + String(niktoHistory.runs[0].status).replace(/_/g, " ") : "No Nikto run yet");
    document.getElementById("older-nikto").classList.toggle("hidden", !niktoHistory.hasMore);
    var button = document.getElementById("run-nikto");
    if (button) button.disabled = !controlsEnabled || niktoHistory.busy || niktoHistory.runs.some(function (run) { return run.status === "queued" || run.status === "running"; });
    if (focusedRun) {
      var replacement = Array.from(host.querySelectorAll("[data-nikto-cancel]")).find(function (node) { return node.dataset.niktoCancel === focusedRun; });
      if (!replacement) replacement = document.querySelector('[data-refresh-check="web-nikto"]');
      if (replacement) replacement.focus({ preventScroll: true });
    }
  }

  async function loadNikto(older, background) {
    if (!document.getElementById("web-nikto-runs") || !orgId) return;
    var pager = savedCheckHistory("web-nikto");
    if (background && pager.state.loading) return;
    return older ? pager.older("runs") : pager.refresh();
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
    activeExposureButton.dataset.requestBusy = "true";
    text(document.getElementById("web-active-feedback"), "The bounded request set can take up to 40 seconds.");
    try {
      var result = await postJson("/api/external-checks/web-active/run");
      text(document.getElementById("web-active-feedback"), "Run #" + result.id + " saved. Load its evidence and coverage state.");
      await loadActiveExposure(); await loadAuditLog();
    } catch (error) { text(document.getElementById("web-active-feedback"), error.message); }
    finally { delete activeExposureButton.dataset.requestBusy; text(activeExposureButton, original); activeExposureButton.disabled = !controlsEnabled; }
  });

  async function loadExternalCheck(type, olderKind) {
    if (!orgId || !["dns", "web"].includes(type)) return;
    var pager = savedCheckHistory(type);
    return olderKind ? pager.older(olderKind) : pager.refresh();
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
    } else if (message.collection_resumed === true && (message.status === "completed" || message.status === "completed_with_warnings")) {
      textMessage = moduleName + " collection resumed" + (message.collection_resumed_with_limits === true ? " with limitations" : "") + " for " + message.domain + ". " +
        (message.initial_baseline === true ? "First baseline saved; changes cannot yet be compared. " : message.change_count ? message.change_count + " change(s) were recorded. " : "Fresh evidence was saved. ") +
        "Review the latest run; resumed collection does not establish that security findings were resolved.";
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
      if (button.disabled) return;
      var type = button.dataset.runExternalCheck;
      var original = button.textContent;
      var feedback = document.getElementById(button.dataset.checkFeedback || type + "-action-feedback");
      button.disabled = true;
      text(button, "Checking…");
      text(feedback, "Collecting fresh " + (type === "dns" ? "DNS and email" : "website") + " evidence…");
      try {
        var run = await postJson("/api/external-checks/" + type + "/run");
        text(feedback, "Check #" + run.id + " recorded: " + String(run.status || "status unavailable").replaceAll("_", " ") + ". Review the saved findings and comparison below.");
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
        text(feedback, error.message);
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
      if (button.disabled || button.dataset.scheduleSaving === "true") return;
      var type = button.dataset.saveSchedule;
      var checkbox = document.querySelector('[data-schedule-enabled="' + type + '"]');
      var interval = document.querySelector('[data-schedule-interval="' + type + '"]');
      if (!checkbox || !interval) return;
      button.dataset.scheduleSaving = "true";
      button.setAttribute("aria-disabled", "true");
      button.setAttribute("aria-busy", "true");
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
        button.dataset.scheduleSaving = "false";
        button.setAttribute("aria-disabled", "false");
        button.setAttribute("aria-busy", "false");
      }
    });
  });

  var workspaceDialog = document.getElementById("workspace-dialog");
  document.querySelectorAll("[data-open-workspace-dialog]").forEach(function (button) {
    button.addEventListener("click", function () {
      if (workspaceDialog && !workspaceDialog.open) {workspaceDialog.showModal();loadWorkspaces();}
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

  async function loadWorkspaces() {
    if (!workspaceRequests && window.DaedalusWorkspaceRequests) {
      workspaceRequests = window.DaedalusWorkspaceRequests.create({userId:shell && shell.dataset.userId,organizationId:orgId,
        fetch:function (url,options) {return fetch(url,options);},selectionBusy:function () {return workspaceSelectionBusy;},
        select:function (id,button) {return selectWorkspace(id,null,button);},onRead:syncPendingMembershipFeeds,
        onState:function () {if (customerCreation) customerCreation.updateControls();}});
      window.daedalusWorkspaceRequests = workspaceRequests;
    }
    if (workspaceRequests) return workspaceRequests.load();
  }

  if (window.DaedalusCustomerCreation) {
    customerCreation = window.DaedalusCustomerCreation.create({userId:shell && shell.dataset.userId,
      fetch:function (url,options) {return fetch(url,options);},workspaceReview:function () {return workspaceRequests;},
      selectionBusy:function () {return workspaceSelectionBusy;},
      select:function (id,button) {return selectWorkspace(id,"overview",button);},
      afterSave:async function () {await loadWorkspaces();if (window.daedalusOnboarding) await window.daedalusOnboarding.load();}});
    window.daedalusCustomerCreation = customerCreation;
  }

  async function requestMembership(domain) {
    var controller = new AbortController();
    var timer = window.setTimeout(function () {controller.abort();},20000);
    try {
      var response = await fetch("/api/membership-requests", {method:"POST",credentials:"same-origin",
        headers:{"Content-Type":"application/json"},body:JSON.stringify({domain:domain}),signal:controller.signal});
      var body; try {body = await response.json();} catch (_) {body = {};}
      if (!response.ok) throw new Error(body && typeof body.detail === "string" ? body.detail : "The access request could not be confirmed.");
      if (!body || !["pending","approved"].includes(body.status) || typeof body.organization !== "string" || !body.organization) throw new Error("The access request could not be confirmed. Use Refresh workspaces to check your saved access request.");
      return body;
    } catch (error) {
      if (controller.signal.aborted) throw new Error("The request timed out. Use Refresh workspaces to check whether your access request was saved before trying again.");
      throw error;
    } finally {window.clearTimeout(timer);}
  }

  var requestAccessForm = document.getElementById("request-access-form");
  var requestAccessBusy = false;
  if (requestAccessForm) {
    requestAccessForm.addEventListener("submit", async function (event) {
      event.preventDefault();
      if (requestAccessBusy) return;
      requestAccessBusy = true;
      var submitButton = requestAccessForm.querySelector('button[type="submit"]');
      if (submitButton) submitButton.disabled = true;
      var feedback = document.getElementById("workspace-feedback");
      text(feedback, "Sending access request…");
      try {
        var form = new FormData(requestAccessForm);
        var body = await requestMembership(form.get("domain"));
        clearMembershipNotice();
        var message = body.status === "approved"
          ? "You already have access to " + body.organization + "."
          : "Request sent to " + body.organization + " admin for approval.";
        text(feedback, message);
        requestAccessForm.reset();
        await loadWorkspaces();
      } catch (error) {
        showError(feedback, error.message);
      } finally {requestAccessBusy = false; if (submitButton) submitButton.disabled = false;}
    });
  }

  function setWorkspaceSelectionBusy(busy) {
    workspaceSelectionBusy = busy;
    var select = document.getElementById("workspace-select");
    if (select) {
      if (busy) select.dataset.selectionWasDisabled = String(select.disabled);
      select.disabled = busy || select.dataset.selectionWasDisabled === "true";
    }
    document.querySelectorAll("[data-select-workspace]").forEach(function (button) { button.setAttribute("aria-disabled", String(busy)); });
    updatePortfolioReadState();
    if (workspaceRequests) workspaceRequests.updateControls();
    if (customerCreation) customerCreation.updateControls();
  }

  async function selectWorkspace(id, targetTab, trigger) {
    if (typeof id !== "number" && (typeof id !== "string" || !/^\d+$/.test(id))) return;
    var selectedId = Number(id);
    if (workspaceSelectionBusy || !Number.isSafeInteger(selectedId) || selectedId <= 0) return;
    if (trigger && (trigger.dataset.workspaceReviewOpen || trigger.id === "workspace-select") && workspaceRequests && !workspaceRequests.canSelect(selectedId)) {
      if (trigger.id === "workspace-select") trigger.value = orgId;
      return;
    }
    var fromPortfolio = trigger && trigger.closest("#portfolio-board");
    if (fromPortfolio && (!portfolioRead.body || portfolioRead.error || portfolioRead.loading
      || !portfolioRead.body.workspaces.some(function (workspace) { return workspace.id === selectedId; })
      || !portfolioRead.body.can_switch_workspaces && String(selectedId) !== String(orgId))) return;
    if (String(selectedId) === String(orgId)) {
      var previousNote = document.getElementById("workspace-selection-note"); if (previousNote) previousNote.hidden = true;
      if (targetTab === "overview") activateTab("overview", true);
      return;
    }
    var note = document.getElementById("workspace-selection-note");
    var restoreFocus = trigger && document.activeElement === trigger;
    if (note) { note.hidden = false; note.textContent = "Opening workspace…"; }
    setWorkspaceSelectionBusy(true);
    if (trigger) trigger.setAttribute("aria-busy", "true");
    try {
      var body = await postJson("/api/workspaces/select", { organization_id: selectedId });
      if (!body || body.ok !== true || body.organization_id !== selectedId) throw new Error("The selected workspace could not be confirmed.");
      if (targetTab === "overview") window.history.replaceState(null, "", window.location.pathname + window.location.search + "#overview");
      window.location.reload();
    } catch (error) {
      if (note) { note.hidden = false; note.textContent = "Workspace switch could not be confirmed. " + error.message + " This page still displays the previous workspace; retry or refresh before continuing."; }
      var select = document.getElementById("workspace-select"); if (select) select.value = orgId;
      setWorkspaceSelectionBusy(false);
      if (trigger) trigger.setAttribute("aria-busy", "false");
      if (restoreFocus && (!document.activeElement || document.activeElement === document.body)) trigger.focus({preventScroll: true});
    }
  }

  document.addEventListener("click", function (event) {
    var selectButton = event.target.closest("[data-select-workspace]");
    if (selectButton) selectWorkspace(selectButton.dataset.selectWorkspace, selectButton.dataset.workspaceReviewTab, selectButton);
  });
  var workspaceSelect = document.getElementById("workspace-select");
  if (workspaceSelect) {
    workspaceSelect.addEventListener("change", function () {
      selectWorkspace(workspaceSelect.value, null, workspaceSelect);
    });
  }

  var issueChallengeButton = document.getElementById("issue-domain-challenge");
  var verifyDomainButton = document.getElementById("verify-domain");
  var replaceChallengeButton = document.getElementById("replace-domain-challenge");
  var verificationFeedback = document.getElementById("verification-feedback");
  var domainChallengeBusy = false;

  function renderDomainChallenge(body) {
    var record = body.txt;
    var current = body.state === "active" && record;
    var challenge = document.getElementById("dns-challenge");
    if (challenge) challenge.classList.toggle("hidden", !current);
    text(document.getElementById("challenge-record-name"), current ? record.record_name : "");
    text(document.getElementById("challenge-record-value"), current ? record.value_available === true && typeof record.record_value === "string" ? record.record_value : "The original value cannot be redisplayed." : "");
    var expiry = current && record.expires_at ? new Date(record.expires_at) : null;
    text(document.getElementById("challenge-expires"), current ? expiry && Number.isFinite(expiry.getTime()) ? "Record expires " + expiry.toLocaleString() + "." : "Record expiry is unavailable." : "");
    if (body.verified) {
      text(verificationFeedback, "Domain ownership is already verified. Refresh the workspace to see its current access.");
    } else if (current && record.value_available !== true) {
      text(verificationFeedback, "The current record remains valid. If you already published it, check DNS now. Use Replace TXT record if you need a new value.");
    } else if (current) {
      text(verificationFeedback, "Publish this record at your DNS provider, then check DNS here. Refreshing keeps the same record.");
    } else {
      text(verificationFeedback, body.state === "expired" ? "The previous record expired. Show DNS TXT record prepares a new one." : "Show DNS TXT record prepares the ownership instructions.");
    }
  }

  async function domainChallengeRequest(path, method) {
    if (domainChallengeBusy) throw new Error("A DNS request is already in progress.");
    domainChallengeBusy = true;
    [issueChallengeButton, verifyDomainButton, replaceChallengeButton].forEach(function (button) { if (button) button.disabled = true; });
    try {
      if (method === "POST") return await postJson(path);
      var response = await fetch(path, { credentials: "same-origin", cache: "no-store" });
      var body = await response.json();
      if (!response.ok) throw new Error(body.detail || "Could not load the ownership instructions");
      return body;
    } finally {
      domainChallengeBusy = false;
      [issueChallengeButton, verifyDomainButton, replaceChallengeButton].forEach(function (button) { if (button) button.disabled = false; });
    }
  }

  if (issueChallengeButton && orgId) {
    issueChallengeButton.addEventListener("click", async function () {
      text(verificationFeedback, "Preparing a DNS TXT record…");
      try {
        var body = await domainChallengeRequest("/api/workspaces/" + orgId + "/domain-challenge/ensure", "POST");
        if (body.verified) return window.location.reload();
        renderDomainChallenge(body);
      } catch (error) {
        showError(verificationFeedback, error.message);
      }
    });
    domainChallengeRequest("/api/workspaces/" + orgId + "/domain-challenge", "GET").then(renderDomainChallenge).catch(function (error) {
      showError(verificationFeedback, error.message);
    });
  }
  if (replaceChallengeButton && orgId) {
    replaceChallengeButton.addEventListener("click", function () {
      requestInlineConfirmation(replaceChallengeButton, "Replace the current TXT record? The previous value will stop verifying this domain. Update DNS with the new value afterward.", "Replace record", async function () {
        var body = await domainChallengeRequest("/api/workspaces/" + orgId + "/domain-challenge", "POST");
        if (body.verified) return window.location.reload();
        renderDomainChallenge(body);
      });
    });
  }
  if (verifyDomainButton && orgId) {
    verifyDomainButton.addEventListener("click", async function () {
      text(verificationFeedback, "Checking the public DNS TXT record…");
      try {
        var body = await domainChallengeRequest("/api/workspaces/" + orgId + "/verify-domain", "POST");
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

  if (orgId && role === "admin" && window.DaedalusProbationApproval) {
    probationApproval = window.DaedalusProbationApproval.create({organizationId:orgId,
      fetch:function (url, options) {return fetch(url, options);},
      onSaved:async function () {await refresh(true);await loadAuditLog();}
    });
    window.daedalusProbationApproval = probationApproval;
    if (probationApproval) probationApproval.load();
  }

  async function loadMemberships(background) {
    if (membershipReview) return membershipReview.load(background);
  }

  function auditEventSummary(entry) {
    var data = entry.details || {};
    if (entry.action === "membership.requested") return (data.email || "A member") + " requested workspace access.";
    if (entry.action === "membership.approved") return (data.email || "The requesting member") + " was approved as a user.";
    if (entry.action === "membership.denied") return "The access request for " + (data.email || "the requesting member") + " was declined.";
    if (entry.action === "membership.revoked") return "Workspace access was removed for " + (data.email || "the shared member") + ".";
    if (entry.action === "membership.role_changed") return (data.email || "The approved member") + " changed from " + (data.from_role || "an unknown role") + " to " + (data.to_role || "an unknown role") + ".";
    if (entry.action === "workspace.probation_expired") return "Domain verification probation expired for " + (data.domain || "this workspace") + " at " + dateLabel(data.expires_at) + ". Recorded when observed: " + dateLabel(data.observed_at) + ".";
    if (entry.action === "probation_override.expired") return "Temporary override #" + data.override_id + " expired at " + dateLabel(data.expires_at) + ". Recorded when observed: " + dateLabel(data.observed_at) + ".";
    if (entry.action === "onboarding.approved" || entry.action === "onboarding.reapproved") return "Complimentary onboarding approved for 30 days, through " + dateLabel(data.review_due_at) + ". Reason: " + (data.reason || "Recorded by platform administrator") + ".";
    if (entry.action === "onboarding.ended") return "Complimentary onboarding ended. Reason: " + (data.reason || "Recorded by platform administrator") + ".";
    if (entry.action === "onboarding.review_due") return "Customer onboarding needs reapproval after " + dateLabel(data.review_due_at) + ".";
    if (entry.action === "probation_override.granted") return "Temporary override #" + data.override_id + " granted through " + dateLabel(data.expires_at) + "." + (data.reason ? " Reason: " + data.reason : "");
    if (entry.action === "probation_override.revoked") return "Temporary override #" + data.override_id + " revoked before its scheduled expiry.";
    return "";
  }

  async function loadAuditLog() {
    if (!orgId || role !== "admin") return;
    if (!auditReview && window.DaedalusAuditReview) {
      auditReview = window.DaedalusAuditReview.create({organizationId:orgId,summary:auditEventSummary,
        fetch:function (url,options) {return fetch(url,options);}});
      window.daedalusAuditHistory = auditReview;
    }
    if (auditReview) return auditReview.load();
  }

  function notificationReviewLabel(tab) {
    var labels = {
      dns: "Review DNS",
      web: "Review website",
      meraki: "Review Meraki",
      cis: "Review CIS",
      scanners: "Review scanners",
      reports: "Review report history",
      members: "Review access",
      overview: "Review workspace access"
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

  function renderNotifications(state, committed) {
    var list = document.getElementById("notification-list");
    var status = document.getElementById("notification-inbox-status");
    var filter = document.getElementById("notification-filter");
    var unreadOnly = filter && filter.value === "unread";
    var older = document.getElementById("notification-older");
    if (older) { older.classList.toggle("hidden", !state.body || !state.body.has_more); older.disabled = false; older.setAttribute("aria-disabled", String(state.busy)); }
    var refreshButton = document.getElementById("notification-refresh");
    if (refreshButton) {
      refreshButton.disabled = false;
      refreshButton.setAttribute("aria-disabled", String(state.busy));
      if (older && older.classList.contains("hidden") && document.activeElement === older) refreshButton.focus({ preventScroll: true });
    }
    var summary = state.loaded ? state.body.unread_count + " unread · Showing " + state.rows.length + " of " + state.body.total_count + (unreadOnly ? " unread notices." : " notices.") : "Loading notifications…";
    if (state.error) summary = state.error + (state.loaded ? " Previously loaded notices remain below; refresh to update them." : " Use Refresh notices to retry.");
    else if (state.busy) summary += " Updating…";
    text(status, summary);
    if (!committed) {
      if (state.error && !state.loaded && list) { list.replaceChildren(); appendEmpty(list, "Notification history is unavailable. Refresh to retry."); }
      return;
    }
    if (state.body) {
      var badge = document.getElementById("notification-badge");
      if (badge) { badge.textContent = state.body.unread_count > 99 ? "99+" : String(state.body.unread_count); badge.classList.toggle("hidden", state.body.unread_count < 1); }
    }
    if (!list) return;
    var focused = list.contains(document.activeElement) ? document.activeElement.closest("[data-notification-open]") : null;
    var focusId = focused && focused.dataset.notificationOpen;
    list.replaceChildren();
    state.rows.forEach(function (notice) {
      var row = document.createElement("article");
      row.className = "notification-row" + (notice.read_at ? " is-read" : " is-unread");
      var main = document.createElement("div"); main.className = "notification-main";
      var title = document.createElement("strong"); title.textContent = notice.title;
      var summary = document.createElement("p"); summary.textContent = readableNotificationSummary(notice.summary);
      var time = document.createElement("time"); time.dateTime = notice.detected_at; time.textContent = "Detected " + dateLabel(notice.detected_at);
      var reason = document.createElement("small"); reason.textContent = String(notice.reason || "").replaceAll("_", " ");
      main.append(title, summary, reason);
      var actions = document.createElement("div"); actions.className = "notification-actions"; actions.append(time);
      var open = document.createElement("button"); open.type = "button"; open.className = "button button-secondary";
      open.textContent = notificationReviewLabel(notice.tab);
      open.dataset.notificationOpen = String(notice.id); open.dataset.notificationTab = notice.tab; open.dataset.notificationRead = notice.read_at ? "true" : "false";
      actions.append(open); row.append(main, actions); list.append(row);
    });
    if (!state.rows.length) appendEmpty(list, state.loaded ? (unreadOnly ? "No unread notices for this workspace." : notificationEmptyMessage()) : "Loading notifications…");
    if (focusId) {
      var replacement = Array.from(list.querySelectorAll("[data-notification-open]")).find(function (button) { return button.dataset.notificationOpen === focusId; });
      if (replacement) replacement.focus({ preventScroll: true });
      else if (filter) filter.focus({ preventScroll: true });
    }
  }

  async function loadNotifications() {
    if (!orgId) return;
    if (!notificationHistory) notificationHistory = window.daedalusHistory.create({ url: "/api/notifications", field: "notifications", fetch: function (url, options) { return fetch(url, options); }, changed: renderNotifications });
    var filter = document.getElementById("notification-filter");
    return notificationHistory.refresh({ unread_only: filter && filter.value === "unread" ? "true" : "false" });
  }

  function restoreNotificationFilter() {
    var filter = document.getElementById("notification-filter");
    if (filter) filter.value = new URLSearchParams(window.location.search).get("notices") === "unread" ? "unread" : "all";
  }
  restoreNotificationFilter();
  var notificationFilter = document.getElementById("notification-filter");
  if (notificationFilter) notificationFilter.addEventListener("change", function () {
    var url = new URL(window.location.href);
    if (notificationFilter.value === "unread") url.searchParams.set("notices", "unread");
    else url.searchParams.delete("notices");
    window.history.replaceState(window.history.state, "", url.pathname + url.search + url.hash);
    loadNotifications();
  });
  window.addEventListener("popstate", function () { restoreNotificationFilter(); loadNotifications(); });
  var notificationOlder = document.getElementById("notification-older");
  if (notificationOlder) notificationOlder.addEventListener("click", function () { if (notificationHistory) notificationHistory.older(); });
  var notificationRefresh = document.getElementById("notification-refresh");
  if (notificationRefresh) notificationRefresh.addEventListener("click", function () { if (!notificationHistory || !notificationHistory.state.busy) loadNotifications(); });

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
  });

  if (orgId) {
    refresh();
    // Heartbeat status expires on the server even when the live stream is quiet.
    window.setInterval(function () { if (!document.hidden) { refresh(); if (activeTab === "web") { loadActiveExposure(undefined, true); loadNikto(undefined, true); } if (activeTab === "cis") loadCIS(true); if (activeTab === "meraki") loadMerakiStatus(true); } }, 15000);
    document.addEventListener("visibilitychange", function () { if (!document.hidden) { refresh(); if (activeTab === "web") { loadActiveExposure(undefined, true); loadNikto(undefined, true); } if (activeTab === "cis") loadCIS(true); if (activeTab === "meraki") loadMerakiStatus(true); } });
  }
  loadWorkspaces();
  loadMemberships(true);
  loadAuditLog();
  loadNotifications();
})();
