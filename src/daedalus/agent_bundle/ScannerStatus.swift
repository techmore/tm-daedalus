import Cocoa
import WebKit

final class StatusApp: NSObject, NSApplicationDelegate, NSMenuDelegate, URLSessionTaskDelegate, WKNavigationDelegate, WKUIDelegate {
    var item: NSStatusItem!
    let menu = NSMenu()
    var engine = "NmapUI: checking…"
    var portal = "Daedalus: checking…"
    var activity = "Scan activity: checking…"
    var recent: [String] = []
    var lastRequest = "Last scan request: checking…"
    var running = false
    var scanning = false
    var working = false
    var localURL: URL?
    var portalURL: URL?
    var token = ""
    var agentID = 0
    var lastPortalPoll = Date.distantPast
    var timer: Timer?
    var rows: [NSMenuItem] = []
    var scannerWindow: NSWindow?
    var scannerWebView: WKWebView?
    var scannerPageLoaded = false
    var scannerPageMessage = ""
    let windowHistory = NSTextField(wrappingLabelWithString: "Managed scan history is loading…")
    let windowBody = NSStackView()
    let windowHistoryPanel = NSStackView()
    let windowHistoryScroll = NSScrollView()
    let hostedReportPanel = NSStackView()
    let hostedReportStatus = NSTextField(wrappingLabelWithString: "")
    var hostedReportFingerprint = ""
    let windowHistoryButton = NSButton(title: "Recent scans", target: nil, action: nil)
    let windowStatus = NSTextField(wrappingLabelWithString: "Connecting to scanner…")
    lazy var session = URLSession(configuration: .ephemeral, delegate: self, delegateQueue: nil)

    func applicationDidFinishLaunching(_ notification: Notification) {
        let configURL = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/Daedalus/managed-agent.json")
        if let data = try? Data(contentsOf: configURL), let config = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            if let address = config["nmapui_url"] as? String, let url = URL(string: address),
               ["http", "https"].contains(url.scheme ?? ""), ["127.0.0.1", "localhost", "[::1]"].contains(url.host ?? ""),
               url.user == nil, url.password == nil, url.query == nil { localURL = url }
            if let address = config["server"] as? String, let url = URL(string: address),
               url.scheme == "https", url.user == nil, url.password == nil, url.query == nil { portalURL = url }
            token = config["agent_token"] as? String ?? ""
            agentID = config["agent_id"] as? Int ?? 0
        }
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        menu.delegate = self
        for _ in 0..<11 { let row = NSMenuItem(title: "", action: nil, keyEquivalent: ""); menu.addItem(row); rows.append(row) }
        menu.addItem(.separator())
        addAction("Open scanner window", #selector(openLocal))
        addAction("Open scanner in browser", #selector(openBrowser))
        addAction("Open Daedalus scan history", #selector(openPortal))
        addAction("Refresh status", #selector(refresh))
        menu.addItem(.separator())
        addAction("Quit status indicator (scanner keeps running)", #selector(quit))
        item.menu = menu
        installMainMenu()
        render()
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in self?.refresh() }
        if let timer = timer { RunLoop.main.add(timer, forMode: .common) }
        refresh()
        if !CommandLine.arguments.contains("--background") { openLocal() }
    }
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool { openLocal(); return true }
    func installMainMenu() {
        let bar = NSMenu()
        let application = NSMenu(); let appItem = NSMenuItem(); appItem.submenu = application; bar.addItem(appItem)
        application.addItem(withTitle: "Open scanner", action: #selector(openLocal), keyEquivalent: "n").target = self
        application.addItem(.separator())
        application.addItem(withTitle: "Quit Daedalus Scanner", action: #selector(quit), keyEquivalent: "q").target = self
        let edit = NSMenu(title: "Edit"); let editItem = NSMenuItem(title: "Edit", action: nil, keyEquivalent: ""); editItem.submenu = edit; bar.addItem(editItem)
        for (title, selector, key) in [("Undo", "undo:", "z"), ("Cut", "cut:", "x"), ("Copy", "copy:", "c"), ("Paste", "paste:", "v"), ("Select All", "selectAll:", "a")] {
            edit.addItem(withTitle: title, action: Selector(selector), keyEquivalent: key)
        }
        let view = NSMenu(title: "View"); let viewItem = NSMenuItem(title: "View", action: nil, keyEquivalent: ""); viewItem.submenu = view; bar.addItem(viewItem)
        view.addItem(withTitle: "Reload scanner", action: #selector(reloadScanner), keyEquivalent: "r").target = self
        NSApp.mainMenu = bar
    }
    func addAction(_ title: String, _ action: Selector) { let row = NSMenuItem(title: title, action: action, keyEquivalent: ""); row.target = self; menu.addItem(row) }
    func menuWillOpen(_ menu: NSMenu) { refresh() }
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
    func get(_ url: URL, authenticated: Bool = false, done: @escaping ([String: Any]?) -> Void) {
        var request = URLRequest(url: url); request.timeoutInterval = 3; request.cachePolicy = .reloadIgnoringLocalCacheData
        if authenticated { request.setValue("Bearer " + token, forHTTPHeaderField: "Authorization") }
        session.dataTask(with: request) { data, response, _ in
            let ok = (response as? HTTPURLResponse)?.statusCode == 200
            let object = ok && (data?.count ?? 0) < 1_000_000 ? data.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] } : nil
            DispatchQueue.main.async { done(object) }
        }.resume()
    }
    @objc func refresh() {
        if let localURL = localURL {
            get(localURL.appendingPathComponent("api/runtime/status")) { [weak self] data in
                guard let self = self else { return }
                self.running = data != nil
                self.engine = data != nil ? "NmapUI: running" : "NmapUI: unavailable"
                let jobs = data?["active_jobs"] as? [[String: Any]] ?? []
                self.working = !jobs.isEmpty
                self.scanning = jobs.contains { $0["job_type"] as? String == "scan" }
                if let job = jobs.first {
                    let details = job["details"] as? [String: Any] ?? [:]
                    let target = details["target"] as? String ?? ""
                    let progress = (details["progress"] as? NSNumber).map { " · \($0.intValue)%" } ?? ""
                    self.activity = "Active: \(job["job_type"] as? String ?? "scan") \(target)\(progress)"
                } else { self.activity = data != nil ? "Scan activity: idle" : "Scan activity: unknown" }
                self.render()
            }
        } else { engine = "NmapUI: configuration unavailable"; activity = "Scan activity: unknown" }
        if let portalURL = portalURL, agentID > 0, !token.isEmpty {
            if Date().timeIntervalSince(lastPortalPoll) < 15 { return }
            lastPortalPoll = Date()
            get(portalURL.appendingPathComponent("api/agents/\(agentID)/client-status"), authenticated: true) { [weak self] data in
                guard let self = self else { return }
                if let data = data {
                    self.portal = (data["bridge_online"] as? Bool == true) ? "Daedalus bridge: connected" : "Daedalus bridge: offline"
                    if let request = data["last_scan_request"] as? [String: Any] {
                        let detail = request["status"] as? String == "failed" ? " · " + (request["result"] as? String ?? "") : ""
                        self.lastRequest = "Last request: \(request["status"] as? String ?? "unknown") · \(request["target"] as? String ?? "")\(detail)"
                    } else { self.lastRequest = "No scan requests recorded" }
                    self.renderHostedReports(data["hosted_reports"] as? [[String: Any]] ?? [])
                    self.recent = (data["recent_runs"] as? [[String: Any]] ?? []).prefix(5).map { run in
                        let status = run["status"] as? String ?? "unknown"
                        let time = self.dateLabel(run["last_occurred_at"] as? String)
                        return "\(status) · \(run["reported_target"] as? String ?? "target unknown") · \(time)"
                    }
                } else { self.portal = "Daedalus: unreachable or access unavailable" }
                self.render()
            }
        } else { portal = "Daedalus: enrollment unavailable" }
        render()
    }
    func dateLabel(_ text: String?) -> String {
        guard let text = text else { return "time unknown" }
        let parser = ISO8601DateFormatter(); parser.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        guard let date = parser.date(from: text) ?? ISO8601DateFormatter().date(from: text) else { return "time unknown" }
        let formatter = DateFormatter(); formatter.dateStyle = .short; formatter.timeStyle = .short; return formatter.string(from: date)
    }
    func render() {
        let values = ["Daedalus Scanner", engine, portal, activity, lastRequest, portal.contains("unreachable") ? "Recent saved runs (cached)" : "Recent saved runs"] + (recent.isEmpty ? ["No saved runs available"] : recent)
        for (index, row) in rows.enumerated() {
            row.isHidden = index >= values.count
            if index < values.count { row.title = String(values[index].filter { !$0.isNewline }.prefix(180)); row.attributedTitle = NSAttributedString(string: row.title, attributes: [.foregroundColor: NSColor.labelColor]); row.isEnabled = false }
        }
        let observation: [String: Any] = ["engine": engine, "portal": portal, "activity": activity, "recent": recent, "last_request": lastRequest, "observed_at": ISO8601DateFormatter().string(from: Date()), "scanner_window_open": scannerWindow?.isVisible ?? false, "scanner_page_loaded": scannerPageLoaded, "scanner_page_message": scannerPageMessage]
        let file = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/Daedalus/scanner-status-observation.json")
        if let data = try? JSONSerialization.data(withJSONObject: observation) {
            try? data.write(to: file, options: .atomic)
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        }
        item.button?.title = scanning ? " Scanning" : (working ? " Working" : " Nmap")
        item.button?.image = NSImage(systemSymbolName: running ? (scanning ? "waveform.path.ecg" : "checkmark.shield") : "exclamationmark.shield", accessibilityDescription: "Scanner status")
        windowHistory.stringValue = "Managed scan history (Daedalus)\n" + (recent.isEmpty ? "No saved runs reported yet." : recent.joined(separator: "\n"))
        windowStatus.stringValue = "\(engine)   ·   \(portal)\n\(activity)" + (scannerPageMessage.isEmpty ? "" : "\n" + scannerPageMessage)
        item.button?.toolTip = "\(engine)\n\(portal)\n\(activity)"
    }
    @objc func openLocal() {
        guard let url = localURL else { return }
        if scannerWindow == nil {
            let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1200, height: 800), styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
            window.title = "Daedalus Scanner"
            window.minSize = NSSize(width: 900, height: 600)
            window.isReleasedWhenClosed = false
            let root = NSView(); window.contentView = root
            let configuration = WKWebViewConfiguration()
            // The web UI receives no portal enrollment token or native script bridge.
            let web = WKWebView(frame: .zero, configuration: configuration)
            web.navigationDelegate = self; web.uiDelegate = self
            let reload = NSButton(title: "Reload", target: self, action: #selector(reloadScanner))
            let browser = NSButton(title: "Open in browser", target: self, action: #selector(openBrowser))
            let history = NSButton(title: "Daedalus history", target: self, action: #selector(openPortal))
            windowHistoryButton.target = self; windowHistoryButton.action = #selector(toggleRecent)
            let controls = NSStackView(views: [reload, windowHistoryButton, browser, history]); controls.spacing = 8
            windowBody.orientation = .vertical; windowBody.alignment = .leading; windowBody.spacing = 0
            windowHistoryPanel.orientation = .vertical; windowHistoryPanel.alignment = .leading
            windowHistoryPanel.edgeInsets = NSEdgeInsets(top: 12, left: 16, bottom: 12, right: 16)
            windowHistoryPanel.addArrangedSubview(windowHistory)
            hostedReportPanel.orientation = .vertical; hostedReportPanel.alignment = .leading; hostedReportPanel.spacing = 6
            windowHistoryPanel.addArrangedSubview(hostedReportPanel)
            windowHistoryPanel.addArrangedSubview(hostedReportStatus)
            windowHistoryScroll.hasVerticalScroller = true
            windowHistoryScroll.drawsBackground = false
            windowHistoryPanel.translatesAutoresizingMaskIntoConstraints = false
            windowHistoryScroll.documentView = windowHistoryPanel
            windowHistoryScroll.isHidden = true
            windowBody.addArrangedSubview(windowHistoryScroll); windowBody.addArrangedSubview(web)
            for view in [windowStatus, controls, windowBody] { view.translatesAutoresizingMaskIntoConstraints = false; root.addSubview(view) }
            NSLayoutConstraint.activate([
                windowStatus.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 16),
                windowStatus.topAnchor.constraint(equalTo: root.topAnchor, constant: 12),
                windowStatus.trailingAnchor.constraint(lessThanOrEqualTo: controls.leadingAnchor, constant: -12),
                controls.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -16),
                controls.centerYAnchor.constraint(equalTo: windowStatus.centerYAnchor),
                windowBody.leadingAnchor.constraint(equalTo: root.leadingAnchor), windowBody.trailingAnchor.constraint(equalTo: root.trailingAnchor),
                windowBody.topAnchor.constraint(equalTo: windowStatus.bottomAnchor, constant: 12), windowBody.bottomAnchor.constraint(equalTo: root.bottomAnchor),
                web.widthAnchor.constraint(equalTo: windowBody.widthAnchor),
                windowHistoryScroll.widthAnchor.constraint(equalTo: windowBody.widthAnchor),
                windowHistoryScroll.heightAnchor.constraint(equalToConstant: 220),
                windowHistoryPanel.leadingAnchor.constraint(equalTo: windowHistoryScroll.contentView.leadingAnchor),
                windowHistoryPanel.topAnchor.constraint(equalTo: windowHistoryScroll.contentView.topAnchor),
                windowHistoryPanel.widthAnchor.constraint(equalTo: windowHistoryScroll.contentView.widthAnchor),
                web.heightAnchor.constraint(greaterThanOrEqualToConstant: 200)
            ])
            scannerWindow = window; scannerWebView = web
            web.load(URLRequest(url: url)); window.center()
        }
        NSApp.setActivationPolicy(.regular)
        scannerWindow?.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true)
    }
    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        scannerPageLoaded = true; scannerPageMessage = ""; render()
    }
    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        scannerPageLoaded = false
        scannerPageMessage = "Scanner page unavailable. Check NmapUI status, then choose Reload."
        render()
    }
    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        scannerPageLoaded = false
        scannerPageMessage = "Scanner page could not finish loading. Choose Reload to retry."
        render()
    }
    func renderHostedReports(_ reports: [[String: Any]]) {
        let fingerprint = reports.map { "\($0["id"] ?? ""):\($0["status"] ?? ""):\($0["progress"] ?? "")" }.joined(separator: "|") + ":loaded"
        guard fingerprint != hostedReportFingerprint else { return }
        hostedReportFingerprint = fingerprint
        for view in hostedReportPanel.arrangedSubviews { hostedReportPanel.removeArrangedSubview(view); view.removeFromSuperview() }
        let title = NSTextField(labelWithString: "Hosted scanner PDFs"); hostedReportPanel.addArrangedSubview(title)
        if reports.isEmpty { hostedReportPanel.addArrangedSubview(NSTextField(labelWithString: "No hosted PDFs reported for this scanner.")) }
        for report in reports.prefix(5) {
            guard let id = report["id"] as? Int, id > 0 else { continue }
            let status = report["status"] as? String ?? "unknown"
            if status == "completed" {
                let button = NSButton(title: "Open PDF #\(id) · \(dateLabel(report["created_at"] as? String))", target: self, action: #selector(openHostedPDF(_:)))
                button.tag = id; hostedReportPanel.addArrangedSubview(button)
            } else {
                let progress = (report["progress"] as? Int).map { " · \($0)%" } ?? ""
                hostedReportPanel.addArrangedSubview(NSTextField(labelWithString: "PDF #\(id): \(status)\(progress)"))
            }
        }
    }
    @objc func openHostedPDF(_ sender: NSButton) {
        guard let portalURL = portalURL, agentID > 0, sender.tag > 0, !token.isEmpty else { return }
        let reportID = sender.tag
        var request = URLRequest(url: portalURL.appendingPathComponent("api/agents/\(agentID)/reports/\(reportID)/download"))
        request.timeoutInterval = 30; request.setValue("Bearer " + token, forHTTPHeaderField: "Authorization")
        hostedReportStatus.stringValue = "Downloading PDF #\(reportID)…"; sender.isEnabled = false
        session.dataTask(with: request) { [weak self] data, response, _ in
            DispatchQueue.main.async {
                guard let self = self else { return }
                sender.isEnabled = true
                guard let response = response as? HTTPURLResponse, response.statusCode == 200,
                      response.mimeType == "application/pdf", let data = data, data.count <= 64 * 1024 * 1024,
                      data.starts(with: Data("%PDF-".utf8)) else {
                    self.hostedReportStatus.stringValue = "PDF #\(reportID) could not be downloaded. Retry or open Daedalus history."; return
                }
                do {
                    let directory = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/Daedalus/hosted-reports")
                    let file = directory.appendingPathComponent("scanner-\(self.agentID)-report-\(reportID).pdf")
                    for path in [directory, file] {
                        if (try? FileManager.default.attributesOfItem(atPath: path.path)[.type] as? FileAttributeType) == .typeSymbolicLink {
                            throw NSError(domain: "Daedalus", code: 1)
                        }
                    }
                    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
                    try data.write(to: file, options: .atomic)
                    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
                    self.hostedReportStatus.stringValue = "PDF #\(reportID) saved locally."
                    NSWorkspace.shared.open(file)
                } catch { self.hostedReportStatus.stringValue = "PDF #\(reportID) could not be saved locally." }
            }
        }.resume()
    }
    @objc func toggleRecent() {
        windowHistoryScroll.isHidden.toggle()
        windowHistoryButton.title = windowHistoryScroll.isHidden ? "Recent scans" : "Hide recent scans"
    }
    @objc func reloadScanner() {
        if let url = scannerWebView?.url, sameScannerOrigin(url) { scannerWebView?.reload() }
        else if let url = localURL { scannerWebView?.load(URLRequest(url: url)) }
    }
    @objc func openBrowser() { if let url = localURL { NSWorkspace.shared.open(url) } }
    func sameScannerOrigin(_ url: URL) -> Bool {
        guard let local = localURL else { return false }
        return url.scheme == local.scheme && url.host == local.host && url.port == local.port && url.user == nil && url.password == nil
    }
    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        guard let url = navigationAction.request.url else { decisionHandler(.cancel); return }
        if sameScannerOrigin(url) { decisionHandler(.allow); return }
        // Keep external pages out of the trusted local scanner window.
        if navigationAction.navigationType == .linkActivated && ["http", "https"].contains(url.scheme ?? "") { NSWorkspace.shared.open(url) }
        decisionHandler(.cancel)
    }
    func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration, for navigationAction: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
        if let url = navigationAction.request.url, ["http", "https"].contains(url.scheme ?? "") { NSWorkspace.shared.open(url) }
        return nil
    }
    @objc func openPortal() { if let url = portalURL { NSWorkspace.shared.open(URL(string: url.absoluteString + "/dashboard#scanners")!) } }
    @objc func quit() { NSApp.terminate(nil) }
}
let app = NSApplication.shared
let delegate = StatusApp()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
