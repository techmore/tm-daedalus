import Cocoa

final class StatusApp: NSObject, NSApplicationDelegate, NSMenuDelegate, URLSessionTaskDelegate {
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
        addAction("Open local scanner", #selector(openLocal))
        addAction("Open Daedalus scan history", #selector(openPortal))
        addAction("Refresh status", #selector(refresh))
        menu.addItem(.separator())
        addAction("Quit status indicator (scanner keeps running)", #selector(quit))
        item.menu = menu
        render()
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in self?.refresh() }
        if let timer = timer { RunLoop.main.add(timer, forMode: .common) }
        refresh()
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
        let observation: [String: Any] = ["engine": engine, "portal": portal, "activity": activity, "recent": recent, "last_request": lastRequest, "observed_at": ISO8601DateFormatter().string(from: Date())]
        let file = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/Daedalus/scanner-status-observation.json")
        if let data = try? JSONSerialization.data(withJSONObject: observation) {
            try? data.write(to: file, options: .atomic)
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        }
        item.button?.title = scanning ? " Scanning" : (working ? " Working" : " Nmap")
        item.button?.image = NSImage(systemSymbolName: running ? (scanning ? "waveform.path.ecg" : "checkmark.shield") : "exclamationmark.shield", accessibilityDescription: "Scanner status")
        item.button?.toolTip = "\(engine)\n\(portal)\n\(activity)"
    }
    @objc func openLocal() { if let url = localURL { NSWorkspace.shared.open(url) } }
    @objc func openPortal() { if let url = portalURL { NSWorkspace.shared.open(URL(string: url.absoluteString + "/dashboard#scanners")!) } }
    @objc func quit() { NSApp.terminate(nil) }
}
let app = NSApplication.shared
let delegate = StatusApp()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
