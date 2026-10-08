import Foundation
import AppKit
import UniformTypeIdentifiers
import ServiceManagement

class MenuBarManager: NSObject, NSMenuItemValidation {
    private var statusItem: NSStatusItem?
    private var menu: NSMenu?
    private var runState: CISRunState = .idle
    private var lastRunDate: Date?
    private var resultsSummary: ReportSummary?
    private var config: Config?
    private var configMessage: String?
    private var loginItemMessage: String?
    
    // Singleton instance
    static let shared = MenuBarManager()
    
    private override init() {
        super.init()
        config = Config.load()
        setupStatusItem()
    }
    
    private func setupStatusItem() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        
        if let button = statusItem?.button {
            button.image = NSImage(systemSymbolName: "checklist", accessibilityDescription: "CIS Compliance")
            button.title = ""
        }
        
        menu = NSMenu()
        menu?.delegate = self
        statusItem?.menu = menu
        
        updateMenu()
    }
    
    func updateRunState(_ state: CISRunState) {
        runState = state
        updateMenu()
    }

    func validateMenuItem(_ menuItem: NSMenuItem) -> Bool {
        if menuItem.action == #selector(runChecks) || menuItem.action == #selector(importDaedalusConfig) {
            return runState.allowsNewRun
        }
        return true
    }

    func updateWithResults(summary: ReportSummary, config: Config) {
        self.resultsSummary = summary
        self.lastRunDate = Date()
        self.config = config
        updateMenu()
    }
    
    private func updateMenu() {
        guard let menu = menu else { return }
        
        menu.removeAllItems()
        
        // Dummy action that does nothing
        let dummySelector = #selector(doNothing)
        
        // App title
        let titleItem = NSMenuItem(title: "CSP - CIS Compliance", action: dummySelector, keyEquivalent: "")
        titleItem.target = self
        menu.addItem(titleItem)
        menu.addItem(NSMenuItem.separator())
        menu.addItem(NSMenuItem(title: runState.label, action: nil, keyEquivalent: ""))
        if let config {
            menu.addItem(NSMenuItem(title: "Workspace: " + (config.reporting.domain.isEmpty ? "not configured" : config.reporting.domain), action: nil, keyEquivalent: ""))
            let profilesEndpoint = DaedalusProfileClient.profileEndpoint(configuredEndpoint: config.reporting.profilesEndpoint, reportEndpoint: config.reporting.endpoint)
            let selected = config.reporting.profileSlug.isEmpty
                ? (profilesEndpoint == nil ? "Bundled CSP checklist (local)" : "Newest compatible profile")
                : config.reporting.profileSlug
            menu.addItem(NSMenuItem(title: "Profile: " + selected, action: nil, keyEquivalent: ""))
        }
        if let summary = resultsSummary {
            menu.addItem(NSMenuItem(title: summary.assessmentCoverageLabel, action: nil, keyEquivalent: ""))
            menu.addItem(NSMenuItem(title: "Manual and error results are unassessed; pass rate uses all checks.", action: nil, keyEquivalent: ""))
            menu.addItem(NSMenuItem.separator())
        }

        let importConfigItem = NSMenuItem(
            title: "Import Daedalus client config…",
            action: #selector(importDaedalusConfig),
            keyEquivalent: ""
        )
        importConfigItem.target = self
        menu.addItem(importConfigItem)
        if let configMessage {
            let messageItem = NSMenuItem(title: configMessage, action: dummySelector, keyEquivalent: "")
            messageItem.target = self
            menu.addItem(messageItem)
        }
        menu.addItem(NSMenuItem.separator())

        let loginService = SMAppService.mainApp
        let loginStatus: String
        switch loginService.status {
        case .enabled: loginStatus = "Launch at login: enabled"
        case .requiresApproval: loginStatus = "Launch at login: approval required"
        case .notRegistered: loginStatus = "Launch at login: off"
        case .notFound: loginStatus = "Launch at login: app unavailable"
        @unknown default: loginStatus = "Launch at login: unknown status"
        }
        menu.addItem(NSMenuItem(title: loginStatus, action: nil, keyEquivalent: ""))
        let isRegistered = loginService.status == .enabled || loginService.status == .requiresApproval
        let loginItem = NSMenuItem(
            title: isRegistered ? "Disable Launch at Login" : "Enable Launch at Login",
            action: #selector(toggleLaunchAtLogin), keyEquivalent: ""
        )
        loginItem.target = self
        loginItem.state = loginService.status == .enabled ? .on : (loginService.status == .requiresApproval ? .mixed : .off)
        menu.addItem(loginItem)
        let settingsItem = NSMenuItem(title: "Open Login Items Settings…", action: #selector(openLoginItemsSettings), keyEquivalent: "")
        settingsItem.target = self
        menu.addItem(settingsItem)
        if let loginItemMessage {
            menu.addItem(NSMenuItem(title: loginItemMessage, action: nil, keyEquivalent: ""))
        }
        menu.addItem(NSMenuItem.separator())
        
        // Last run date
        if let lastRunDate = lastRunDate {
            let dateFormatter = DateFormatter()
            dateFormatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
            let dateString = dateFormatter.string(from: lastRunDate)
            
            let lastRunItem = NSMenuItem(title: "Last Run: \(dateString)", action: dummySelector, keyEquivalent: "")
            lastRunItem.target = self
            menu.addItem(lastRunItem)
            menu.addItem(NSMenuItem.separator())
        }
        
        // Results summary
        if let summary = resultsSummary {
            // Title for results section
            let resultsTitle = NSMenuItem(title: "RESULTS SUMMARY", action: dummySelector, keyEquivalent: "")
            resultsTitle.target = self
            menu.addItem(resultsTitle)
            
            // Total checks
            let totalItem = NSMenuItem(title: "Total checks run: \(summary.totalChecks)", action: dummySelector, keyEquivalent: "")
            totalItem.target = self
            menu.addItem(totalItem)
            
            // Passed checks
            let passedItem = NSMenuItem(title: "Passed: \(summary.passedChecks) (\(ReportSummary.percentageLabel(count: summary.passedChecks, total: summary.totalChecks)))", action: dummySelector, keyEquivalent: "")
            passedItem.target = self
            menu.addItem(passedItem)
            
            // Failed checks
            let failedItem = NSMenuItem(title: "Failed: \(summary.failedChecks) (\(ReportSummary.percentageLabel(count: summary.failedChecks, total: summary.totalChecks)))", action: dummySelector, keyEquivalent: "")
            failedItem.target = self
            menu.addItem(failedItem)
            
            // Manual checks
            let manualItem = NSMenuItem(title: "Manual: \(summary.manualChecks) (\(ReportSummary.percentageLabel(count: summary.manualChecks, total: summary.totalChecks)))", action: dummySelector, keyEquivalent: "")
            manualItem.target = self
            menu.addItem(manualItem)
            
            // Error checks
            let errorItem = NSMenuItem(title: "Errors: \(summary.errorChecks) (\(ReportSummary.percentageLabel(count: summary.errorChecks, total: summary.totalChecks)))", action: dummySelector, keyEquivalent: "")
            errorItem.target = self
            menu.addItem(errorItem)
            
            // Overall compliance score
            let scoreItem = NSMenuItem(title: "Pass rate across all checks: \(ReportSummary.percentageLabel(count: summary.passedChecks, total: summary.totalChecks))", action: dummySelector, keyEquivalent: "")
            scoreItem.target = self
            menu.addItem(scoreItem)
            menu.addItem(NSMenuItem.separator())
            
            // Category summaries
            let categoryTitle = NSMenuItem(title: "CATEGORY SUMMARIES", action: dummySelector, keyEquivalent: "")
            categoryTitle.target = self
            menu.addItem(categoryTitle)
            
            // macOS
            let macOSItem = NSMenuItem(title: "macOS: \(ReportSummary.percentageLabel(count: summary.macOSChecks.passed, total: summary.macOSChecks.total)) (\(summary.macOSChecks.passed)/\(summary.macOSChecks.total) passed)", action: dummySelector, keyEquivalent: "")
            macOSItem.target = self
            menu.addItem(macOSItem)
            
            // Chrome
            let chromeItem = NSMenuItem(title: "Chrome: \(ReportSummary.percentageLabel(count: summary.chromeChecks.passed, total: summary.chromeChecks.total)) (\(summary.chromeChecks.passed)/\(summary.chromeChecks.total) passed)", action: dummySelector, keyEquivalent: "")
            chromeItem.target = self
            menu.addItem(chromeItem)
            
            // Safari
            let safariItem = NSMenuItem(title: "Safari: \(ReportSummary.percentageLabel(count: summary.safariChecks.passed, total: summary.safariChecks.total)) (\(summary.safariChecks.passed)/\(summary.safariChecks.total) passed)", action: dummySelector, keyEquivalent: "")
            safariItem.target = self
            menu.addItem(safariItem)
            menu.addItem(NSMenuItem.separator())
        }
        
        // Send to server button
        if let config = config {
            let sendItem = NSMenuItem(title: "Retry saved reports", action: #selector(sendToServer), keyEquivalent: "")
            sendItem.target = self
            menu.addItem(sendItem)
            
            // Show server info
            let serverItem = NSMenuItem(title: "Server: \(config.reporting.endpoint)", action: nil, keyEquivalent: "")
            menu.addItem(serverItem)
            menu.addItem(NSMenuItem.separator())
        }
        
        // Run checks button
        let runItem = NSMenuItem(title: "Run Checks", action: #selector(runChecks), keyEquivalent: "r")
        runItem.target = self
        menu.addItem(runItem)
        
        // Quit button
        let quitItem = NSMenuItem(title: "Quit", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        menu.addItem(quitItem)
        
        // Update status item button to show compliance score if available
        if let button = statusItem?.button, let summary = resultsSummary {
            let score = Int(summary.complianceScore)
            let scoreColor = summary.totalChecks > 0 && (summary.passedChecks > 0 || summary.failedChecks > 0)
                ? getColorForScore(summary.complianceScore) : NSColor.secondaryLabelColor
            
            // Create a colored circle with the score inside
            let image = createScoreImage(score: score, color: scoreColor)
            button.image = image
        }
    }
    
    private func getColorForScore(_ score: Double) -> NSColor {
        if score >= 80 {
            return NSColor.systemGreen
        } else if score >= 60 {
            return NSColor.systemYellow
        } else if score >= 40 {
            return NSColor.systemOrange
        } else {
            return NSColor.systemRed
        }
    }
    
    private func createScoreImage(score: Int, color: NSColor) -> NSImage {
        let size = NSSize(width: 22, height: 22)
        let image = NSImage(size: size)
        
        image.lockFocus()
        
        // Draw circle
        let circlePath = NSBezierPath(ovalIn: NSRect(x: 1, y: 1, width: 20, height: 20))
        color.setFill()
        circlePath.fill()
        
        // Draw "CSP" text instead of score
        let text = "CSP"
        let font = NSFont.boldSystemFont(ofSize: 10)
        let attributes: [NSAttributedString.Key: Any] = [
            .font: font,
            .foregroundColor: NSColor.white
        ]
        
        let stringSize = text.size(withAttributes: attributes)
        let stringRect = NSRect(
            x: (size.width - stringSize.width) / 2,
            y: (size.height - stringSize.height) / 2,
            width: stringSize.width,
            height: stringSize.height
        )
        
        text.draw(in: stringRect, withAttributes: attributes)
        
        image.unlockFocus()
        return image
    }

    @objc private func importDaedalusConfig() {
        let panel = NSOpenPanel()
        panel.title = "Choose the Daedalus CIS client config"
        panel.prompt = "Import Config"
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.allowedContentTypes = [
            UTType(filenameExtension: "yaml") ?? .plainText,
            UTType(filenameExtension: "yml") ?? .plainText,
        ]
        panel.begin { [weak self] response in
            guard response == .OK, let sourceURL = panel.url else { return }
            guard self?.runState.allowsNewRun == true else {
                self?.configMessage = "Wait for the current assessment before importing a config"
                self?.updateMenu()
                return
            }
            let hasScopedAccess = sourceURL.startAccessingSecurityScopedResource()
            defer {
                if hasScopedAccess {
                    sourceURL.stopAccessingSecurityScopedResource()
                }
            }

            do {
                let yamlString = try String(contentsOf: sourceURL, encoding: .utf8)
                let importedConfig = Config.parse(yamlString: yamlString)
                guard importedConfig.reporting.apiKey.count >= 16,
                      Config.isAllowedReportingEndpoint(importedConfig.reporting.endpoint) else {
                    throw ConfigImportError.invalidConfig
                }

                let supportDirectory = CISClientPaths.applicationSupportDirectory
                try CISClientPaths.ensurePrivateDirectory(supportDirectory)
                let destinationURL = supportDirectory.appendingPathComponent("cis-client.yaml")
                try Data(yamlString.utf8).write(to: destinationURL, options: .atomic)
                try FileManager.default.setAttributes(
                    [.posixPermissions: 0o600],
                    ofItemAtPath: destinationURL.path
                )

                DispatchQueue.main.async {
                    self?.config = importedConfig
                    self?.runState = .idle
                    // Results from the prior workspace/profile must not be
                    // shown under the newly imported configuration.
                    self?.resultsSummary = nil
                    self?.lastRunDate = nil
                    self?.configMessage = "Private client config imported"
                    self?.updateMenu()
                }
            } catch {
                DispatchQueue.main.async {
                    self?.configMessage = "Config import failed; check the downloaded file"
                    self?.updateMenu()
                }
            }
        }
    }

    private enum ConfigImportError: Error {
        case invalidConfig
    }
    
    @objc private func toggleLaunchAtLogin() {
        do {
            let service = SMAppService.mainApp
            switch service.status {
            case .enabled, .requiresApproval:
                try service.unregister()
                loginItemMessage = "Launch at login disabled"
            case .notRegistered, .notFound:
                try service.register()
                loginItemMessage = service.status == .requiresApproval
                    ? "Approve CSP in Login Items Settings"
                    : "Launch at login requested"
            @unknown default:
                loginItemMessage = "Review launch settings in System Settings"
            }
        } catch {
            loginItemMessage = "Could not change launch at login"
            let alert = NSAlert()
            alert.messageText = "Launch at login could not be changed"
            alert.informativeText = "Install CSP CIS in Applications, then try again. System Settings may need your approval. \(error.localizedDescription)"
            alert.addButton(withTitle: "OK")
            alert.runModal()
        }
        updateMenu()
    }

    @objc private func openLoginItemsSettings() {
        SMAppService.openSystemSettingsLoginItems()
    }

    @objc private func sendToServer() {
        guard let config else { return }
        DispatchQueue.global(qos: .utility).async {
            CISApp.retryPendingReports(config: config)
        }
    }

    @objc private func runChecks() {
        guard let app = NSApp.delegate as? CISApp else { return }
        DispatchQueue.global(qos: .userInitiated).async {
            app.runChecks()
        }
    }
    
    @objc private func doNothing() {
        // This is a dummy method that does nothing
        // It's used to keep menu items from being grayed out
    }
}

extension MenuBarManager: NSMenuDelegate {
    func menuWillOpen(_ menu: NSMenu) {
        // Reflect approval changes made in System Settings whenever opened.
        updateMenu()
        // Refresh data when menu opens
        if resultsSummary == nil {
            // Try to load the latest report
            let fileManager = FileManager.default
            
            do {
                let reportsDirectory = try CISClientPaths.reportsDirectory()
                let reportFiles = try fileManager.contentsOfDirectory(atPath: reportsDirectory.path)
                    .filter { $0.hasSuffix(".json") }
                    .sorted(by: >)  // Sort in descending order to get the latest file first
                
                if let latestReport = reportFiles.first {
                    let reportPath = reportsDirectory.appendingPathComponent(latestReport)
                    
                    if let reportData = try? Data(contentsOf: reportPath) {
                        if let jsonObject = try? JSONSerialization.jsonObject(with: reportData) as? [String: Any],
                           let summaryDict = jsonObject["compliance_summary"] as? [String: Any] {
                            
                            // Extract summary data
                            let totalChecks = summaryDict["total_checks"] as? Int ?? 0
                            let passedChecks = summaryDict["passed_checks"] as? Int ?? 0
                            let failedChecks = summaryDict["failed_checks"] as? Int ?? 0
                            let manualChecks = summaryDict["manual_checks"] as? Int ?? 0
                            let errorChecks = summaryDict["error_checks"] as? Int ?? 0
                            let complianceScore = summaryDict["overall_compliance_score"] as? Double ?? 0.0
                            
                            // Extract category summaries
                            let categoryScores = summaryDict["category_scores"] as? [String: [String: Any]] ?? [:]
                            
                            let macOSDict = categoryScores["macos"] ?? [:]
                            let chromeDict = categoryScores["chrome"] ?? [:]
                            let safariDict = categoryScores["safari"] ?? [:]
                            
                            let macOSSummary = CategorySummary(
                                total: macOSDict["total"] as? Int ?? 0,
                                passed: macOSDict["passed"] as? Int ?? 0,
                                failed: 0, // Not in the JSON format
                                manual: 0, // Not in the JSON format
                                error: 0,  // Not in the JSON format
                                score: macOSDict["score"] as? Double ?? 0.0
                            )
                            
                            let chromeSummary = CategorySummary(
                                total: chromeDict["total"] as? Int ?? 0,
                                passed: chromeDict["passed"] as? Int ?? 0,
                                failed: 0, // Not in the JSON format
                                manual: 0, // Not in the JSON format
                                error: 0,  // Not in the JSON format
                                score: chromeDict["score"] as? Double ?? 0.0
                            )
                            
                            let safariSummary = CategorySummary(
                                total: safariDict["total"] as? Int ?? 0,
                                passed: safariDict["passed"] as? Int ?? 0,
                                failed: 0, // Not in the JSON format
                                manual: 0, // Not in the JSON format
                                error: 0,  // Not in the JSON format
                                score: safariDict["score"] as? Double ?? 0.0
                            )
                            
                            let summary = ReportSummary(
                                totalChecks: totalChecks,
                                passedChecks: passedChecks,
                                failedChecks: failedChecks,
                                manualChecks: manualChecks,
                                errorChecks: errorChecks,
                                complianceScore: complianceScore,
                                macOSChecks: macOSSummary,
                                chromeChecks: chromeSummary,
                                safariChecks: safariSummary
                            )
                            
                            self.resultsSummary = summary
                            
                            // Extract timestamp
                            if let reportInfo = jsonObject["report_info"] as? [String: Any],
                               let timestamp = reportInfo["timestamp"] as? String {
                                let dateFormatter = DateFormatter()
                                dateFormatter.dateFormat = "yyyy-MM-dd_HH-mm-ss"
                                self.lastRunDate = dateFormatter.date(from: timestamp)
                            }
                            
                            // Load config if not already loaded
                            if self.config == nil {
                                self.config = Config.load()
                            }
                            
                            updateMenu()
                        }
                    }
                }
            } catch {
                print("Error loading latest report: \(error)")
            }
        }
    }
}
