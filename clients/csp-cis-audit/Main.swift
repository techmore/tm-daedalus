import Foundation
import Dispatch
import AppKit

// Configuration structure
struct Config {
    struct Reporting {
        var endpoint: String
        var profilesEndpoint: String
        var profileSlug: String
        var domain: String
        var apiKey: String
    }
    
    struct Timeouts {
        var `default`: Double
        var filesystem: Double
        var network: Double
        var checks: [String: Double]
    }
    
    var reporting: Reporting
    var timeouts: Timeouts
    
    static let defaultConfig = Config(
        reporting: Reporting(endpoint: "", profilesEndpoint: "", profileSlug: "", domain: "", apiKey: ""),
        timeouts: Timeouts(default: 10.0, filesystem: 30.0, network: 20.0, checks: [:])
    )

    static func isAllowedReportingEndpoint(_ endpoint: String) -> Bool {
        guard let components = URLComponents(string: endpoint),
              let scheme = components.scheme?.lowercased(),
              let host = components.host?.lowercased(),
              components.user == nil,
              components.password == nil,
              components.query == nil,
              components.fragment == nil else {
            return false
        }
        let isLoopback = ["localhost", "127.0.0.1", "::1"].contains(host)
        return scheme == "https" || (scheme == "http" && isLoopback)
    }

    static func load() -> Config {
        let fileManager = FileManager.default
        let configURL = CISClientPaths.applicationSupportDirectory
            .appendingPathComponent("cis-client.yaml")
        guard fileManager.fileExists(atPath: configURL.path) else {
            print("[WARNING] Import a Daedalus client config to enable report submission; using defaults")
            return defaultConfig
        }
        guard let attributes = try? fileManager.attributesOfItem(atPath: configURL.path),
              let permissions = (attributes[.posixPermissions] as? NSNumber)?.intValue,
              (permissions & 0o077) == 0 else {
            print("[WARNING] Daedalus client config must be private (chmod 600); using default configuration")
            return defaultConfig
        }
        
        do {
            let yamlString = try String(contentsOf: configURL, encoding: .utf8)
            return parse(yamlString: yamlString)
        } catch {
            print("[WARNING] Failed to read CIS client configuration: \(error), using default configuration")
            return defaultConfig
        }
    }

    static func parse(yamlString: String) -> Config {
        var reporting = Reporting(
            endpoint: "",
            profilesEndpoint: "",
            profileSlug: "",
            domain: "",
            apiKey: ""
        )
        var timeouts = Timeouts(default: 10.0, filesystem: 30.0, network: 20.0, checks: [:])
        var currentSection = ""
        var checksSection = false

        for line in yamlString.components(separatedBy: .newlines) {
            let valueLine = line.trimmingCharacters(in: .whitespacesAndNewlines)
            if valueLine.isEmpty || valueLine.hasPrefix("#") { continue }
            if valueLine.hasSuffix(":") {
                currentSection = String(valueLine.dropLast()).trimmingCharacters(in: .whitespacesAndNewlines)
                checksSection = currentSection == "checks"
                continue
            }
            guard let colonIndex = valueLine.firstIndex(of: ":") else { continue }
            let key = valueLine[..<colonIndex].trimmingCharacters(in: .whitespacesAndNewlines)
            var value = valueLine[valueLine.index(after: colonIndex)...]
                .trimmingCharacters(in: .whitespacesAndNewlines)
            if value.hasPrefix("\"") && value.hasSuffix("\"") {
                value = String(value.dropFirst().dropLast())
            }

            switch currentSection {
            case "reporting":
                if key == "endpoint" {
                    reporting.endpoint = value
                } else if key == "profiles_endpoint" {
                    reporting.profilesEndpoint = value
                } else if key == "profile_slug" {
                    reporting.profileSlug = value
                } else if key == "domain" {
                    reporting.domain = value
                } else if key == "api_key" {
                    reporting.apiKey = value
                }
            case "timeouts":
                if !checksSection {
                    if key == "default", let timeout = Double(value) {
                        timeouts.default = timeout
                    } else if key == "filesystem", let timeout = Double(value) {
                        timeouts.filesystem = timeout
                    } else if key == "network", let timeout = Double(value) {
                        timeouts.network = timeout
                    }
                } else if let timeout = Double(value) {
                    timeouts.checks[key] = timeout
                }
            case "checks":
                if let timeout = Double(value) {
                    timeouts.checks[key] = timeout
                }
            default:
                break
            }
        }
        return Config(reporting: reporting, timeouts: timeouts)
    }
}

// Entry point for the CIS Swift Client
class CISApp: NSObject, NSApplicationDelegate {
    // File handle for logging
    private var logFileHandle: FileHandle? = nil
    // Synchronization queue for file handle access
    private let fileHandleQueue = DispatchQueue(label: "com.csp.cis-compliance.fileHandleQueue")
    private let checkRunLock = NSLock()
    private var checkRunInProgress = false
    private var periodicCheckIn: DispatchSourceTimer?
    private var periodicReportRetry: DispatchSourceTimer?
    private var periodicClientHeartbeat: DispatchSourceTimer?
    private static let reportUploadLock = NSLock()
    
    // Add applicationDidFinishLaunching to initialize MenuBarManager
    func applicationDidFinishLaunching(_ notification: Notification) {
        #if DEBUG
        // App-hosted fixture tests must never launch audits or report uploads.
        if NSClassFromString("XCTestCase") != nil { return }
        #endif
        // Initialize and set up the menu bar
        _ = MenuBarManager.shared // This will call setupStatusItem() via init

        DispatchQueue.global(qos: .utility).async {
            CISApp.retryPendingReports()
        }
        let retryTimer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        retryTimer.schedule(deadline: .now() + .seconds(15 * 60), repeating: .seconds(15 * 60), leeway: .seconds(60))
        retryTimer.setEventHandler { CISApp.retryPendingReports() }
        periodicReportRetry = retryTimer
        retryTimer.resume()

        let heartbeatTimer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        heartbeatTimer.schedule(deadline: .now(), repeating: .seconds(5 * 60), leeway: .seconds(30))
        heartbeatTimer.setEventHandler { CISApp.sendClientHeartbeat() }
        periodicClientHeartbeat = heartbeatTimer
        heartbeatTimer.resume()

        // Run checks in background
        DispatchQueue.global(qos: .background).async {
            self.runChecks()
        }

        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        timer.schedule(deadline: .now() + .seconds(24 * 60 * 60), repeating: .seconds(24 * 60 * 60), leeway: .seconds(300))
        timer.setEventHandler { [weak self] in
            self?.runChecks()
        }
        periodicCheckIn = timer
        timer.resume()
    }

    // Thread-safe method to write to the log file
    private func writeToLog(_ message: String) {
        fileHandleQueue.sync {
            if let fileHandle = self.logFileHandle {
                fileHandle.write(Data(message.utf8))
            }
        }
    }
    static func main() {
        let app = NSApplication.shared
        let delegate = CISApp()
        app.delegate = delegate
        app.run()
    }
    
    func runChecks() {
        checkRunLock.lock()
        let mayStart = !checkRunInProgress
        if mayStart { checkRunInProgress = true }
        checkRunLock.unlock()
        guard mayStart else {
            print("[INFO] A CIS check run is already in progress; skipping this request.")
            return
        }
        defer {
            checkRunLock.lock()
            checkRunInProgress = false
            checkRunLock.unlock()
        }

        print("\n===== CIS BENCHMARK CHECK RUNNER =====")
        print("Starting at: \(Date())")
        
        // Load configuration
        let config = Config.load()
        print("[INFO] Using reporting endpoint: \(config.reporting.endpoint)")
        print("[INFO] Using domain: \(config.reporting.domain)")
        
        let checklistPath = "checklist.yaml"
        
        // Prefer the workspace's published Daedalus profile. If the portal is
        // unavailable or no profile is selected, retain the bundled checklist.
        let profilesEndpoint = DaedalusProfileClient.profileEndpoint(
            configuredEndpoint: config.reporting.profilesEndpoint,
            reportEndpoint: config.reporting.endpoint
        )
        let activeProfile = profilesEndpoint.flatMap { endpoint in
            DaedalusProfileClient.fetch(
                endpoint: endpoint,
                apiKey: config.reporting.apiKey,
                preferredSlug: config.reporting.profileSlug
            )
        }
        if !config.reporting.profileSlug.isEmpty && activeProfile == nil {
            print("[ERROR] The configured Daedalus profile could not be loaded. Skipping this run rather than reporting the bundled CSP checklist under a different profile selection.")
            return
        }
        if let activeProfile,
           let incompatibility = DaedalusProfileClient.incompatibilityReason(
                for: activeProfile,
                osMajorVersion: ProcessInfo.processInfo.operatingSystemVersion.majorVersion
           ) {
            print("[ERROR] \(incompatibility) Skipping this run; no results were collected or uploaded.")
            return
        }
        let checks: [CISCheck]
        if let activeProfile {
            checks = activeProfile.checks
        } else {
            print("\n[INFO] Loading checks from bundled \(checklistPath)...")
            checks = ChecklistLoader.load(from: checklistPath)
        }
        
        // Count by category
        let macOSChecks = checks.filter { $0.category == "macos" }
        let chromeChecks = checks.filter { $0.category == "chrome" }
        let safariChecks = checks.filter { $0.category == "safari" }
        
        print("\n[INFO] Loaded \(checks.count) total checks:")
        print("  - macOS: \(macOSChecks.count) checks")
        print("  - Chrome: \(chromeChecks.count) checks")
        print("  - Safari: \(safariChecks.count) checks")
        
        // Setup logging
        let dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "yyyy-MM-dd_HH-mm-ss"
        let logTimestamp = dateFormatter.string(from: Date())
        let logFileURL: URL
        do {
            logFileURL = try CISClientPaths.logsDirectory()
                .appendingPathComponent("cis_run_\(logTimestamp).log")
        } catch {
            print("[ERROR] Could not prepare the private CIS log directory.")
            return
        }
        
        // Create log file
        FileManager.default.createFile(atPath: logFileURL.path, contents: nil)
        self.logFileHandle = FileHandle(forWritingAtPath: logFileURL.path)
        
        // Write log header
        var logHeader = "\n===== CIS BENCHMARK CHECK RUN LOG =====\nStarted at: \(Date())\n\nConfiguration:\n- Reporting Endpoint: \(config.reporting.endpoint)\n- Domain: \(config.reporting.domain)\n- API Key: \(config.reporting.apiKey.isEmpty ? "Not set" : "*****")\n- Default Timeout: \(config.timeouts.default) seconds\n- Filesystem Timeout: \(config.timeouts.filesystem) seconds\n- Network Timeout: \(config.timeouts.network) seconds\n- Checks:\n"
        for (key, value) in config.timeouts.checks {
            logHeader += "- \(key): \(value) seconds\n"
        }
        logHeader += "\n"
        
        // Write to log file in a thread-safe way
        self.writeToLog(logHeader)
        
        // Initialize results array
        var results = [CheckResult]()
        
        // Run macOS checks
        print("\n[INFO] Running macOS checks with detailed logging...")
        
        for (index, check) in macOSChecks.enumerated() {
            let checkLogMessage = "\n[CHECK \(index+1)/\(macOSChecks.count)] Running: [\(check.id)] \(check.description)"
            print(checkLogMessage)
            self.writeToLog("\(checkLogMessage)\n")
            
            // Create a semaphore for timeout handling
            let semaphore = DispatchSemaphore(value: 0)
            
            // Create a result placeholder
            var checkResult: CheckResult? = nil
            
            // Run the check in a background thread
            DispatchQueue.global(qos: .userInitiated).async {
                let startTime = Date()
                checkResult = MacOSChecks.run(check: check)
                let endTime = Date()
                let executionTime = endTime.timeIntervalSince(startTime)
                
                self.writeToLog("  - Completed in \(String(format: "%.2f", executionTime)) seconds\n")
                print("  - Completed in \(String(format: "%.2f", executionTime)) seconds")
                self.writeToLog("  - Status: \(checkResult?.status.uppercased() ?? "unknown")\n")
                print("  - Status: \(checkResult?.status.uppercased() ?? "unknown")")
                self.writeToLog("  - Details: \(checkResult?.details ?? "unknown")\n")
                print("  - Details: \(checkResult?.details ?? "unknown")")
                semaphore.signal()
            }
            
            // Get timeout from config based on check ID
            let timeoutInterval: Double
            
            // Check if there's a specific timeout for this check ID
            if let specificTimeout = config.timeouts.checks[check.id] {
                timeoutInterval = specificTimeout
            }
            // Filesystem-intensive checks
            else if check.id.contains("directory") || check.id.contains("file") || 
                    check.id.contains("permission") || check.id.contains("scan") {
                timeoutInterval = config.timeouts.filesystem
            }
            // Network-related checks
            else if check.id.contains("network") || check.id.contains("update") || 
                    check.id.contains("download") || check.id.contains("internet") {
                timeoutInterval = config.timeouts.network
            }
            // Default timeout for all other checks
            else {
                timeoutInterval = config.timeouts.default
            }
            
            let waitResult = semaphore.wait(timeout: .now() + timeoutInterval)
            
            if waitResult == .timedOut {
                let timeoutLogMessage = "  [ERROR] Check timed out after \(Int(timeoutInterval)) seconds!"
                print(timeoutLogMessage)
                self.writeToLog("\(timeoutLogMessage)\n")
                
                var timeoutDetails = "Check timed out after \(Int(timeoutInterval)) seconds"
                
                // Add remediation advice for specific checks
                switch check.id {
                case "macos_1":
                    timeoutDetails += ". This check verifies if all Apple-provided software is current. Try running 'softwareupdate -l' manually."
                case "macos_64", "macos_65", "macos_66", "macos_67":
                    timeoutDetails += ". This check involves scanning user directories which can be time-consuming. Try increasing the timeout or running with elevated permissions."
                case "macos_82":
                    timeoutDetails += ". This check verifies Gatekeeper settings. Try running 'spctl --status' manually to check Gatekeeper status."
                default:
                    break
                }
                
                let timeoutResult = CheckResult(check: check, status: "error", details: timeoutDetails)
                results.append(timeoutResult)
                self.writeToLog("  - Details: \(timeoutDetails)\n")
            } else if let result = checkResult {
                results.append(result)
            } else {
                let errorLogMessage = "  [ERROR] Check returned nil result!"
                print(errorLogMessage)
                self.writeToLog("\(errorLogMessage)\n")
                
                let errorDetails = "Check returned nil result"
                let errorResult = CheckResult(check: check, status: "error", details: errorDetails)
                results.append(errorResult)
                self.writeToLog("  - Details: \(errorDetails)\n")
            }
        }
        
        // Run Chrome checks if Chrome is installed
        if chromeChecks.count > 0 {
            print("\n[INFO] Running Chrome checks...")
            self.writeToLog("\n[INFO] Running Chrome checks...\n")
            
            for (index, check) in chromeChecks.enumerated() {
                let checkLogMessage = "\n[CHECK \(index+1)/\(chromeChecks.count)] Running: [\(check.id)] \(check.description)"
                print(checkLogMessage)
                self.writeToLog("\(checkLogMessage)\n")
                
                // Create a semaphore for timeout handling
                let semaphore = DispatchSemaphore(value: 0)
                
                // Create a result placeholder
                var checkResult: CheckResult? = nil
                
                // Run the check in a background thread
                DispatchQueue.global(qos: .userInitiated).async {
                    let startTime = Date()
                    checkResult = ChromeChecks.run(check: check)
                    let endTime = Date()
                    let executionTime = endTime.timeIntervalSince(startTime)
                    
                    self.writeToLog("  - Completed in \(String(format: "%.2f", executionTime)) seconds\n")
                    print("  - Completed in \(String(format: "%.2f", executionTime)) seconds")
                    self.writeToLog("  - Status: \(checkResult?.status.uppercased() ?? "unknown")\n")
                    print("  - Status: \(checkResult?.status.uppercased() ?? "unknown")")
                    self.writeToLog("  - Details: \(checkResult?.details ?? "unknown")\n")
                    print("  - Details: \(checkResult?.details ?? "unknown")")
                    semaphore.signal()
                }
                
                // Get timeout from config based on check ID
                let timeoutInterval = config.timeouts.default
                
                let waitResult = semaphore.wait(timeout: .now() + timeoutInterval)
                
                if waitResult == .timedOut {
                    let timeoutLogMessage = "  [ERROR] Check timed out after \(Int(timeoutInterval)) seconds!"
                    print(timeoutLogMessage)
                    self.writeToLog("\(timeoutLogMessage)\n")
                    
                    let timeoutDetails = "Check timed out after \(Int(timeoutInterval)) seconds"
                    let timeoutResult = CheckResult(check: check, status: "error", details: timeoutDetails)
                    results.append(timeoutResult)
                    self.writeToLog("  - Details: \(timeoutDetails)\n")
                } else if let result = checkResult {
                    results.append(result)
                } else {
                    let errorLogMessage = "  [ERROR] Check returned nil result!"
                    print(errorLogMessage)
                    self.writeToLog("\(errorLogMessage)\n")
                    
                    let errorDetails = "Check returned nil result"
                    let errorResult = CheckResult(check: check, status: "error", details: errorDetails)
                    results.append(errorResult)
                    self.writeToLog("  - Details: \(errorDetails)\n")
                }
            }
        }
        
        // Run Safari checks
        if safariChecks.count > 0 {
            print("\n[INFO] Running Safari checks...")
            self.writeToLog("\n[INFO] Running Safari checks...\n")
            
            for (index, check) in safariChecks.enumerated() {
                let checkLogMessage = "\n[CHECK \(index+1)/\(safariChecks.count)] Running: [\(check.id)] \(check.description)"
                print(checkLogMessage)
                self.writeToLog("\(checkLogMessage)\n")
                
                // Create a semaphore for timeout handling
                let semaphore = DispatchSemaphore(value: 0)
                
                // Create a result placeholder
                var checkResult: CheckResult? = nil
                
                // Run the check in a background thread
                DispatchQueue.global(qos: .userInitiated).async {
                    let startTime = Date()
                    checkResult = SafariChecks.run(check: check)
                    let endTime = Date()
                    let executionTime = endTime.timeIntervalSince(startTime)
                    
                    self.writeToLog("  - Completed in \(String(format: "%.2f", executionTime)) seconds\n")
                    print("  - Completed in \(String(format: "%.2f", executionTime)) seconds")
                    self.writeToLog("  - Status: \(checkResult?.status.uppercased() ?? "unknown")\n")
                    print("  - Status: \(checkResult?.status.uppercased() ?? "unknown")")
                    self.writeToLog("  - Details: \(checkResult?.details ?? "unknown")\n")
                    print("  - Details: \(checkResult?.details ?? "unknown")")
                    semaphore.signal()
                }
                
                // Get timeout from config based on check ID
                let timeoutInterval = config.timeouts.default
                
                let waitResult = semaphore.wait(timeout: .now() + timeoutInterval)
                
                if waitResult == .timedOut {
                    let timeoutLogMessage = "  [ERROR] Check timed out after \(Int(timeoutInterval)) seconds!"
                    print(timeoutLogMessage)
                    logFileHandle?.write(Data("\(timeoutLogMessage)\n".utf8))
                    
                    let timeoutDetails = "Check timed out after \(Int(timeoutInterval)) seconds"
                    let timeoutResult = CheckResult(check: check, status: "error", details: timeoutDetails)
                    results.append(timeoutResult)
                    logFileHandle?.write(Data("  - Details: \(timeoutDetails)\n".utf8))
                } else if let result = checkResult {
                    let statusLogMessage = "  - Status: \(result.status.uppercased())"
                    let detailsLogMessage = "  - Details: \(result.details)"
                    print(statusLogMessage)
                    print(detailsLogMessage)
                    logFileHandle?.write(Data("\(statusLogMessage)\n\(detailsLogMessage)\n".utf8))
                    results.append(result)
                } else {
                    let errorLogMessage = "  [ERROR] Check returned nil result!"
                    print(errorLogMessage)
                    logFileHandle?.write(Data("\(errorLogMessage)\n".utf8))
                    
                    let errorDetails = "Check returned nil result"
                    let errorResult = CheckResult(check: check, status: "error", details: errorDetails)
                    results.append(errorResult)
                    logFileHandle?.write(Data("  - Details: \(errorDetails)\n".utf8))
                }
            }
        }
        
        // Print summary
        CISApp.printResultsSummary(results)
        
        // Save results locally
        CISApp.saveResultsLocally(results, activeProfile: activeProfile, config: config)
        
        // Log completion
        let completionMessage = "\n[COMPLETE] CIS benchmark checks completed at: \(Date())"
        print(completionMessage)
        self.writeToLog("\(completionMessage)\n")
        
        // Close log file
        self.fileHandleQueue.sync {
            self.logFileHandle?.closeFile()
            self.logFileHandle = nil
        }
        
        // Update menu bar with results
        DispatchQueue.main.async {
            // Create summary for menu bar
            let totalChecks = results.count
            let passedChecks = results.filter { $0.status == "pass" }.count
            let failedChecks = results.filter { $0.status == "fail" }.count
            let manualChecks = results.filter { $0.status == "manual" }.count
            let errorChecks = results.filter { $0.status == "error" }.count
            let complianceScore = totalChecks > 0 ? Double(passedChecks) / Double(totalChecks) * 100.0 : 0.0
            
            // Create category summaries
            let macOSResults = results.filter { $0.check.category == "macos" }
            let macOSTotal = macOSResults.count
            let macOSPassed = macOSResults.filter { $0.status == "pass" }.count
            let macOSFailed = macOSResults.filter { $0.status == "fail" }.count
            let macOSManual = macOSResults.filter { $0.status == "manual" }.count
            let macOSError = macOSResults.filter { $0.status == "error" }.count
            let macOSScore = macOSTotal > 0 ? Double(macOSPassed) / Double(macOSTotal) * 100.0 : 0.0
            
            let chromeResults = results.filter { $0.check.category == "chrome" }
            let chromeTotal = chromeResults.count
            let chromePassed = chromeResults.filter { $0.status == "pass" }.count
            let chromeFailed = chromeResults.filter { $0.status == "fail" }.count
            let chromeManual = chromeResults.filter { $0.status == "manual" }.count
            let chromeError = chromeResults.filter { $0.status == "error" }.count
            let chromeScore = chromeTotal > 0 ? Double(chromePassed) / Double(chromeTotal) * 100.0 : 0.0
            
            let safariResults = results.filter { $0.check.category == "safari" }
            let safariTotal = safariResults.count
            let safariPassed = safariResults.filter { $0.status == "pass" }.count
            let safariFailed = safariResults.filter { $0.status == "fail" }.count
            let safariManual = safariResults.filter { $0.status == "manual" }.count
            let safariError = safariResults.filter { $0.status == "error" }.count
            let safariScore = safariTotal > 0 ? Double(safariPassed) / Double(safariTotal) * 100.0 : 0.0
            
            let macOSSummary = CategorySummary(
                total: macOSTotal,
                passed: macOSPassed,
                failed: macOSFailed,
                manual: macOSManual,
                error: macOSError,
                score: macOSScore
            )
            
            let chromeSummary = CategorySummary(
                total: chromeTotal,
                passed: chromePassed,
                failed: chromeFailed,
                manual: chromeManual,
                error: chromeError,
                score: chromeScore
            )
            
            let safariSummary = CategorySummary(
                total: safariTotal,
                passed: safariPassed,
                failed: safariFailed,
                manual: safariManual,
                error: safariError,
                score: safariScore
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
            
            MenuBarManager.shared.updateWithResults(summary: summary, config: config)
        }
    }
    
    static func printResultsSummary(_ results: [CheckResult]) {
        // Count results by status
        let passCount = results.filter { $0.status == "pass" }.count
        let failCount = results.filter { $0.status == "fail" }.count
        let manualCount = results.filter { $0.status == "manual" }.count
        let errorCount = results.filter { $0.status == "error" }.count
        
        // Calculate compliance score
        let totalChecks = results.count
        let complianceScore = totalChecks > 0 ? Double(passCount) / Double(totalChecks) * 100.0 : 0.0
        
        print("\n===== RESULTS SUMMARY =====")
        print("Total checks run: \(totalChecks)")
        print("Passed: \(passCount) (\(String(format: "%.2f%%", Double(passCount) / Double(totalChecks) * 100.0)))")
        print("Failed: \(failCount) (\(String(format: "%.2f%%", Double(failCount) / Double(totalChecks) * 100.0)))")
        print("Manual: \(manualCount) (\(String(format: "%.2f%%", Double(manualCount) / Double(totalChecks) * 100.0)))")
        print("Errors: \(errorCount) (\(String(format: "%.2f%%", Double(errorCount) / Double(totalChecks) * 100.0)))")
        print("Overall Compliance Score: \(String(format: "%.2f%%", complianceScore))")
        
        // Get category-specific results
        let macOSResults = results.filter { $0.check.category == "macos" }
        let chromeResults = results.filter { $0.check.category == "chrome" }
        let safariResults = results.filter { $0.check.category == "safari" }
        
        let macOSPass = macOSResults.filter { $0.status == "pass" }.count
        let chromePass = chromeResults.filter { $0.status == "pass" }.count
        let safariPass = safariResults.filter { $0.status == "pass" }.count
        
        let macOSScore = macOSResults.count > 0 ? Double(macOSPass) / Double(macOSResults.count) * 100.0 : 0.0
        let chromeScore = chromeResults.count > 0 ? Double(chromePass) / Double(chromeResults.count) * 100.0 : 0.0
        let safariScore = safariResults.count > 0 ? Double(safariPass) / Double(safariResults.count) * 100.0 : 0.0
        
        print("\n===== CATEGORY SUMMARIES =====")
        print("macOS: \(String(format: "%.2f%%", macOSScore)) (\(macOSPass)/\(macOSResults.count) passed)")
        print("Chrome: \(String(format: "%.2f%%", chromeScore)) (\(chromePass)/\(chromeResults.count) passed)")
        print("Safari: \(String(format: "%.2f%%", safariScore)) (\(safariPass)/\(safariResults.count) passed)")
        
        // Print failed checks
        let failedChecks = results.filter { $0.status == "fail" }
        if !failedChecks.isEmpty {
            print("\n----- FAILED CHECKS -----")
            for result in failedChecks {
                print("[\(result.check.id)] \(result.check.description)")
                print("  Details: \(result.details)")
            }
        }
        
        // Print error checks
        let errorChecks = results.filter { $0.status == "error" }
        if !errorChecks.isEmpty {
            print("\n----- CHECKS WITH ERRORS -----")
            for result in errorChecks {
                print("[\(result.check.id)] \(result.check.description)")
                print("  Error: \(result.details)")
            }
        }
    }
    
    static func iso8601ReportTimestamp(_ date: Date) -> String {
        ISO8601DateFormatter().string(from: date)
    }

    static func saveResultsLocally(_ results: [CheckResult], activeProfile: DaedalusPublishedProfile? = nil, config: Config = Config.load()) {
        
        // Create a formatted timestamp for the filename
        let dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "yyyy-MM-dd_HH-mm-ss"
        let generatedAt = Date()
        let dateString = dateFormatter.string(from: generatedAt)
        let timestamp = dateFormatter.string(from: generatedAt)
        let reportTimestamp = Self.iso8601ReportTimestamp(generatedAt)
        let reportIdentifier = UUID().uuidString.lowercased()
        
        // Get system information
        let systemInfo = collectSystemInfo()
        let deviceIdentifier: String
        do {
            deviceIdentifier = try CISClientPaths.deviceIdentifier()
        } catch {
            print("Could not create a private, stable device identifier; report was not saved or uploaded.")
            return
        }
        
        // Calculate compliance scores
        let passCount = results.filter { $0.status == "pass" }.count
        let failCount = results.filter { $0.status == "fail" }.count
        let manualCount = results.filter { $0.status == "manual" }.count
        let errorCount = results.filter { $0.status == "error" }.count
        let totalChecks = results.count
        let complianceScore = totalChecks > 0 ? Double(passCount) / Double(totalChecks) * 100.0 : 0.0
        
        // Get category-specific results
        let macOSResults = results.filter { $0.check.category == "macos" }
        let chromeResults = results.filter { $0.check.category == "chrome" }
        let safariResults = results.filter { $0.check.category == "safari" }
        
        let macOSPass = macOSResults.filter { $0.status == "pass" }.count
        let chromePass = chromeResults.filter { $0.status == "pass" }.count
        let safariPass = safariResults.filter { $0.status == "pass" }.count
        
        let macOSScore = macOSResults.count > 0 ? Double(macOSPass) / Double(macOSResults.count) * 100.0 : 0.0
        let chromeScore = chromeResults.count > 0 ? Double(chromePass) / Double(chromeResults.count) * 100.0 : 0.0
        let safariScore = safariResults.count > 0 ? Double(safariPass) / Double(safariResults.count) * 100.0 : 0.0
        
        let reportsDirectory: URL
        do {
            reportsDirectory = try CISClientPaths.reportsDirectory()
        } catch {
            print("Failed to prepare the private reports directory.")
            return
        }
        
        // Create the report files
        let reportFileSuffix = String(reportIdentifier.prefix(8))
        let jsonReportFile = reportsDirectory.appendingPathComponent("cis_report_\(dateString)_\(reportFileSuffix).json")
        let textReportFile = reportsDirectory.appendingPathComponent("cis_report_\(dateString)_\(reportFileSuffix).txt")
        
        // Create a comprehensive report structure
        // Keep workspace identity in the report; credentials are sent only in headers.
        let report = [
            "domain": config.reporting.domain,
            "profile_slug": activeProfile?.slug ?? "",
            "profile_version": activeProfile?.version ?? "",
            "device_uuid": deviceIdentifier,
            "report_id": reportIdentifier,
            "report_info": [
                "timestamp": reportTimestamp,
                "report_version": "1.0"
            ],
            "system_info": [
                "hostname": systemInfo.hostname,
                "ip_addresses": systemInfo.ipAddresses,
                "os_version": systemInfo.osVersion,
                "cpu_info": systemInfo.cpuInfo,
                "ram_total": systemInfo.ramTotal,
                "ram_used": systemInfo.ramUsed,
                "disk_total": systemInfo.diskTotal,
                "disk_used": systemInfo.diskUsed,
                "disk_free": systemInfo.diskFree
            ],
            "compliance_summary": [
                "total_checks": totalChecks,
                "passed_checks": passCount,
                "failed_checks": failCount,
                "manual_checks": manualCount,
                "error_checks": errorCount,
                "overall_compliance_score": complianceScore,
                "category_scores": [
                    "macos": [
                        "total": macOSResults.count,
                        "passed": macOSPass,
                        "score": macOSScore
                    ],
                    "chrome": [
                        "total": chromeResults.count,
                        "passed": chromePass,
                        "score": chromeScore
                    ],
                    "safari": [
                        "total": safariResults.count,
                        "passed": safariPass,
                        "score": safariScore
                    ]
                ]
            ],
            "results": results.map { result -> [String: Any] in
                var item: [String: Any] = [
                "id": result.check.id,
                "category": result.check.category,
                "description": result.check.description,
                "status": result.status,
                "details": result.details
                ]
                if let ruleID = result.check.ruleID { item["rule_id"] = ruleID }
                if let benchmarkIDs = result.check.benchmarkIDs { item["benchmark_ids"] = benchmarkIDs }
                return item
            }
        ] as [String : Any]
        
        // Convert to JSON
        do {
            let jsonData = try JSONSerialization.data(withJSONObject: report, options: .prettyPrinted)
            try jsonData.write(to: jsonReportFile)
            print("JSON report saved to: \(jsonReportFile.path)")
            
            // Create a human-readable text report
            var textReport = "CIS BENCHMARK REPORT\n"
            textReport += "===================\n\n"
            textReport += "REPORT IDENTIFICATION\n"
            textReport += "---------------------\n"
            textReport += "Domain: \(config.reporting.domain)\n"
            textReport += "Device ID: \(deviceIdentifier)\n"
            textReport += "Report ID: \(reportIdentifier)\n"
            textReport += "Generated: \(timestamp)\n\n"
            textReport += "CLIENT DEVICE INFORMATION\n"
            textReport += "------------------------\n"
            textReport += "Hostname: \(systemInfo.hostname)\n"
            textReport += "Hardware Model: \(systemInfo.hardwareModel)\n"
            textReport += "Serial Number: Redacted\n"
            textReport += "OS Version: \(systemInfo.osVersion.components(separatedBy: "\n").first ?? systemInfo.osVersion)\n"
            textReport += "IP Address: \(systemInfo.ipAddresses.first ?? "Unknown")\n"
            
            textReport += "SYSTEM INFORMATION\n"
            textReport += "------------------\n"
            textReport += "Hostname: \(systemInfo.hostname)\n"
            textReport += "Hardware Model: \(systemInfo.hardwareModel)\n"
            textReport += "Serial Number: Redacted\n"
            textReport += "Boot Time: \(systemInfo.bootTime)\n\n"
            
            textReport += "NETWORK INFORMATION\n"
            textReport += "-------------------\n"
            textReport += "IP Addresses: \(systemInfo.ipAddresses.joined(separator: ", "))\n\n"
            
            textReport += "OPERATING SYSTEM\n"
            textReport += "----------------\n"
            textReport += "OS Version:\n\(systemInfo.osVersion)\n\n"
            
            textReport += "HARDWARE SPECIFICATIONS\n"
            textReport += "----------------------\n"
            textReport += "CPU: \(systemInfo.cpuInfo)\n"
            textReport += "CPU Cores: \(systemInfo.cpuCores)\n"
            textReport += "CPU Threads: \(systemInfo.cpuThreads)\n"
            textReport += "RAM: \(systemInfo.ramUsed) used of \(systemInfo.ramTotal)\n"
            textReport += "Disk: \(systemInfo.diskUsed) used, \(systemInfo.diskFree) free of \(systemInfo.diskTotal)\n\n"
            
            textReport += "SECURITY SETTINGS\n"
            textReport += "-----------------\n"
            for (key, value) in systemInfo.securitySettings.sorted(by: { $0.key < $1.key }) {
                textReport += "\(key): \(value)\n"
            }
            textReport += "\n"
            
            textReport += "INSTALLED APPLICATIONS (Top 50)\n"
            textReport += "-----------------------------\n"
            for app in systemInfo.installedApps.sorted(by: { $0.name < $1.name }) {
                textReport += "\(app.name): \(app.version)\n"
            }
            textReport += "\n"
            
            textReport += "COMPLIANCE SUMMARY\n"
            textReport += "------------------\n"
            textReport += "Overall Compliance Score: \(String(format: "%.2f%%", complianceScore))\n"
            textReport += "Total Checks: \(totalChecks)\n"
            textReport += "Passed: \(passCount) (\(String(format: "%.2f%%", Double(passCount) / Double(totalChecks) * 100.0)))\n"
            textReport += "Failed: \(failCount) (\(String(format: "%.2f%%", Double(failCount) / Double(totalChecks) * 100.0)))\n"
            textReport += "Manual: \(manualCount) (\(String(format: "%.2f%%", Double(manualCount) / Double(totalChecks) * 100.0)))\n"
            textReport += "Errors: \(errorCount) (\(String(format: "%.2f%%", Double(errorCount) / Double(totalChecks) * 100.0)))\n\n"
            
            textReport += "CATEGORY SCORES\n"
            textReport += "---------------\n"
            textReport += "macOS: \(String(format: "%.2f%%", macOSScore)) (\(macOSPass)/\(macOSResults.count) passed)\n"
            textReport += "Chrome: \(String(format: "%.2f%%", chromeScore)) (\(chromePass)/\(chromeResults.count) passed)\n"
            textReport += "Safari: \(String(format: "%.2f%%", safariScore)) (\(safariPass)/\(safariResults.count) passed)\n\n"
            
            // Add failed checks
            let failedChecks = results.filter { $0.status == "fail" }
            if !failedChecks.isEmpty {
                textReport += "FAILED CHECKS\n"
                textReport += "-------------\n"
                for result in failedChecks {
                    textReport += "[\(result.check.id)] \(result.check.description)\n"
                    textReport += "  Details: \(result.details)\n\n"
                }
            }
            
            // Add error checks
            let errorChecks = results.filter { $0.status == "error" }
            if !errorChecks.isEmpty {
                textReport += "CHECKS WITH ERRORS\n"
                textReport += "------------------\n"
                for result in errorChecks {
                    textReport += "[\(result.check.id)] \(result.check.description)\n"
                    textReport += "  Error: \(result.details)\n\n"
                }
            }
            
            try textReport.write(to: textReportFile, atomically: true, encoding: .utf8)
            print("Text report saved to: \(textReportFile.path)")
            
            // Send report to configured endpoint
            print("\n[INFO] Attempting to send report to configured endpoint...")
            
            // Send to reporting endpoint
            Self.reportUploadLock.lock()
            defer { Self.reportUploadLock.unlock() }
            if sendReport(jsonData: jsonData, to: config.reporting.endpoint, description: "reporting endpoint", config: config) {
                try CISUploadOutbox.recordReceipt(for: jsonReportFile)
            }
            
        } catch {
            print("Failed to save reports: \(error)")
        }
    }
    
    static func retryPendingReports(config: Config = Config.load()) {
        guard Config.isAllowedReportingEndpoint(config.reporting.endpoint),
              config.reporting.apiKey.count >= 16,
              !config.reporting.domain.isEmpty,
              reportUploadLock.try() else { return }
        defer { reportUploadLock.unlock() }
        do {
            let directory = try CISClientPaths.reportsDirectory()
            var attempted = 0
            for reportURL in try CISUploadOutbox.pendingReports(in: directory) {
                guard let data = try? Data(contentsOf: reportURL),
                      CISUploadOutbox.matchesWorkspace(data, domain: config.reporting.domain) else { continue }
                if attempted >= 10 { break }
                attempted += 1
                if sendReport(jsonData: data, to: config.reporting.endpoint, description: "saved report", config: config) {
                    try CISUploadOutbox.recordReceipt(for: reportURL)
                }
            }
        } catch {
            print("[ERROR] Could not process the private report upload queue.")
        }
    }

    static func sendClientHeartbeat(config: Config = Config.load()) {
        guard let identifier = try? CISClientPaths.deviceIdentifier(),
              let request = DaedalusProfileClient.heartbeatRequest(reportEndpoint: config.reporting.endpoint,
                  apiKey: config.reporting.apiKey, deviceIdentifier: identifier) else { return }
        let session = DaedalusProfileClient.protectedSession()
        defer { session.invalidateAndCancel() }
        let semaphore = DispatchSemaphore(value: 0)
        let task = session.dataTask(with: request) { _, _, _ in semaphore.signal() }
        task.resume()
        if semaphore.wait(timeout: .now() + 15) == .timedOut { task.cancel() }
    }

    @discardableResult
    static func sendReport(jsonData: Data, to endpoint: String, description: String, config: Config = Config.load(), session providedSession: URLSession? = nil) -> Bool {
        guard let url = URL(string: endpoint), Config.isAllowedReportingEndpoint(endpoint),
              config.reporting.apiKey.count >= 16,
              CISUploadOutbox.matchesWorkspace(jsonData, domain: config.reporting.domain),
              let report = try? JSONSerialization.jsonObject(with: jsonData) as? [String: Any],
              let deviceIdentifier = report["device_uuid"] as? String, !deviceIdentifier.isEmpty,
              let reportId = report["report_id"] as? String, !reportId.isEmpty else {
            print("[ERROR] Report requires a private client config and matching workspace identity.")
            return false
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.timeoutInterval = 30
        request.setValue(config.reporting.domain, forHTTPHeaderField: "X-Domain")
        request.setValue(config.reporting.apiKey, forHTTPHeaderField: "X-API-Key")
        request.setValue(deviceIdentifier, forHTTPHeaderField: "X-Device-UUID")
        request.setValue(reportId, forHTTPHeaderField: "X-Report-ID")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = jsonData

        let semaphore = DispatchSemaphore(value: 0)
        let outcome = CISUploadOutcome()
        let session = providedSession ?? DaedalusProfileClient.protectedSession()
        defer { session.invalidateAndCancel() }
        let task = session.dataTask(with: request) { data, response, error in
            defer { semaphore.signal() }
            guard error == nil, let response = response as? HTTPURLResponse else {
                print("[WARNING] Upload unavailable; saved report remains queued.")
                return
            }
            guard (200..<300).contains(response.statusCode), let data,
                  let body = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  body["accepted"] as? Bool == true else {
                print("[WARNING] Report was not acknowledged (HTTP \(response.statusCode)); saved report remains queued.")
                return
            }
            outcome.recordAccepted()
            print("[SUCCESS] \(description) acknowledged by Daedalus.")
        }
        task.resume()
        guard semaphore.wait(timeout: .now() + 32) == .success else {
            task.cancel()
            print("[WARNING] Upload timed out; saved report remains queued.")
            return false
        }
        return outcome.accepted
    }

    static func collectSystemInfo() -> SystemInfo {
        // Get hostname
        let hostname = ProcessInfo.processInfo.hostName
        
        // Get IP addresses
        var ipAddresses = [String]()
        let process = Process()
        process.launchPath = "/sbin/ifconfig"
        let pipe = Pipe()
        process.standardOutput = pipe
        
        do {
            try process.run()
            process.waitUntilExit()
            
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            if let output = String(data: data, encoding: .utf8) {
                // Parse the output to find IP addresses
                let pattern = "inet \\d+\\.\\d+\\.\\d+\\.\\d+"
                if let regex = try? NSRegularExpression(pattern: pattern, options: []) {
                    let matches = regex.matches(in: output, options: [], range: NSRange(output.startIndex..., in: output))
                    for match in matches {
                        if let range = Range(match.range, in: output) {
                            let ipLine = output[range]
                            let components = ipLine.split(separator: " ")
                            if components.count >= 2 {
                                ipAddresses.append(String(components[1]))
                            }
                        }
                    }
                }
            }
        } catch {
            print("Error getting IP addresses: \(error)")
        }
        
        // Get detailed OS version
        var osVersion = ProcessInfo.processInfo.operatingSystemVersionString
        let swVersProcess = Process()
        swVersProcess.launchPath = "/usr/bin/sw_vers"
        let swVersPipe = Pipe()
        swVersProcess.standardOutput = swVersPipe
        
        do {
            try swVersProcess.run()
            swVersProcess.waitUntilExit()
            
            let data = swVersPipe.fileHandleForReading.readDataToEndOfFile()
            if let output = String(data: data, encoding: .utf8) {
                osVersion = output.trimmingCharacters(in: .whitespacesAndNewlines)
            }
        } catch {
            print("Error getting detailed OS version: \(error)")
        }
        
        // Get CPU info
        var cpuInfo = "Unknown CPU"
        var cpuCores = "Unknown"
        var cpuThreads = "Unknown"
        
        // Get CPU model
        let cpuProcess = Process()
        cpuProcess.launchPath = "/usr/sbin/sysctl"
        cpuProcess.arguments = ["-n", "machdep.cpu.brand_string"]
        let cpuPipe = Pipe()
        cpuProcess.standardOutput = cpuPipe
        
        do {
            try cpuProcess.run()
            cpuProcess.waitUntilExit()
            
            let data = cpuPipe.fileHandleForReading.readDataToEndOfFile()
            if let output = String(data: data, encoding: .utf8) {
                cpuInfo = output.trimmingCharacters(in: .whitespacesAndNewlines)
            }
        } catch {
            print("Error getting CPU info: \(error)")
        }
        
        // Get CPU cores
        let coresProcess = Process()
        coresProcess.launchPath = "/usr/sbin/sysctl"
        coresProcess.arguments = ["-n", "hw.physicalcpu"]
        let coresPipe = Pipe()
        coresProcess.standardOutput = coresPipe
        
        do {
            try coresProcess.run()
            coresProcess.waitUntilExit()
            
            let data = coresPipe.fileHandleForReading.readDataToEndOfFile()
            if let output = String(data: data, encoding: .utf8) {
                cpuCores = output.trimmingCharacters(in: .whitespacesAndNewlines)
            }
        } catch {
            print("Error getting CPU cores: \(error)")
        }
        
        // Get CPU threads
        let threadsProcess = Process()
        threadsProcess.launchPath = "/usr/sbin/sysctl"
        threadsProcess.arguments = ["-n", "hw.logicalcpu"]
        let threadsPipe = Pipe()
        threadsProcess.standardOutput = threadsPipe
        
        do {
            try threadsProcess.run()
            threadsProcess.waitUntilExit()
            
            let data = threadsPipe.fileHandleForReading.readDataToEndOfFile()
            if let output = String(data: data, encoding: .utf8) {
                cpuThreads = output.trimmingCharacters(in: .whitespacesAndNewlines)
            }
        } catch {
            print("Error getting CPU threads: \(error)")
        }
        
        // Get RAM info
        let totalRAM = ProcessInfo.processInfo.physicalMemory
        let totalRAMGB = String(format: "%.2f GB", Double(totalRAM) / 1_073_741_824)
        
        // Get used RAM
        var usedRAMGB = "Unknown"
        let vmStatProcess = Process()
        vmStatProcess.launchPath = "/usr/bin/vm_stat"
        let vmStatPipe = Pipe()
        vmStatProcess.standardOutput = vmStatPipe
        
        do {
            try vmStatProcess.run()
            vmStatProcess.waitUntilExit()
            
            let data = vmStatPipe.fileHandleForReading.readDataToEndOfFile()
            if let output = String(data: data, encoding: .utf8) {
                // Parse vm_stat output to calculate used memory
                let pageSize = 4096 // Default page size on macOS
                var freePages = 0
                
                let lines = output.components(separatedBy: "\n")
                for line in lines {
                    if line.contains("Pages free:") {
                        let components = line.components(separatedBy: ":")
                        if components.count > 1 {
                            let valueStr = components[1].trimmingCharacters(in: .whitespacesAndNewlines)
                                                      .replacingOccurrences(of: ".", with: "")
                            if let value = Int(valueStr) {
                                freePages = value
                            }
                        }
                    }
                }
                
                let freeRAM = Double(freePages * pageSize)
                let usedRAM = Double(totalRAM) - freeRAM
                usedRAMGB = String(format: "%.2f GB", usedRAM / 1_073_741_824)
            }
        } catch {
            print("Error getting RAM usage: \(error)")
        }
        
        // Get disk space info
        var diskTotal = "Unknown"
        var diskUsed = "Unknown"
        var diskFree = "Unknown"
        
        let fileManager = FileManager.default
        do {
            let systemAttributes = try fileManager.attributesOfFileSystem(forPath: "/")
            if let totalSize = systemAttributes[.systemSize] as? NSNumber,
               let freeSize = systemAttributes[.systemFreeSize] as? NSNumber {
                
                diskTotal = String(format: "%.2f GB", Double(totalSize.int64Value) / 1_073_741_824)
                diskFree = String(format: "%.2f GB", Double(freeSize.int64Value) / 1_073_741_824)
                diskUsed = String(format: "%.2f GB", Double(totalSize.int64Value - freeSize.int64Value) / 1_073_741_824)
            }
        } catch {
            print("Error getting disk space info: \(error)")
        }
        
        // Get installed applications
        var installedApps = [(name: String, version: String)]()
        let appsProcess = Process()
        appsProcess.launchPath = "/usr/bin/mdfind"
        appsProcess.arguments = ["kMDItemKind == 'Application'"]
        let appsPipe = Pipe()
        appsProcess.standardOutput = appsPipe
        
        do {
            try appsProcess.run()
            appsProcess.waitUntilExit()
            
            let data = appsPipe.fileHandleForReading.readDataToEndOfFile()
            if let output = String(data: data, encoding: .utf8) {
                let appPaths = output.components(separatedBy: "\n").filter { !$0.isEmpty }
                
                // Limit to 50 apps to avoid excessive output
                let limitedAppPaths = appPaths.prefix(50)
                
                for appPath in limitedAppPaths {
                    // Get app name from path
                    let appName = URL(fileURLWithPath: appPath).lastPathComponent.replacingOccurrences(of: ".app", with: "")
                    
                    // Get app version
                    let infoPath = appPath + "/Contents/Info.plist"
                    if let infoDict = NSDictionary(contentsOfFile: infoPath),
                       let version = infoDict["CFBundleShortVersionString"] as? String {
                        installedApps.append((name: appName, version: version))
                    } else {
                        installedApps.append((name: appName, version: "Unknown"))
                    }
                }
            }
        } catch {
            print("Error getting installed applications: \(error)")
        }
        
        // Get security settings
        var securitySettings = [String: String]()
        
        // Check FileVault status
        let fileVaultProcess = Process()
        fileVaultProcess.launchPath = "/usr/bin/fdesetup"
        fileVaultProcess.arguments = ["status"]
        let fileVaultPipe = Pipe()
        fileVaultProcess.standardOutput = fileVaultPipe
        
        do {
            try fileVaultProcess.run()
            fileVaultProcess.waitUntilExit()
            
            let data = fileVaultPipe.fileHandleForReading.readDataToEndOfFile()
            if let output = String(data: data, encoding: .utf8) {
                securitySettings["FileVault"] = output.trimmingCharacters(in: .whitespacesAndNewlines)
            }
        } catch {
            securitySettings["FileVault"] = "Error getting FileVault status"
        }
        
        // Check SIP status
        let sipProcess = Process()
        sipProcess.launchPath = "/usr/bin/csrutil"
        sipProcess.arguments = ["status"]
        let sipPipe = Pipe()
        sipProcess.standardOutput = sipPipe
        
        do {
            try sipProcess.run()
            sipProcess.waitUntilExit()
            
            let data = sipPipe.fileHandleForReading.readDataToEndOfFile()
            if let output = String(data: data, encoding: .utf8) {
                securitySettings["SIP"] = output.trimmingCharacters(in: .whitespacesAndNewlines)
            }
        } catch {
            securitySettings["SIP"] = "Error getting SIP status"
        }
        
        // Get hardware model
        var hardwareModel = "Unknown"
        let modelProcess = Process()
        modelProcess.launchPath = "/usr/sbin/sysctl"
        modelProcess.arguments = ["-n", "hw.model"]
        let modelPipe = Pipe()
        modelProcess.standardOutput = modelPipe
        
        do {
            try modelProcess.run()
            modelProcess.waitUntilExit()
            
            let data = modelPipe.fileHandleForReading.readDataToEndOfFile()
            if let output = String(data: data, encoding: .utf8) {
                hardwareModel = output.trimmingCharacters(in: .whitespacesAndNewlines)
            }
        } catch {
            print("Error getting hardware model: \(error)")
        }
        
        // The server needs a stable device key, not a hardware serial number.
        let serialNumber = "Redacted"
        
        // Get boot time
        var bootTime = "Unknown"
        let uptimeProcess = Process()
        uptimeProcess.launchPath = "/usr/bin/uptime"
        let uptimePipe = Pipe()
        uptimeProcess.standardOutput = uptimePipe
        
        do {
            try uptimeProcess.run()
            uptimeProcess.waitUntilExit()
            
            let data = uptimePipe.fileHandleForReading.readDataToEndOfFile()
            if let output = String(data: data, encoding: .utf8) {
                bootTime = output.trimmingCharacters(in: .whitespacesAndNewlines)
            }
        } catch {
            print("Error getting uptime: \(error)")
        }
        
        return SystemInfo(
            hostname: hostname,
            ipAddresses: ipAddresses,
            osVersion: osVersion,
            cpuInfo: cpuInfo,
            cpuCores: cpuCores,
            cpuThreads: cpuThreads,
            ramTotal: totalRAMGB,
            ramUsed: usedRAMGB,
            diskTotal: diskTotal,
            diskUsed: diskUsed,
            diskFree: diskFree,
            hardwareModel: hardwareModel,
            serialNumber: serialNumber,
            bootTime: bootTime,
            installedApps: installedApps,
            securitySettings: securitySettings
        )
    }
}

// Receipt files contain no credentials or check evidence. Missing receipts remain
// retryable after network failures or process exit, using the original report ID.
enum CISUploadOutbox {
    static func matchesWorkspace(_ data: Data, domain: String) -> Bool {
        guard !domain.isEmpty,
              let report = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let reportDomain = report["domain"] as? String else { return false }
        return reportDomain.lowercased() == domain.lowercased()
    }

    static func receiptURL(for report: URL) -> URL {
        report.appendingPathExtension("uploaded")
    }

    static func pendingReports(in directory: URL) throws -> [URL] {
        try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "json" && !FileManager.default.fileExists(atPath: receiptURL(for: $0).path) }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
    }

    static func recordReceipt(for report: URL) throws {
        let receipt = receiptURL(for: report)
        try Data(ISO8601DateFormatter().string(from: Date()).utf8).write(to: receipt, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: receipt.path)
    }
}

private final class CISUploadOutcome {
    private let lock = NSLock()
    private var value = false
    func recordAccepted() { lock.lock(); value = true; lock.unlock() }
    var accepted: Bool { lock.lock(); defer { lock.unlock() }; return value }
}
