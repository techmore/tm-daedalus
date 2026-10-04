import Foundation

// This file contains update and privacy-related checks for macOS
struct MacOSUpdateChecks {
    
    // MARK: - Software Updates
    
    // Check if Auto Update is enabled
    static func checkAutoUpdate(check: CISCheck, command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand) -> CheckResult {
        MacOSChecks.legacyBooleanPreference(check: check, domain: "/Library/Preferences/com.apple.SoftwareUpdate", key: "AutomaticCheckEnabled", expected: true, command: command)
    }
    
    // Check if Download New Updates When Available is enabled
    static func checkDownloadNewUpdates(check: CISCheck, command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand) -> CheckResult {
        MacOSChecks.legacyBooleanPreference(check: check, domain: "/Library/Preferences/com.apple.SoftwareUpdate", key: "AutomaticDownload", expected: true, command: command)
    }
    
    // Check if Install of macOS Updates is enabled
    static func checkInstallMacOSUpdates(check: CISCheck, command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand) -> CheckResult {
        MacOSChecks.legacyBooleanPreference(check: check, domain: "/Library/Preferences/com.apple.SoftwareUpdate", key: "AutomaticallyInstallMacOSUpdates", expected: true, command: command)
    }
    
    // Check if Install Application Updates from the App Store is enabled
    static func checkInstallAppStoreUpdates(check: CISCheck, command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand) -> CheckResult {
        MacOSChecks.legacyBooleanPreference(check: check, domain: "/Library/Preferences/com.apple.commerce", key: "AutoUpdate", expected: true, command: command)
    }
    
    // Check if Install Security Responses and System Files is enabled
    static func checkInstallSecurityResponses(check: CISCheck, command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand) -> CheckResult {
        MacOSChecks.legacyBooleanPreference(check: check, domain: "/Library/Preferences/com.apple.SoftwareUpdate", key: "ConfigDataInstall", expected: true, command: command)
    }
    
    // Check if Software Update Deferment is 30 days or less
    static func checkSoftwareUpdateDeferment(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/defaults"
        process.arguments = ["read", "/Library/Preferences/com.apple.SoftwareUpdate", "MaxDeferrals"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            // If the command fails, it likely means the setting doesn't exist, which is good (no deferment)
            return CheckResult(check: check, status: "pass", details: "Software Update Deferment appears to be not configured (default).")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        
        if let deferrals = Int(output), deferrals <= 30 {
            return CheckResult(check: check, status: "pass", details: "Software Update Deferment is set to \(deferrals) days.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Software Update Deferment is set to more than 30 days or is invalid.")
        }
    }
    
    // Check if all Apple-provided software is current
    static func checkAppleSoftwareCurrent(check: CISCheck,
        command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand
    ) -> CheckResult {
        let evidence = command("/usr/sbin/softwareupdate", ["-l"])
        func unknown() -> CheckResult {
            CheckResult(check: check, status: "manual", details: "A complete supported Software Update query was unavailable. A timeout, failed query or unsupported catalog response does not establish that software is current.")
        }
        guard evidence.unavailable == nil, evidence.exitCode == 0,
              evidence.output.utf8.count + evidence.error.utf8.count <= 65_536 else { return unknown() }
        let lines = (evidence.output + "\n" + evidence.error).components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
        let progress: Set<String> = ["Software Update Tool", "Finding available software"]
        let none: Set<String> = ["No new software available", "No new software available."]
        let noUpdateLines = lines.filter { none.contains($0) }
        if noUpdateLines.count == 1 && lines.allSatisfy({ progress.contains($0) || none.contains($0) }) {
            return CheckResult(check: check, status: "pass", details: "The completed Software Update query offered no new updates. This records the current catalog response, not exhaustive installed-software or patch compliance.")
        }
        let heading = "Software Update found the following new or updated software:"
        let labels = lines.filter { $0.hasPrefix("* Label: ") && $0.count > 9 && $0.count <= 512 }
        guard noUpdateLines.isEmpty, lines.filter({ $0 == heading }).count == 1, !labels.isEmpty, Set(labels).count == labels.count,
              lines.allSatisfy({ progress.contains($0) || $0 == heading || labels.contains($0) || ($0.hasPrefix("Title: ") && $0.count <= 2048) }) else { return unknown() }
        return CheckResult(check: check, status: "fail", details: "The completed Software Update query offered \(labels.count) update(s). No updates were installed; catalog availability can change.")
    }

    // MARK: - Privacy Settings
    
    // Check if Location Services is disabled
    static func checkLocationServicesDisabled(check: CISCheck, command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand) -> CheckResult {
        MacOSChecks.legacyBooleanPreference(check: check, domain: "/var/db/locationd/Library/Preferences/ByHost/com.apple.locationd", key: "LocationServicesEnabled", expected: false, command: command)
    }
    
    // Check if Sending diagnostic and usage data to Apple is disabled
    static func checkDiagnosticDataDisabled(check: CISCheck, command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand) -> CheckResult {
        MacOSChecks.legacyBooleanPreference(check: check, domain: "/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist", key: "AutoSubmit", expected: false, command: command)
    }
    
    // Check if Limit Ad Tracking is enabled
    static func checkLimitAdTracking(check: CISCheck, command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand) -> CheckResult {
        MacOSChecks.legacyBooleanPreference(check: check, domain: "com.apple.AdLib", key: "allowApplePersonalizedAdvertising", expected: false, command: command)
    }
    
    // Check if Siri is disabled
    static func checkSiriDisabled(check: CISCheck, command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand) -> CheckResult {
        MacOSChecks.legacyBooleanPreference(check: check, domain: "com.apple.assistant.support", key: "Assistant Enabled", expected: false, command: command)
    }
    
    // Check if Dictation is disabled
    static func checkDictationDisabled(check: CISCheck, command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand) -> CheckResult {
        MacOSChecks.legacyBooleanPreference(check: check, domain: "com.apple.HIToolbox", key: "AppleDictationAutoEnable", expected: false, command: command)
    }
    
    // Check if Spotlight Suggestions are disabled
    static func checkSpotlightSuggestionsDisabled(check: CISCheck, command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand) -> CheckResult {
        MacOSChecks.legacyBooleanPreference(check: check, domain: "com.apple.spotlight", key: "WebSearchEnabled", expected: false, command: command)
    }
}
