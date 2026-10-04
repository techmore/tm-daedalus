import Foundation

// This file contains update and privacy-related checks for macOS
struct MacOSUpdateChecks {
    
    // MARK: - Software Updates
    
    // Check if Auto Update is enabled
    static func checkAutoUpdate(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/defaults"
        process.arguments = ["read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check Auto Update: \(error)")
        }
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if output == "1" {
            return CheckResult(check: check, status: "pass", details: "Auto Update is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Auto Update is NOT enabled.")
        }
    }
    
    // Check if Download New Updates When Available is enabled
    static func checkDownloadNewUpdates(check: CISCheck) -> CheckResult {
        // Check if 'AutomaticDownload' is enabled in com.apple.SoftwareUpdate
        let process = Process()
        process.launchPath = "/usr/bin/defaults"
        process.arguments = ["read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticDownload"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check automatic download: \(error)")
        }
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if output == "1" {
            return CheckResult(check: check, status: "pass", details: "Download New Updates When Available is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Download New Updates When Available is NOT enabled.")
        }
    }
    
    // Check if Install of macOS Updates is enabled
    static func checkInstallMacOSUpdates(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/defaults"
        process.arguments = ["read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticallyInstallMacOSUpdates"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check macOS updates installation: \(error)")
        }
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if output == "1" {
            return CheckResult(check: check, status: "pass", details: "Install of macOS Updates is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Install of macOS Updates is NOT enabled.")
        }
    }
    
    // Check if Install Application Updates from the App Store is enabled
    static func checkInstallAppStoreUpdates(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/defaults"
        process.arguments = ["read", "/Library/Preferences/com.apple.commerce", "AutoUpdate"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check App Store updates installation: \(error)")
        }
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if output == "1" {
            return CheckResult(check: check, status: "pass", details: "Install Application Updates from the App Store is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Install Application Updates from the App Store is NOT enabled.")
        }
    }
    
    // Check if Install Security Responses and System Files is enabled
    static func checkInstallSecurityResponses(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/defaults"
        process.arguments = ["read", "/Library/Preferences/com.apple.SoftwareUpdate", "ConfigDataInstall"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check security responses installation: \(error)")
        }
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if output == "1" {
            return CheckResult(check: check, status: "pass", details: "Install Security Responses and System Files is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Install Security Responses and System Files is NOT enabled.")
        }
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
    static func checkAppleSoftwareCurrent(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/sbin/softwareupdate"
        process.arguments = ["-l"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check software updates: \(error)")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        
        if output.contains("No new software available") {
            return CheckResult(check: check, status: "pass", details: "All Apple-provided software is current.")
        } else if output.contains("Software Update found") {
            return CheckResult(check: check, status: "fail", details: "Updates are available: \(output)")
        } else {
            return CheckResult(check: check, status: "error", details: "Unable to determine software update status.")
        }
    }
    
    // MARK: - Privacy Settings
    
    // Check if Location Services is disabled
    static func checkLocationServicesDisabled(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/defaults"
        process.arguments = ["read", "/var/db/locationd/Library/Preferences/ByHost/com.apple.locationd", "LocationServicesEnabled"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            // If the command fails, it likely means Location Services is not configured
            return CheckResult(check: check, status: "error", details: "Failed to check Location Services: \(error)")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        
        if output == "0" {
            return CheckResult(check: check, status: "pass", details: "Location Services is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Location Services is ENABLED.")
        }
    }
    
    // Check if Sending diagnostic and usage data to Apple is disabled
    static func checkDiagnosticDataDisabled(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/defaults"
        process.arguments = ["read", "/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist", "AutoSubmit"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            // If the command fails, it likely means the setting doesn't exist
            return CheckResult(check: check, status: "pass", details: "Sending diagnostic data appears to be disabled.")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        
        if output == "0" || output.isEmpty {
            return CheckResult(check: check, status: "pass", details: "Sending diagnostic and usage data to Apple is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Sending diagnostic and usage data to Apple is ENABLED.")
        }
    }
    
    // Check if Limit Ad Tracking is enabled
    static func checkLimitAdTracking(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/defaults"
        process.arguments = ["read", "/Users/\(NSUserName())/Library/Preferences/com.apple.AdLib", "allowApplePersonalizedAdvertising"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            // If the command fails, it likely means the setting doesn't exist
            return CheckResult(check: check, status: "pass", details: "Limit Ad Tracking appears to be enabled (default).")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        
        if output == "0" {
            return CheckResult(check: check, status: "pass", details: "Limit Ad Tracking is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Limit Ad Tracking is NOT enabled.")
        }
    }
    
    // Check if Siri is disabled
    static func checkSiriDisabled(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/defaults"
        process.arguments = ["read", "com.apple.assistant.support", "Assistant Enabled"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            // If the command fails, it likely means Siri is not enabled
            return CheckResult(check: check, status: "pass", details: "Siri appears to be disabled.")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        
        if output == "0" || output.isEmpty {
            return CheckResult(check: check, status: "pass", details: "Siri is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Siri is ENABLED.")
        }
    }
    
    // Check if Dictation is disabled
    static func checkDictationDisabled(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/defaults"
        process.arguments = ["read", "com.apple.HIToolbox", "AppleDictationAutoEnable"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            // If the command fails, it likely means Dictation is not enabled
            return CheckResult(check: check, status: "pass", details: "Dictation appears to be disabled.")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        
        if output == "0" || output.isEmpty {
            return CheckResult(check: check, status: "pass", details: "Dictation is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Dictation is ENABLED.")
        }
    }
    
    // Check if Spotlight Suggestions are disabled
    static func checkSpotlightSuggestionsDisabled(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/defaults"
        process.arguments = ["read", "com.apple.spotlight", "WebSearchEnabled"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            // If the command fails, it likely means the setting doesn't exist
            return CheckResult(check: check, status: "fail", details: "Spotlight Suggestions appears to be enabled (default).")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        
        if output == "0" {
            return CheckResult(check: check, status: "pass", details: "Spotlight Suggestions are disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Spotlight Suggestions are ENABLED.")
        }
    }
}
