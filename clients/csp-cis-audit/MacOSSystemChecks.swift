import Foundation

// This file contains system-level checks for macOS
struct MacOSSystemChecks {
    
    // MARK: - System Integrity and Security
    
    // Check if System Integrity Protection is enabled
    static func checkSIPEnabled(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/csrutil"
        process.arguments = ["status"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check System Integrity Protection status: \(error)")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        if output.contains("System Integrity Protection status: enabled") {
            return CheckResult(check: check, status: "pass", details: "System Integrity Protection is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "System Integrity Protection is NOT enabled.")
        }
    }
    
    // Check if Apple Mobile File Integrity is enabled
    static func checkAMFIEnabled(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/sbin/nvram"
        process.arguments = ["-p"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check AMFI status: \(error)")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        
        // If amfi_get_out_of_my_way=1 is set, AMFI is disabled
        if output.contains("amfi_get_out_of_my_way") {
            return CheckResult(check: check, status: "fail", details: "Apple Mobile File Integrity is NOT enabled.")
        } else {
            return CheckResult(check: check, status: "pass", details: "Apple Mobile File Integrity is enabled.")
        }
    }
    
    // Check if Sealed System Volume is enabled
    static func checkSSVEnabled(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/csrutil"
        process.arguments = ["authenticated-root", "status"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check Sealed System Volume status: \(error)")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        if output.contains("enabled") {
            return CheckResult(check: check, status: "pass", details: "Sealed System Volume is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Sealed System Volume is NOT enabled.")
        }
    }
    
    // Check if Gatekeeper is enabled
    static func checkGatekeeperEnabled(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/sbin/spctl"
        process.arguments = ["--status"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check Gatekeeper status: \(error)")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        if output.contains("assessments enabled") {
            return CheckResult(check: check, status: "pass", details: "Gatekeeper is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Gatekeeper is NOT enabled.")
        }
    }
    
    // Check if FileVault is enabled
    static func checkFileVaultEnabled(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/fdesetup"
        process.arguments = ["status"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check FileVault status: \(error)")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        if output.contains("FileVault is On") {
            return CheckResult(check: check, status: "pass", details: "FileVault is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "FileVault is NOT enabled.")
        }
    }
    
    // Check if Secure Keyboard Entry in Terminal.app is enabled
    static func checkSecureKeyboardEntry(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/defaults"
        process.arguments = ["read", "com.apple.Terminal", "SecureKeyboardEntry"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check Secure Keyboard Entry: \(error)")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if output == "1" {
            return CheckResult(check: check, status: "pass", details: "Secure Keyboard Entry in Terminal.app is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Secure Keyboard Entry in Terminal.app is NOT enabled.")
        }
    }
    
    // MARK: - Security Auditing
    
    // Check if security auditing is enabled
    static func checkSecurityAuditingEnabled(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/bin/launchctl"
        process.arguments = ["list", "com.apple.auditd"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check security auditing: \(error)")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        if output.contains("com.apple.auditd") {
            return CheckResult(check: check, status: "pass", details: "Security auditing is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Security auditing is NOT enabled.")
        }
    }
    
    // Check if security auditing flags are configured for startup and time changes
    static func checkAuditFlagsStartup(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/sudo"
        process.arguments = ["-n", "/usr/bin/grep", "flags", "/etc/security/audit_control"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check audit flags: \(error)")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        
        if output.contains("aa") || output.contains("ad") {
            return CheckResult(check: check, status: "pass", details: "Security auditing flags are properly configured for startup and time changes.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Security auditing flags are NOT properly configured for startup and time changes.")
        }
    }
    
    // Check if security auditing flags are configured for system-wide settings
    static func checkAuditFlagsSystemWide(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/sudo"
        process.arguments = ["-n", "/usr/bin/grep", "flags", "/etc/security/audit_control"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check audit flags: \(error)")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        
        if output.contains("lo") {
            return CheckResult(check: check, status: "pass", details: "Security auditing flags are properly configured for system-wide settings.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Security auditing flags are NOT properly configured for system-wide settings.")
        }
    }
    
    // Check if security auditing flags are configured for authentication and authorization
    static func checkAuditFlagsAuth(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/sudo"
        process.arguments = ["-n", "/usr/bin/grep", "flags", "/etc/security/audit_control"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check audit flags: \(error)")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        
        if output.contains("am") || output.contains("aa") {
            return CheckResult(check: check, status: "pass", details: "Security auditing flags are properly configured for authentication and authorization.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Security auditing flags are NOT properly configured for authentication and authorization.")
        }
    }
    
    // Check if security auditing flags are configured for file system events
    static func checkAuditFlagsFileSystem(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/sudo"
        process.arguments = ["-n", "/usr/bin/grep", "flags", "/etc/security/audit_control"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check audit flags: \(error)")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        
        if output.contains("fd") || output.contains("fw") {
            return CheckResult(check: check, status: "pass", details: "Security auditing flags are properly configured for file system events.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Security auditing flags are NOT properly configured for file system events.")
        }
    }
    
    // Check if security auditing flags are configured for user events
    static func checkAuditFlagsUserEvents(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/sudo"
        process.arguments = ["-n", "/usr/bin/grep", "flags", "/etc/security/audit_control"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check audit flags: \(error)")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        
        if output.contains("lo") || output.contains("ex") {
            return CheckResult(check: check, status: "pass", details: "Security auditing flags are properly configured for user events.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Security auditing flags are NOT properly configured for user events.")
        }
    }
    
    // Check if security auditing flags are configured for network events
    static func checkAuditFlagsNetworkEvents(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/sudo"
        process.arguments = ["-n", "/usr/bin/grep", "flags", "/etc/security/audit_control"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check audit flags: \(error)")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        
        if output.contains("ip") || output.contains("nt") {
            return CheckResult(check: check, status: "pass", details: "Security auditing flags are properly configured for network events.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Security auditing flags are NOT properly configured for network events.")
        }
    }
    
    // Check if security auditing flags are configured for process events
    static func checkAuditFlagsProcessEvents(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/sudo"
        process.arguments = ["-n", "/usr/bin/grep", "flags", "/etc/security/audit_control"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check audit flags: \(error)")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        
        if output.contains("ex") || output.contains("pc") {
            return CheckResult(check: check, status: "pass", details: "Security auditing flags are properly configured for process events.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Security auditing flags are NOT properly configured for process events.")
        }
    }
    
    // Check if security auditing retention is configured
    static func checkAuditRetention(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/sudo"
        process.arguments = ["-n", "/usr/bin/grep", "expire-after", "/etc/security/audit_control"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check audit retention: \(error)")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        
        if !output.isEmpty {
            // Check if retention is at least 7 days (604800 seconds)
            if let range = output.range(of: "\\d+", options: .regularExpression),
               let seconds = Int(output[range]) {
                if seconds >= 604800 {
                    return CheckResult(check: check, status: "pass", details: "Security auditing retention is configured for at least 7 days.")
                } else {
                    return CheckResult(check: check, status: "fail", details: "Security auditing retention is configured but for less than 7 days.")
                }
            }
            return CheckResult(check: check, status: "pass", details: "Security auditing retention is configured.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Security auditing retention is NOT configured.")
        }
    }
    
    // Check if login items are not added
    static func checkLoginItemsNotAdded(check: CISCheck) -> CheckResult {
        let homeDir = FileManager.default.homeDirectoryForCurrentUser
        let plistPath = homeDir.appendingPathComponent("Library/Preferences/com.apple.loginitems.plist").path
        
        guard FileManager.default.fileExists(atPath: plistPath) else {
            // If the file doesn't exist, there are no login items
            return CheckResult(check: check, status: "pass", details: "No login items are configured.")
        }
        
        guard let plist = NSDictionary(contentsOfFile: plistPath),
              let items = plist["SessionItems"] as? [String: Any],
              let customListItems = items["CustomListItems"] as? [[String: Any]] else {
            // If we can't read the plist or it doesn't have the expected structure, assume no login items
            return CheckResult(check: check, status: "pass", details: "No login items appear to be configured.")
        }
        
        if customListItems.isEmpty {
            return CheckResult(check: check, status: "pass", details: "No login items are configured.")
        } else {
            return CheckResult(check: check, status: "fail", details: "\(customListItems.count) login items are configured.")
        }
    }
    
    // Check if Secure Empty Trash is enabled
    static func checkSecureEmptyTrash(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/defaults"
        process.arguments = ["read", "com.apple.finder", "EmptyTrashSecurely"]
        
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        
        do {
            try process.run()
        } catch {
            // If the command fails, it might be because the setting doesn't exist, which means it's not enabled
            return CheckResult(check: check, status: "fail", details: "Secure Empty Trash is not enabled.")
        }
        
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        
        if output.contains("1") {
            return CheckResult(check: check, status: "pass", details: "Secure Empty Trash is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Secure Empty Trash is not enabled.")
        }
    }
}
