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
    static func checkSecurityAuditingEnabled(
        check: CISCheck,
        command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand
    ) -> CheckResult {
        MacOSChecks.checkAuditServiceEnabled(check: check, command: command)
    }

    // Read the fixed audit policy without privilege escalation or uploading its contents.
    static func auditPolicyField(_ field: String, readControl: (URL) -> Data?) -> String? {
        guard let data = readControl(URL(fileURLWithPath: "/etc/security/audit_control")),
              data.count <= MacOSChecks.auditControlMaximumBytes,
              let text = String(data: data, encoding: .utf8) else { return nil }
        let values = text.components(separatedBy: .newlines).compactMap { line -> String? in
            let value = line.components(separatedBy: "#")[0].trimmingCharacters(in: .whitespaces)
            guard value.hasPrefix(field + ":") else { return nil }
            return String(value.dropFirst(field.count + 1)).trimmingCharacters(in: .whitespaces)
        }
        guard values.count == 1, !values[0].isEmpty else { return nil }
        return values[0]
    }

    static func checkAuditFlags(
        check: CISCheck, classes: Set<String>,
        readControl: (URL) -> Data? = MacOSChecks.readAuditControl
    ) -> CheckResult {
        func result(_ state: String, _ detail: String) -> CheckResult {
            CheckResult(check: check, status: state, details: detail)
        }
        guard let field = auditPolicyField("flags", readControl: readControl) else {
            return result("manual", "Audit flags were missing, inaccessible or duplicated; selection was not inferred.")
        }
        let tokens = field.components(separatedBy: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        let known: Set<String> = ["no","fr","fw","fa","fm","fc","fd","cl","pc","nt","ip","na","ad","lo","aa","ap","res","io","ex","ot","all"]
        guard tokens.allSatisfy({ known.contains($0) }), Set(tokens).count == tokens.count else {
            return result("manual", "Audit flags contain unknown, prefixed or duplicate selections requiring review.")
        }
        let selected = Set(tokens)
        let enabled = selected.contains("all") || !selected.intersection(classes).isEmpty
        return result(enabled ? "pass" : "fail", "CSP criterion: at least one required event class must select both successful and failed events. This does not attest complete event coverage or active kernel auditing.")
    }

    static func checkAuditFlagsStartup(check: CISCheck) -> CheckResult {
        checkAuditFlags(check: check, classes: ["ad"])
    }

    static func checkAuditFlagsSystemWide(check: CISCheck) -> CheckResult {
        checkAuditFlags(check: check, classes: ["ad"])
    }

    static func checkAuditFlagsAuth(check: CISCheck) -> CheckResult {
        checkAuditFlags(check: check, classes: ["aa"])
    }

    static func checkAuditFlagsFileSystem(check: CISCheck) -> CheckResult {
        checkAuditFlags(check: check, classes: ["fr", "fw", "fa", "fm", "fc", "fd", "cl"])
    }

    static func checkAuditFlagsUserEvents(check: CISCheck) -> CheckResult {
        checkAuditFlags(check: check, classes: ["lo"])
    }

    static func checkAuditFlagsNetworkEvents(check: CISCheck) -> CheckResult {
        checkAuditFlags(check: check, classes: ["nt"])
    }

    static func checkAuditFlagsProcessEvents(check: CISCheck) -> CheckResult {
        checkAuditFlags(check: check, classes: ["pc", "ex"])
    }

    static func checkAuditRetention(
        check: CISCheck, readControl: (URL) -> Data? = MacOSChecks.readAuditControl
    ) -> CheckResult {
        guard let value = auditPolicyField("expire-after", readControl: readControl),
              value.range(of: "^[0-9]{1,12}[shdy]$", options: .regularExpression) != nil,
              let number = Double(value.dropLast()), let unit = value.last else {
            return CheckResult(check: check, status: "manual", details: "Audit expiration was missing, inaccessible or unsupported. Combined age/size conditions require manual review; no retention duration was inferred.")
        }
        let units: [Character: Double] = ["s":1,"h":3600,"d":86400,"y":31536000]
        let days = number * (units[unit] ?? 0) / 86400
        return CheckResult(check: check, status: days >= 7 ? "pass" : "fail",
            details: "CSP criterion: the explicit age-only audit expiration must be at least seven days. This checks policy, not the presence or age of retained audit records.")
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
