import Foundation

// This file contains password policy and authentication-related checks for macOS
struct MacOSPasswordChecks {
    
    // MARK: - Password Policies
    
    // Check if password account lockout threshold is configured
    static func checkPasswordLockoutThreshold(check: CISCheck,
        command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand
    ) -> CheckResult {
        let mapped = CISCheck(id: check.id, category: check.category, description: check.description, ruleID: "pwpolicy_account_lockout_enforce")
        let evidence = MacOSChecks.runAdditionalTahoeCommand(check: mapped, command: command, legacyPasswordCriteria: true)
        return CheckResult(check: check, status: evidence.status, details: evidence.details)
    }
    
    // Check if password minimum length is configured
    static func checkPasswordMinLength(check: CISCheck,
        command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand
    ) -> CheckResult {
        let mapped = CISCheck(id: check.id, category: check.category, description: check.description, ruleID: "pwpolicy_minimum_length_enforce")
        let evidence = MacOSChecks.runAdditionalTahoeCommand(check: mapped, command: command, legacyPasswordCriteria: true)
        return CheckResult(check: check, status: evidence.status, details: evidence.details)
    }
    
    // Check if password complexity is configured
    static func checkPasswordComplexity(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/pwpolicy"
        process.arguments = ["getaccountpolicies"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check password complexity: \(error)")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        
        let complexityPatterns = [
            "requiresAlpha", "requiresNumeric", "requiresSymbol", "requiresMixedCase",
            "policyAttributePassword matches '.*[a-zA-Z].*'",
            "policyAttributePassword matches '.*[0-9].*'",
            "policyAttributePassword matches '.*[^a-zA-Z0-9].*'"
        ]
        
        var foundPatterns: [String] = []
        for pattern in complexityPatterns {
            if output.contains(pattern) {
                foundPatterns.append(pattern)
            }
        }
        
        if foundPatterns.count >= 3 {
            return CheckResult(check: check, status: "pass", details: "Password complexity is properly configured with \(foundPatterns.count) requirements.")
        } else if !foundPatterns.isEmpty {
            return CheckResult(check: check, status: "fail", details: "Password complexity is configured but does not meet minimum requirements.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Password complexity is NOT configured.")
        }
    }
    
    // Check if password history is configured
    static func checkPasswordHistory(check: CISCheck,
        command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand
    ) -> CheckResult {
        let mapped = CISCheck(id: check.id, category: check.category, description: check.description, ruleID: "pwpolicy_history_enforce")
        let evidence = MacOSChecks.runAdditionalTahoeCommand(check: mapped, command: command, legacyPasswordCriteria: true)
        return CheckResult(check: check, status: evidence.status, details: evidence.details)
    }
    
    // Check if password maximum age is configured
    static func checkPasswordMaxAge(check: CISCheck,
        command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand
    ) -> CheckResult {
        let mapped = CISCheck(id: check.id, category: check.category, description: check.description, ruleID: "pwpolicy_max_lifetime_enforce")
        let evidence = MacOSChecks.runAdditionalTahoeCommand(check: mapped, command: command, legacyPasswordCriteria: true)
        return CheckResult(check: check, status: evidence.status, details: evidence.details)
    }
    
    // Check if password minimum age is configured
    static func checkPasswordMinAge(check: CISCheck,
        command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand
    ) -> CheckResult {
        let evidence = command("/usr/bin/pwpolicy", ["-getglobalpolicy"])
        func unknown() -> CheckResult {
            CheckResult(check: check, status: "manual", details: "A supported explicit legacy minimum password age was not available. Modern account-policy enforcement and directory accounts require separate review.")
        }
        guard evidence.unavailable == nil, evidence.exitCode == 0,
              evidence.error.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              evidence.output.utf8.count <= 65_536 else { return unknown() }
        let tokens = evidence.output.split(whereSeparator: { $0.isWhitespace })
        guard !tokens.isEmpty, tokens.count <= 1_000 else { return unknown() }
        var values: [String: String] = [:]
        for token in tokens {
            let parts = token.split(separator: "=", omittingEmptySubsequences: false)
            guard parts.count == 2, !parts[0].isEmpty, !parts[1].isEmpty,
                  parts[0].allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "_") }),
                  values[String(parts[0])] == nil else { return unknown() }
            values[String(parts[0])] = String(parts[1])
        }
        guard let raw = values["minMinutesUntilChangePassword"],
              let minutes = Int(raw), minutes >= 0, minutes <= 5_256_000,
              String(minutes) == raw else { return unknown() }
        return CheckResult(check: check, status: minutes >= 1_440 ? "pass" : "fail",
            details: "Captured legacy minimum password age: \(minutes) minutes; legacy criterion is at least 1440 minutes. This evaluates the reported legacy field only, not modern account-policy or directory enforcement.")
    }

    // Check if login keychain is locked when system sleeps
    static func checkLoginKeychainLocked(check: CISCheck,
        command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand,
        homeDirectory: String = NSHomeDirectory()
    ) -> CheckResult {
        func unknown() -> CheckResult {
            CheckResult(check: check, status: "manual", details: "Login keychain sleep-lock settings were unavailable or unsupported. No state is inferred from a timeout or failed read.")
        }
        guard homeDirectory.hasPrefix("/"), !homeDirectory.contains("\""),
              !homeDirectory.contains("\n"), !homeDirectory.contains("\r") else { return unknown() }
        let path = URL(fileURLWithPath: homeDirectory).appendingPathComponent("Library/Keychains/login.keychain-db").path
        let evidence = command("/usr/bin/security", ["show-keychain-info", path])
        guard evidence.unavailable == nil, evidence.exitCode == 0,
              evidence.output.utf8.count + evidence.error.utf8.count <= 16_384 else { return unknown() }
        let stdout = evidence.output.trimmingCharacters(in: .whitespacesAndNewlines)
        let stderr = evidence.error.trimmingCharacters(in: .whitespacesAndNewlines)
        // Apple's tool writes successful settings to stderr. Never merge an error
        // message with a settings line or interpret unrelated keychain metadata.
        guard stdout.isEmpty || stderr.isEmpty else { return unknown() }
        let value = stdout.isEmpty ? stderr : stdout
        let prefix = "Keychain \"" + path + "\""
        guard value.hasPrefix(prefix) else { return unknown() }
        let flags = String(value.dropFirst(prefix.count))
        guard flags.range(of: #"^( lock-on-sleep)?( use-lock-interval)? (no-timeout|timeout=(0|[1-9][0-9]{0,9})s)$"#, options: .regularExpression) != nil else { return unknown() }
        if let timeout = flags.split(separator: " ").last, timeout.hasPrefix("timeout=") {
            guard let seconds = Int(timeout.dropFirst(8).dropLast()), seconds < Int(Int32.max) else { return unknown() }
        }
        let enabled = flags.split(separator: " ").contains("lock-on-sleep")
        return CheckResult(check: check, status: enabled ? "pass" : "fail",
            details: "Current user's login keychain reports sleep locking " + (enabled ? "enabled." : "disabled.") + " Timeout settings are evaluated separately. This is captured configuration, not a live sleep/unlock test or an assessment of other users.")
    }

    // MARK: - File Permissions
    
    // Check if users' home directories permissions are 750 or more restrictive
    static func checkHomeDirectoryPermissions(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/find"
        process.arguments = ["/Users", "-mindepth", "1", "-maxdepth", "1", "-type", "d", "-perm", "-751", "-ls"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check home directory permissions: \(error)")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        
        if output.isEmpty {
            return CheckResult(check: check, status: "pass", details: "All users' home directories have permissions 750 or more restrictive.")
        } else {
            let lines = output.split(separator: "\n")
            return CheckResult(check: check, status: "fail", details: "Found \(lines.count) home directories with permissions less restrictive than 750.")
        }
    }
    
    // Check if users' dot-files permissions are 750 or more restrictive
    static func checkDotFilePermissions(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/find"
        process.arguments = ["/Users", "-name", ".*", "-type", "f", "-perm", "-751", "-ls"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check dot-file permissions: \(error)")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        
        if output.isEmpty {
            return CheckResult(check: check, status: "pass", details: "All users' dot-files have permissions 750 or more restrictive.")
        } else {
            let lines = output.split(separator: "\n")
            return CheckResult(check: check, status: "fail", details: "Found \(lines.count) dot-files with permissions less restrictive than 750.")
        }
    }
    
    // Check if users' .ssh directory permissions are 700 or more restrictive
    static func checkSSHDirectoryPermissions(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/find"
        process.arguments = ["/Users", "-name", ".ssh", "-type", "d", "-perm", "-701", "-ls"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check .ssh directory permissions: \(error)")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        
        if output.isEmpty {
            return CheckResult(check: check, status: "pass", details: "All users' .ssh directories have permissions 700 or more restrictive.")
        } else {
            let lines = output.split(separator: "\n")
            return CheckResult(check: check, status: "fail", details: "Found \(lines.count) .ssh directories with permissions less restrictive than 700.")
        }
    }
    
    // Check if users' .ssh/config permissions are 600 or more restrictive
    static func checkSSHConfigPermissions(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/find"
        process.arguments = ["/Users", "-name", "config", "-path", "*/.ssh/*", "-type", "f", "-perm", "-601", "-ls"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check .ssh/config permissions: \(error)")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        
        if output.isEmpty {
            return CheckResult(check: check, status: "pass", details: "All users' .ssh/config files have permissions 600 or more restrictive.")
        } else {
            let lines = output.split(separator: "\n")
            return CheckResult(check: check, status: "fail", details: "Found \(lines.count) .ssh/config files with permissions less restrictive than 600.")
        }
    }
    
    // Check if users' .ssh/authorized_keys permissions are 600 or more restrictive
    static func checkSSHAuthorizedKeysPermissions(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/find"
        process.arguments = ["/Users", "-name", "authorized_keys", "-path", "*/.ssh/*", "-type", "f", "-perm", "-601", "-ls"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check .ssh/authorized_keys permissions: \(error)")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        
        if output.isEmpty {
            return CheckResult(check: check, status: "pass", details: "All users' .ssh/authorized_keys files have permissions 600 or more restrictive.")
        } else {
            let lines = output.split(separator: "\n")
            return CheckResult(check: check, status: "fail", details: "Found \(lines.count) .ssh/authorized_keys files with permissions less restrictive than 600.")
        }
    }
}
