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
    static func checkPasswordComplexity(check: CISCheck,
        command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand
    ) -> CheckResult {
        func unknown() -> CheckResult {
            CheckResult(check: check, status: "manual", details: "Complete explicit legacy complexity fields were unavailable. Modern account-policy predicates and directory enforcement require separate review.")
        }
        guard let values = legacyGlobalPolicy(command: command) else { return unknown() }
        let keys = ["requiresAlpha", "requiresNumeric", "requiresSymbol", "requiresMixedCase"]
        var enabled = 0
        for key in keys {
            guard let value = values[key], value == "0" || value == "1" else { return unknown() }
            if value == "1" { enabled += 1 }
        }
        return CheckResult(check: check, status: enabled >= 3 ? "pass" : "fail",
            details: "Captured legacy complexity fields: \(enabled) of 4 enabled; existing legacy criterion is at least 3 distinct fields. This does not evaluate modern account-policy predicates, password acceptance or directory enforcement.")
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
    
    private static func legacyGlobalPolicy(
        command: (String, [String]) -> MacOSChecks.CommandEvidence
    ) -> [String: String]? {
        let evidence = command("/usr/bin/pwpolicy", ["-getglobalpolicy"])
        guard evidence.unavailable == nil, evidence.exitCode == 0,
              evidence.error.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              evidence.output.utf8.count <= 65_536 else { return nil }
        let tokens = evidence.output.split(whereSeparator: { $0.isWhitespace })
        guard !tokens.isEmpty, tokens.count <= 1_000 else { return nil }
        var values: [String: String] = [:]
        for token in tokens {
            let parts = token.split(separator: "=", omittingEmptySubsequences: false)
            guard parts.count == 2, !parts[0].isEmpty, !parts[1].isEmpty,
                  parts[0].allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "_") }),
                  values[String(parts[0])] == nil else { return nil }
            values[String(parts[0])] = String(parts[1])
        }
        return values
    }

    // Check if password minimum age is configured
    static func checkPasswordMinAge(check: CISCheck,
        command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand
    ) -> CheckResult {
        func unknown() -> CheckResult {
            CheckResult(check: check, status: "manual", details: "A supported explicit legacy minimum password age was not available. Modern account-policy enforcement and directory accounts require separate review.")
        }
        guard let values = legacyGlobalPolicy(command: command) else { return unknown() }
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
    
    // Read every matching mode, rather than selecting only files with all
    // bits in an unsafe mask. Never include filesystem paths in report details.
    private static func legacyPermissions(check: CISCheck, selection: [String], allowed: Int,
        command: (String, [String]) -> MacOSChecks.CommandEvidence
    ) -> CheckResult {
        let evidence = command("/usr/bin/find", ["/Users"] + selection + ["-exec", "/usr/bin/stat", "-f", "%Lp", "{}", "+"])
        func unknown() -> CheckResult {
            CheckResult(check: check, status: "manual", details: "Complete readable mode evidence was unavailable for the selected /Users scope. Missing, failed or truncated enumeration does not establish compliant permissions.")
        }
        guard evidence.unavailable == nil, evidence.exitCode == 0,
              evidence.error.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              evidence.output.utf8.count <= 65_536 else { return unknown() }
        let lines = evidence.output.split(separator: "\n", omittingEmptySubsequences: false)
        let rows = lines.last == "" ? Array(lines.dropLast()) : lines
        guard !rows.isEmpty, rows.count <= 5_000 else { return unknown() }
        var violations = 0
        for row in rows {
            guard !row.isEmpty, row.count <= 4,
                  row.allSatisfy({ "01234567".contains($0) }),
                  let mode = Int(row, radix: 8), mode <= 0o7777 else { return unknown() }
            if mode & ~allowed != 0 { violations += 1 }
        }
        return CheckResult(check: check, status: violations == 0 ? "pass" : "fail",
            details: "Captured modes for \(rows.count) matching entries in the local /Users scope; \(violations) exceed the allowed legacy permission mask. Other home-directory locations, ACLs, ownership and subsequent changes require separate review.")
    }

    static func checkHomeDirectoryPermissions(check: CISCheck,
        command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand
    ) -> CheckResult {
        legacyPermissions(check: check, selection: ["-mindepth", "1", "-maxdepth", "1", "-type", "d"], allowed: 0o750, command: command)
    }
    static func checkDotFilePermissions(check: CISCheck,
        command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand
    ) -> CheckResult {
        legacyPermissions(check: check, selection: ["-name", ".*", "-type", "f"], allowed: 0o750, command: command)
    }
    static func checkSSHDirectoryPermissions(check: CISCheck,
        command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand
    ) -> CheckResult {
        legacyPermissions(check: check, selection: ["-name", ".ssh", "-type", "d"], allowed: 0o700, command: command)
    }
    static func checkSSHConfigPermissions(check: CISCheck,
        command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand
    ) -> CheckResult {
        legacyPermissions(check: check, selection: ["-name", "config", "-path", "*/.ssh/*", "-type", "f"], allowed: 0o600, command: command)
    }
    static func checkSSHAuthorizedKeysPermissions(check: CISCheck,
        command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand
    ) -> CheckResult {
        legacyPermissions(check: check, selection: ["-name", "authorized_keys", "-path", "*/.ssh/*", "-type", "f"], allowed: 0o600, command: command)
    }
}
