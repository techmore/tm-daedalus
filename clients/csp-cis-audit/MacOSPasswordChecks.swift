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
    static func checkPasswordMinAge(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/pwpolicy"
        process.arguments = ["getaccountpolicies"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check password minimum age: \(error)")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        
        if output.contains("minMinutesUntilChangePassword") {
            // Extract the value
            if let range = output.range(of: "minMinutesUntilChangePassword\\s*=\\s*\\d+", options: .regularExpression),
               let valueRange = output[range].range(of: "\\d+", options: .regularExpression) {
                let value = output[range][valueRange]
                if let minutes = Int(value) {
                    let days = minutes / 1440 // Convert minutes to days
                    if days >= 1 {
                        return CheckResult(check: check, status: "pass", details: "Password minimum age is configured to \(days) days.")
                    } else {
                        return CheckResult(check: check, status: "fail", details: "Password minimum age is configured but less than 1 day.")
                    }
                }
            }
            return CheckResult(check: check, status: "pass", details: "Password minimum age is configured.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Password minimum age is NOT configured.")
        }
    }
    
    // Check if login keychain is locked when system sleeps
    static func checkLoginKeychainLocked(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/security"
        process.arguments = ["show-keychain-info", "/Users/\(NSUserName())/Library/Keychains/login.keychain-db"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check login keychain: \(error)")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        
        if output.contains("lock-on-sleep") || output.contains("timeout=") {
            return CheckResult(check: check, status: "pass", details: "Login keychain is locked when system sleeps.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Login keychain is NOT locked when system sleeps.")
        }
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
