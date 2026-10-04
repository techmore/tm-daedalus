import Foundation

// This file contains user account and login-related checks for macOS
struct MacOSUserChecks {
    
    // MARK: - Login Window and User Account Settings
    
    static func checkGuestAccountDisabled(check: CISCheck, command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand) -> CheckResult {
        MacOSChecks.legacyBooleanPreference(check: check, domain: "/Library/Preferences/com.apple.loginwindow", key: "GuestEnabled", expected: false, command: command)
    }

    static func checkGuestSharingDisabled(check: CISCheck, command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand) -> CheckResult {
        MacOSChecks.legacyBooleanPreference(check: check, domain: "/Library/Preferences/SystemConfiguration/com.apple.smb.server", key: "AllowGuestAccess", expected: false, command: command)
    }

    // Check if Automatic Login is disabled
    static func checkAutomaticLoginDisabled(
        check: CISCheck,
        readPreference: (String, String) -> Any? = MacOSChecks.readSystemPlistPreference
    ) -> CheckResult {
        guard let value = readPreference("/Library/Preferences/com.apple.loginwindow.plist", "autoLoginUser") as? String,
              !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return CheckResult(check: check, status: "manual",
                details: "No explicit automatic-login account could be read. Missing, inaccessible or unsupported preference evidence does not prove login enabled or disabled.")
        }
        return CheckResult(check: check, status: "fail",
            details: "The system login-window preference explicitly names an automatic-login account. The account name is not collected in the report.")
    }

    // Check if Fast User Switching is disabled
    static func checkFastUserSwitchingDisabled(check: CISCheck,
        command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand
    ) -> CheckResult {
        MacOSChecks.legacyBooleanPreference(check: check, domain: "/Library/Preferences/.GlobalPreferences", key: "MultipleSessionEnabled", expected: false, command: command)
    }
    
    // Check if Show All Users on Login Screen is disabled
    static func checkShowAllUsersDisabled(check: CISCheck,
        command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand
    ) -> CheckResult {
        MacOSChecks.legacyBooleanPreference(check: check, domain: "/Library/Preferences/com.apple.loginwindow", key: "SHOWFULLNAME", expected: true, command: command)
    }
    
    // Check if Show password hints is disabled
    static func checkPasswordHintsDisabled(check: CISCheck,
        command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand
    ) -> CheckResult {
        let evidence = command("/usr/bin/defaults", ["read", "/Library/Preferences/com.apple.loginwindow", "RetriesUntilHint"])
        let value = evidence.output.trimmingCharacters(in: .whitespacesAndNewlines)
        guard evidence.unavailable == nil, evidence.exitCode == 0,
              evidence.error.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              let attempts = Int(value), attempts >= 0, String(attempts) == value else {
            return CheckResult.unavailablePreference(check: check,
                detail: "An explicit supported password-hint retry count could not be read. Login-window behavior was not inferred.")
        }
        return CheckResult(check: check, status: attempts == 0 ? "pass" : "fail",
            details: "RetriesUntilHint explicitly reads " + String(attempts) + ". This check expects zero. Local preference evidence does not establish managed enforcement for every user.")
    }
    
    // Legacy profile thresholds are retained; unreadable settings remain unassessed.
    static func checkScreensaverTimeout(check: CISCheck,
        command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand
    ) -> CheckResult {
        legacyScreensaverNumber(check: check, key: "idleTime", currentHost: true, integer: true, command: command) { $0 > 0 && $0 <= 1200 }
    }

    static func checkScreensaverPasswordRequired(check: CISCheck,
        command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand
    ) -> CheckResult {
        MacOSChecks.legacyBooleanPreference(check: check, domain: "com.apple.screensaver", key: "askForPassword", expected: true, command: command)
    }

    static func checkScreensaverGracePeriod(check: CISCheck,
        command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand
    ) -> CheckResult {
        legacyScreensaverNumber(check: check, key: "askForPasswordDelay", currentHost: false, integer: false, command: command) { $0 <= 5 }
    }

    private static func legacyScreensaverNumber(check: CISCheck, key: String,
        currentHost: Bool, integer: Bool,
        command: (String, [String]) -> MacOSChecks.CommandEvidence,
        compliant: (Double) -> Bool
    ) -> CheckResult {
        let arguments = (currentHost ? ["-currentHost"] : []) + ["read", "com.apple.screensaver", key]
        let evidence = command("/usr/bin/defaults", arguments)
        let value = evidence.output.trimmingCharacters(in: .whitespacesAndNewlines)
        let pattern = integer ? "^(0|[1-9][0-9]*)$" : "^(0|[1-9][0-9]*)(\\.[0-9]+)?$"
        guard evidence.unavailable == nil, evidence.exitCode == 0,
              evidence.error.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              value.range(of: pattern, options: .regularExpression) != nil,
              let number = Double(value), number.isFinite, number >= 0,
              !integer || Int(value) != nil else {
            return CheckResult.unavailablePreference(check: check,
                detail: "A supported explicit screensaver setting could not be read. Session-lock behavior was not inferred.")
        }
        return CheckResult(check: check, status: compliant(number) ? "pass" : "fail",
            details: key + " explicitly reads " + value + " seconds. Local preference evidence does not establish effective session-lock behavior or managed enforcement for every user.")
    }

    // A missing or failed directory query does not establish root login state.
    static func checkRootAccountDisabled(check: CISCheck,
        command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand
    ) -> CheckResult {
        let evidence = command("/usr/bin/dscl", [".", "-read", "/Users/root", "AuthenticationAuthority"])
        guard evidence.unavailable == nil, evidence.exitCode == 0,
              evidence.error.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return CheckResult(check: check, status: "manual", details: "Root directory evidence is unavailable. Root login state was not inferred from a failed query.")
        }
        let value = evidence.output.trimmingCharacters(in: .whitespacesAndNewlines)
        guard value.hasPrefix("AuthenticationAuthority:"),
              !value.dropFirst("AuthenticationAuthority:".count).trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return CheckResult(check: check, status: "manual", details: "No supported explicit root authentication authority was returned. Confirm root login state using the applicable platform procedure.")
        }
        return CheckResult(check: check, status: "manual", details: "A root authentication authority is present. Its mechanisms require review; this legacy collector does not establish whether root login is enabled or disabled.")
    }
}
