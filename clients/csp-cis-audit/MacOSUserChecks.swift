import Foundation

// This file contains user account and login-related checks for macOS
struct MacOSUserChecks {
    
    // MARK: - Login Window and User Account Settings
    
    // Check if Guest account is disabled
    static func checkGuestAccountDisabled(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/defaults"
        process.arguments = ["read", "/Library/Preferences/com.apple.loginwindow", "GuestEnabled"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            // If the command fails, it likely means the setting doesn't exist, which is good (default is disabled)
            return CheckResult(check: check, status: "pass", details: "Guest account appears to be disabled.")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if output == "0" || output.isEmpty {
            return CheckResult(check: check, status: "pass", details: "Guest account is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Guest account is ENABLED.")
        }
    }
    
    // Check if Guest access to shared folders is disabled
    static func checkGuestSharingDisabled(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/defaults"
        process.arguments = ["read", "/Library/Preferences/SystemConfiguration/com.apple.smb.server", "AllowGuestAccess"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            // If the command fails, it likely means the setting doesn't exist, which is good (default is disabled)
            return CheckResult(check: check, status: "pass", details: "Guest access to shared folders appears to be disabled.")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if output == "0" || output.isEmpty {
            return CheckResult(check: check, status: "pass", details: "Guest access to shared folders is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Guest access to shared folders is ENABLED.")
        }
    }
    
    // Check if Automatic Login is disabled
    static func checkAutomaticLoginDisabled(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/defaults"
        process.arguments = ["read", "/Library/Preferences/com.apple.loginwindow", "autoLoginUser"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            // If the command fails, it likely means the setting doesn't exist, which is good (no auto login)
            return CheckResult(check: check, status: "pass", details: "Automatic Login appears to be disabled.")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        if output.isEmpty {
            return CheckResult(check: check, status: "pass", details: "Automatic Login is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Automatic Login is ENABLED for user: \(output.trimmingCharacters(in: .whitespacesAndNewlines))")
        }
    }
    
    // Check if Fast User Switching is disabled
    static func checkFastUserSwitchingDisabled(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/defaults"
        process.arguments = ["read", "/Library/Preferences/.GlobalPreferences", "MultipleSessionEnabled"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            // If the command fails, it likely means the setting doesn't exist, which is good (default is disabled)
            return CheckResult(check: check, status: "pass", details: "Fast User Switching appears to be disabled.")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if output == "0" || output.isEmpty {
            return CheckResult(check: check, status: "pass", details: "Fast User Switching is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Fast User Switching is ENABLED.")
        }
    }
    
    // Check if Show All Users on Login Screen is disabled
    static func checkShowAllUsersDisabled(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/defaults"
        process.arguments = ["read", "/Library/Preferences/com.apple.loginwindow", "SHOWFULLNAME"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            // If the command fails, it likely means the setting doesn't exist
            return CheckResult(check: check, status: "fail", details: "Show All Users on Login Screen appears to be enabled (default).")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if output == "1" {
            return CheckResult(check: check, status: "pass", details: "Show All Users on Login Screen is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Show All Users on Login Screen is ENABLED.")
        }
    }
    
    // Check if Show password hints is disabled
    static func checkPasswordHintsDisabled(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/defaults"
        process.arguments = ["read", "/Library/Preferences/com.apple.loginwindow", "RetriesUntilHint"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            // If the command fails, it likely means the setting doesn't exist
            return CheckResult(check: check, status: "fail", details: "Password hints appear to be enabled (default).")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if output == "0" {
            return CheckResult(check: check, status: "pass", details: "Password hints are disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Password hints are ENABLED.")
        }
    }
    
    // Check if the screensaver is enabled and set to begin after 20 minutes or less
    static func checkScreensaverTimeout(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/defaults"
        process.arguments = ["-currentHost", "read", "com.apple.screensaver", "idleTime"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            // If the command fails, it likely means the setting doesn't exist
            return CheckResult(check: check, status: "fail", details: "Screensaver timeout setting not found.")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        
        if let idleTime = Int(output), idleTime <= 1200 { // 1200 seconds = 20 minutes
            return CheckResult(check: check, status: "pass", details: "Screensaver is set to begin after \(idleTime/60) minutes.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Screensaver is NOT set to begin after 20 minutes or less.")
        }
    }
    
    // Check if screensaver requires a password
    static func checkScreensaverPasswordRequired(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/defaults"
        process.arguments = ["read", "com.apple.screensaver", "askForPassword"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            // If the command fails, it likely means the setting doesn't exist
            return CheckResult(check: check, status: "fail", details: "Screensaver password requirement not found.")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        
        if output == "1" {
            return CheckResult(check: check, status: "pass", details: "Screensaver requires a password.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Screensaver does NOT require a password.")
        }
    }
    
    // Check if password screensaver grace period is set to 5 seconds or less
    static func checkScreensaverGracePeriod(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/defaults"
        process.arguments = ["read", "com.apple.screensaver", "askForPasswordDelay"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            // If the command fails, it likely means the setting doesn't exist
            return CheckResult(check: check, status: "fail", details: "Screensaver password delay setting not found.")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        
        if let delay = Double(output), delay <= 5.0 {
            return CheckResult(check: check, status: "pass", details: "Screensaver grace period is set to \(delay) seconds.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Screensaver grace period is NOT set to 5 seconds or less.")
        }
    }
    
    // Check if root account is disabled
    static func checkRootAccountDisabled(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/dscl"
        process.arguments = [".", "-read", "/Users/root", "AuthenticationAuthority"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            // If the command fails, it likely means the root account is disabled
            return CheckResult(check: check, status: "pass", details: "Root account appears to be disabled.")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        
        if output.contains("No such key") || output.contains("dsAttrTypeNative:AuthenticationAuthority") == false {
            return CheckResult(check: check, status: "pass", details: "Root account is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Root account is ENABLED.")
        }
    }
}
