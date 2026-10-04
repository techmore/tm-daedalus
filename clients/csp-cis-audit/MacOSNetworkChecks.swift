import Foundation

// This file contains network and sharing-related checks for macOS
struct MacOSNetworkChecks {
    
    // MARK: - Firewall Settings
    
    // Check if Firewall is enabled
    static func checkFirewall(check: CISCheck, command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand) -> CheckResult {
        MacOSSystemChecks.exactStatus(check: check, path: "/usr/libexec/ApplicationFirewall/socketfilterfw", arguments: ["--getglobalstate"], enabled: "Firewall is enabled. (State = 1)", disabled: "Firewall is disabled. (State = 0)", scope: "This records a local configuration response, not reachability, traffic filtering or managed enforcement. Other response formats require review.", command: command)
    }
    
    // Check if Firewall Stealth Mode is enabled
    static func checkFirewallStealthMode(check: CISCheck, command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand) -> CheckResult {
        MacOSSystemChecks.exactStatus(check: check, path: "/usr/libexec/ApplicationFirewall/socketfilterfw", arguments: ["--getstealthmode"], enabled: "Firewall stealth mode is on", disabled: "Firewall stealth mode is off", scope: "This records a local configuration response, not reachability, traffic filtering or managed enforcement. Other response formats require review.", command: command)
    }
    
    // Check if Firewall is configured to block all incoming connections
    static func checkFirewallBlockAll(check: CISCheck, command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand) -> CheckResult {
        MacOSSystemChecks.exactStatus(check: check, path: "/usr/libexec/ApplicationFirewall/socketfilterfw", arguments: ["--getblockall"], enabled: "Firewall has block all state set to enabled.", disabled: "Firewall has block all state set to disabled.", scope: "This records a local configuration response, not reachability, traffic filtering or managed enforcement. Other response formats require review.", command: command)
    }
    
    // MARK: - Network Services
    
    // Check if Remote Login (SSH) is disabled
    static func checkRemoteLoginDisabled(check: CISCheck, command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand) -> CheckResult {
        MacOSSystemChecks.exactStatus(check: check, path: "/usr/sbin/systemsetup", arguments: ["-getremotelogin"], enabled: "Remote Login: Off", disabled: "Remote Login: On", scope: "This records a local configuration response, not reachability, traffic filtering or managed enforcement. Other response formats require review.", command: command)
    }
    
    // Check if Remote Management (ARD) is disabled
    static func checkRemoteManagementDisabled(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/defaults"
        process.arguments = ["read", "/Library/Preferences/com.apple.RemoteManagement", "ARD_AllLocalUsers"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            // If the command fails, it likely means ARD is not configured, which is good
            return CheckResult(check: check, status: "pass", details: "Remote Management appears to be disabled.")
        }
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        if output.contains("0") || output.isEmpty {
            return CheckResult(check: check, status: "pass", details: "Remote Management is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Remote Management is ENABLED.")
        }
    }
    
    // Check if Remote Apple Events are disabled
    static func checkRemoteAppleEventsDisabled(check: CISCheck, command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand) -> CheckResult {
        MacOSSystemChecks.exactStatus(check: check, path: "/usr/sbin/systemsetup", arguments: ["-getremoteappleevents"], enabled: "Remote Apple Events: Off", disabled: "Remote Apple Events: On", scope: "This records a local configuration response, not reachability, traffic filtering or managed enforcement. Other response formats require review.", command: command)
    }
    
    // Check if Internet Sharing is disabled
    static func checkInternetSharingDisabled(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/defaults"
        process.arguments = ["read", "/Library/Preferences/SystemConfiguration/com.apple.nat", "Enabled"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            // If the command fails, it likely means Internet Sharing is not configured, which is good
            return CheckResult(check: check, status: "pass", details: "Internet Sharing appears to be disabled.")
        }
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        if output.contains("0") || output.isEmpty {
            return CheckResult(check: check, status: "pass", details: "Internet Sharing is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Internet Sharing is ENABLED.")
        }
    }
    
    // Check if Media Sharing is disabled
    static func checkMediaSharingDisabled(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/defaults"
        process.arguments = ["read", "com.apple.amp.mediasharingd", "home-sharing-enabled"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            // If the command fails, it likely means Media Sharing is not configured, which is good
            return CheckResult(check: check, status: "pass", details: "Media Sharing appears to be disabled.")
        }
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        if output.contains("0") || output.isEmpty {
            return CheckResult(check: check, status: "pass", details: "Media Sharing is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Media Sharing is ENABLED.")
        }
    }
    
    // Check if DVD/CD Sharing is disabled
    static func checkDVDSharingDisabled(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/bin/launchctl"
        process.arguments = ["list", "com.apple.ODSAgent"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check DVD/CD Sharing: \(error)")
        }
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        if output.isEmpty || !output.contains("com.apple.ODSAgent") {
            return CheckResult(check: check, status: "pass", details: "DVD/CD Sharing is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "DVD/CD Sharing is ENABLED.")
        }
    }
    
    // Check if Screen Sharing is disabled
    static func checkScreenSharingDisabled(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/bin/launchctl"
        process.arguments = ["list", "com.apple.screensharing"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check Screen Sharing: \(error)")
        }
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        if output.isEmpty || !output.contains("com.apple.screensharing") {
            return CheckResult(check: check, status: "pass", details: "Screen Sharing is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Screen Sharing is ENABLED.")
        }
    }
    
    // Check if File Sharing is disabled
    static func checkFileSharingDisabled(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/bin/launchctl"
        process.arguments = ["list", "com.apple.smbd"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check File Sharing: \(error)")
        }
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        if output.isEmpty || !output.contains("com.apple.smbd") {
            return CheckResult(check: check, status: "pass", details: "File Sharing is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "File Sharing is ENABLED.")
        }
    }
    
    // Check if Printer Sharing is disabled
    static func checkPrinterSharingDisabled(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/sbin/system_profiler"
        process.arguments = ["SPPrintersDataType"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check Printer Sharing: \(error)")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        if !output.contains("Shared: Yes") {
            return CheckResult(check: check, status: "pass", details: "Printer Sharing is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Printer Sharing is ENABLED.")
        }
    }
    
    // MARK: - Bluetooth and Wireless
    
    // Check if Bluetooth Sharing is disabled
    static func checkBluetoothSharingDisabled(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/bin/launchctl"
        process.arguments = ["print-disabled", "system"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check Bluetooth Sharing: \(error)")
        }
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        if output.contains("com.apple.bluetoothd"), output.contains("true") {
            return CheckResult(check: check, status: "pass", details: "Bluetooth Sharing is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Bluetooth Sharing is ENABLED.")
        }
    }
    
    // Check if AirDrop is disabled
    static func checkAirDropDisabled(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/defaults"
        process.arguments = ["read", "com.apple.NetworkBrowser", "DisableAirDrop"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            // If the command fails, it likely means AirDrop is not disabled
            return CheckResult(check: check, status: "fail", details: "AirDrop appears to be enabled.")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if output == "1" {
            return CheckResult(check: check, status: "pass", details: "AirDrop is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "AirDrop is ENABLED.")
        }
    }
    
    // Check if AirPlay Receiver is disabled
    static func checkAirPlayReceiverDisabled(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/defaults"
        process.arguments = ["read", "com.apple.airplay", "receiver-enabled"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            // If the command fails, it likely means AirPlay Receiver is not enabled
            return CheckResult(check: check, status: "pass", details: "AirPlay Receiver appears to be disabled.")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if output == "0" || output.isEmpty {
            return CheckResult(check: check, status: "pass", details: "AirPlay Receiver is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "AirPlay Receiver is ENABLED.")
        }
    }
    
    // Check if Content Caching is disabled
    static func checkContentCachingDisabled(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/AssetCacheManagerUtil"
        process.arguments = ["status"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check content caching: \(error)")
        }
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        if output.contains("Activated: false") {
            return CheckResult(check: check, status: "pass", details: "Content Caching is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Content Caching is ENABLED.")
        }
    }
    
    // MARK: - Time and Date
    
    // Check if Set Time and Date Automatically is enabled
    static func checkTimeAndDateAutomatically(check: CISCheck, command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand) -> CheckResult {
        MacOSSystemChecks.exactStatus(check: check, path: "/usr/sbin/systemsetup", arguments: ["-getusingnetworktime"], enabled: "Network Time: On", disabled: "Network Time: Off", scope: "This records a local configuration response, not reachability, traffic filtering or managed enforcement. Other response formats require review.", command: command)
    }
    
    // Check if NTP servers are configured properly
    static func checkNTPServers(check: CISCheck) -> CheckResult {
        CheckResult(check: check, status: "manual", details: "Review the configured time sources against the organization's approved-server policy and verify synchronization. A reported server name alone does not establish proper configuration or a synchronized clock; no approved-server policy was supplied.")
    }
}
