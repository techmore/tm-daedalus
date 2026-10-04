import Foundation

// This file contains network and sharing-related checks for macOS
struct MacOSNetworkChecks {
    
    private static func usableSharingEvidence(_ evidence: MacOSChecks.CommandEvidence) -> Bool {
        evidence.unavailable == nil && evidence.exitCode == 0 && evidence.error.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && evidence.output.utf8.count <= 65_536
    }
    private static func sharingUnknown(_ check: CISCheck) -> CheckResult {
        CheckResult(check: check, status: "manual", details: "Complete explicit sharing-state evidence was not collected. Missing, failed, duplicate or unsupported output does not establish disabled sharing.")
    }
    private static func explicitDisabledService(check: CISCheck, label: String, command: (String, [String]) -> MacOSChecks.CommandEvidence) -> CheckResult {
        let evidence = command("/bin/launchctl", ["print-disabled", "system"])
        guard usableSharingEvidence(evidence), evidence.output.contains("disabled services = {"), evidence.output.contains("}") else { return sharingUnknown(check) }
        let entries = evidence.output.components(separatedBy: .newlines).map { $0.trimmingCharacters(in: .whitespaces) }.filter { $0.hasPrefix("\"" + label + "\" => ") }
        let disabled = "\"" + label + "\" => disabled"
        let enabled = "\"" + label + "\" => enabled"
        guard entries.count == 1, entries[0] == disabled || entries[0] == enabled else { return sharingUnknown(check) }
        return CheckResult(check: check, status: entries[0] == disabled ? "pass" : "fail", details: label + " has an explicit " + (entries[0] == disabled ? "disabled" : "enabled") + " system service override. This does not test reachability, loaded process state or every sharing protocol.")
    }

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
    static func checkRemoteManagementDisabled(check: CISCheck, command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand) -> CheckResult {
        let evidence = command("/usr/libexec/mdmclient", ["QuerySecurityInfo"])
        guard usableSharingEvidence(evidence) else { return sharingUnknown(check) }
        let values = evidence.output.components(separatedBy: .newlines).map { $0.trimmingCharacters(in: .whitespaces) }.filter { $0.hasPrefix("RemoteDesktopEnabled = ") }
        guard values.count == 1, values[0] == "RemoteDesktopEnabled = 0;" || values[0] == "RemoteDesktopEnabled = 1;" else { return sharingUnknown(check) }
        return CheckResult(check: check, status: values[0] == "RemoteDesktopEnabled = 0;" ? "pass" : "fail", details: "Local security information reports remote desktop " + (values[0] == "RemoteDesktopEnabled = 0;" ? "disabled" : "enabled") + "; reachability and every permission were not tested.")
    }
    
    // Check if Remote Apple Events are disabled
    static func checkRemoteAppleEventsDisabled(check: CISCheck, command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand) -> CheckResult {
        MacOSSystemChecks.exactStatus(check: check, path: "/usr/sbin/systemsetup", arguments: ["-getremoteappleevents"], enabled: "Remote Apple Events: Off", disabled: "Remote Apple Events: On", scope: "This records a local configuration response, not reachability, traffic filtering or managed enforcement. Other response formats require review.", command: command)
    }
    
    // Check if Internet Sharing is disabled
    static func checkInternetSharingDisabled(check: CISCheck, command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand) -> CheckResult {
        MacOSChecks.legacyBooleanPreference(check: check, domain: "/Library/Preferences/SystemConfiguration/com.apple.nat", key: "Enabled", expected: false, command: command)
    }
    
    // Check if Media Sharing is disabled
    static func checkMediaSharingDisabled(check: CISCheck, command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand) -> CheckResult {
        MacOSChecks.legacyBooleanPreference(check: check, domain: "com.apple.amp.mediasharingd", key: "home-sharing-enabled", expected: false, command: command)
    }
    
    // Check if DVD/CD Sharing is disabled
    static func checkDVDSharingDisabled(check: CISCheck, command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand) -> CheckResult {
        explicitDisabledService(check: check, label: "com.apple.ODSAgent", command: command)
    }
    
    // Check if Screen Sharing is disabled
    static func checkScreenSharingDisabled(check: CISCheck, command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand) -> CheckResult {
        explicitDisabledService(check: check, label: "com.apple.screensharing", command: command)
    }
    
    // Check if File Sharing is disabled
    static func checkFileSharingDisabled(check: CISCheck, command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand) -> CheckResult {
        explicitDisabledService(check: check, label: "com.apple.smbd", command: command)
    }
    
    // Check if Printer Sharing is disabled
    static func checkPrinterSharingDisabled(check: CISCheck, command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand) -> CheckResult {
        let evidence = command("/usr/sbin/cupsctl", [])
        guard usableSharingEvidence(evidence) else { return sharingUnknown(check) }
        let values = evidence.output.components(separatedBy: .newlines).map { $0.trimmingCharacters(in: .whitespaces) }.filter { $0.hasPrefix("_share_printers=") }
        guard values.count == 1, values[0] == "_share_printers=0" || values[0] == "_share_printers=1" else { return sharingUnknown(check) }
        return CheckResult(check: check, status: values[0] == "_share_printers=0" ? "pass" : "fail", details: "CUPS explicitly reports " + values[0] + "; this is printer-sharing configuration, not a network reachability test.")
    }
    
    // MARK: - Bluetooth and Wireless
    
    // Check if Bluetooth Sharing is disabled
    static func checkBluetoothSharingDisabled(check: CISCheck) -> CheckResult {
        CheckResult(check: check, status: "manual", details: "Review Bluetooth file-sharing settings and applicability. General bluetoothd service state does not establish Bluetooth Sharing. Supported file-sharing policy evidence was not collected.")
    }
    
    // Check if AirDrop is disabled
    static func checkAirDropDisabled(check: CISCheck, command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand) -> CheckResult {
        MacOSChecks.legacyBooleanPreference(check: check, domain: "com.apple.NetworkBrowser", key: "DisableAirDrop", expected: true, command: command)
    }
    
    // Check if AirPlay Receiver is disabled
    static func checkAirPlayReceiverDisabled(check: CISCheck, command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand) -> CheckResult {
        MacOSChecks.legacyBooleanPreference(check: check, domain: "com.apple.airplay", key: "receiver-enabled", expected: false, command: command)
    }
    
    // Check if Content Caching is disabled
    static func checkContentCachingDisabled(check: CISCheck) -> CheckResult {
        CheckResult(check: check, status: "manual", details: "Review effective Content Caching activation and managed policy. A complete supported cache-status response was not collected; missing or failed utility output does not establish disabled caching.")
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
