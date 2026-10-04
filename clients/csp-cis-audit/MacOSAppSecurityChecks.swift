import Foundation
import CoreFoundation

// This file contains application security checks for macOS
struct MacOSAppSecurityChecks {
    
    // MARK: - Gatekeeper and XProtect
    
    // Check if Gatekeeper is configured to only allow code signed by Apple
    static func checkGatekeeperStrictConfig(check: CISCheck,
        command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand,
        readPreference: (String, String) -> Any? = { suite, key in
            CFPreferencesCopyAppValue(key as CFString, suite as CFString)
        }
    ) -> CheckResult {
        let evidence = command("/usr/sbin/spctl", ["--status"])
        func unknown() -> CheckResult {
            CheckResult(check: check, status: "manual", details: "The stricter Gatekeeper policy was not established by readable explicit evidence. Enabled assessments alone do not establish the App Store-only setting.")
        }
        guard evidence.unavailable == nil, evidence.exitCode == 0,
              evidence.error.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return unknown() }
        let status = evidence.output.trimmingCharacters(in: .whitespacesAndNewlines)
        if status == "assessments disabled" {
            return CheckResult(check: check, status: "fail", details: "Gatekeeper reports assessments disabled; the stricter legacy setting is not satisfied.")
        }
        guard status == "assessments enabled",
              let raw = readPreference("com.apple.systempolicy.control", "AllowIdentifiedDevelopers") as? NSNumber,
              CFGetTypeID(raw) == CFBooleanGetTypeID() else { return unknown() }
        return CheckResult(check: check, status: raw.boolValue ? "fail" : "pass",
            details: "Gatekeeper reports assessments enabled and the captured system-policy setting " + (raw.boolValue ? "allows identified developers." : "selects App Store-only.") + " This describes collected settings, not a live app acceptance test or all policy exceptions.")
    }

    // Check if Automatic Opening of Safe Files in Safari is disabled
    static func checkSafariAutoOpenSafeFiles(check: CISCheck, command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand) -> CheckResult {
        MacOSChecks.legacyBooleanPreference(check: check, domain: "com.apple.Safari", key: "AutoOpenSafeDownloads", expected: false, command: command)
    }
    
    // Check if Automatic Execution of JavaScript is disabled in downloaded files
    static func checkJavaScriptAutoExecDisabled(check: CISCheck) -> CheckResult {
        CheckResult(check: check, status: "manual", details: "Review handling of downloaded JavaScript files and the applications that open them. A Safari popup-window preference does not establish downloaded-file execution policy. Supported execution-policy evidence was not collected.")
    }
    
    // Check if Automatic Execution of Java Applets is disabled
    static func checkJavaAppletsDisabled(check: CISCheck, command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand) -> CheckResult {
        MacOSChecks.legacyBooleanPreference(check: check, domain: "com.apple.Safari", key: "WebKitJavaEnabled", expected: false, command: command)
    }
    
    // Check if Automatic Execution of Plugins is disabled
    static func checkPluginsDisabled(check: CISCheck, command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand) -> CheckResult {
        MacOSChecks.legacyBooleanPreference(check: check, domain: "com.apple.Safari", key: "WebKitPluginsEnabled", expected: false, command: command)
    }
    
    // Check if Quarantine of Downloaded Files is enabled
    static func checkQuarantineEnabled(check: CISCheck) -> CheckResult {
        CheckResult(check: check, status: "manual", details: "Review quarantine metadata on representative downloaded files and the responsible applications. A global LaunchServices preference does not establish that every downloaded file is quarantined. Supported file-provenance evidence was not collected.")
    }
    
    // Check if XProtect Updater is enabled
    static func checkXProtectEnabled(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/defaults"
        process.arguments = ["read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticSecurityUpdates"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "fail", details: "XProtect Updater appears to be disabled.")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        
        if output == "1" {
            return CheckResult(check: check, status: "pass", details: "XProtect Updater is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "XProtect Updater is DISABLED.")
        }
    }
    
    // Check if XProtect Signatures are updated regularly
    static func checkXProtectSignatures(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/find"
        process.arguments = ["/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources", "-name", "*.plist", "-mtime", "-30"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check XProtect signatures: \(error)")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        
        if !output.isEmpty {
            return CheckResult(check: check, status: "pass", details: "XProtect Signatures have been updated within the last 30 days.")
        } else {
            return CheckResult(check: check, status: "fail", details: "XProtect Signatures have NOT been updated within the last 30 days.")
        }
    }
    
    // Check if MRT.app is enabled
    static func checkMRTEnabled(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/defaults"
        process.arguments = ["read", "/Library/Preferences/com.apple.security.common", "OSXMRTEnabled"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            // If the command fails, check if MRT.app exists
            let mrtProcess = Process()
            mrtProcess.launchPath = "/bin/ls"
            mrtProcess.arguments = ["-la", "/System/Library/CoreServices/MRT.app"]
            let mrtPipe = Pipe()
            mrtProcess.standardOutput = mrtPipe
            mrtProcess.standardError = mrtPipe
            do {
                try mrtProcess.run()
            } catch {
                return CheckResult(check: check, status: "fail", details: "MRT.app does not appear to be installed.")
            }
            mrtProcess.waitUntilExit()
            
            let mrtData = mrtPipe.fileHandleForReading.readDataToEndOfFile()
            let mrtOutput = String(data: mrtData, encoding: .utf8) ?? ""
            
            if !mrtOutput.isEmpty {
                return CheckResult(check: check, status: "pass", details: "MRT.app is installed and appears to be enabled by default.")
            } else {
                return CheckResult(check: check, status: "fail", details: "MRT.app is not installed.")
            }
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        
        if output == "1" || output.isEmpty {
            return CheckResult(check: check, status: "pass", details: "MRT.app is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "MRT.app is DISABLED.")
        }
    }
    
    // Permission audits must not reset grants or infer approval from app counts.
    static func checkCameraAccess(check: CISCheck) -> CheckResult {
        MacOSHardwareChecks.checkCameraAccess(check: check)
    }

    static func checkMicrophoneAccess(check: CISCheck) -> CheckResult {
        MacOSHardwareChecks.checkMicrophoneAccess(check: check)
    }

    static func checkFullDiskAccess(check: CISCheck) -> CheckResult {
        MacOSHardwareChecks.checkFullDiskAccess(check: check)
    }
}
