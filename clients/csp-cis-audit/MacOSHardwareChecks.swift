import Foundation

struct MacOSHardwareChecks {
    // Check if Bluetooth is disabled when not needed
    static func checkBluetoothDisabled(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/defaults"
        process.arguments = ["read", "/Library/Preferences/com.apple.Bluetooth", "ControllerPowerState"]
        
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check Bluetooth status: \(error)")
        }
        
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        
        if output.contains("0") {
            return CheckResult(check: check, status: "pass", details: "Bluetooth is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Bluetooth is enabled. Consider disabling when not in use.")
        }
    }
    
    // Check if Camera access is limited to approved apps
    static func checkCameraAccess(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/tccutil"
        process.arguments = ["list"]
        
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check camera access: \(error)")
        }
        
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        
        // Count how many apps have camera access
        let cameraLines = output.components(separatedBy: .newlines).filter { 
            $0.contains("kTCCServiceCamera") && $0.contains("ALLOWED") 
        }
        
        if cameraLines.count <= 5 {
            return CheckResult(check: check, status: "pass", details: "Camera access is limited to \(cameraLines.count) approved apps.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Camera access is granted to \(cameraLines.count) apps, which exceeds the recommended limit.")
        }
    }
    
    // Check if Microphone access is limited to approved apps
    static func checkMicrophoneAccess(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/tccutil"
        process.arguments = ["list"]
        
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check microphone access: \(error)")
        }
        
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        
        // Count how many apps have microphone access
        let micLines = output.components(separatedBy: .newlines).filter { 
            $0.contains("kTCCServiceMicrophone") && $0.contains("ALLOWED") 
        }
        
        if micLines.count <= 5 {
            return CheckResult(check: check, status: "pass", details: "Microphone access is limited to \(micLines.count) approved apps.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Microphone access is granted to \(micLines.count) apps, which exceeds the recommended limit.")
        }
    }
    
    // Check if Screen Recording access is limited to approved apps
    static func checkScreenRecordingAccess(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/tccutil"
        process.arguments = ["list"]
        
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check screen recording access: \(error)")
        }
        
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        
        // Count how many apps have screen recording access
        let screenLines = output.components(separatedBy: .newlines).filter { 
            $0.contains("kTCCServiceScreenCapture") && $0.contains("ALLOWED") 
        }
        
        if screenLines.count <= 3 {
            return CheckResult(check: check, status: "pass", details: "Screen Recording access is limited to \(screenLines.count) approved apps.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Screen Recording access is granted to \(screenLines.count) apps, which exceeds the recommended limit.")
        }
    }
    
    // Check if Automation access is limited to approved apps
    static func checkAutomationAccess(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/tccutil"
        process.arguments = ["list"]
        
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check automation access: \(error)")
        }
        
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        
        // Count how many apps have automation access
        let automationLines = output.components(separatedBy: .newlines).filter { 
            $0.contains("kTCCServiceAppleEvents") && $0.contains("ALLOWED") 
        }
        
        if automationLines.count <= 5 {
            return CheckResult(check: check, status: "pass", details: "Automation access is limited to \(automationLines.count) approved apps.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Automation access is granted to \(automationLines.count) apps, which exceeds the recommended limit.")
        }
    }
    
    // Check if USB restricted mode is enabled
    static func checkUSBRestrictedMode(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/defaults"
        process.arguments = ["read", "/Library/Preferences/com.apple.security.smartcard", "DisabledTokens"]
        
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        
        do {
            try process.run()
        } catch {
            // If the command fails, it might be because the key doesn't exist, which means USB restricted mode is not enabled
            return CheckResult(check: check, status: "fail", details: "USB restricted mode is not enabled.")
        }
        
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        
        if output.contains("com.apple.security.smartcard") {
            return CheckResult(check: check, status: "pass", details: "USB restricted mode is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "USB restricted mode is not properly configured.")
        }
    }
    
    // Check if Full Disk Access is limited to approved apps
    static func checkFullDiskAccess(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/tccutil"
        process.arguments = ["list"]
        
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check full disk access: \(error)")
        }
        
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        
        // Count how many apps have full disk access
        let fdaLines = output.components(separatedBy: .newlines).filter { 
            $0.contains("kTCCServiceSystemPolicyAllFiles") && $0.contains("ALLOWED") 
        }
        
        if fdaLines.count <= 3 {
            return CheckResult(check: check, status: "pass", details: "Full Disk Access is limited to \(fdaLines.count) approved apps.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Full Disk Access is granted to \(fdaLines.count) apps, which exceeds the recommended limit.")
        }
    }
}
