import Foundation

struct MacOSPrivacyChecks {
    // Check if Location Services is disabled
    static func checkLocationServicesDisabled(check: CISCheck, command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand) -> CheckResult {
        MacOSChecks.legacyBooleanPreference(check: check, domain: "/var/db/locationd/Library/Preferences/ByHost/com.apple.locationd", key: "LocationServicesEnabled", expected: false, command: command)
    }
    
    // Check if sending diagnostic and usage data to Apple is disabled
    static func checkDiagnosticDataDisabled(check: CISCheck, command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand) -> CheckResult {
        MacOSChecks.legacyBooleanPreference(check: check, domain: "/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist", key: "AutoSubmit", expected: false, command: command)
    }
    
    // Check if Limit Ad Tracking is enabled
    static func checkLimitAdTracking(check: CISCheck, command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand) -> CheckResult {
        MacOSChecks.legacyBooleanPreference(check: check, domain: "com.apple.AdLib", key: "allowApplePersonalizedAdvertising", expected: false, command: command)
    }
    
    // Check if Siri is disabled
    static func checkSiriDisabled(check: CISCheck, command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand) -> CheckResult {
        MacOSChecks.legacyBooleanPreference(check: check, domain: "com.apple.assistant.support", key: "Assistant Enabled", expected: false, command: command)
    }
    
    // Check if Dictation is disabled
    static func checkDictationDisabled(check: CISCheck, command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand) -> CheckResult {
        MacOSChecks.legacyBooleanPreference(check: check, domain: "com.apple.speech.recognition.AppleSpeechRecognition.prefs", key: "DictationIMMasterDictationEnabled", expected: false, command: command)
    }
    
    // Check if Spotlight Suggestions are disabled
    static func checkSpotlightSuggestionsDisabled(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/defaults"
        process.arguments = ["read", "com.apple.spotlight", "orderedItems"]
        
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check Spotlight Suggestions: \(error)")
        }
        
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        
        if !output.contains("SUGGESTIONS") || output.contains("SUGGESTIONS") && output.contains("enabled = 0") {
            return CheckResult(check: check, status: "pass", details: "Spotlight Suggestions are disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Spotlight Suggestions are enabled.")
        }
    }
    
    // Check if Safari Spotlight Suggestions are disabled
    static func checkSafariSpotlightSuggestionsDisabled(check: CISCheck) -> CheckResult {
        let homeDir = FileManager.default.homeDirectoryForCurrentUser
        let plistPath = homeDir.appendingPathComponent("Library/Preferences/com.apple.Safari.plist").path
        
        // First check if the file exists
        guard FileManager.default.fileExists(atPath: plistPath) else {
            return CheckResult(check: check, status: "manual", details: "Safari preferences file not found. This could mean Safari has never been launched or preferences have been reset. Manual verification required.")
        }
        
        // Try to read the plist using defaults command as a fallback
        let process = Process()
        process.launchPath = "/usr/bin/defaults"
        process.arguments = ["read", "com.apple.Safari", "UniversalSearchEnabled"]
        
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        
        do {
            try process.run()
            process.waitUntilExit()
            
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? ""
            
            if output.contains("0") || output.contains("false") {
                return CheckResult(check: check, status: "pass", details: "Safari Spotlight Suggestions are disabled.")
            } else if output.contains("1") || output.contains("true") {
                return CheckResult(check: check, status: "fail", details: "Safari Spotlight Suggestions are enabled.")
            } else {
                // Try to read directly from the plist as a last resort
                if let plist = NSDictionary(contentsOfFile: plistPath),
                   let spotlightSuggestions = plist["UniversalSearchEnabled"] as? Bool {
                    if !spotlightSuggestions {
                        return CheckResult(check: check, status: "pass", details: "Safari Spotlight Suggestions are disabled.")
                    } else {
                        return CheckResult(check: check, status: "fail", details: "Safari Spotlight Suggestions are enabled.")
                    }
                }
            }
        } catch {
            // Command failed, try direct plist read as fallback
            if let plist = NSDictionary(contentsOfFile: plistPath),
               let spotlightSuggestions = plist["UniversalSearchEnabled"] as? Bool {
                if !spotlightSuggestions {
                    return CheckResult(check: check, status: "pass", details: "Safari Spotlight Suggestions are disabled.")
                } else {
                    return CheckResult(check: check, status: "fail", details: "Safari Spotlight Suggestions are enabled.")
                }
            }
        }
        
        // If we get here, we couldn't determine the status
        return CheckResult(check: check, status: "manual", details: "Could not determine Safari Spotlight Suggestions status. Manual verification required.")
    }
    
    // Check if Safari Prevent cross-site tracking is enabled
    static func checkSafariPreventCrossSiteTracking(check: CISCheck) -> CheckResult {
        let homeDir = FileManager.default.homeDirectoryForCurrentUser
        let plistPath = homeDir.appendingPathComponent("Library/Preferences/com.apple.Safari.plist").path
        
        // First check if the file exists
        guard FileManager.default.fileExists(atPath: plistPath) else {
            return CheckResult(check: check, status: "manual", details: "Safari preferences file not found. This could mean Safari has never been launched or preferences have been reset. Manual verification required.")
        }
        
        // Try to read the plist using defaults command as a fallback
        let process = Process()
        process.launchPath = "/usr/bin/defaults"
        process.arguments = ["read", "com.apple.Safari", "WebKitPreferences.privateClickMeasurementEnabled"]
        
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        
        do {
            try process.run()
            process.waitUntilExit()
            
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? ""
            
            if output.contains("1") || output.contains("true") {
                return CheckResult(check: check, status: "pass", details: "Safari Prevent cross-site tracking is enabled.")
            } else if output.contains("0") || output.contains("false") {
                return CheckResult(check: check, status: "fail", details: "Safari Prevent cross-site tracking is NOT enabled.")
            }
        } catch {
            // Command failed, try direct plist read as fallback
        }
        
        // Try direct plist reading as a fallback
        if let plist = NSDictionary(contentsOfFile: plistPath),
           let preventTracking = plist["WebKitPreferences.privateClickMeasurementEnabled"] as? Bool {
            if preventTracking {
                return CheckResult(check: check, status: "pass", details: "Safari Prevent cross-site tracking is enabled.")
            } else {
                return CheckResult(check: check, status: "fail", details: "Safari Prevent cross-site tracking is NOT enabled.")
            }
        }
        
        // If we get here, we couldn't determine the status
        return CheckResult(check: check, status: "manual", details: "Could not determine Safari cross-site tracking prevention status. Manual verification required.")
    }
    
    // Check if Safari Block all cookies is enabled
    static func checkSafariBlockAllCookies(check: CISCheck) -> CheckResult {
        let homeDir = FileManager.default.homeDirectoryForCurrentUser
        let plistPath = homeDir.appendingPathComponent("Library/Preferences/com.apple.Safari.plist").path
        
        // First check if the file exists
        guard FileManager.default.fileExists(atPath: plistPath) else {
            return CheckResult(check: check, status: "manual", details: "Safari preferences file not found. This could mean Safari has never been launched or preferences have been reset. Manual verification required.")
        }
        
        // Try to read the plist using defaults command as a fallback
        let process = Process()
        process.launchPath = "/usr/bin/defaults"
        process.arguments = ["read", "com.apple.Safari", "WebKitPreferences.privateBrowsingEnabled"]
        
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        
        do {
            try process.run()
            process.waitUntilExit()
            
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? ""
            
            if output.contains("1") || output.contains("true") {
                return CheckResult(check: check, status: "pass", details: "Safari Block all cookies is enabled.")
            } else if output.contains("0") || output.contains("false") {
                return CheckResult(check: check, status: "fail", details: "Safari Block all cookies is NOT enabled.")
            }
        } catch {
            // Command failed, try direct plist read as fallback
        }
        
        // Try direct plist reading as a fallback
        if let plist = NSDictionary(contentsOfFile: plistPath),
           let blockCookies = plist["WebKitPreferences.privateBrowsingEnabled"] as? Bool {
            if blockCookies {
                return CheckResult(check: check, status: "pass", details: "Safari Block all cookies is enabled.")
            } else {
                return CheckResult(check: check, status: "fail", details: "Safari Block all cookies is NOT enabled.")
            }
        }
        
        // If we get here, we couldn't determine the status
        return CheckResult(check: check, status: "manual", details: "Could not determine Safari cookie blocking status. Manual verification required.")
    }
    
    // Check if Safari Web Content is set to deny without user prompt
    static func checkSafariWebContentDeny(check: CISCheck) -> CheckResult {
        let homeDir = FileManager.default.homeDirectoryForCurrentUser
        let plistPath = homeDir.appendingPathComponent("Library/Preferences/com.apple.Safari.plist").path
        
        // First check if the file exists
        guard FileManager.default.fileExists(atPath: plistPath) else {
            return CheckResult(check: check, status: "manual", details: "Safari preferences file not found. This could mean Safari has never been launched or preferences have been reset. Manual verification required.")
        }
        
        // Try to read the plist using defaults command as a fallback
        let process = Process()
        process.launchPath = "/usr/bin/defaults"
        process.arguments = ["read", "com.apple.Safari", "WebKitPreferences.javaScriptCanOpenWindowsAutomatically"]
        
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        
        do {
            try process.run()
            process.waitUntilExit()
            
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? ""
            
            if output.contains("0") || output.contains("false") {
                return CheckResult(check: check, status: "pass", details: "Safari Web Content is set to deny without user prompt.")
            } else if output.contains("1") || output.contains("true") {
                return CheckResult(check: check, status: "fail", details: "Safari Web Content is NOT set to deny without user prompt.")
            }
        } catch {
            // Command failed, try direct plist read as fallback
        }
        
        // Try direct plist reading as a fallback
        if let plist = NSDictionary(contentsOfFile: plistPath),
           let webContentSetting = plist["WebKitPreferences.javaScriptCanOpenWindowsAutomatically"] as? Bool {
            if !webContentSetting {
                return CheckResult(check: check, status: "pass", details: "Safari Web Content is set to deny without user prompt.")
            } else {
                return CheckResult(check: check, status: "fail", details: "Safari Web Content is NOT set to deny without user prompt.")
            }
        }
        
        // If we get here, we couldn't determine the status
        return CheckResult(check: check, status: "manual", details: "Could not determine Safari Web Content settings. Manual verification required.")
    }
}
