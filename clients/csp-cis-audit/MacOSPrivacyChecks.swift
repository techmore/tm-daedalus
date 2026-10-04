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
    
    static func checkSpotlightSuggestionsDisabled(check: CISCheck) -> CheckResult {
        CheckResult(check: check, status: "manual", details: "Review the effective Spotlight Suggestions setting for this user. An absent SUGGESTIONS label or an unrelated disabled orderedItems entry does not establish this setting; a supported typed mapping was not collected.")
    }

    static func checkSafariSpotlightSuggestionsDisabled(check: CISCheck, command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand) -> CheckResult {
        MacOSChecks.legacyBooleanPreference(check: check, domain: "com.apple.Safari", key: "UniversalSearchEnabled", expected: false, command: command)
    }

    static func checkSafariPreventCrossSiteTracking(check: CISCheck) -> CheckResult {
        CheckResult(check: check, status: "manual", details: "Review Safari's effective Prevent cross-site tracking setting. Private click measurement is a separate feature and does not establish this protection. A supported tracking-prevention setting was not collected.")
    }

    static func checkSafariBlockAllCookies(check: CISCheck) -> CheckResult {
        CheckResult(check: check, status: "manual", details: "Review Safari's effective cookie policy. Private browsing does not establish Block all cookies. A supported cookie-blocking policy was not collected.")
    }

    static func checkSafariWebContentDeny(check: CISCheck) -> CheckResult {
        CheckResult(check: check, status: "manual", details: "Review the requested website permission and its effective default and per-site exceptions. Whether JavaScript can open windows does not establish that all web content is denied without prompting. A supported permission inventory was not collected.")
    }
}
