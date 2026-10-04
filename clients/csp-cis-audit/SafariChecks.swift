import Foundation

struct SafariChecks {
    static func run(check: CISCheck, readPreferences: () -> [String: Any]? = { getSafariPreferences() as? [String: Any] }) -> CheckResult {
        let preferences = readPreferences()
        switch check.description {
        // Privacy and Security
        case let desc where desc.contains("Open safe files after downloading"):
            return checkOpenSafeFilesDisabled(check: check, preferences: preferences)
        case let desc where desc.contains("AutoFill is disabled"):
            return checkAutoFillDisabled(check: check, preferences: preferences)
        case let desc where desc.contains("AutoFill web forms is disabled"):
            return checkAutoFillWebFormsDisabled(check: check, preferences: preferences)
        case let desc where desc.contains("AutoFill credit cards is disabled"):
            return checkAutoFillCreditCardsDisabled(check: check, preferences: preferences)
        case let desc where desc.contains("AutoFill contact information is disabled"):
            return checkAutoFillContactInfoDisabled(check: check, preferences: preferences)
        case let desc where desc.contains("AutoFill usernames and passwords is disabled"):
            return checkAutoFillPasswordsDisabled(check: check, preferences: preferences)
        case let desc where desc.contains("Block pop-up windows is enabled"):
            return checkBlockPopupsEnabled(check: check, preferences: preferences)
        case let desc where desc.contains("JavaScript is disabled"):
            return checkJavaScriptDisabled(check: check, preferences: preferences)
        case let desc where desc.contains("Warn when visiting a fraudulent website"):
            return checkFraudulentWebsiteWarningEnabled(check: check, preferences: preferences)
            
        // Privacy Features
        case let desc where desc.contains("Prevent cross-site tracking"):
            return checkPreventCrossSiteTracking(check: check, preferences: preferences)
        case let desc where desc.contains("Block all cookies"):
            return checkBlockAllCookies(check: check, preferences: preferences)
        case let desc where desc.contains("Website tracking"):
            return checkWebsiteTracking(check: check, preferences: preferences)
        case let desc where desc.contains("Ask websites not to track me"):
            return checkAskWebsitesNotToTrack(check: check, preferences: preferences)
        case let desc where desc.contains("Privacy preserving ad measurement"):
            return checkPrivacyPreservingAdMeasurement(check: check, preferences: preferences)
            
        // Extension Settings
        case let desc where desc.contains("Allow Extensions"):
            return checkExtensionsDisabled(check: check, preferences: preferences)
        case let desc where desc.contains("Enable JavaScript") && desc.contains("untrusted sites"):
            return checkJavaScriptDisabledForUntrustedSites(check: check, preferences: preferences)
        case let desc where desc.contains("Internet plug-ins"):
            return checkInternetPluginsDisabled(check: check, preferences: preferences)
        case let desc where desc.contains("Java") && !desc.contains("JavaScript"):
            return checkJavaDisabled(check: check, preferences: preferences)
            
        // Advanced Settings
        case let desc where desc.contains("Show full website address"):
            return checkShowFullWebsiteAddress(check: check, preferences: preferences)
        case let desc where desc.contains("Show Develop menu in menu bar"):
            return checkShowDevelopMenu(check: check, preferences: preferences)
        case let desc where desc.contains("Show status bar"):
            return checkShowStatusBar(check: check, preferences: preferences)
        case let desc where desc.contains("Smart Search Field") && desc.contains("search suggestions"):
            return checkSmartSearchFieldSuggestionsDisabled(check: check, preferences: preferences)
        case let desc where desc.contains("Default search engine"):
            return checkDefaultSearchEngine(check: check, preferences: preferences)
            
        default:
            return CheckResult(check: check, status: "manual", details: "Not yet implemented")
        }
    }

    // MARK: - Helper Methods
    
    private static func getSafariPreferences() -> NSDictionary? {
        let homeDir = FileManager.default.homeDirectoryForCurrentUser
        let plistPath = homeDir.appendingPathComponent("Library/Preferences/com.apple.Safari.plist").path
        guard FileManager.default.fileExists(atPath: plistPath),
              let plist = NSDictionary(contentsOfFile: plistPath) else {
            return nil
        }
        return plist
    }
    
    // MARK: - Privacy and Security Checks
    
    private static func checkOpenSafeFilesDisabled(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        guard let plist = preferences,
              let openSafeFiles = plist["AutoOpenSafeDownloads"] as? Bool else {
            return CheckResult.unavailablePreference(check: check, detail: "Required Safari preference evidence was not captured.")
        }
        if openSafeFiles == false {
            return CheckResult(check: check, status: "pass", details: "'Open safe files after downloading' is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "'Open safe files after downloading' is ENABLED.")
        }
    }

    // Check if AutoFill is disabled in Safari
    private static func checkAutoFillDisabled(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        guard let plist = preferences else {
            return CheckResult.unavailablePreference(check: check, detail: "Could not read Safari preferences.")
        }
        
        // Check for AutoFill settings
        guard let autoFillAddressesEnabled = plist["AutoFillFromAddressBook"] as? Bool,
              let autoFillCreditCardsEnabled = plist["AutoFillCreditCardData"] as? Bool,
              let autoFillPasswordsEnabled = plist["AutoFillPasswords"] as? Bool else {
            return CheckResult.unavailablePreference(check: check, detail: "Complete Safari AutoFill preference evidence was not captured.")
        }
        
        if !autoFillAddressesEnabled && !autoFillCreditCardsEnabled && !autoFillPasswordsEnabled {
            return CheckResult(check: check, status: "pass", details: "All AutoFill features are disabled in Safari.")
        } else {
            var details = "Some AutoFill features are still enabled in Safari: "
            if autoFillAddressesEnabled { details += "Addresses " }
            if autoFillCreditCardsEnabled { details += "Credit Cards " }
            if autoFillPasswordsEnabled { details += "Passwords" }
            return CheckResult(check: check, status: "fail", details: details)
        }
    }
    
    // Check if AutoFill web forms is disabled
    private static func checkAutoFillWebFormsDisabled(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        guard let plist = preferences else {
            return CheckResult.unavailablePreference(check: check, detail: "Could not read Safari preferences.")
        }
        
        guard let autoFillFormsEnabled = plist["AutoFillMiscellaneousForms"] as? Bool else {
            return CheckResult.unavailablePreference(check: check, detail: "Required Safari AutoFill preference evidence was not captured.")
        }
        
        if !autoFillFormsEnabled {
            return CheckResult(check: check, status: "pass", details: "AutoFill web forms is disabled in Safari.")
        } else {
            return CheckResult(check: check, status: "fail", details: "AutoFill web forms is enabled in Safari.")
        }
    }
    
    // Check if AutoFill credit cards is disabled
    private static func checkAutoFillCreditCardsDisabled(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        guard let plist = preferences else {
            return CheckResult.unavailablePreference(check: check, detail: "Could not read Safari preferences.")
        }
        
        guard let autoFillCreditCardsEnabled = plist["AutoFillCreditCardData"] as? Bool else {
            return CheckResult.unavailablePreference(check: check, detail: "Required Safari AutoFill preference evidence was not captured.")
        }
        
        if !autoFillCreditCardsEnabled {
            return CheckResult(check: check, status: "pass", details: "AutoFill credit cards is disabled in Safari.")
        } else {
            return CheckResult(check: check, status: "fail", details: "AutoFill credit cards is enabled in Safari.")
        }
    }
    
    // Check if AutoFill contact information is disabled
    private static func checkAutoFillContactInfoDisabled(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        guard let plist = preferences else {
            return CheckResult.unavailablePreference(check: check, detail: "Could not read Safari preferences.")
        }
        
        guard let autoFillAddressesEnabled = plist["AutoFillFromAddressBook"] as? Bool else {
            return CheckResult.unavailablePreference(check: check, detail: "Required Safari AutoFill preference evidence was not captured.")
        }
        
        if !autoFillAddressesEnabled {
            return CheckResult(check: check, status: "pass", details: "AutoFill contact information is disabled in Safari.")
        } else {
            return CheckResult(check: check, status: "fail", details: "AutoFill contact information is enabled in Safari.")
        }
    }
    
    // Check if AutoFill usernames and passwords is disabled
    private static func checkAutoFillPasswordsDisabled(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        guard let plist = preferences else {
            return CheckResult.unavailablePreference(check: check, detail: "Could not read Safari preferences.")
        }
        
        guard let autoFillPasswordsEnabled = plist["AutoFillPasswords"] as? Bool else {
            return CheckResult.unavailablePreference(check: check, detail: "Required Safari AutoFill preference evidence was not captured.")
        }
        
        if !autoFillPasswordsEnabled {
            return CheckResult(check: check, status: "pass", details: "AutoFill usernames and passwords is disabled in Safari.")
        } else {
            return CheckResult(check: check, status: "fail", details: "AutoFill usernames and passwords is enabled in Safari.")
        }
    }

    // Check if Block pop-up windows is enabled in Safari
    private static func checkBlockPopupsEnabled(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        guard let plist = preferences,
              let blockPopups = plist["WebKitJavaScriptCanOpenWindowsAutomatically"] as? Bool else {
            return CheckResult.unavailablePreference(check: check, detail: "Could not read Safari pop-up blocker settings.")
        }
        
        // Note: The setting is inverted - when false, pop-ups are blocked
        if !blockPopups {
            return CheckResult(check: check, status: "pass", details: "Safari is set to block pop-up windows.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Safari is NOT set to block pop-up windows.")
        }
    }

    // Check if JavaScript is disabled in Safari
    private static func checkJavaScriptDisabled(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        guard let plist = preferences,
              let javascriptEnabled = plist["WebKitJavaScriptEnabled"] as? Bool else {
            return CheckResult.unavailablePreference(check: check, detail: "Could not read Safari JavaScript settings.")
        }
        
        if !javascriptEnabled {
            return CheckResult(check: check, status: "pass", details: "JavaScript is disabled in Safari.")
        } else {
            return CheckResult(check: check, status: "fail", details: "JavaScript is enabled in Safari.")
        }
    }
    
    // Check if fraudulent website warning is enabled
    private static func checkFraudulentWebsiteWarningEnabled(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        guard let plist = preferences,
              let warnAboutFraudulentWebsites = plist["WarnAboutFraudulentWebsites"] as? Bool else {
            return CheckResult.unavailablePreference(check: check, detail: "Required Safari preference evidence was not captured.")
        }
        
        if warnAboutFraudulentWebsites {
            return CheckResult(check: check, status: "pass", details: "Warn when visiting a fraudulent website is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Warn when visiting a fraudulent website is disabled.")
        }
    }
    
    // MARK: - Privacy Features
    
    // Check if prevent cross-site tracking is enabled
    private static func checkPreventCrossSiteTracking(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        guard let plist = preferences,
              let preventCrossSiteTracking = plist["WebKitPreferences.storageBlockingPolicy"] as? Int else {
            return CheckResult.unavailablePreference(check: check, detail: "Required Safari preference evidence was not captured.")
        }
        
        if preventCrossSiteTracking >= 1 {
            return CheckResult(check: check, status: "pass", details: "Prevent cross-site tracking is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Prevent cross-site tracking is disabled.")
        }
    }
    
    // Check if block all cookies is enabled
    private static func checkBlockAllCookies(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        guard let plist = preferences,
              let blockAllCookies = plist["BlockAllCookies"] as? Bool else {
            return CheckResult.unavailablePreference(check: check, detail: "Required Safari preference evidence was not captured.")
        }
        
        if blockAllCookies {
            return CheckResult(check: check, status: "pass", details: "Block all cookies is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Block all cookies is disabled.")
        }
    }
    
    // Check if website tracking is set to prevent cross-site tracking
    private static func checkWebsiteTracking(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        guard let plist = preferences,
              let trackingPolicy = plist["WebKitPreferences.trackingPreventionEnabled"] as? Bool else {
            return CheckResult.unavailablePreference(check: check, detail: "Required Safari preference evidence was not captured.")
        }
        
        if trackingPolicy {
            return CheckResult(check: check, status: "pass", details: "Website tracking is set to prevent cross-site tracking.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Website tracking is not set to prevent cross-site tracking.")
        }
    }
    
    // Check if 'Ask websites not to track me' is enabled
    private static func checkAskWebsitesNotToTrack(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        guard let plist = preferences,
              let sendDoNotTrack = plist["SendDoNotTrackHTTPHeader"] as? Bool else {
            return CheckResult.unavailablePreference(check: check, detail: "Required Safari preference evidence was not captured.")
        }
        
        if sendDoNotTrack {
            return CheckResult(check: check, status: "pass", details: "Ask websites not to track me is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Ask websites not to track me is disabled.")
        }
    }
    
    // Check if privacy preserving ad measurement is disabled
    private static func checkPrivacyPreservingAdMeasurement(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        guard let plist = preferences,
              let adMeasurementEnabled = plist["WebKitPreferences.privateClickMeasurementEnabled"] as? Bool else {
            return CheckResult.unavailablePreference(check: check, detail: "Required Safari preference evidence was not captured.")
        }
        
        if !adMeasurementEnabled {
            return CheckResult(check: check, status: "pass", details: "Privacy preserving ad measurement is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Privacy preserving ad measurement is enabled.")
        }
    }
    
    // MARK: - Extension Settings
    
    // Check if extensions are disabled
    private static func checkExtensionsDisabled(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        guard let plist = preferences,
              let extensionsEnabled = plist["ExtensionsEnabled"] as? Bool else {
            return CheckResult.unavailablePreference(check: check, detail: "Required Safari preference evidence was not captured.")
        }
        
        if !extensionsEnabled {
            return CheckResult(check: check, status: "pass", details: "Extensions are disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Extensions are enabled.")
        }
    }
    
    // Check if JavaScript is disabled for untrusted sites
    private static func checkJavaScriptDisabledForUntrustedSites(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        CheckResult(check: check, status: "manual", details: "Review JavaScript execution settings and the organization's trusted-site policy. The popup-window preference javaScriptCanOpenWindowsAutomatically does not establish whether scripts execute on untrusted sites. Supported site-specific execution evidence and trust criteria were not collected; no Safari setting was changed.")
    }

    // Check if Internet plug-ins are disabled
    private static func checkInternetPluginsDisabled(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        guard let plist = preferences,
              let pluginsEnabled = plist["WebKitPluginsEnabled"] as? Bool else {
            return CheckResult.unavailablePreference(check: check, detail: "Required Safari preference evidence was not captured.")
        }
        
        if !pluginsEnabled {
            return CheckResult(check: check, status: "pass", details: "Internet plug-ins are disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Internet plug-ins are enabled.")
        }
    }
    
    // Check if Java is disabled
    private static func checkJavaDisabled(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        guard let plist = preferences,
              let javaEnabled = plist["WebKitJavaEnabled"] as? Bool else {
            return CheckResult.unavailablePreference(check: check, detail: "Required Safari preference evidence was not captured.")
        }
        
        if !javaEnabled {
            return CheckResult(check: check, status: "pass", details: "Java is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Java is enabled.")
        }
    }
    
    // MARK: - Advanced Settings
    
    // Check if full website address is shown
    private static func checkShowFullWebsiteAddress(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        guard let plist = preferences,
              let showFullURL = plist["ShowFullURLInSmartSearchField"] as? Bool else {
            return CheckResult.unavailablePreference(check: check, detail: "Required Safari preference evidence was not captured.")
        }
        
        if showFullURL {
            return CheckResult(check: check, status: "pass", details: "Show full website address is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Show full website address is disabled.")
        }
    }
    
    // Check if Develop menu is shown in menu bar
    private static func checkShowDevelopMenu(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        guard let plist = preferences,
              let showDevelopMenu = plist["IncludeDevelopMenu"] as? Bool else {
            return CheckResult.unavailablePreference(check: check, detail: "Required Safari preference evidence was not captured.")
        }
        
        if showDevelopMenu {
            return CheckResult(check: check, status: "pass", details: "Show Develop menu in menu bar is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Show Develop menu in menu bar is disabled.")
        }
    }
    
    // Check if status bar is shown
    private static func checkShowStatusBar(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        guard let plist = preferences,
              let showStatusBar = plist["ShowStatusBar"] as? Bool else {
            return CheckResult.unavailablePreference(check: check, detail: "Required Safari preference evidence was not captured.")
        }
        
        if showStatusBar {
            return CheckResult(check: check, status: "pass", details: "Show status bar is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Show status bar is disabled.")
        }
    }
    
    // Check if Smart Search Field suggestions are disabled
    private static func checkSmartSearchFieldSuggestionsDisabled(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        guard let plist = preferences,
              let suggestionsEnabled = plist["UniversalSearchEnabled"] as? Bool else {
            return CheckResult.unavailablePreference(check: check, detail: "Required Safari preference evidence was not captured.")
        }
        
        if !suggestionsEnabled {
            return CheckResult(check: check, status: "pass", details: "Smart Search Field suggestions are disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Smart Search Field suggestions are enabled.")
        }
    }
    
    // Check if default search engine is set to a privacy-focused engine
    private static func checkDefaultSearchEngine(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        guard let plist = preferences,
              let searchEngine = plist["SearchProviderIdentifier"] as? String else {
            return CheckResult.unavailablePreference(check: check, detail: "Required Safari preference evidence was not captured.")
        }
        
        let privacyFocusedEngines = ["com.duckduckgo", "com.startpage", "com.qwant"]
        
        if privacyFocusedEngines.contains(where: { searchEngine.contains($0) }) {
            return CheckResult(check: check, status: "pass", details: "Default search engine is set to a privacy-focused engine.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Default search engine is not set to a privacy-focused engine.")
        }
    }
}

