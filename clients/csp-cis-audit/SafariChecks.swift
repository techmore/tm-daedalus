import Foundation

struct SafariChecks {
    static func run(check: CISCheck) -> CheckResult {
        switch check.description {
        // Privacy and Security
        case let desc where desc.contains("Open safe files after downloading"):
            return checkOpenSafeFilesDisabled(check: check)
        case let desc where desc.contains("AutoFill is disabled"):
            return checkAutoFillDisabled(check: check)
        case let desc where desc.contains("AutoFill web forms is disabled"):
            return checkAutoFillWebFormsDisabled(check: check)
        case let desc where desc.contains("AutoFill credit cards is disabled"):
            return checkAutoFillCreditCardsDisabled(check: check)
        case let desc where desc.contains("AutoFill contact information is disabled"):
            return checkAutoFillContactInfoDisabled(check: check)
        case let desc where desc.contains("AutoFill usernames and passwords is disabled"):
            return checkAutoFillPasswordsDisabled(check: check)
        case let desc where desc.contains("Block pop-up windows is enabled"):
            return checkBlockPopupsEnabled(check: check)
        case let desc where desc.contains("JavaScript is disabled"):
            return checkJavaScriptDisabled(check: check)
        case let desc where desc.contains("Warn when visiting a fraudulent website"):
            return checkFraudulentWebsiteWarningEnabled(check: check)
            
        // Privacy Features
        case let desc where desc.contains("Prevent cross-site tracking"):
            return checkPreventCrossSiteTracking(check: check)
        case let desc where desc.contains("Block all cookies"):
            return checkBlockAllCookies(check: check)
        case let desc where desc.contains("Website tracking"):
            return checkWebsiteTracking(check: check)
        case let desc where desc.contains("Ask websites not to track me"):
            return checkAskWebsitesNotToTrack(check: check)
        case let desc where desc.contains("Privacy preserving ad measurement"):
            return checkPrivacyPreservingAdMeasurement(check: check)
            
        // Extension Settings
        case let desc where desc.contains("Allow Extensions"):
            return checkExtensionsDisabled(check: check)
        case let desc where desc.contains("Enable JavaScript") && desc.contains("untrusted sites"):
            return checkJavaScriptDisabledForUntrustedSites(check: check)
        case let desc where desc.contains("Internet plug-ins"):
            return checkInternetPluginsDisabled(check: check)
        case let desc where desc.contains("Java") && !desc.contains("JavaScript"):
            return checkJavaDisabled(check: check)
            
        // Advanced Settings
        case let desc where desc.contains("Show full website address"):
            return checkShowFullWebsiteAddress(check: check)
        case let desc where desc.contains("Show Develop menu in menu bar"):
            return checkShowDevelopMenu(check: check)
        case let desc where desc.contains("Show status bar"):
            return checkShowStatusBar(check: check)
        case let desc where desc.contains("Smart Search Field") && desc.contains("search suggestions"):
            return checkSmartSearchFieldSuggestionsDisabled(check: check)
        case let desc where desc.contains("Default search engine"):
            return checkDefaultSearchEngine(check: check)
            
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
    
    private static func checkOpenSafeFilesDisabled(check: CISCheck) -> CheckResult {
        guard let plist = getSafariPreferences(),
              let openSafeFiles = plist["AutoOpenSafeDownloads"] as? Bool else {
            // If not found, default is false (disabled) in newer macOS versions
            return CheckResult(check: check, status: "pass", details: "'Open safe files after downloading' appears to be disabled.")
        }
        if openSafeFiles == false {
            return CheckResult(check: check, status: "pass", details: "'Open safe files after downloading' is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "'Open safe files after downloading' is ENABLED.")
        }
    }

    // Check if AutoFill is disabled in Safari
    private static func checkAutoFillDisabled(check: CISCheck) -> CheckResult {
        guard let plist = getSafariPreferences() else {
            return CheckResult(check: check, status: "error", details: "Could not read Safari preferences.")
        }
        
        // Check for AutoFill settings
        let autoFillAddressesEnabled = plist["AutoFillFromAddressBook"] as? Bool ?? true
        let autoFillCreditCardsEnabled = plist["AutoFillCreditCardData"] as? Bool ?? true
        let autoFillPasswordsEnabled = plist["AutoFillPasswords"] as? Bool ?? true
        
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
    private static func checkAutoFillWebFormsDisabled(check: CISCheck) -> CheckResult {
        guard let plist = getSafariPreferences() else {
            return CheckResult(check: check, status: "error", details: "Could not read Safari preferences.")
        }
        
        let autoFillFormsEnabled = plist["AutoFillMiscellaneousForms"] as? Bool ?? true
        
        if !autoFillFormsEnabled {
            return CheckResult(check: check, status: "pass", details: "AutoFill web forms is disabled in Safari.")
        } else {
            return CheckResult(check: check, status: "fail", details: "AutoFill web forms is enabled in Safari.")
        }
    }
    
    // Check if AutoFill credit cards is disabled
    private static func checkAutoFillCreditCardsDisabled(check: CISCheck) -> CheckResult {
        guard let plist = getSafariPreferences() else {
            return CheckResult(check: check, status: "error", details: "Could not read Safari preferences.")
        }
        
        let autoFillCreditCardsEnabled = plist["AutoFillCreditCardData"] as? Bool ?? true
        
        if !autoFillCreditCardsEnabled {
            return CheckResult(check: check, status: "pass", details: "AutoFill credit cards is disabled in Safari.")
        } else {
            return CheckResult(check: check, status: "fail", details: "AutoFill credit cards is enabled in Safari.")
        }
    }
    
    // Check if AutoFill contact information is disabled
    private static func checkAutoFillContactInfoDisabled(check: CISCheck) -> CheckResult {
        guard let plist = getSafariPreferences() else {
            return CheckResult(check: check, status: "error", details: "Could not read Safari preferences.")
        }
        
        let autoFillAddressesEnabled = plist["AutoFillFromAddressBook"] as? Bool ?? true
        
        if !autoFillAddressesEnabled {
            return CheckResult(check: check, status: "pass", details: "AutoFill contact information is disabled in Safari.")
        } else {
            return CheckResult(check: check, status: "fail", details: "AutoFill contact information is enabled in Safari.")
        }
    }
    
    // Check if AutoFill usernames and passwords is disabled
    private static func checkAutoFillPasswordsDisabled(check: CISCheck) -> CheckResult {
        guard let plist = getSafariPreferences() else {
            return CheckResult(check: check, status: "error", details: "Could not read Safari preferences.")
        }
        
        let autoFillPasswordsEnabled = plist["AutoFillPasswords"] as? Bool ?? true
        
        if !autoFillPasswordsEnabled {
            return CheckResult(check: check, status: "pass", details: "AutoFill usernames and passwords is disabled in Safari.")
        } else {
            return CheckResult(check: check, status: "fail", details: "AutoFill usernames and passwords is enabled in Safari.")
        }
    }

    // Check if Block pop-up windows is enabled in Safari
    private static func checkBlockPopupsEnabled(check: CISCheck) -> CheckResult {
        guard let plist = getSafariPreferences(),
              let blockPopups = plist["WebKitJavaScriptCanOpenWindowsAutomatically"] as? Bool else {
            return CheckResult(check: check, status: "error", details: "Could not read Safari pop-up blocker settings.")
        }
        
        // Note: The setting is inverted - when false, pop-ups are blocked
        if !blockPopups {
            return CheckResult(check: check, status: "pass", details: "Safari is set to block pop-up windows.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Safari is NOT set to block pop-up windows.")
        }
    }

    // Check if JavaScript is disabled in Safari
    private static func checkJavaScriptDisabled(check: CISCheck) -> CheckResult {
        guard let plist = getSafariPreferences(),
              let javascriptEnabled = plist["WebKitJavaScriptEnabled"] as? Bool else {
            return CheckResult(check: check, status: "error", details: "Could not read Safari JavaScript settings.")
        }
        
        if !javascriptEnabled {
            return CheckResult(check: check, status: "pass", details: "JavaScript is disabled in Safari.")
        } else {
            return CheckResult(check: check, status: "fail", details: "JavaScript is enabled in Safari.")
        }
    }
    
    // Check if fraudulent website warning is enabled
    private static func checkFraudulentWebsiteWarningEnabled(check: CISCheck) -> CheckResult {
        guard let plist = getSafariPreferences(),
              let warnAboutFraudulentWebsites = plist["WarnAboutFraudulentWebsites"] as? Bool else {
            // Default is enabled in modern macOS
            return CheckResult(check: check, status: "pass", details: "Warn when visiting a fraudulent website appears to be enabled.")
        }
        
        if warnAboutFraudulentWebsites {
            return CheckResult(check: check, status: "pass", details: "Warn when visiting a fraudulent website is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Warn when visiting a fraudulent website is disabled.")
        }
    }
    
    // MARK: - Privacy Features
    
    // Check if prevent cross-site tracking is enabled
    private static func checkPreventCrossSiteTracking(check: CISCheck) -> CheckResult {
        guard let plist = getSafariPreferences(),
              let preventCrossSiteTracking = plist["WebKitPreferences.storageBlockingPolicy"] as? Int else {
            // Default is enabled (policy 1) in modern macOS
            return CheckResult(check: check, status: "pass", details: "Prevent cross-site tracking appears to be enabled.")
        }
        
        if preventCrossSiteTracking >= 1 {
            return CheckResult(check: check, status: "pass", details: "Prevent cross-site tracking is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Prevent cross-site tracking is disabled.")
        }
    }
    
    // Check if block all cookies is enabled
    private static func checkBlockAllCookies(check: CISCheck) -> CheckResult {
        guard let plist = getSafariPreferences(),
              let blockAllCookies = plist["BlockAllCookies"] as? Bool else {
            // Default is disabled in modern macOS
            return CheckResult(check: check, status: "fail", details: "Block all cookies appears to be disabled.")
        }
        
        if blockAllCookies {
            return CheckResult(check: check, status: "pass", details: "Block all cookies is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Block all cookies is disabled.")
        }
    }
    
    // Check if website tracking is set to prevent cross-site tracking
    private static func checkWebsiteTracking(check: CISCheck) -> CheckResult {
        guard let plist = getSafariPreferences(),
              let trackingPolicy = plist["WebKitPreferences.trackingPreventionEnabled"] as? Bool else {
            // Default is enabled in modern macOS
            return CheckResult(check: check, status: "pass", details: "Website tracking prevention appears to be enabled.")
        }
        
        if trackingPolicy {
            return CheckResult(check: check, status: "pass", details: "Website tracking is set to prevent cross-site tracking.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Website tracking is not set to prevent cross-site tracking.")
        }
    }
    
    // Check if 'Ask websites not to track me' is enabled
    private static func checkAskWebsitesNotToTrack(check: CISCheck) -> CheckResult {
        guard let plist = getSafariPreferences(),
              let sendDoNotTrack = plist["SendDoNotTrackHTTPHeader"] as? Bool else {
            // Default is disabled in modern macOS
            return CheckResult(check: check, status: "fail", details: "Ask websites not to track me appears to be disabled.")
        }
        
        if sendDoNotTrack {
            return CheckResult(check: check, status: "pass", details: "Ask websites not to track me is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Ask websites not to track me is disabled.")
        }
    }
    
    // Check if privacy preserving ad measurement is disabled
    private static func checkPrivacyPreservingAdMeasurement(check: CISCheck) -> CheckResult {
        guard let plist = getSafariPreferences(),
              let adMeasurementEnabled = plist["WebKitPreferences.privateClickMeasurementEnabled"] as? Bool else {
            // Default is enabled in modern macOS
            return CheckResult(check: check, status: "fail", details: "Privacy preserving ad measurement appears to be enabled.")
        }
        
        if !adMeasurementEnabled {
            return CheckResult(check: check, status: "pass", details: "Privacy preserving ad measurement is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Privacy preserving ad measurement is enabled.")
        }
    }
    
    // MARK: - Extension Settings
    
    // Check if extensions are disabled
    private static func checkExtensionsDisabled(check: CISCheck) -> CheckResult {
        guard let plist = getSafariPreferences(),
              let extensionsEnabled = plist["ExtensionsEnabled"] as? Bool else {
            // Default is enabled in modern macOS
            return CheckResult(check: check, status: "fail", details: "Extensions appear to be enabled.")
        }
        
        if !extensionsEnabled {
            return CheckResult(check: check, status: "pass", details: "Extensions are disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Extensions are enabled.")
        }
    }
    
    // Check if JavaScript is disabled for untrusted sites
    private static func checkJavaScriptDisabledForUntrustedSites(check: CISCheck) -> CheckResult {
        guard let plist = getSafariPreferences(),
              let javascriptFromUntrustedSites = plist["WebKitPreferences.javaScriptCanOpenWindowsAutomatically"] as? Bool else {
            // Default is enabled in modern macOS
            return CheckResult(check: check, status: "fail", details: "JavaScript for untrusted sites appears to be enabled.")
        }
        
        if !javascriptFromUntrustedSites {
            return CheckResult(check: check, status: "pass", details: "JavaScript is disabled for untrusted sites.")
        } else {
            return CheckResult(check: check, status: "fail", details: "JavaScript is enabled for untrusted sites.")
        }
    }
    
    // Check if Internet plug-ins are disabled
    private static func checkInternetPluginsDisabled(check: CISCheck) -> CheckResult {
        guard let plist = getSafariPreferences(),
              let pluginsEnabled = plist["WebKitPluginsEnabled"] as? Bool else {
            // Default is disabled in modern macOS
            return CheckResult(check: check, status: "pass", details: "Internet plug-ins appear to be disabled.")
        }
        
        if !pluginsEnabled {
            return CheckResult(check: check, status: "pass", details: "Internet plug-ins are disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Internet plug-ins are enabled.")
        }
    }
    
    // Check if Java is disabled
    private static func checkJavaDisabled(check: CISCheck) -> CheckResult {
        guard let plist = getSafariPreferences(),
              let javaEnabled = plist["WebKitJavaEnabled"] as? Bool else {
            // Default is disabled in modern macOS
            return CheckResult(check: check, status: "pass", details: "Java appears to be disabled.")
        }
        
        if !javaEnabled {
            return CheckResult(check: check, status: "pass", details: "Java is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Java is enabled.")
        }
    }
    
    // MARK: - Advanced Settings
    
    // Check if full website address is shown
    private static func checkShowFullWebsiteAddress(check: CISCheck) -> CheckResult {
        guard let plist = getSafariPreferences(),
              let showFullURL = plist["ShowFullURLInSmartSearchField"] as? Bool else {
            // Default is disabled in modern macOS
            return CheckResult(check: check, status: "fail", details: "Show full website address appears to be disabled.")
        }
        
        if showFullURL {
            return CheckResult(check: check, status: "pass", details: "Show full website address is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Show full website address is disabled.")
        }
    }
    
    // Check if Develop menu is shown in menu bar
    private static func checkShowDevelopMenu(check: CISCheck) -> CheckResult {
        guard let plist = getSafariPreferences(),
              let showDevelopMenu = plist["IncludeDevelopMenu"] as? Bool else {
            // Default is disabled in modern macOS
            return CheckResult(check: check, status: "fail", details: "Show Develop menu in menu bar appears to be disabled.")
        }
        
        if showDevelopMenu {
            return CheckResult(check: check, status: "pass", details: "Show Develop menu in menu bar is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Show Develop menu in menu bar is disabled.")
        }
    }
    
    // Check if status bar is shown
    private static func checkShowStatusBar(check: CISCheck) -> CheckResult {
        guard let plist = getSafariPreferences(),
              let showStatusBar = plist["ShowStatusBar"] as? Bool else {
            // Default is disabled in modern macOS
            return CheckResult(check: check, status: "fail", details: "Show status bar appears to be disabled.")
        }
        
        if showStatusBar {
            return CheckResult(check: check, status: "pass", details: "Show status bar is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Show status bar is disabled.")
        }
    }
    
    // Check if Smart Search Field suggestions are disabled
    private static func checkSmartSearchFieldSuggestionsDisabled(check: CISCheck) -> CheckResult {
        guard let plist = getSafariPreferences(),
              let suggestionsEnabled = plist["UniversalSearchEnabled"] as? Bool else {
            // Default is enabled in modern macOS
            return CheckResult(check: check, status: "fail", details: "Smart Search Field suggestions appear to be enabled.")
        }
        
        if !suggestionsEnabled {
            return CheckResult(check: check, status: "pass", details: "Smart Search Field suggestions are disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Smart Search Field suggestions are enabled.")
        }
    }
    
    // Check if default search engine is set to a privacy-focused engine
    private static func checkDefaultSearchEngine(check: CISCheck) -> CheckResult {
        guard let plist = getSafariPreferences(),
              let searchEngine = plist["SearchProviderIdentifier"] as? String else {
            // Default is Google in modern macOS
            return CheckResult(check: check, status: "fail", details: "Default search engine appears to be set to Google.")
        }
        
        let privacyFocusedEngines = ["com.duckduckgo", "com.startpage", "com.qwant"]
        
        if privacyFocusedEngines.contains(where: { searchEngine.contains($0) }) {
            return CheckResult(check: check, status: "pass", details: "Default search engine is set to a privacy-focused engine.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Default search engine is not set to a privacy-focused engine.")
        }
    }
}

