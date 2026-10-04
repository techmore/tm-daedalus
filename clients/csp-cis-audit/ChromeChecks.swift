import Foundation
import CoreFoundation

struct ChromeChecks {
    static func run(check: CISCheck, readPreferences: () -> [String: Any]? = { getChromePreferences() },
                    readManagedPolicy: (String) -> (Any?, Bool) = ChromeChecks.readManagedPolicy) -> CheckResult {
        let preferences = readPreferences()
        switch check.description {
        // Privacy and Security
        case let desc where desc.contains("Safe Browsing settings are enabled"):
            return managedSafeBrowsing(check: check, enhanced: false, readPolicy: readManagedPolicy)
        case let desc where desc.contains("Safe Browsing Protection Level"):
            return managedSafeBrowsing(check: check, enhanced: true, readPolicy: readManagedPolicy)
        case let desc where desc.contains("Allow Google Cast to connect to Cast devices"):
            return checkGoogleCastDisabled(check: check, preferences: preferences)
        case let desc where desc.contains("Allow queries to a Google time service"):
            return checkGoogleTimeService(check: check, preferences: preferences)
        case let desc where desc.contains("Allow the audio sandbox to run"):
            return checkAudioSandbox(check: check, preferences: preferences)
        case let desc where desc.contains("Ask where to save each file before downloading"):
            return checkAskWhereToSave(check: check, preferences: preferences)
        case let desc where desc.contains("Continue running background apps when Chrome is closed"):
            return checkBackgroundAppsDisabled(check: check, preferences: preferences)
        case let desc where desc.contains("Control SafeSites adult content filtering"):
            return checkSafeSitesContentFiltering(check: check, preferences: preferences)
        case let desc where desc.contains("Disable Certificate Transparency enforcement"):
            return checkCertificateTransparency(check: check, preferences: preferences)
        case let desc where desc.contains("Disable saving browser history"):
            return checkSavingBrowserHistory(check: check, preferences: preferences)
        case let desc where desc.contains("DNS interception checks enabled"):
            return checkDNSInterceptionChecks(check: check, preferences: preferences)
        case let desc where desc.contains("Enable component updates in Google Chrome"):
            return checkComponentUpdatesEnabled(check: check, preferences: preferences)
        case let desc where desc.contains("Enable third party software injection blocking"):
            return checkThirdPartySoftwareInjection(check: check, preferences: preferences)
            
        // Privacy Features
        case let desc where desc.contains("Import autofill form data from default browser"):
            return checkImportAutofillDisabled(check: check, preferences: preferences)
        case let desc where desc.contains("Import of homepage from default browser"):
            return checkImportHomepageDisabled(check: check, preferences: preferences)
        case let desc where desc.contains("Import search engines from default browser"):
            return checkImportSearchEnginesDisabled(check: check, preferences: preferences)
        case let desc where desc.contains("Enable security warnings for command-line flags"):
            return checkSecurityWarningsEnabled(check: check, preferences: preferences)
        case let desc where desc.contains("Enable reporting of usage and crash-related data"):
            return checkReportingDisabled(check: check, preferences: preferences)
        case let desc where desc.contains("Enable Safe Browsing for trusted sources"):
            return checkSafeBrowsingTrustedSourcesDisabled(check: check, preferences: preferences)
        case let desc where desc.contains("Enable search suggestions"):
            return checkSearchSuggestionsDisabled(check: check, preferences: preferences)
        case let desc where desc.contains("Set disk cache size"):
            return checkDiskCacheSize(check: check, preferences: preferences)
            
        // Cookie and Site Data Settings
        case let desc where desc.contains("Block third-party cookies"):
            return checkBlockThirdPartyCookies(check: check, preferences: preferences)
        case let desc where desc.contains("Clear cookies and site data when you quit Chrome"):
            return checkClearCookiesOnQuit(check: check, preferences: preferences)
        case let desc where desc.contains("Default cookies setting"):
            return checkDefaultCookiesSetting(check: check, preferences: preferences)
        case let desc where desc.contains("Enable Do Not Track"):
            return checkDoNotTrackEnabled(check: check, preferences: preferences)
            
        // Extension Settings
        case let desc where desc.contains("Configure extension installation blocklist"):
            return checkExtensionBlocklist(check: check, preferences: preferences)
        case let desc where desc.contains("Configure allowed Chrome Web Store extensions"):
            return checkAllowedExtensions(check: check, preferences: preferences)
        case let desc where desc.contains("Control which extensions can access file URLs"):
            return checkExtensionFileAccess(check: check, preferences: preferences)
        case let desc where desc.contains("Control which extensions can inject scripts"):
            return checkExtensionScriptInjection(check: check, preferences: preferences)
            
        // Password Settings
        case let desc where desc.contains("Enable saving passwords to the password manager"):
            return managedDisabledPolicy(check: check, key: "PasswordManagerEnabled", readPolicy: readManagedPolicy)
        case let desc where desc.contains("Enable Autofill for addresses"):
            return managedDisabledPolicy(check: check, key: "AutofillAddressEnabled", readPolicy: readManagedPolicy)
        case let desc where desc.contains("Enable Autofill for credit cards"):
            return managedDisabledPolicy(check: check, key: "AutofillCreditCardEnabled", readPolicy: readManagedPolicy)
        case let desc where desc.contains("Enable Autofill for payment methods"):
            return checkAutofillPaymentMethodsDisabled(check: check, preferences: preferences)
            
        default:
            return CheckResult(check: check, status: "manual", details: "Not yet implemented")
        }
    }

    static func readManagedPolicy(_ key: String) -> (Any?, Bool) {
        let domain = "com.google.Chrome" as CFString
        return (CFPreferencesCopyAppValue(key as CFString, domain),
                CFPreferencesAppValueIsForced(key as CFString, domain))
    }

    private static func managedDisabledPolicy(check: CISCheck, key: String,
        readPolicy: (String) -> (Any?, Bool)) -> CheckResult {
        let (raw, forced) = readPolicy(key)
        guard forced, let value = raw as? NSNumber,
              CFGetTypeID(value) == CFBooleanGetTypeID() else {
            return CheckResult(check: check, status: "manual", details: key + " was not captured as an explicit forced Boolean in the current user's com.google.Chrome preference domain. Missing, recommended or wrongly typed values do not establish mandatory policy. Review chrome://policy for browser acceptance and precedence.")
        }
        return CheckResult(check: check, status: value.boolValue ? "fail" : "pass", details: "CSP criterion: " + key + " must be disabled. The current user's macOS preference domain reports a forced Boolean " + (value.boolValue ? "enabled." : "disabled.") + " This is captured platform policy evidence, not a live Chrome acceptance test or proof for every browser profile. No policy was changed.")
    }

    // MARK: - Helper Methods
    
    private static func getChromePreferences() -> [String: Any]? {
        let homeDir = FileManager.default.homeDirectoryForCurrentUser
        let prefsPath = homeDir.appendingPathComponent("Library/Application Support/Google/Chrome/Default/Preferences").path
        guard FileManager.default.fileExists(atPath: prefsPath),
              let data = try? Data(contentsOf: URL(fileURLWithPath: prefsPath)),
              let prefs = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }
        return prefs
    }
    
    // MARK: - Privacy and Security Checks
    
    private static func managedSafeBrowsing(check: CISCheck, enhanced: Bool,
        readPolicy: (String) -> (Any?, Bool)) -> CheckResult {
        let key = "SafeBrowsingProtectionLevel"
        let (raw, forced) = readPolicy(key)
        guard forced, let value = raw as? NSNumber,
              CFGetTypeID(value) != CFBooleanGetTypeID(),
              ["c", "C", "s", "S", "i", "I", "l", "L", "q", "Q"].contains(String(cString: value.objCType)),
              [0, 1, 2].contains(value.intValue) else {
            return CheckResult(check: check, status: "manual", details: "SafeBrowsingProtectionLevel was not captured as a forced supported integer (0, 1 or 2) in the current user's com.google.Chrome domain. Missing, recommended or unsupported evidence was not inferred as protection. Review chrome://policy for browser acceptance and precedence.")
        }
        let level = value.intValue
        let matches = enhanced ? level == 2 : level > 0
        let criterion = enhanced ? "enhanced protection (2)" : "standard or enhanced protection (1 or 2)"
        return CheckResult(check: check, status: matches ? "pass" : "fail", details: "CSP criterion: Safe Browsing requires " + criterion + ". Captured forced macOS SafeBrowsingProtectionLevel=" + String(level) + ". This is current-user platform policy evidence, not live browser acceptance or a malicious-site test. Enhanced mode shares more browsing information with Google. No policy was changed.")
    }

    private static func checkGoogleCastDisabled(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        guard let prefs = preferences,
              let discovery = prefs["discovery"] as? [String: Any],
              let deviceDiscoveryConfig = discovery["device_discovery_config"] as? [String: Any],
              let mdnsEnabled = deviceDiscoveryConfig["mdns_enabled"] as? Bool else {
            return CheckResult.unavailablePreference(check: check, detail: "Could not read Chrome Google Cast settings.")
        }
        if !mdnsEnabled {
            return CheckResult(check: check, status: "pass", details: "Google Cast is disabled from connecting to Cast devices on all IP addresses.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Google Cast is enabled to connect to Cast devices on all IP addresses.")
        }
    }
    
    private static func checkGoogleTimeService(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        guard let prefs = preferences,
              let browser = prefs["browser"] as? [String: Any],
              let enableTimeService = browser["enable_time_service"] as? Bool else {
            return CheckResult.unavailablePreference(check: check, detail: "Could not read Chrome time service settings.")
        }
        if enableTimeService {
            return CheckResult(check: check, status: "pass", details: "Queries to Google time service are enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Queries to Google time service are disabled.")
        }
    }
    
    private static func checkAudioSandbox(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        guard let prefs = preferences,
              let browser = prefs["browser"] as? [String: Any],
              let audioSandboxEnabled = browser["audio_sandbox_enabled"] as? Bool else {
            return CheckResult.unavailablePreference(check: check, detail: "Could not read Chrome audio sandbox settings.")
        }
        if audioSandboxEnabled {
            return CheckResult(check: check, status: "pass", details: "Audio sandbox is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Audio sandbox is disabled.")
        }
    }

    // Check if 'Ask where to save each file before downloading' is enabled
    private static func checkAskWhereToSave(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        guard let prefs = preferences,
              let download = prefs["download"] as? [String: Any],
              let promptForDownload = download["prompt_for_download"] as? Bool else {
            return CheckResult.unavailablePreference(check: check, detail: "Could not read Chrome download preferences.")
        }
        
        if promptForDownload {
            return CheckResult(check: check, status: "pass", details: "Chrome is configured to ask where to save each file before downloading.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Chrome is NOT configured to ask where to save each file before downloading.")
        }
    }
    
    private static func checkSafeSitesContentFiltering(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        guard let prefs = preferences,
              let safebrowsing = prefs["safebrowsing"] as? [String: Any],
              let safeSitesFiltering = safebrowsing["safe_sites_filtering_enabled"] as? Bool else {
            return CheckResult.unavailablePreference(check: check, detail: "Could not read Chrome SafeSites content filtering settings.")
        }
        
        if safeSitesFiltering {
            return CheckResult(check: check, status: "pass", details: "SafeSites adult content filtering is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "SafeSites adult content filtering is disabled.")
        }
    }
    
    private static func checkCertificateTransparency(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        guard let prefs = preferences,
              let certificateTransparency = prefs["certificate_transparency"] as? [String: Any],
              let disabledForLegacyCas = certificateTransparency["disabled_for_legacy_cas"] as? Bool else {
            return CheckResult.unavailablePreference(check: check, detail: "Required Chrome preference evidence was not captured.")
        }
        
        if !disabledForLegacyCas {
            return CheckResult(check: check, status: "pass", details: "Certificate Transparency enforcement for Legacy CAs is not disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Certificate Transparency enforcement for Legacy CAs is disabled.")
        }
    }
    
    private static func checkSavingBrowserHistory(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        guard let prefs = preferences,
              let savingBrowserHistoryDisabled = prefs["savingBrowserHistoryDisabled"] as? Bool else {
            return CheckResult.unavailablePreference(check: check, detail: "Required Chrome preference evidence was not captured.")
        }
        
        if !savingBrowserHistoryDisabled {
            return CheckResult(check: check, status: "pass", details: "Saving browser history is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Saving browser history is disabled.")
        }
    }
    
    private static func checkDNSInterceptionChecks(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        guard let prefs = preferences,
              let browser = prefs["browser"] as? [String: Any],
              let dnsInterceptionChecksEnabled = browser["dns_interception_checks_enabled"] as? Bool else {
            return CheckResult.unavailablePreference(check: check, detail: "Required Chrome preference evidence was not captured.")
        }
        
        if dnsInterceptionChecksEnabled {
            return CheckResult(check: check, status: "pass", details: "DNS interception checks are enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "DNS interception checks are disabled.")
        }
    }

    // Check if 'Continue running background apps when Chrome is closed' is disabled
    private static func checkBackgroundAppsDisabled(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        guard let prefs = preferences,
              let backgroundMode = prefs["background_mode"] as? [String: Any],
              let enabled = backgroundMode["enabled"] as? Bool else {
            return CheckResult.unavailablePreference(check: check, detail: "Could not read Chrome background mode settings.")
        }
        
        if !enabled {
            return CheckResult(check: check, status: "pass", details: "Chrome is set to NOT continue running background apps when closed.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Chrome is set to continue running background apps when closed.")
        }
    }

    // Check if 'Enable component updates in Google Chrome' is enabled
    private static func checkComponentUpdatesEnabled(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        guard let prefs = preferences,
              let componentUpdater = prefs["component_updater"] as? [String: Any],
              let enableComponentUpdates = componentUpdater["enable_component_updates"] as? Bool else {
            return CheckResult.unavailablePreference(check: check, detail: "Could not read Chrome component updater settings.")
        }
        
        if enableComponentUpdates {
            return CheckResult(check: check, status: "pass", details: "Component updates in Google Chrome are enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Component updates in Google Chrome are disabled.")
        }
    }
    
    private static func checkThirdPartySoftwareInjection(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        guard let prefs = preferences,
              let browser = prefs["browser"] as? [String: Any],
              let thirdPartySoftwareInjectionBlocking = browser["third_party_software_injection_blocking_enabled"] as? Bool else {
            return CheckResult.unavailablePreference(check: check, detail: "Could not read Chrome third party software injection settings.")
        }
        
        if thirdPartySoftwareInjectionBlocking {
            return CheckResult(check: check, status: "pass", details: "Third party software injection blocking is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Third party software injection blocking is disabled.")
        }
    }
    
    // MARK: - Privacy Features
    
    private static func checkImportAutofillDisabled(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        guard let prefs = preferences,
              let importAutofillFormData = prefs["import_autofill_form_data"] as? Bool else {
            return CheckResult.unavailablePreference(check: check, detail: "Required Chrome preference evidence was not captured.")
        }
        
        if !importAutofillFormData {
            return CheckResult(check: check, status: "pass", details: "Import autofill form data from default browser is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Import autofill form data from default browser is enabled.")
        }
    }
    
    private static func checkImportHomepageDisabled(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        guard let prefs = preferences,
              let importHomepage = prefs["import_homepage"] as? Bool else {
            return CheckResult.unavailablePreference(check: check, detail: "Required Chrome preference evidence was not captured.")
        }
        
        if !importHomepage {
            return CheckResult(check: check, status: "pass", details: "Import of homepage from default browser is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Import of homepage from default browser is enabled.")
        }
    }
    
    private static func checkImportSearchEnginesDisabled(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        guard let prefs = preferences,
              let importSearchEngine = prefs["import_search_engine"] as? Bool else {
            return CheckResult.unavailablePreference(check: check, detail: "Required Chrome preference evidence was not captured.")
        }
        
        if !importSearchEngine {
            return CheckResult(check: check, status: "pass", details: "Import search engines from default browser is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Import search engines from default browser is enabled.")
        }
    }
    
    private static func checkSecurityWarningsEnabled(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        guard let prefs = preferences,
              let browser = prefs["browser"] as? [String: Any],
              let securityWarnings = browser["enable_security_warnings_for_command_line_flags"] as? Bool else {
            return CheckResult.unavailablePreference(check: check, detail: "Required Chrome preference evidence was not captured.")
        }
        
        if securityWarnings {
            return CheckResult(check: check, status: "pass", details: "Security warnings for command-line flags are enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Security warnings for command-line flags are disabled.")
        }
    }
    
    private static func checkReportingDisabled(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        guard let prefs = preferences,
              let reporting = prefs["reporting"] as? [String: Any],
              let enabled = reporting["enabled"] as? Bool else {
            return CheckResult.unavailablePreference(check: check, detail: "Required Chrome preference evidence was not captured.")
        }
        
        if !enabled {
            return CheckResult(check: check, status: "pass", details: "Reporting of usage and crash-related data is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Reporting of usage and crash-related data is enabled.")
        }
    }
    
    private static func checkSafeBrowsingTrustedSourcesDisabled(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        guard let prefs = preferences,
              let safebrowsing = prefs["safebrowsing"] as? [String: Any],
              let trustedSourcesEnabled = safebrowsing["trusted_sources_enabled"] as? Bool else {
            return CheckResult.unavailablePreference(check: check, detail: "Required Chrome preference evidence was not captured.")
        }
        
        if !trustedSourcesEnabled {
            return CheckResult(check: check, status: "pass", details: "Safe Browsing for trusted sources is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Safe Browsing for trusted sources is enabled.")
        }
    }
    
    private static func checkSearchSuggestionsDisabled(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        guard let prefs = preferences,
              let searchSuggestEnabled = prefs["search_suggest_enabled"] as? Bool else {
            return CheckResult.unavailablePreference(check: check, detail: "Required Chrome preference evidence was not captured.")
        }
        
        if !searchSuggestEnabled {
            return CheckResult(check: check, status: "pass", details: "Search suggestions are disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Search suggestions are enabled.")
        }
    }
    
    private static func checkDiskCacheSize(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        guard let prefs = preferences,
              let net = prefs["net"] as? [String: Any],
              let diskCacheSize = net["disk_cache_size"] as? Int else {
            return CheckResult.unavailablePreference(check: check, detail: "Required Chrome preference evidence was not captured.")
        }
        
        // Recommended size is 100MB or less
        if diskCacheSize <= 104857600 {
            return CheckResult(check: check, status: "pass", details: "Disk cache size is set to an appropriate value.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Disk cache size is set too high.")
        }
    }
    
    // MARK: - Cookie and Site Data Settings
    
    private static func checkBlockThirdPartyCookies(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        guard let prefs = preferences,
              let blockThirdPartyCookies = prefs["block_third_party_cookies"] as? Bool else {
            return CheckResult.unavailablePreference(check: check, detail: "Required Chrome preference evidence was not captured.")
        }
        
        if blockThirdPartyCookies {
            return CheckResult(check: check, status: "pass", details: "Block third-party cookies is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Block third-party cookies is disabled.")
        }
    }
    
    private static func checkClearCookiesOnQuit(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        guard let prefs = preferences,
              let clearOnExit = prefs["clear_on_exit"] as? Bool else {
            return CheckResult.unavailablePreference(check: check, detail: "Required Chrome preference evidence was not captured.")
        }
        
        if clearOnExit {
            return CheckResult(check: check, status: "pass", details: "Clear cookies and site data when quitting Chrome is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Clear cookies and site data when quitting Chrome is disabled.")
        }
    }
    
    private static func checkDefaultCookiesSetting(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        guard let prefs = preferences,
              let cookieControls = prefs["cookie_controls"] as? [String: Any],
              let mode = cookieControls["mode"] as? Int else {
            return CheckResult.unavailablePreference(check: check, detail: "Required Chrome preference evidence was not captured.")
        }
        
        // Mode 2 is "keep local data until you quit your browser"
        if mode == 2 {
            return CheckResult(check: check, status: "pass", details: "Default cookies setting is set to keep local data until browser is closed.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Default cookies setting is not set to keep local data until browser is closed.")
        }
    }
    
    private static func checkDoNotTrackEnabled(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        guard let prefs = preferences,
              let doNotTrack = prefs["enable_do_not_track"] as? Bool else {
            return CheckResult.unavailablePreference(check: check, detail: "Required Chrome preference evidence was not captured.")
        }
        
        if doNotTrack {
            return CheckResult(check: check, status: "pass", details: "Do Not Track is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Do Not Track is disabled.")
        }
    }
    
    // MARK: - Extension Settings
    
    private static func checkExtensionBlocklist(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        CheckResult(check: check, status: "manual", details: "Review effective Chrome extension installation block rules and their exceptions against the organization's approved policy. Nonempty local extension preference lists do not establish policy enforcement or approval. Supported effective ExtensionSettings and relevant policy precedence were not collected; no extension setting was changed.")
    }

    private static func checkAllowedExtensions(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        CheckResult(check: check, status: "manual", details: "Review effective Chrome approved extension IDs and installation sources against the organization's approved policy. Nonempty local extension preference lists do not establish policy enforcement or approval. Supported effective ExtensionSettings and relevant policy precedence were not collected; no extension setting was changed.")
    }

    private static func checkExtensionFileAccess(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        CheckResult(check: check, status: "manual", details: "Review effective Chrome extension file-URL permissions against the organization's approved policy. Nonempty local extension preference lists do not establish policy enforcement or approval. Supported effective ExtensionSettings and relevant policy precedence were not collected; no extension setting was changed.")
    }

    private static func checkExtensionScriptInjection(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        CheckResult(check: check, status: "manual", details: "Review effective Chrome extension host permissions and script-injection restrictions against the organization's approved policy. Nonempty local extension preference lists do not establish policy enforcement or approval. Supported effective ExtensionSettings and relevant policy precedence were not collected; no extension setting was changed.")
    }

    // MARK: - Password Settings
    

    

    

    
    private static func checkAutofillPaymentMethodsDisabled(check: CISCheck, preferences: [String: Any]?) -> CheckResult {
        guard let prefs = preferences,
              let autofill = prefs["autofill"] as? [String: Any],
              let paymentMethodEnabled = autofill["payment_method_enabled"] as? Bool else {
            return CheckResult.unavailablePreference(check: check, detail: "Required Chrome preference evidence was not captured.")
        }
        
        if !paymentMethodEnabled {
            return CheckResult(check: check, status: "pass", details: "Autofill for payment methods is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Autofill for payment methods is enabled.")
        }
    }
}
