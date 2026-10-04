import Foundation

struct ChromeChecks {
    static func run(check: CISCheck) -> CheckResult {
        switch check.description {
        // Privacy and Security
        case let desc where desc.contains("Safe Browsing settings are enabled"):
            return checkSafeBrowsing(check: check)
        case let desc where desc.contains("Safe Browsing Protection Level"):
            return checkSafeBrowsingProtectionLevel(check: check)
        case let desc where desc.contains("Allow Google Cast to connect to Cast devices"):
            return checkGoogleCastDisabled(check: check)
        case let desc where desc.contains("Allow queries to a Google time service"):
            return checkGoogleTimeService(check: check)
        case let desc where desc.contains("Allow the audio sandbox to run"):
            return checkAudioSandbox(check: check)
        case let desc where desc.contains("Ask where to save each file before downloading"):
            return checkAskWhereToSave(check: check)
        case let desc where desc.contains("Continue running background apps when Chrome is closed"):
            return checkBackgroundAppsDisabled(check: check)
        case let desc where desc.contains("Control SafeSites adult content filtering"):
            return checkSafeSitesContentFiltering(check: check)
        case let desc where desc.contains("Disable Certificate Transparency enforcement"):
            return checkCertificateTransparency(check: check)
        case let desc where desc.contains("Disable saving browser history"):
            return checkSavingBrowserHistory(check: check)
        case let desc where desc.contains("DNS interception checks enabled"):
            return checkDNSInterceptionChecks(check: check)
        case let desc where desc.contains("Enable component updates in Google Chrome"):
            return checkComponentUpdatesEnabled(check: check)
        case let desc where desc.contains("Enable third party software injection blocking"):
            return checkThirdPartySoftwareInjection(check: check)
            
        // Privacy Features
        case let desc where desc.contains("Import autofill form data from default browser"):
            return checkImportAutofillDisabled(check: check)
        case let desc where desc.contains("Import of homepage from default browser"):
            return checkImportHomepageDisabled(check: check)
        case let desc where desc.contains("Import search engines from default browser"):
            return checkImportSearchEnginesDisabled(check: check)
        case let desc where desc.contains("Enable security warnings for command-line flags"):
            return checkSecurityWarningsEnabled(check: check)
        case let desc where desc.contains("Enable reporting of usage and crash-related data"):
            return checkReportingDisabled(check: check)
        case let desc where desc.contains("Enable Safe Browsing for trusted sources"):
            return checkSafeBrowsingTrustedSourcesDisabled(check: check)
        case let desc where desc.contains("Enable search suggestions"):
            return checkSearchSuggestionsDisabled(check: check)
        case let desc where desc.contains("Set disk cache size"):
            return checkDiskCacheSize(check: check)
            
        // Cookie and Site Data Settings
        case let desc where desc.contains("Block third-party cookies"):
            return checkBlockThirdPartyCookies(check: check)
        case let desc where desc.contains("Clear cookies and site data when you quit Chrome"):
            return checkClearCookiesOnQuit(check: check)
        case let desc where desc.contains("Default cookies setting"):
            return checkDefaultCookiesSetting(check: check)
        case let desc where desc.contains("Enable Do Not Track"):
            return checkDoNotTrackEnabled(check: check)
            
        // Extension Settings
        case let desc where desc.contains("Configure extension installation blocklist"):
            return checkExtensionBlocklist(check: check)
        case let desc where desc.contains("Configure allowed Chrome Web Store extensions"):
            return checkAllowedExtensions(check: check)
        case let desc where desc.contains("Control which extensions can access file URLs"):
            return checkExtensionFileAccess(check: check)
        case let desc where desc.contains("Control which extensions can inject scripts"):
            return checkExtensionScriptInjection(check: check)
            
        // Password Settings
        case let desc where desc.contains("Enable saving passwords to the password manager"):
            return checkPasswordSavingDisabled(check: check)
        case let desc where desc.contains("Enable Autofill for addresses"):
            return checkAutofillAddressesDisabled(check: check)
        case let desc where desc.contains("Enable Autofill for credit cards"):
            return checkAutofillCreditCardsDisabled(check: check)
        case let desc where desc.contains("Enable Autofill for payment methods"):
            return checkAutofillPaymentMethodsDisabled(check: check)
            
        default:
            return CheckResult(check: check, status: "manual", details: "Not yet implemented")
        }
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
    
    private static func checkSafeBrowsing(check: CISCheck) -> CheckResult {
        guard let prefs = getChromePreferences(),
              let safebrowsing = prefs["safebrowsing"] as? [String: Any],
              let enabled = safebrowsing["enabled"] as? Bool else {
            return CheckResult(check: check, status: "error", details: "Could not read Chrome Safe Browsing setting.")
        }
        if enabled {
            return CheckResult(check: check, status: "pass", details: "Safe Browsing is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Safe Browsing is NOT enabled.")
        }
    }
    
    private static func checkSafeBrowsingProtectionLevel(check: CISCheck) -> CheckResult {
        guard let prefs = getChromePreferences(),
              let safebrowsing = prefs["safebrowsing"] as? [String: Any],
              let level = safebrowsing["protection_level"] as? String else {
            return CheckResult(check: check, status: "error", details: "Could not read Chrome Safe Browsing Protection Level.")
        }
        if level == "enhanced" {
            return CheckResult(check: check, status: "pass", details: "Safe Browsing Protection Level is set to enhanced.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Safe Browsing Protection Level is not set to enhanced.")
        }
    }
    
    private static func checkGoogleCastDisabled(check: CISCheck) -> CheckResult {
        guard let prefs = getChromePreferences(),
              let discovery = prefs["discovery"] as? [String: Any],
              let deviceDiscoveryConfig = discovery["device_discovery_config"] as? [String: Any],
              let mdnsEnabled = deviceDiscoveryConfig["mdns_enabled"] as? Bool else {
            return CheckResult(check: check, status: "error", details: "Could not read Chrome Google Cast settings.")
        }
        if !mdnsEnabled {
            return CheckResult(check: check, status: "pass", details: "Google Cast is disabled from connecting to Cast devices on all IP addresses.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Google Cast is enabled to connect to Cast devices on all IP addresses.")
        }
    }
    
    private static func checkGoogleTimeService(check: CISCheck) -> CheckResult {
        guard let prefs = getChromePreferences(),
              let browser = prefs["browser"] as? [String: Any],
              let enableTimeService = browser["enable_time_service"] as? Bool else {
            return CheckResult(check: check, status: "error", details: "Could not read Chrome time service settings.")
        }
        if enableTimeService {
            return CheckResult(check: check, status: "pass", details: "Queries to Google time service are enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Queries to Google time service are disabled.")
        }
    }
    
    private static func checkAudioSandbox(check: CISCheck) -> CheckResult {
        guard let prefs = getChromePreferences(),
              let browser = prefs["browser"] as? [String: Any],
              let audioSandboxEnabled = browser["audio_sandbox_enabled"] as? Bool else {
            return CheckResult(check: check, status: "error", details: "Could not read Chrome audio sandbox settings.")
        }
        if audioSandboxEnabled {
            return CheckResult(check: check, status: "pass", details: "Audio sandbox is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Audio sandbox is disabled.")
        }
    }

    // Check if 'Ask where to save each file before downloading' is enabled
    private static func checkAskWhereToSave(check: CISCheck) -> CheckResult {
        guard let prefs = getChromePreferences(),
              let download = prefs["download"] as? [String: Any],
              let promptForDownload = download["prompt_for_download"] as? Bool else {
            return CheckResult(check: check, status: "error", details: "Could not read Chrome download preferences.")
        }
        
        if promptForDownload {
            return CheckResult(check: check, status: "pass", details: "Chrome is configured to ask where to save each file before downloading.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Chrome is NOT configured to ask where to save each file before downloading.")
        }
    }
    
    private static func checkSafeSitesContentFiltering(check: CISCheck) -> CheckResult {
        guard let prefs = getChromePreferences(),
              let safebrowsing = prefs["safebrowsing"] as? [String: Any],
              let safeSitesFiltering = safebrowsing["safe_sites_filtering_enabled"] as? Bool else {
            return CheckResult(check: check, status: "error", details: "Could not read Chrome SafeSites content filtering settings.")
        }
        
        if safeSitesFiltering {
            return CheckResult(check: check, status: "pass", details: "SafeSites adult content filtering is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "SafeSites adult content filtering is disabled.")
        }
    }
    
    private static func checkCertificateTransparency(check: CISCheck) -> CheckResult {
        guard let prefs = getChromePreferences(),
              let certificateTransparency = prefs["certificate_transparency"] as? [String: Any],
              let disabledForLegacyCas = certificateTransparency["disabled_for_legacy_cas"] as? Bool else {
            // Default is disabled, which is good
            return CheckResult(check: check, status: "pass", details: "Certificate Transparency enforcement for Legacy CAs is not disabled.")
        }
        
        if !disabledForLegacyCas {
            return CheckResult(check: check, status: "pass", details: "Certificate Transparency enforcement for Legacy CAs is not disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Certificate Transparency enforcement for Legacy CAs is disabled.")
        }
    }
    
    private static func checkSavingBrowserHistory(check: CISCheck) -> CheckResult {
        guard let prefs = getChromePreferences(),
              let savingBrowserHistoryDisabled = prefs["savingBrowserHistoryDisabled"] as? Bool else {
            // Default is enabled (not disabled), which is good
            return CheckResult(check: check, status: "pass", details: "Saving browser history is enabled.")
        }
        
        if !savingBrowserHistoryDisabled {
            return CheckResult(check: check, status: "pass", details: "Saving browser history is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Saving browser history is disabled.")
        }
    }
    
    private static func checkDNSInterceptionChecks(check: CISCheck) -> CheckResult {
        guard let prefs = getChromePreferences(),
              let browser = prefs["browser"] as? [String: Any],
              let dnsInterceptionChecksEnabled = browser["dns_interception_checks_enabled"] as? Bool else {
            // Default is enabled, which is good
            return CheckResult(check: check, status: "pass", details: "DNS interception checks are enabled.")
        }
        
        if dnsInterceptionChecksEnabled {
            return CheckResult(check: check, status: "pass", details: "DNS interception checks are enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "DNS interception checks are disabled.")
        }
    }

    // Check if 'Continue running background apps when Chrome is closed' is disabled
    private static func checkBackgroundAppsDisabled(check: CISCheck) -> CheckResult {
        guard let prefs = getChromePreferences(),
              let backgroundMode = prefs["background_mode"] as? [String: Any],
              let enabled = backgroundMode["enabled"] as? Bool else {
            return CheckResult(check: check, status: "error", details: "Could not read Chrome background mode settings.")
        }
        
        if !enabled {
            return CheckResult(check: check, status: "pass", details: "Chrome is set to NOT continue running background apps when closed.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Chrome is set to continue running background apps when closed.")
        }
    }

    // Check if 'Enable component updates in Google Chrome' is enabled
    private static func checkComponentUpdatesEnabled(check: CISCheck) -> CheckResult {
        guard let prefs = getChromePreferences(),
              let componentUpdater = prefs["component_updater"] as? [String: Any],
              let enableComponentUpdates = componentUpdater["enable_component_updates"] as? Bool else {
            return CheckResult(check: check, status: "error", details: "Could not read Chrome component updater settings.")
        }
        
        if enableComponentUpdates {
            return CheckResult(check: check, status: "pass", details: "Component updates in Google Chrome are enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Component updates in Google Chrome are disabled.")
        }
    }
    
    private static func checkThirdPartySoftwareInjection(check: CISCheck) -> CheckResult {
        guard let prefs = getChromePreferences(),
              let browser = prefs["browser"] as? [String: Any],
              let thirdPartySoftwareInjectionBlocking = browser["third_party_software_injection_blocking_enabled"] as? Bool else {
            return CheckResult(check: check, status: "error", details: "Could not read Chrome third party software injection settings.")
        }
        
        if thirdPartySoftwareInjectionBlocking {
            return CheckResult(check: check, status: "pass", details: "Third party software injection blocking is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Third party software injection blocking is disabled.")
        }
    }
    
    // MARK: - Privacy Features
    
    private static func checkImportAutofillDisabled(check: CISCheck) -> CheckResult {
        guard let prefs = getChromePreferences(),
              let importAutofillFormData = prefs["import_autofill_form_data"] as? Bool else {
            // If not set, default is enabled which fails the check
            return CheckResult(check: check, status: "fail", details: "Import autofill form data from default browser is enabled.")
        }
        
        if !importAutofillFormData {
            return CheckResult(check: check, status: "pass", details: "Import autofill form data from default browser is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Import autofill form data from default browser is enabled.")
        }
    }
    
    private static func checkImportHomepageDisabled(check: CISCheck) -> CheckResult {
        guard let prefs = getChromePreferences(),
              let importHomepage = prefs["import_homepage"] as? Bool else {
            // If not set, default is enabled which fails the check
            return CheckResult(check: check, status: "fail", details: "Import of homepage from default browser is enabled.")
        }
        
        if !importHomepage {
            return CheckResult(check: check, status: "pass", details: "Import of homepage from default browser is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Import of homepage from default browser is enabled.")
        }
    }
    
    private static func checkImportSearchEnginesDisabled(check: CISCheck) -> CheckResult {
        guard let prefs = getChromePreferences(),
              let importSearchEngine = prefs["import_search_engine"] as? Bool else {
            // If not set, default is enabled which fails the check
            return CheckResult(check: check, status: "fail", details: "Import search engines from default browser is enabled.")
        }
        
        if !importSearchEngine {
            return CheckResult(check: check, status: "pass", details: "Import search engines from default browser is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Import search engines from default browser is enabled.")
        }
    }
    
    private static func checkSecurityWarningsEnabled(check: CISCheck) -> CheckResult {
        guard let prefs = getChromePreferences(),
              let browser = prefs["browser"] as? [String: Any],
              let securityWarnings = browser["enable_security_warnings_for_command_line_flags"] as? Bool else {
            // If not set, default is enabled which passes the check
            return CheckResult(check: check, status: "pass", details: "Security warnings for command-line flags are enabled.")
        }
        
        if securityWarnings {
            return CheckResult(check: check, status: "pass", details: "Security warnings for command-line flags are enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Security warnings for command-line flags are disabled.")
        }
    }
    
    private static func checkReportingDisabled(check: CISCheck) -> CheckResult {
        guard let prefs = getChromePreferences(),
              let reporting = prefs["reporting"] as? [String: Any],
              let enabled = reporting["enabled"] as? Bool else {
            // If not set, default is enabled which fails the check
            return CheckResult(check: check, status: "fail", details: "Reporting of usage and crash-related data is enabled.")
        }
        
        if !enabled {
            return CheckResult(check: check, status: "pass", details: "Reporting of usage and crash-related data is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Reporting of usage and crash-related data is enabled.")
        }
    }
    
    private static func checkSafeBrowsingTrustedSourcesDisabled(check: CISCheck) -> CheckResult {
        guard let prefs = getChromePreferences(),
              let safebrowsing = prefs["safebrowsing"] as? [String: Any],
              let trustedSourcesEnabled = safebrowsing["trusted_sources_enabled"] as? Bool else {
            // Default is disabled, which is good
            return CheckResult(check: check, status: "pass", details: "Safe Browsing for trusted sources appears to be disabled.")
        }
        
        if !trustedSourcesEnabled {
            return CheckResult(check: check, status: "pass", details: "Safe Browsing for trusted sources is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Safe Browsing for trusted sources is enabled.")
        }
    }
    
    private static func checkSearchSuggestionsDisabled(check: CISCheck) -> CheckResult {
        guard let prefs = getChromePreferences(),
              let searchSuggestEnabled = prefs["search_suggest_enabled"] as? Bool else {
            // Default is enabled, which fails the check
            return CheckResult(check: check, status: "fail", details: "Search suggestions appear to be enabled.")
        }
        
        if !searchSuggestEnabled {
            return CheckResult(check: check, status: "pass", details: "Search suggestions are disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Search suggestions are enabled.")
        }
    }
    
    private static func checkDiskCacheSize(check: CISCheck) -> CheckResult {
        guard let prefs = getChromePreferences(),
              let net = prefs["net"] as? [String: Any],
              let diskCacheSize = net["disk_cache_size"] as? Int else {
            // Default is not set, which fails the check
            return CheckResult(check: check, status: "fail", details: "Disk cache size is not configured.")
        }
        
        // Recommended size is 100MB or less
        if diskCacheSize <= 104857600 {
            return CheckResult(check: check, status: "pass", details: "Disk cache size is set to an appropriate value.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Disk cache size is set too high.")
        }
    }
    
    // MARK: - Cookie and Site Data Settings
    
    private static func checkBlockThirdPartyCookies(check: CISCheck) -> CheckResult {
        guard let prefs = getChromePreferences(),
              let blockThirdPartyCookies = prefs["block_third_party_cookies"] as? Bool else {
            // Default is disabled, which fails the check
            return CheckResult(check: check, status: "fail", details: "Block third-party cookies appears to be disabled.")
        }
        
        if blockThirdPartyCookies {
            return CheckResult(check: check, status: "pass", details: "Block third-party cookies is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Block third-party cookies is disabled.")
        }
    }
    
    private static func checkClearCookiesOnQuit(check: CISCheck) -> CheckResult {
        guard let prefs = getChromePreferences(),
              let clearOnExit = prefs["clear_on_exit"] as? Bool else {
            // Default is disabled, which fails the check
            return CheckResult(check: check, status: "fail", details: "Clear cookies and site data when quitting Chrome appears to be disabled.")
        }
        
        if clearOnExit {
            return CheckResult(check: check, status: "pass", details: "Clear cookies and site data when quitting Chrome is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Clear cookies and site data when quitting Chrome is disabled.")
        }
    }
    
    private static func checkDefaultCookiesSetting(check: CISCheck) -> CheckResult {
        guard let prefs = getChromePreferences(),
              let cookieControls = prefs["cookie_controls"] as? [String: Any],
              let mode = cookieControls["mode"] as? Int else {
            // Default is keep until session end (2), which passes the check
            return CheckResult(check: check, status: "pass", details: "Default cookies setting appears to be set to keep local data until browser is closed.")
        }
        
        // Mode 2 is "keep local data until you quit your browser"
        if mode == 2 {
            return CheckResult(check: check, status: "pass", details: "Default cookies setting is set to keep local data until browser is closed.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Default cookies setting is not set to keep local data until browser is closed.")
        }
    }
    
    private static func checkDoNotTrackEnabled(check: CISCheck) -> CheckResult {
        guard let prefs = getChromePreferences(),
              let doNotTrack = prefs["enable_do_not_track"] as? Bool else {
            // Default is disabled, which fails the check
            return CheckResult(check: check, status: "fail", details: "Do Not Track appears to be disabled.")
        }
        
        if doNotTrack {
            return CheckResult(check: check, status: "pass", details: "Do Not Track is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Do Not Track is disabled.")
        }
    }
    
    // MARK: - Extension Settings
    
    private static func checkExtensionBlocklist(check: CISCheck) -> CheckResult {
        guard let prefs = getChromePreferences(),
              let extensions = prefs["extensions"] as? [String: Any],
              let blocklist = extensions["blocklist"] as? [String] else {
            // Default is no blocklist, which fails the check
            return CheckResult(check: check, status: "fail", details: "Extension installation blocklist is not configured.")
        }
        
        if !blocklist.isEmpty {
            return CheckResult(check: check, status: "pass", details: "Extension installation blocklist is configured.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Extension installation blocklist is empty.")
        }
    }
    
    private static func checkAllowedExtensions(check: CISCheck) -> CheckResult {
        guard let prefs = getChromePreferences(),
              let extensions = prefs["extensions"] as? [String: Any],
              let allowlist = extensions["allowed_types"] as? [String] else {
            // Default is no allowlist, which fails the check
            return CheckResult(check: check, status: "fail", details: "Allowed Chrome Web Store extensions list is not configured.")
        }
        
        if !allowlist.isEmpty {
            return CheckResult(check: check, status: "pass", details: "Allowed Chrome Web Store extensions list is configured.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Allowed Chrome Web Store extensions list is empty.")
        }
    }
    
    private static func checkExtensionFileAccess(check: CISCheck) -> CheckResult {
        guard let prefs = getChromePreferences(),
              let extensions = prefs["extensions"] as? [String: Any],
              let fileAccess = extensions["file_access"] as? [String: Bool] else {
            // Default is no restrictions, which fails the check
            return CheckResult(check: check, status: "fail", details: "Extension file URL access control is not configured.")
        }
        
        if !fileAccess.isEmpty {
            return CheckResult(check: check, status: "pass", details: "Extension file URL access control is configured.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Extension file URL access control is empty.")
        }
    }
    
    private static func checkExtensionScriptInjection(check: CISCheck) -> CheckResult {
        guard let prefs = getChromePreferences(),
              let extensions = prefs["extensions"] as? [String: Any],
              let scriptInjection = extensions["script_injection"] as? [String: Bool] else {
            // Default is no restrictions, which fails the check
            return CheckResult(check: check, status: "fail", details: "Extension script injection control is not configured.")
        }
        
        if !scriptInjection.isEmpty {
            return CheckResult(check: check, status: "pass", details: "Extension script injection control is configured.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Extension script injection control is empty.")
        }
    }
    
    // MARK: - Password Settings
    
    private static func checkPasswordSavingDisabled(check: CISCheck) -> CheckResult {
        guard let prefs = getChromePreferences(),
              let passwordManager = prefs["password_manager"] as? [String: Any],
              let savingEnabled = passwordManager["saving_enabled"] as? Bool else {
            // Default is enabled, which fails the check
            return CheckResult(check: check, status: "fail", details: "Saving passwords to the password manager appears to be enabled.")
        }
        
        if !savingEnabled {
            return CheckResult(check: check, status: "pass", details: "Saving passwords to the password manager is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Saving passwords to the password manager is enabled.")
        }
    }
    
    private static func checkAutofillAddressesDisabled(check: CISCheck) -> CheckResult {
        guard let prefs = getChromePreferences(),
              let autofill = prefs["autofill"] as? [String: Any],
              let addressEnabled = autofill["address_enabled"] as? Bool else {
            // Default is enabled, which fails the check
            return CheckResult(check: check, status: "fail", details: "Autofill for addresses appears to be enabled.")
        }
        
        if !addressEnabled {
            return CheckResult(check: check, status: "pass", details: "Autofill for addresses is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Autofill for addresses is enabled.")
        }
    }
    
    private static func checkAutofillCreditCardsDisabled(check: CISCheck) -> CheckResult {
        guard let prefs = getChromePreferences(),
              let autofill = prefs["autofill"] as? [String: Any],
              let creditCardEnabled = autofill["credit_card_enabled"] as? Bool else {
            // Default is enabled, which fails the check
            return CheckResult(check: check, status: "fail", details: "Autofill for credit cards appears to be enabled.")
        }
        
        if !creditCardEnabled {
            return CheckResult(check: check, status: "pass", details: "Autofill for credit cards is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Autofill for credit cards is enabled.")
        }
    }
    
    private static func checkAutofillPaymentMethodsDisabled(check: CISCheck) -> CheckResult {
        guard let prefs = getChromePreferences(),
              let autofill = prefs["autofill"] as? [String: Any],
              let paymentMethodEnabled = autofill["payment_method_enabled"] as? Bool else {
            // Default is enabled, which fails the check
            return CheckResult(check: check, status: "fail", details: "Autofill for payment methods appears to be enabled.")
        }
        
        if !paymentMethodEnabled {
            return CheckResult(check: check, status: "pass", details: "Autofill for payment methods is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Autofill for payment methods is enabled.")
        }
    }
}
