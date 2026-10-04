//
//  CSP_CIS_AuditTests.swift
//  CSP-CIS_AuditTests
//
//  Created by sean dolbec on 5/23/25.
//

import Foundation
import Testing
import XCTest
@testable import CSP_CIS_Audit

struct CSP_CIS_AuditTests {

    @Test func missingBrowserPreferencesRemainManualWithoutGuessingDefaults() {
        let chrome = CISCheck(id: "chrome_1", category: "chrome", description: "Ensure Safe Browsing settings are enabled")
        let chromeMissing: [[String: Any]?] = [nil, [:], ["safebrowsing": ["enabled": "unknown"]]]
        for evidence in chromeMissing {
            let result = ChromeChecks.run(check: chrome, readPreferences: { evidence })
            #expect(result.status == "manual")
            #expect(result.details.contains("effective default or managed policy"))
        }
        #expect(ChromeChecks.run(check: chrome, readPreferences: { ["safebrowsing": ["enabled": true]] }).status == "pass")
        #expect(ChromeChecks.run(check: chrome, readPreferences: { ["safebrowsing": ["enabled": false]] }).status == "fail")
        let safari = CISCheck(id: "safari_8", category: "safari", description: "Ensure JavaScript is disabled")
        let safariMissing: [[String: Any]?] = [nil, [:], ["WebKitJavaScriptEnabled": "unknown"]]
        for evidence in safariMissing {
            #expect(SafariChecks.run(check: safari, readPreferences: { evidence }).status == "manual")
        }
        #expect(SafariChecks.run(check: safari, readPreferences: { ["WebKitJavaScriptEnabled": false] }).status == "pass")
        #expect(SafariChecks.run(check: safari, readPreferences: { ["WebKitJavaScriptEnabled": true] }).status == "fail")
    }

    @Test func allBrowserDispatchPathsKeepAbsentPreferencesUnassessed() {
        let chromeDescriptions = [
            "Ensure Safe Browsing settings are enabled",
            "Ensure Safe Browsing Protection Level",
            "Ensure Allow Google Cast to connect to Cast devices",
            "Ensure Allow queries to a Google time service",
            "Ensure Allow the audio sandbox to run",
            "Ensure Ask where to save each file before downloading",
            "Ensure Continue running background apps when Chrome is closed",
            "Ensure Control SafeSites adult content filtering",
            "Ensure Disable Certificate Transparency enforcement",
            "Ensure Disable saving browser history",
            "Ensure DNS interception checks enabled",
            "Ensure Enable component updates in Google Chrome",
            "Ensure Enable third party software injection blocking",
            "Ensure Import autofill form data from default browser",
            "Ensure Import of homepage from default browser",
            "Ensure Import search engines from default browser",
            "Ensure Enable security warnings for command-line flags",
            "Ensure Enable reporting of usage and crash-related data",
            "Ensure Enable Safe Browsing for trusted sources",
            "Ensure Enable search suggestions",
            "Ensure Set disk cache size",
            "Ensure Block third-party cookies",
            "Ensure Clear cookies and site data when you quit Chrome",
            "Ensure Default cookies setting",
            "Ensure Enable Do Not Track",
            "Ensure Configure extension installation blocklist",
            "Ensure Configure allowed Chrome Web Store extensions",
            "Ensure Control which extensions can access file URLs",
            "Ensure Control which extensions can inject scripts",
            "Ensure Enable saving passwords to the password manager",
            "Ensure Enable Autofill for addresses",
            "Ensure Enable Autofill for credit cards",
            "Ensure Enable Autofill for payment methods"
        ]
        for description in chromeDescriptions {
            let check = CISCheck(id: "fixture", category: "chrome", description: description)
            let unavailable: [[String: Any]?] = [nil, [:], ["irrelevant": "unknown"]]
            for preferences in unavailable {
                #expect(ChromeChecks.run(check: check, readPreferences: { preferences }).status == "manual")
            }
        }
        let safariDescriptions = [
            "Ensure Open safe files after downloading",
            "Ensure AutoFill is disabled",
            "Ensure AutoFill web forms is disabled",
            "Ensure AutoFill credit cards is disabled",
            "Ensure AutoFill contact information is disabled",
            "Ensure AutoFill usernames and passwords is disabled",
            "Ensure Block pop-up windows is enabled",
            "Ensure JavaScript is disabled",
            "Ensure Warn when visiting a fraudulent website",
            "Ensure Prevent cross-site tracking",
            "Ensure Block all cookies",
            "Ensure Website tracking",
            "Ensure Ask websites not to track me",
            "Ensure Privacy preserving ad measurement",
            "Ensure Allow Extensions",
            "Ensure Enable JavaScript untrusted sites",
            "Ensure Internet plug-ins",
            "Ensure Java",
            "Ensure Show full website address",
            "Ensure Show Develop menu in menu bar",
            "Ensure Show status bar",
            "Ensure Smart Search Field search suggestions",
            "Ensure Default search engine"
        ]
        for description in safariDescriptions {
            let check = CISCheck(id: "fixture", category: "safari", description: description)
            let unavailable: [[String: Any]?] = [nil, [:], ["irrelevant": "unknown"]]
            for preferences in unavailable {
                #expect(SafariChecks.run(check: check, readPreferences: { preferences }).status == "manual")
            }
        }
    }

    @Test func safariAutoFillNeedsCompleteTypedEvidence() {
        let check = CISCheck(id: "fixture", category: "safari", description: "Ensure AutoFill is disabled")
        let incomplete: [[String: Any]] = [[:], ["AutoFillFromAddressBook": false], ["AutoFillFromAddressBook": false, "AutoFillCreditCardData": false, "AutoFillPasswords": "unknown"]]
        for preferences in incomplete {
            #expect(SafariChecks.run(check: check, readPreferences: { preferences }).status == "manual")
        }
        let disabled: [String: Any] = ["AutoFillFromAddressBook": false, "AutoFillCreditCardData": false, "AutoFillPasswords": false]
        #expect(SafariChecks.run(check: check, readPreferences: { disabled }).status == "pass")
        var enabled = disabled
        enabled["AutoFillPasswords"] = true
        #expect(SafariChecks.run(check: check, readPreferences: { enabled }).status == "fail")
        let creditCards = CISCheck(id: "fixture", category: "safari", description: "Ensure AutoFill credit cards is disabled")
        #expect(SafariChecks.run(check: creditCards, readPreferences: { ["AutoFillCreditCardData": "unknown"] }).status == "manual")
        #expect(SafariChecks.run(check: creditCards, readPreferences: { ["AutoFillCreditCardData": false] }).status == "pass")
        #expect(SafariChecks.run(check: creditCards, readPreferences: { ["AutoFillCreditCardData": true] }).status == "fail")
    }

    @Test func legacyAuditPolicyRequiresExactReadableFields() {
        let check = CISCheck(id: "fixture", category: "macos", description: "Fixture")
        func flags(_ text: String?) -> String {
            MacOSSystemChecks.checkAuditFlags(check: check, classes: ["aa"]) { url in
                #expect(url.path == "/etc/security/audit_control")
                return text.map { Data($0.utf8) }
            }.status
        }
        #expect(flags("flags:aa,ad\n") == "pass")
        #expect(flags("flags:all") == "pass")
        #expect(flags("flags:lo") == "fail")
        for value in [nil, "permission denied aa", "# flags:aa", "flags:+aa", "flags:all,^aa", "flags:aaaa", "flags:aa\nflags:lo", "flags:aa,aa"] {
            #expect(flags(value) == "manual")
        }
        func retention(_ value: String?) -> String {
            MacOSSystemChecks.checkAuditRetention(check: check) { _ in value.map { Data($0.utf8) } }.status
        }
        #expect(retention("expire-after:7d") == "pass")
        #expect(retention("expire-after:604800s") == "pass")
        #expect(retention("expire-after:1d") == "fail")
        for value in [nil, "sudo: permission denied", "expire-after:error", "expire-after:7d OR 1G", "expire-after:1G", "expire-after:10m", "expire-after:7d\nexpire-after:1d"] {
            #expect(retention(value) == "manual")
        }
    }

    @Test func legacyAuditCheckDoesNotPassOnErrorTextMentioningAuditd() {
        let check = CISCheck(id: "macos_22", category: "macos", description: "Ensure security auditing is enabled")
        let error = MacOSSystemChecks.checkSecurityAuditingEnabled(check: check) { _, _ in
            .init(error: "Could not find service com.apple.auditd", exitCode: 113)
        }
        #expect(error.status == "fail")
        #expect(error.check.id == "macos_22")
        let denied = MacOSSystemChecks.checkSecurityAuditingEnabled(check: check) { _, _ in
            .init(error: "permission denied: com.apple.auditd", exitCode: 1)
        }
        #expect(denied.status == "manual")
        let enabled = MacOSSystemChecks.checkSecurityAuditingEnabled(check: check) { executable, _ in
            if executable == "/bin/launchctl" { return .init(output: "system/com.apple.auditd = {}") }
            if executable == "/usr/bin/stat" { return .init(output: "Regular File") }
            return .init(output: "audit condition: AUC_AUDITING")
        }
        #expect(enabled.status == "pass")
        #expect(enabled.check.id == "macos_22")
    }

    @Test func legacyAutomaticLoginDoesNotInferStateOrDiscloseAccountNames() {
        let check = CISCheck(id: "macos_13", category: "macos", description: "Ensure Automatic Login is disabled")
        for value in [nil, "", " ", NSNumber(value: true), ["unexpected"]] as [Any?] {
            let result = MacOSUserChecks.checkAutomaticLoginDisabled(check: check) { path, key in
                #expect(path == "/Library/Preferences/com.apple.loginwindow.plist")
                #expect(key == "autoLoginUser")
                return value
            }
            #expect(result.status == "manual")
        }
        let result = MacOSUserChecks.checkAutomaticLoginDisabled(check: check) { _, _ in "private-fixture-account" }
        #expect(result.status == "fail")
        #expect(!result.details.contains("private-fixture-account"))
    }


    @Test func queuedReportsCannotMoveToAnotherWorkspace() {
        let report = Data(#"{"domain":"csp.example","device_uuid":"test-device","report_id":"test-report"}"#.utf8)
        #expect(CISUploadOutbox.matchesWorkspace(report, domain: "CSP.EXAMPLE"))
        #expect(!CISUploadOutbox.matchesWorkspace(report, domain: "bfs.example"))
        #expect(!CISUploadOutbox.matchesWorkspace(report, domain: ""))
        #expect(!CISUploadOutbox.matchesWorkspace(Data("{}".utf8), domain: "csp.example"))
    }

    @Test func uploadReceiptsRemoveOnlyAcknowledgedReportsFromQueue() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let first = directory.appendingPathComponent("cis_report_1.json")
        let second = directory.appendingPathComponent("cis_report_2.json")
        try Data("{}".utf8).write(to: first)
        try Data("{}".utf8).write(to: second)
        #expect(try CISUploadOutbox.pendingReports(in: directory).map(\.lastPathComponent) == [first.lastPathComponent, second.lastPathComponent])
        try CISUploadOutbox.recordReceipt(for: first)
        #expect(try CISUploadOutbox.pendingReports(in: directory).map(\.lastPathComponent) == [second.lastPathComponent])
        let receiptAttributes = try FileManager.default.attributesOfItem(atPath: CISUploadOutbox.receiptURL(for: first).path)
        #expect((receiptAttributes[.posixPermissions] as? NSNumber)?.intValue == 0o600)
    }

    @Test func authenticatedRedirectsStayOnTheOriginalOrigin() throws {
        let source = try #require(URL(string: "https://app.example/api/cis/report"))
        #expect(DaedalusOriginRedirectGuard.allowsRedirect(from: source, to: URL(string: "https://app.example:443/api/cis/report/")!))
        #expect(!DaedalusOriginRedirectGuard.allowsRedirect(from: source, to: URL(string: "https://other.example/api/cis/report")!))
        #expect(!DaedalusOriginRedirectGuard.allowsRedirect(from: source, to: URL(string: "http://app.example/api/cis/report")!))
        #expect(!DaedalusOriginRedirectGuard.allowsRedirect(from: source, to: URL(string: "https://app.example:8443/api/cis/report")!))
    }

    @Test func uploadsRequireAnExplicitServerAcknowledgement() {
        let data = Data(#"{"domain":"csp.example","device_uuid":"test-device","report_id":"test-report"}"#.utf8)
        var config = Config.defaultConfig
        config.reporting.domain = "csp.example"
        config.reporting.endpoint = "https://fixture.invalid/api/cis/report"
        config.reporting.apiKey = "fixture-key-not-a-secret"
        for (status, body, expected) in [(200, #"{"accepted":true}"#, true), (200, "<html>Sign in</html>", false), (422, #"{"accepted":true}"#, false)] {
            UploadFixtureProtocol.statusCode = status
            UploadFixtureProtocol.body = Data(body.utf8)
            let configuration = URLSessionConfiguration.ephemeral
            configuration.protocolClasses = [UploadFixtureProtocol.self]
            let session = URLSession(configuration: configuration)
            #expect(CISApp.sendReport(jsonData: data, to: config.reporting.endpoint, description: "fixture", config: config, session: session) == expected)
        }
    }

    @Test func reportCollectionTimestampUsesISO8601() throws {
        let date = Date(timeIntervalSince1970: 1_791_072_000)
        let timestamp = CISApp.iso8601ReportTimestamp(date)
        let parsed = try #require(ISO8601DateFormatter().date(from: timestamp))

        #expect(parsed == date)
    }

    @Test func example() async throws {
        // Write your test here and use APIs like `#expect(...)` to check expected conditions.
    }

    @Test func publishedDaedalusProfileDecodesAndCanBePinnedBySlug() throws {
        let json = """
        {
          "domain": "example.org",
          "profiles": [
            {
              "slug": "browser-baseline",
              "name": "Browser baseline",
              "version": "2.0",
              "platform": "browser",
              "description": "Browser checks",
              "checks": [{"id": "browser_1", "category": "chrome", "description": "Safe Browsing settings are enabled"}]
            },
            {
              "slug": "macos-baseline",
              "name": "macOS baseline",
              "version": "1.1",
              "platform": "macos",
              "description": "Managed macOS checks",
              "benchmark": {"name": "CIS Tahoe", "version": "1.1.0", "level": "1", "os_version": "26.0"},
              "checks": [{"id": "os_gatekeeper_enable", "rule_id": "os_gatekeeper_enable", "benchmark_ids": ["2.6.5"], "category": "macos", "description": "Enable Gatekeeper"}]
            }
          ]
        }
        """

        let profile = try DaedalusProfileClient.selectProfile(
            from: Data(json.utf8),
            preferredSlug: "MACOS-BASELINE"
        )

        #expect(profile.slug == "macos-baseline")
        #expect(profile.version == "1.1")
        #expect(profile.checks.first?.id == "os_gatekeeper_enable")
        #expect(profile.checks.first?.ruleID == "os_gatekeeper_enable")
        #expect(profile.checks.first?.benchmarkIDs == ["2.6.5"])
        #expect(profile.benchmark?.level == "1")
        #expect(profile.benchmark?.osVersion == "26.0")
    }

    @Test func declaredMacOSProfileTargetMustMatchHostBeforeAuditRuns() throws {
        let json = """
        {
          "domain": "example.org",
          "profiles": [{
            "slug": "tahoe-level-1",
            "name": "Tahoe Level 1",
            "version": "1.1.0-r2",
            "platform": "macos",
            "description": "Fixture profile",
            "benchmark": {"name": "CIS Apple macOS 26.0 Tahoe Benchmark", "os_version": "26.0"},
            "checks": [{"id": "rule_1", "category": "macos", "description": "Fixture check"}]
          }]
        }
        """
        let profile = try DaedalusProfileClient.selectProfile(from: Data(json.utf8), preferredSlug: "tahoe-level-1")

        #expect(DaedalusProfileClient.incompatibilityReason(for: profile, osMajorVersion: 26) == nil)
        #expect(DaedalusProfileClient.incompatibilityReason(for: profile, osMajorVersion: 27)
            == "This profile targets macOS 26.0; the current host is macOS 27.")
    }

    @Test func profileWithoutDeclaredOSVersionRemainsPortable() throws {
        let json = """
        {"domain":"example.org","profiles":[{"slug":"baseline","name":"Baseline","version":"1.0","platform":"macos","description":"Fixture","checks":[{"id":"rule_1","category":"macos","description":"Fixture check"}]}]}
        """
        let profile = try DaedalusProfileClient.selectProfile(from: Data(json.utf8), preferredSlug: "baseline")

        #expect(DaedalusProfileClient.incompatibilityReason(for: profile, osMajorVersion: 27) == nil)
    }

    @Test func profileEndpointCanBeDerivedFromTheDaedalusReportEndpoint() {
        let endpoint = DaedalusProfileClient.profileEndpoint(
            configuredEndpoint: "",
            reportEndpoint: "https://app.example.org/api/cis/report"
        )

        #expect(endpoint == "https://app.example.org/api/cis/client/profiles")
    }

    @Test func workspaceConfigIsNotBundledWithTheApp() {
        #expect(Bundle(for: CISApp.self).url(forResource: "config", withExtension: "yaml") == nil)
    }

    @Test func unconfiguredClientCannotSubmitReports() {
        #expect(Config.defaultConfig.reporting.endpoint.isEmpty)
        #expect(Config.defaultConfig.reporting.apiKey.isEmpty)
    }

    @Test func reportAndProfileEndpointsRequireAProtectedOrigin() {
        #expect(Config.isAllowedReportingEndpoint("https://app.example.org/api/cis/report"))
        #expect(Config.isAllowedReportingEndpoint("http://127.0.0.1:8000/api/cis/report"))
        #expect(!Config.isAllowedReportingEndpoint("http://app.example.org/api/cis/report"))
        #expect(!Config.isAllowedReportingEndpoint("https://user:pass@app.example.org/api/cis/report"))
        #expect(!Config.isAllowedReportingEndpoint("https://app.example.org/api/cis/report?token=secret"))
    }

    @Test func unknownTahoeRuleCannotFallBackToDescriptionBasedDispatch() {
        let check = CISCheck(
            id: "unrecognized_rule",
            category: "macos",
            description: "Ensure Firewall is enabled",
            ruleID: "unrecognized_rule",
            benchmarkIDs: ["2.2.1"]
        )
        let result = MacOSChecks.run(check: check)

        #expect(result.status == "manual")
        #expect(MacOSChecks.macOS26PreferenceRules["system_settings_firewall_enable"] != nil)
        #expect(MacOSChecks.macOS26PreferenceRules["unrecognized_rule"] == nil)
    }

    @Test func tahoeDisabledPreferenceNeedsExplicitBooleanEvidence() {
        let check = CISCheck(id: "os_airdrop_disable", category: "macos", description: "Disable AirDrop", ruleID: "os_airdrop_disable")
        #expect(MacOSChecks.runTahoe(check: check, osMajorVersion: 26) { _, _ in nil }.status == "manual")
        #expect(MacOSChecks.runTahoe(check: check, osMajorVersion: 26) { _, _ in "false" }.status == "manual")
        #expect(MacOSChecks.runTahoe(check: check, osMajorVersion: 26) { _, _ in NSNumber(value: 0) }.status == "manual")
        #expect(MacOSChecks.runTahoe(check: check, osMajorVersion: 26) { _, _ in NSNumber(value: false) }.status == "pass")
        #expect(MacOSChecks.runTahoe(check: check, osMajorVersion: 26) { _, _ in NSNumber(value: true) }.status == "fail")
    }

    @Test func tahoeCompositeGuestRuleRequiresBothPreferences() {
        let check = CISCheck(id: "system_settings_guest_account_disable", category: "macos", description: "Disable Guest", ruleID: "system_settings_guest_account_disable")
        let passing = MacOSChecks.runTahoe(check: check, osMajorVersion: 26) { suite, key in
            #expect(suite == "com.apple.MCX")
            return NSNumber(value: key == "DisableGuestAccount")
        }
        #expect(passing.status == "pass")
        let missing = MacOSChecks.runTahoe(check: check, osMajorVersion: 26) { _, key in
            key == "DisableGuestAccount" ? NSNumber(value: true) : nil
        }
        #expect(missing.status == "manual")
        let failing = MacOSChecks.runTahoe(check: check, osMajorVersion: 26) { _, key in
            key == "EnableGuestAccount" ? NSNumber(value: true) : nil
        }
        #expect(failing.status == "fail")
    }

    @Test func tahoeFirewallReadsThePinnedPreferenceDomain() {
        let check = CISCheck(id: "system_settings_firewall_enable", category: "macos", description: "Firewall", ruleID: "system_settings_firewall_enable")
        let result = MacOSChecks.runTahoe(check: check, osMajorVersion: 26) { suite, key in
            #expect(suite == "com.apple.security.firewall")
            #expect(key == "EnableFirewall")
            return NSNumber(value: true)
        }
        #expect(result.status == "pass")
        #expect(MacOSChecks.runTahoe(check: check, osMajorVersion: 25) { _, _ in
            Issue.record("An incompatible OS must not read evidence")
            return NSNumber(value: true)
        }.status == "manual")
    }

    @Test func tahoePasswordHintRequiresAnIntegerZero() {
        let check = CISCheck(id: "system_settings_password_hints_disable", category: "macos", description: "Hints", ruleID: "system_settings_password_hints_disable")
        #expect(MacOSChecks.runTahoe(check: check, osMajorVersion: 26) { _, _ in NSNumber(value: false) }.status == "manual")
        #expect(MacOSChecks.runTahoe(check: check, osMajorVersion: 26) { _, _ in NSNumber(value: 0.5) }.status == "manual")
        #expect(MacOSChecks.runTahoe(check: check, osMajorVersion: 26) { _, _ in NSNumber(value: 0) }.status == "pass")
        #expect(MacOSChecks.runTahoe(check: check, osMajorVersion: 26) { _, _ in NSNumber(value: 3) }.status == "fail")
    }

    private func commandResult(_ rule: String, evidence: MacOSChecks.CommandEvidence, preference: Any? = nil) -> CheckResult {
        let check = CISCheck(id: rule, category: "macos", description: "Fixture", ruleID: rule)
        return MacOSChecks.runTahoe(check: check, osMajorVersion: 26, command: { _, _ in evidence }) { _, _ in preference }
    }

    @Test func tahoeSIPRequiresFullyEnabledEvidence() {
        #expect(commandResult("os_sip_enable", evidence: .init(output: "System Integrity Protection status: enabled.\n")).status == "pass")
        #expect(commandResult("os_sip_enable", evidence: .init(output: "System Integrity Protection status: disabled.\n")).status == "fail")
        #expect(commandResult("os_sip_enable", evidence: .init(output: "System Integrity Protection status: unknown (Custom Configuration).\n")).status == "fail")
        #expect(commandResult("os_sip_enable", evidence: .init(output: "enabled")).status == "manual")
        #expect(commandResult("os_sip_enable", evidence: .init(output: "System Integrity Protection status: enabled.", error: "Permission denied", exitCode: 1)).status == "manual")
    }

    @Test func tahoeSealedRootMatchesMountFlagsNotSubstrings() {
        #expect(commandResult("os_authenticated_root_enable", evidence: .init(output: "/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)\n")).status == "pass")
        #expect(commandResult("os_authenticated_root_enable", evidence: .init(output: "/dev/disk3s1 on / (apfs, unsealed, local)\n")).status == "fail")
        #expect(commandResult("os_authenticated_root_enable", evidence: .init(output: "/dev/disk3s2 on /other (apfs, sealed)\n")).status == "manual")
        #expect(commandResult("os_authenticated_root_enable", evidence: .init(output: "")).status == "manual")
    }

    @Test func tahoeAMFIRequiresSuccessfulNVRAMEnumeration() {
        #expect(commandResult("os_mobile_file_integrity_enable", evidence: .init(output: "boot-args\t-v\n")).status == "pass")
        #expect(commandResult("os_mobile_file_integrity_enable", evidence: .init(output: "boot-args\tamfi_get_out_of_my_way=1\n")).status == "fail")
        #expect(commandResult("os_mobile_file_integrity_enable", evidence: .init()).status == "manual")
        #expect(commandResult("os_mobile_file_integrity_enable", evidence: .init(error: "Error getting variable", exitCode: 1)).status == "manual")
    }

    @Test func tahoeRootAccountDoesNotTreatDirectoryErrorsAsDisabled() {
        #expect(commandResult("os_root_disable", evidence: .init(error: "No such key: AuthenticationAuthority", exitCode: 1)).status == "pass")
        #expect(commandResult("os_root_disable", evidence: .init(output: "AuthenticationAuthority: ;ShadowHash;\n")).status == "fail")
        #expect(commandResult("os_root_disable", evidence: .init(error: "Operation not permitted", exitCode: 1)).status == "manual")
        #expect(commandResult("os_root_disable", evidence: .init()).status == "manual")
    }

    @Test func tahoeFileVaultRequiresEncryptionAndManagedProhibition() {
        #expect(commandResult("system_settings_filevault_enforce", evidence: .init(output: "FileVault is On.\n"), preference: NSNumber(value: true)).status == "pass")
        #expect(commandResult("system_settings_filevault_enforce", evidence: .init(output: "FileVault is On.\n")).status == "manual")
        #expect(commandResult("system_settings_filevault_enforce", evidence: .init(output: "FileVault is Off.\n")).status == "fail")
        #expect(commandResult("system_settings_filevault_enforce", evidence: .init(output: "FileVault is On.\n"), preference: NSNumber(value: false)).status == "fail")
        #expect(commandResult("system_settings_filevault_enforce", evidence: .init(output: "Encryption in progress: Percent completed = 12\n"), preference: NSNumber(value: true)).status == "manual")
        #expect(commandResult("system_settings_filevault_enforce", evidence: .init(output: "FileVault is On.\n"), preference: NSNumber(value: 1)).status == "manual")
    }

    @Test func tahoePrinterAndRemoteManagementRequireExactValues() {
        #expect(commandResult("system_settings_printer_sharing_disable", evidence: .init(output: "_share_printers=0\n")).status == "pass")
        #expect(commandResult("system_settings_printer_sharing_disable", evidence: .init(output: "_share_printers=1\n")).status == "fail")
        #expect(commandResult("system_settings_printer_sharing_disable", evidence: .init(output: "unrelated=0\n")).status == "manual")
        #expect(commandResult("system_settings_remote_management_disable", evidence: .init(output: "    RemoteDesktopEnabled = 0;\n")).status == "pass")
        #expect(commandResult("system_settings_remote_management_disable", evidence: .init(output: "    RemoteDesktopEnabled = 1;\n")).status == "fail")
        #expect(commandResult("system_settings_remote_management_disable", evidence: .init(error: "must be root", exitCode: 1)).status == "manual")
    }

    @Test func tahoeLaunchServicesDistinguishAbsentAndPermissionDenied() {
        let rule = "system_settings_ssh_disable"
        let check = CISCheck(id: rule, category: "macos", description: "Fixture", ruleID: rule)
        func evaluate(_ list: MacOSChecks.CommandEvidence, _ service: MacOSChecks.CommandEvidence) -> CheckResult {
            MacOSChecks.runTahoe(check: check, osMajorVersion: 26, command: { path, args in
                #expect(path == "/bin/launchctl")
                return args == ["print-disabled", "system"] ? list : service
            }) { _, _ in nil }
        }
        let absent = MacOSChecks.CommandEvidence(error: "Bad request.\nCould not find service \"com.openssh.sshd\" in domain for system\n", exitCode: 113)
        let noOverride = MacOSChecks.CommandEvidence(output: "disabled services = {\n}\n")
        #expect(evaluate(noOverride, absent).status == "pass")
        #expect(evaluate(noOverride, .init(output: "system/com.openssh.sshd = { active count = 1 }\n")).status == "fail")
        #expect(evaluate(noOverride, .init(error: "Operation not permitted", exitCode: 1)).status == "manual")
        #expect(evaluate(.init(output: "disabled services = {\n\"com.openssh.sshd\" => enabled\n}\n"), absent).status == "fail")
        #expect(evaluate(.init(error: "Permission denied", exitCode: 1), absent).status == "manual")
        #expect(evaluate(.init(unavailable: "timed out"), absent).status == "manual")
    }

    @Test func tahoeSMBAndAppleEventsRequireExplicitDisabledOverride() {
        #expect(commandResult("system_settings_smbd_disable", evidence: .init(output: "disabled services = {\n\"com.apple.smbd\" => disabled\n}\n")).status == "pass")
        #expect(commandResult("system_settings_rae_disable", evidence: .init(output: "disabled services = {\n\"com.apple.AEServer\" => enabled\n}\n")).status == "fail")
        #expect(commandResult("system_settings_smbd_disable", evidence: .init(output: "disabled services = {\n}\n")).status == "fail")
    }

    @Test func tahoeAdditionalPreferencesMatchPinnedSuitesKeysAndTypes() {
        let fixtures: [(String, String, String, Bool)] = [
            ("os_config_data_install_enforce", "com.apple.SoftwareUpdate", "ConfigDataInstall", true),
            ("os_mail_summary_disable", "com.apple.applicationaccess", "allowMailSummary", false),
            ("os_notes_transcription_disable", "com.apple.applicationaccess", "allowNotesTranscription", false),
            ("os_notes_transcription_summary_disable", "com.apple.applicationaccess", "allowNotesTranscriptionSummary", false),
            ("os_writing_tools_disable", "com.apple.applicationaccess", "allowWritingTools", false),
            ("system_settings_external_intelligence_disable", "com.apple.applicationaccess", "allowExternalIntelligenceIntegrations", false),
            ("system_settings_external_intelligence_sign_in_disable", "com.apple.applicationaccess", "allowExternalIntelligenceIntegrationsSignIn", false),
            ("system_settings_personalized_advertising_disable", "com.apple.applicationaccess", "allowApplePersonalizedAdvertising", false),
            ("system_settings_improve_assistive_voice_disable", "com.apple.Accessibility", "AXSAudioDonationSiriImprovementEnabled", false),
            ("system_settings_loginwindow_prompt_username_password_enforce", "com.apple.loginwindow", "SHOWFULLNAME", true)
        ]
        for (rule, suite, key, expected) in fixtures {
            let check = CISCheck(id: rule, category: "macos", description: "Untrusted remote description", ruleID: rule)
            func evaluate(_ value: Any?) -> CheckResult {
                var reads = 0
                let result = MacOSChecks.runTahoe(check: check, osMajorVersion: 26, command: { _, _ in
                    Issue.record("Preference rules must not execute tools")
                    return .init(unavailable: "Unexpected command")
                }) { actualSuite, actualKey in
                    reads += 1
                    #expect(actualSuite == suite)
                    #expect(actualKey == key)
                    return value
                }
                #expect(reads == 1)
                return result
            }
            #expect(evaluate(NSNumber(value: expected)).status == "pass")
            #expect(evaluate(NSNumber(value: !expected)).status == "fail")
            #expect(evaluate(nil).status == "manual")
            #expect(evaluate(expected ? "true" : "false").status == "manual")
            #expect(evaluate(NSNumber(value: expected ? 1 : 0)).status == "manual")
            #expect(evaluate(NSNumber(value: 0.5)).status == "manual")
        }
    }

    @Test func tahoeCommandDeadlinesFitTheCompositeCheckBudget() {
        // Two tools each permit 3s execution, two 0.5s termination waits and
        // a 1s reader cleanup. The timeout path ends the check after its first
        // unavailable result, so a second tool only follows successful listing.
        #expect(MacOSChecks.commandTimeoutSeconds == 3)
        #expect(MacOSChecks.commandTimeoutSeconds * 2 + 2 < Config.defaultConfig.timeouts.default)
    }

    @Test func tahoeCommandRegistryUsesOnlyBundledToolArguments() {
        let commands: [String: (String, [String])] = [
            "os_sip_enable": ("/usr/bin/csrutil", ["status"]),
            "os_authenticated_root_enable": ("/sbin/mount", []),
            "os_mobile_file_integrity_enable": ("/usr/sbin/nvram", ["-p"]),
            "os_root_disable": ("/usr/bin/dscl", ["/Local/Default", "read", "/Users/root", "AuthenticationAuthority"]),
            "system_settings_filevault_enforce": ("/usr/bin/fdesetup", ["status"]),
            "system_settings_printer_sharing_disable": ("/usr/sbin/cupsctl", []),
            "system_settings_remote_management_disable": ("/usr/libexec/mdmclient", ["QuerySecurityInfo"])
        ]
        for (rule, expected) in commands {
            let check = CISCheck(id: rule, category: "macos", description: "Untrusted description", ruleID: rule)
            var calls = 0
            let result = MacOSChecks.runTahoe(check: check, osMajorVersion: 26, command: { path, arguments in
                calls += 1
                #expect(path == expected.0)
                #expect(arguments == expected.1)
                return .init(unavailable: "Fixture tool unavailable")
            }) { _, _ in nil }
            #expect(calls == 1)
            #expect(result.status == "manual")
            #expect(MacOSChecks.runTahoe(check: check, osMajorVersion: 25, command: { _, _ in
                Issue.record("An incompatible OS must not execute a command")
                return .init()
            }) { _, _ in nil }.status == "manual")
        }
    }

    @Test func tahoeInactiveServicesUseFixedLabelsAndKnownNotFoundEvidence() {
        let labels = ["system_settings_screen_sharing_disable": "com.apple.screensharing", "system_settings_ssh_disable": "com.openssh.sshd", "os_tftpd_disable": "com.apple.tftpd", "os_uucp_disable": "com.apple.uucp", "os_httpd_disable": "org.apache.httpd"]
        for (rule, label) in labels {
            let check = CISCheck(id: rule, category: "macos", description: "Fixture", ruleID: rule)
            var calls = 0
            let result = MacOSChecks.runTahoe(check: check, osMajorVersion: 26, command: { path, arguments in
                calls += 1
                #expect(path == "/bin/launchctl")
                if arguments == ["print-disabled", "system"] { return .init(output: "disabled services = {\n}\n") }
                #expect(arguments == ["print", "system/" + label])
                return .init(error: "Could not find service \"\(label)\" in domain for system", exitCode: 113)
            }) { _, _ in nil }
            #expect(calls == 2)
            #expect(result.status == "pass")
        }
    }

    @Test func tahoeNextPreferencesUseExactSuitesKeysAndCompositeEvidence() {
        let fixtures: [(String, String, [String: NSNumber])] = [
            ("system_settings_improve_search_disable", "com.apple.assistant.support", ["Search Queries Data Sharing Status": NSNumber(value: 2)]),
            ("system_settings_improve_siri_dictation_disable", "com.apple.assistant.support", ["Siri Data Sharing Opt-In Status": NSNumber(value: 2)]),
            ("system_settings_time_server_enforce", "com.apple.timed", ["TMAutomaticTimeOnlyEnabled": NSNumber(value: true)]),
            ("icloud_sync_disable", "com.apple.applicationaccess", ["allowCloudDesktopAndDocuments": NSNumber(value: false)]),
            ("os_bonjour_disable", "com.apple.mDNSResponder", ["NoMulticastAdvertisements": NSNumber(value: true)]),
            ("system_settings_content_caching_disable", "com.apple.applicationaccess", ["allowContentCaching": NSNumber(value: false)]),
            ("system_settings_media_sharing_disabled", "com.apple.applicationaccess", ["allowMediaSharing": NSNumber(value: false), "allowMediaSharingModification": NSNumber(value: false)]),
            ("system_settings_time_machine_auto_backup_enable", "com.apple.TimeMachine", ["AutoBackup": NSNumber(value: true)])
        ]
        for (rule, suite, values) in fixtures {
            let check = CISCheck(id: rule, category: "macos", description: "Fixture", ruleID: rule)
            let passing = MacOSChecks.runTahoe(check: check, osMajorVersion: 26) { actualSuite, key in
                #expect(actualSuite == suite)
                #expect(values[key] != nil)
                return values[key]
            }
            #expect(passing.status == "pass")
            #expect(MacOSChecks.runTahoe(check: check, osMajorVersion: 26) { _, _ in nil }.status == "manual")
            #expect(MacOSChecks.runTahoe(check: check, osMajorVersion: 26) { _, _ in "false" }.status == "manual")
        }
        for rule in ["system_settings_improve_search_disable", "system_settings_improve_siri_dictation_disable"] {
            let check = CISCheck(id: rule, category: "macos", description: "Fixture", ruleID: rule)
            #expect(MacOSChecks.runTahoe(check: check, osMajorVersion: 26) { _, _ in NSNumber(value: true) }.status == "manual")
            #expect(MacOSChecks.runTahoe(check: check, osMajorVersion: 26) { _, _ in NSNumber(value: 2.5) }.status == "manual")
            #expect(MacOSChecks.runTahoe(check: check, osMajorVersion: 26) { _, _ in NSNumber(value: 1) }.status == "fail")
        }
        let media = CISCheck(id: "system_settings_media_sharing_disabled", category: "macos", description: "Fixture", ruleID: "system_settings_media_sharing_disabled")
        #expect(MacOSChecks.runTahoe(check: media, osMajorVersion: 26) { _, key in key == "allowMediaSharing" ? NSNumber(value: false) : nil }.status == "manual")
        #expect(MacOSChecks.runTahoe(check: media, osMajorVersion: 26) { _, key in key == "allowMediaSharing" ? NSNumber(value: true) : nil }.status == "fail")
    }

    @Test func tahoeCISRangesUsePinnedThresholdsAndRejectMissingOrInvalidEvidence() {
        let fixtures: [(String, String, String, Double)] = [
            ("system_settings_screensaver_ask_for_password_delay_enforce", "com.apple.screensaver", "askForPasswordDelay", 5),
            ("os_software_update_deferral", "com.apple.applicationaccess", "enforcedSoftwareUpdateDelay", 30)
        ]
        for (rule, suite, key, maximum) in fixtures {
            let check = CISCheck(id: rule, category: "macos", description: "Fixture", ruleID: rule)
            func evaluate(_ value: Any?) -> CheckResult {
                MacOSChecks.runTahoe(check: check, osMajorVersion: 26) { actualSuite, actualKey in
                    #expect(actualSuite == suite)
                    #expect(actualKey == key)
                    return value
                }
            }
            #expect(evaluate(NSNumber(value: 0)).status == "pass")
            #expect(evaluate(NSNumber(value: maximum)).status == "pass")
            #expect(evaluate(NSNumber(value: maximum + 0.5)).status == "fail")
            #expect(evaluate(NSNumber(value: -1)).status == "fail")
            #expect(evaluate(NSNumber(value: Double.nan)).status == "manual")
            #expect(evaluate(NSNumber(value: Double.infinity)).status == "manual")
            #expect(evaluate(NSNumber(value: false)).status == "manual")
            #expect(evaluate("0").status == "manual")
            #expect(evaluate(nil).status == "manual")
        }
    }

    @Test func tahoeTimeServerUsesPinnedCISStringWithoutLoggingArbitraryText() {
        let check = CISCheck(id: "system_settings_time_server_configure", category: "macos", description: "Fixture", ruleID: "system_settings_time_server_configure")
        func evaluate(_ value: Any?) -> CheckResult {
            MacOSChecks.runTahoe(check: check, osMajorVersion: 26) { suite, key in
                #expect(suite == "com.apple.MCX")
                #expect(key == "timeServer")
                return value
            }
        }
        #expect(evaluate("time.apple.com").status == "pass")
        #expect(evaluate("time.nist.gov").status == "fail")
        #expect(evaluate(nil).status == "manual")
        #expect(evaluate(NSNumber(value: true)).status == "manual")
        let sentinel = "arbitrary-preference-sentinel"
        #expect(!evaluate(sentinel).details.contains(sentinel))
    }

    @Test func tahoeScreensaverTimeoutMustActivateWithinPinnedCISDeadline() {
        let check = CISCheck(id: "system_settings_screensaver_timeout_enforce", category: "macos", description: "Fixture", ruleID: "system_settings_screensaver_timeout_enforce")
        func evaluate(_ value: Any?) -> CheckResult {
            MacOSChecks.runTahoe(check: check, osMajorVersion: 26) { suite, key in
                #expect(suite == "com.apple.screensaver")
                #expect(key == "idleTime")
                return value
            }
        }
        #expect(evaluate(NSNumber(value: 1)).status == "pass")
        #expect(evaluate(NSNumber(value: 900)).status == "pass")
        #expect(evaluate(NSNumber(value: 0)).status == "fail")
        #expect(evaluate(NSNumber(value: 901)).status == "fail")
        #expect(evaluate(NSNumber(value: -1)).status == "fail")
        #expect(evaluate(NSNumber(value: 899.5)).status == "manual")
        #expect(evaluate(NSNumber(value: true)).status == "manual")
        #expect(evaluate(nil).status == "manual")
        #expect(evaluate("900").status == "manual")
    }

    @Test func tahoeHotCornersNeedAllFourKnownIntegerActions() {
        let check = CISCheck(id: "system_settings_hot_corners_secure", category: "macos", description: "Fixture", ruleID: "system_settings_hot_corners_secure")
        let keys: Set<String> = ["wvous-bl-corner", "wvous-tl-corner", "wvous-tr-corner", "wvous-br-corner"]
        var observed: Set<String> = []
        let result = MacOSChecks.runTahoe(check: check, osMajorVersion: 26) { suite, key in
            #expect(suite == "com.apple.dock")
            #expect(keys.contains(key))
            observed.insert(key)
            return NSNumber(value: 0)
        }
        #expect(result.status == "pass")
        #expect(observed == keys)
        #expect(MacOSChecks.runTahoe(check: check, osMajorVersion: 26) { _, key in key == "wvous-bl-corner" ? NSNumber(value: 6) : nil }.status == "fail")
        #expect(MacOSChecks.runTahoe(check: check, osMajorVersion: 26) { _, key in key == "wvous-bl-corner" ? nil : NSNumber(value: 0) }.status == "manual")
        #expect(MacOSChecks.runTahoe(check: check, osMajorVersion: 26) { _, _ in NSNumber(value: false) }.status == "manual")
        #expect(MacOSChecks.runTahoe(check: check, osMajorVersion: 26) { _, _ in NSNumber(value: 5.5) }.status == "manual")
        #expect(MacOSChecks.runTahoe(check: check, osMajorVersion: 26) { _, _ in NSNumber(value: -1) }.status == "manual")
    }

    @Test func tahoeOnDeviceDictationRequiresKnownAppleSiliconApplicability() {
        let check = CISCheck(id: "os_on_device_dictation_enforce", category: "macos", description: "Fixture", ruleID: "os_on_device_dictation_enforce")
        let applicability: [Bool?] = [nil, false]
        for hardware in applicability {
            #expect(MacOSChecks.runTahoe(check: check, osMajorVersion: 26, appleSilicon: hardware) { _, _ in
                Issue.record("An inapplicable hardware rule must not read preferences")
                return NSNumber(value: true)
            }.status == "manual")
        }
        func evaluate(_ value: Any?) -> CheckResult {
            MacOSChecks.runTahoe(check: check, osMajorVersion: 26, appleSilicon: true) { suite, key in
                #expect(suite == "com.apple.applicationaccess")
                #expect(key == "forceOnDeviceOnlyDictation")
                return value
            }
        }
        #expect(evaluate(NSNumber(value: true)).status == "pass")
        #expect(evaluate(NSNumber(value: false)).status == "fail")
        #expect(evaluate(NSNumber(value: 1)).status == "manual")
        #expect(evaluate(nil).status == "manual")
    }

    @Test func tahoeBluetoothSharingUsesCurrentHostEvidenceOnly() {
        let check = CISCheck(id: "system_settings_bluetooth_sharing_disable", category: "macos", description: "Fixture", ruleID: "system_settings_bluetooth_sharing_disable")
        func evaluate(_ value: Any?) -> CheckResult {
            MacOSChecks.runTahoe(check: check, osMajorVersion: 26, readHostPreference: { suite, key in
                #expect(suite == "com.apple.Bluetooth")
                #expect(key == "PrefKeyServicesEnabled")
                return value
            }) { _, _ in
                Issue.record("Host-specific settings must not use the unscoped preference provider")
                return nil
            }
        }
        #expect(evaluate(NSNumber(value: false)).status == "pass")
        #expect(evaluate(NSNumber(value: true)).status == "fail")
        #expect(evaluate(nil).status == "manual")
        #expect(evaluate("false").status == "manual")
        #expect(evaluate(NSNumber(value: 0)).status == "manual")
    }

    @Test func tahoeLocationMenuUsesTypedFixedSystemPlistEvidence() {
        let check = CISCheck(id: "system_settings_location_services_menu_enforce", category: "macos", description: "Fixture", ruleID: "system_settings_location_services_menu_enforce")
        func evaluate(_ value: Any?) -> CheckResult {
            MacOSChecks.runTahoe(check: check, osMajorVersion: 26, readSystemPreference: { path, key in
                #expect(path == "/Library/Preferences/com.apple.locationmenu.plist")
                #expect(key == "ShowSystemServices")
                return value
            }) { _, _ in
                Issue.record("A system plist rule must not inspect ordinary user preferences")
                return nil
            }
        }
        #expect(evaluate(NSNumber(value: true)).status == "pass")
        #expect(evaluate(NSNumber(value: false)).status == "fail")
        #expect(evaluate(NSNumber(value: 1)).status == "manual")
        #expect(evaluate("true").status == "manual")
        #expect(evaluate(nil).status == "manual")
    }

    @Test func tahoeUpdateCheckAgeUsesPinnedCalendarDaysWithoutInferringInstalledPatches() throws {
        let check = CISCheck(id: "system_settings_softwareupdate_current", category: "macos", description: "Fixture", ruleID: "system_settings_softwareupdate_current")
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(secondsFromGMT: 0)!
        let now = try #require(MacOSChecks.datePreference("2026-09-29T12:00:00Z"))
        func evaluate(_ value: Any?) -> CheckResult {
            MacOSChecks.runTahoe(check: check, osMajorVersion: 26, readSystemPreference: { path, key in
                #expect(path == "/Library/Preferences/com.apple.SoftwareUpdate.plist")
                #expect(key == "LastFullSuccessfulDate")
                return value
            }, now: now, calendar: calendar) { _, _ in
                Issue.record("A system plist rule must not inspect ordinary user preferences")
                return nil
            }
        }
        let latest = evaluate(now)
        #expect(latest.status == "pass")
        #expect(latest.details.contains("not proof that every available patch was installed"))
        #expect(evaluate("2026-08-30 12:00:00 +0000").status == "pass")
        #expect(evaluate("2026-08-29T12:00:00Z").status == "fail")
        #expect(evaluate("2026-08-30").status == "pass")
        #expect(evaluate("2026-09-30T12:00:00Z").status == "manual")
        #expect(evaluate("2026-02-30").status == "manual")
        #expect(evaluate("not a timestamp").status == "manual")
        #expect(evaluate(NSNumber(value: true)).status == "manual")
        #expect(evaluate(nil).status == "manual")
        #expect(evaluate(Date(timeIntervalSince1970: .nan)).status == "manual")
    }

    @Test func tahoeSystemPlistReaderIsBoundedAndRejectsUnsupportedFiles() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let plist = directory.appendingPathComponent("fixture.plist")
        let data = try PropertyListSerialization.data(fromPropertyList: ["ShowSystemServices": true], format: .binary, options: 0)
        try data.write(to: plist)
        let value = MacOSChecks.readSystemPlistPreference(plist.path, "ShowSystemServices") as? NSNumber
        #expect(value?.boolValue == true)
        #expect(MacOSChecks.readSystemPlistPreference(plist.path, "missing") == nil)
        #expect(MacOSChecks.readSystemPlistPreference(directory.path, "ShowSystemServices") == nil)
        #expect(MacOSChecks.readSystemPlistPreference(directory.appendingPathComponent("absent.plist").path, "ShowSystemServices") == nil)
        let link = directory.appendingPathComponent("link.plist")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: plist)
        #expect(MacOSChecks.readSystemPlistPreference(link.path, "ShowSystemServices") == nil)
        try Data(repeating: 0, count: 1_048_577).write(to: plist)
        #expect(MacOSChecks.readSystemPlistPreference(plist.path, "ShowSystemServices") == nil)
        try Data("not a plist".utf8).write(to: plist)
        #expect(MacOSChecks.readSystemPlistPreference(plist.path, "ShowSystemServices") == nil)
    }

    @Test func downloadedDaedalusConfigParsesProfileSettings() {
        let config = Config.parse(yamlString: """
        reporting:
          endpoint: "https://app.example.org/api/cis/report"
          profiles_endpoint: "https://app.example.org/api/cis/client/profiles"
          profile_slug: "macos-baseline"
          domain: "example.org"
          api_key: "unit-test-key-not-a-secret"
        """)

        #expect(config.reporting.endpoint == "https://app.example.org/api/cis/report")
        #expect(config.reporting.profilesEndpoint == "https://app.example.org/api/cis/client/profiles")
        #expect(config.reporting.profileSlug == "macos-baseline")
        #expect(config.reporting.domain == "example.org")
        #expect(config.reporting.apiKey == "unit-test-key-not-a-secret")
    }

}

// Used only by the single acknowledgement fixture; no network request escapes.
private final class UploadFixtureProtocol: URLProtocol {
    static var statusCode = 200
    static var body = Data()
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        let response = HTTPURLResponse(url: request.url!, statusCode: Self.statusCode, httpVersion: "HTTP/1.1", headerFields: ["Content-Type": "application/json"])!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Self.body)
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

final class CISHeartbeatRequestTests: XCTestCase {
    func testHeartbeatUsesSameOriginAndKeepsKeyOutOfBodyAndURL() throws {
        let key = "fixture-private-key-123456"
        let request = try XCTUnwrap(DaedalusProfileClient.heartbeatRequest(reportEndpoint: "https://example.test/api/cis/report", apiKey: key, deviceIdentifier: "fixture-device"))
        XCTAssertEqual(request.url?.absoluteString, "https://example.test/api/cis/client/heartbeat")
        XCTAssertEqual(request.httpMethod, "POST")
        XCTAssertEqual(request.value(forHTTPHeaderField: "X-API-Key"), key)
        let body = try XCTUnwrap(request.httpBody)
        let payload = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: String])
        XCTAssertEqual(payload, ["device_identifier": "fixture-device"])
    }

    func testHeartbeatRejectsUnsafeOrUnrelatedEndpoints() {
        for endpoint in ["http://example.test/api/cis/report", "https://example.test/other", "https://example.test/api/cis/report?token=x", "https://example.test/api/cis/report#fragment", "https://user:pass@example.test/api/cis/report"] {
            XCTAssertNil(DaedalusProfileClient.heartbeatRequest(reportEndpoint: endpoint, apiKey: "fixture-private-key-123456", deviceIdentifier: "fixture-device"))
        }
        XCTAssertNotNil(DaedalusProfileClient.heartbeatRequest(reportEndpoint: "http://127.0.0.1:8000/api/cis/report", apiKey: "fixture-private-key-123456", deviceIdentifier: "fixture-device"))
    }
}
