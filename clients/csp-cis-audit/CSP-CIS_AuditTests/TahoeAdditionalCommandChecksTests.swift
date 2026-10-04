import Foundation
import Darwin
import Testing
@testable import CSP_CIS_Audit

struct TahoeAdditionalCommandChecksTests {
    private func run(_ rule: String, _ evidence: MacOSChecks.CommandEvidence) -> String {
        evaluate(rule) { _, _ in evidence }
    }

    private func evaluate(_ rule: String, command: (String, [String]) -> MacOSChecks.CommandEvidence) -> String {
        let check = CISCheck(id: rule, category: "macos", description: "Untrusted fixture text", ruleID: rule)
        return MacOSChecks.runTahoe(check: check, osMajorVersion: 26, command: command, readPreference: { _, _ in nil }).status
    }

    @Test func xprotectRequiresBothDistinctEnabledModes() {
        let rule = "os_anti_virus_installed"
        #expect(run(rule, .init(output: "launch scans: enabled\nbackground scans: enabled\n")) == "pass")
        #expect(run(rule, .init(output: "launch scans: disabled\nbackground scans: enabled")) == "fail")
        #expect(run(rule, .init(output: "launch scans: enabled\nlaunch scans: enabled")) == "manual")
        #expect(run(rule, .init(output: "launch scans: enabled")) == "manual")
        #expect(run(rule, .init(error: "permission denied", exitCode: 1)) == "manual")
    }

    @Test func disabledNfsServiceWithNoProcessIsValid() {
        let rule = "os_nfsd_disable"
        let disabledStatus = evaluate(rule) { executable, arguments in
            if executable == "/sbin/nfsd" {
                #expect(arguments == ["status"])
                return .init(output: "nfsd service is disabled", exitCode: 1)
            }
            #expect(executable == "/usr/bin/pgrep" && arguments == ["nfsd"])
            return .init(exitCode: 1)
        }
        #expect(disabledStatus == "pass")
        #expect(evaluate(rule) { executable, _ in
            executable == "/sbin/nfsd" ? .init(output: "nfsd service is disabled") : .init(output: "123\n")
        } == "fail")
        #expect(evaluate(rule) { executable, _ in
            executable == "/sbin/nfsd" ? .init(output: "nfsd service is disabled") : .init(error: "permission denied", exitCode: 1)
        } == "manual")
        #expect(run(rule, .init(output: "nfsd service is enabled")) == "fail")
        #expect(run(rule, .init(output: "", exitCode: 1)) == "manual")
    }

    @Test func guestFolderRuleInspectsOnlyNamesAndDoesNotDiscloseThem() {
        let rule = "os_guest_folder_removed"
        #expect(run(rule, .init(output: "Deleted Users\nShared\nsean\n")) == "pass")
        for entry in ["Guest", "Guest-Shared"] {
            #expect(run(rule, .init(output: "Shared\n\(entry)\n")) == "fail")
        }

        let check = CISCheck(id: rule, category: "macos", description: "Fixture", ruleID: rule)
        let result = MacOSChecks.runTahoe(check: check, osMajorVersion: 26, command: { executable, arguments in
            #expect(executable == "/bin/ls")
            #expect(arguments == ["-1", "/Users"])
            return .init(output: "Shared\nGuest-Private-Name\n")
        }, readPreference: { _, _ in nil })
        #expect(result.status == "fail")
        #expect(!result.details.contains("Guest-Private-Name"))
        #expect(!result.details.contains("Shared"))
    }

    @Test func guestFolderRuleKeepsUnusableOrAmbiguousEvidenceManual() {
        let rule = "os_guest_folder_removed"
        #expect(run(rule, .init(unavailable: "output limit")) == "manual")
        #expect(run(rule, .init(error: "permission denied", exitCode: 1)) == "manual")
        #expect(run(rule, .init(output: "")) == "manual")
        #expect(run(rule, .init(output: "Shared\n\nGuest\n")) == "manual")
        #expect(run(rule, .init(output: "/Users/Shared\n")) == "manual")
        #expect(run(rule, .init(output: "Shared\0Other\n")) == "manual")
    }

    @Test func powerSettingsRequireExplicitZeroForAllReportedSources() {
        for (rule, key) in [("os_power_nap_disable", "powernap"), ("system_settings_wake_network_access_disable", "womp")] {
            #expect(run(rule, .init(output: "Battery Power:\n \(key) 0\nAC Power:\n \(key) 0")) == "pass")
            #expect(run(rule, .init(output: "\(key) 0\n\(key) 1")) == "fail")
            #expect(run(rule, .init(output: "Battery Power:\n \(key) 0\nAC Power:\n sleep 1")) == "manual")
            #expect(run(rule, .init(output: "Battery Power:\n \(key) 1\nAC Power:\n sleep 1")) == "fail")
            #expect(run(rule, .init(output: "Battery Power:\n \(key) 0\n \(key) 0")) == "manual")
            #expect(run(rule, .init(output: "sleep 1")) == "manual")
            #expect(run(rule, .init(output: "\(key) unknown")) == "manual")
        }
    }

    @Test func timedRequiresExplicitSystemServiceEvidence() {
        let rule = "os_time_server_enabled"
        #expect(run(rule, .init(output: "system/com.apple.timed = {\n state = running\n}")) == "pass")
        #expect(run(rule, .init(error: "Could not find service com.apple.timed in domain for system", exitCode: 113)) == "fail")
        #expect(run(rule, .init(error: "Operation not permitted", exitCode: 1)) == "manual")
        #expect(run(rule, .init(output: "com.apple.timed")) == "manual")
    }

    @Test func auditMetadataMatchesPinnedOwnerGroupAndModes() {
        for rule in ["audit_control_owner_configure", "audit_control_group_configure", "audit_control_mode_configure"] {
            #expect(run(rule, .init(output: "Regular File:0:0:440\n")) == "pass")
            #expect(run(rule, .init(error: "No such file or directory", exitCode: 1)) == "manual")
            #expect(run(rule, .init(output: "Regular File:0:0:invalid")) == "manual")
        }
        #expect(run("audit_control_owner_configure", .init(output: "Regular File:501:0:440")) == "fail")
        #expect(run("audit_control_group_configure", .init(output: "Regular File:0:20:440")) == "fail")
        #expect(run("audit_control_mode_configure", .init(output: "Regular File:0:0:400")) == "pass")
        for type in ["Directory", "Symbolic Link", "Fifo"] {
            #expect(run("audit_control_mode_configure", .init(output: "\(type):0:0:400")) == "manual")
        }
        for mode in ["000", "444", "640", "1440"] {
            #expect(run("audit_control_mode_configure", .init(output: "Regular File:0:0:\(mode)")) == "fail")
        }
    }

    @Test func newRulesUseOnlyBundledExecutablesAndArguments() {
        let commands: [String: (String, [String])] = [
            "os_anti_virus_installed": ("/usr/bin/xprotect", ["status"]),
            "os_guest_folder_removed": ("/bin/ls", ["-1", "/Users"]),
            "os_nfsd_disable": ("/sbin/nfsd", ["status"]),
            "os_power_nap_disable": ("/usr/bin/pmset", ["-g", "custom"]),
            "system_settings_wake_network_access_disable": ("/usr/bin/pmset", ["-g", "custom"]),
            "os_time_server_enabled": ("/bin/launchctl", ["print", "system/com.apple.timed"]),
            "system_settings_guest_access_smb_disable": ("/usr/sbin/sysadminctl", ["-smbGuestAccess", "status"]),
            "os_safari_advertising_privacy_protection_enable": ("/usr/bin/profiles", ["-P", "-o", "stdout"]),
            "os_safari_open_safe_downloads_disable": ("/usr/bin/profiles", ["-P", "-o", "stdout"]),
            "os_safari_prevent_cross-site_tracking_enable": ("/usr/bin/profiles", ["-P", "-o", "stdout"]),
            "os_safari_show_full_website_address_enable": ("/usr/bin/profiles", ["-P", "-o", "stdout"]),
            "os_safari_show_status_bar_enabled": ("/usr/bin/profiles", ["-P", "-o", "stdout"]),
            "os_safari_warn_fraudulent_website_enable": ("/usr/bin/profiles", ["-P", "-o", "stdout"]),
            "audit_control_owner_configure": ("/usr/bin/stat", ["-f", "%HT:%u:%g:%Lp", "/etc/security/audit_control"]),
            "audit_control_group_configure": ("/usr/bin/stat", ["-f", "%HT:%u:%g:%Lp", "/etc/security/audit_control"]),
            "audit_control_mode_configure": ("/usr/bin/stat", ["-f", "%HT:%u:%g:%Lp", "/etc/security/audit_control"])
        ]
        #expect(Set(commands.keys) == MacOSChecks.additionalMacOS26CommandRuleIDs)
        for (rule, expected) in commands {
            let status = evaluate(rule) { executable, arguments in
                #expect(executable == expected.0 && arguments == expected.1)
                return .init(unavailable: "Fixture deliberately denies access")
            }
            #expect(status == "manual")
        }
    }

    @Test func safariTahoeRulesRequireThePinnedManagedProfileValues() {
        let fixtures: [String: (String, String)] = [
            "os_safari_advertising_privacy_protection_enable": (
                "\"WebKitPreferences.privateClickMeasurementEnabled\" = 1;",
                "\"WebKitPreferences.privateClickMeasurementEnabled\" = 0;"
            ),
            "os_safari_open_safe_downloads_disable": (
                "AutoOpenSafeDownloads = 0;", "AutoOpenSafeDownloads = 1;"
            ),
            "os_safari_prevent_cross-site_tracking_enable": (
                "\"WebKitPreferences.storageBlockingPolicy\" = 1;",
                "\"WebKitPreferences.storageBlockingPolicy\" = 0;"
            ),
            "os_safari_show_full_website_address_enable": (
                "ShowFullURLInSmartSearchField = 1;", "ShowFullURLInSmartSearchField = 0;"
            ),
            "os_safari_show_status_bar_enabled": (
                "ShowOverlayStatusBar = 1;", "ShowOverlayStatusBar = 0;"
            ),
            "os_safari_warn_fraudulent_website_enable": (
                "WarnAboutFraudulentWebsites = 1;", "WarnAboutFraudulentWebsites = 0;"
            )
        ]
        for (rule, values) in fixtures {
            #expect(run(rule, .init(output: values.0)) == "pass", "\(rule)")
            #expect(run(rule, .init(output: values.1)) == "fail", "\(rule)")
            #expect(run(rule, .init(output: "")) == "fail", "\(rule)")
            #expect(run(rule, .init(output: "\(values.0)\n\(values.1)")) == "manual", "\(rule)")
            #expect(run(rule, .init(output: values.0, unavailable: "fixture output was truncated")) == "manual", "\(rule)")
        }
        #expect(run("os_safari_prevent_cross-site_tracking_enable", .init(output: "\"BlockStoragePolicy\" = 2;")) == "pass")
        #expect(run("os_safari_prevent_cross-site_tracking_enable", .init(output: "\"BlockStoragePolicy\" = 1;")) == "fail")
        #expect(run("os_safari_show_status_bar_enabled", .init(output: "ShowOverlayStatusBar = true;")) == "manual")
    }

    @Test func safariProfileDetailsDoNotIncludeConfigurationDump() {
        let secretLookingProfileOutput = "WarnAboutFraudulentWebsites = 1; private-profile-value"
        let check = CISCheck(
            id: "os_safari_warn_fraudulent_website_enable",
            category: "macos",
            description: "Fixture",
            ruleID: "os_safari_warn_fraudulent_website_enable"
        )
        let result = MacOSChecks.runTahoe(check: check, osMajorVersion: 26, command: { _, _ in
            .init(output: secretLookingProfileOutput)
        }, readPreference: { _, _ in nil })
        #expect(result.status == "pass")
        #expect(!result.details.contains("private-profile-value"))
        #expect(!result.details.contains("WarnAboutFraudulentWebsites"))
    }

    @Test func smbGuestAccessRequiresExplicitStatus() {
        let rule = "system_settings_guest_access_smb_disable"
        #expect(run(rule, .init(output: "SMB guest access disabled")) == "pass")
        #expect(run(rule, .init(error: "SMB guest access enabled")) == "fail")
        #expect(run(rule, .init(output: "SMB guest access disabled", error: "SMB guest access enabled")) == "manual")
        #expect(run(rule, .init(error: "Operation not permitted", exitCode: 1)) == "manual")
        #expect(run(rule, .init(output: "unknown status")) == "manual")
    }

    @Test func auditEvidenceBatchIsRegisteredAndMacOS26Gated() {
        let rules: Set<String> = [
            "audit_files_owner_configure", "audit_files_group_configure", "audit_files_mode_configure",
            "audit_folder_owner_configure", "audit_folder_group_configure", "audit_folders_mode_configure",
            "audit_acls_files_configure", "audit_acls_folders_configure", "audit_control_acls_configure"
        ]
        #expect(rules == MacOSChecks.additionalMacOS26AuditEvidenceRuleIDs)
        #expect(rules.isSubset(of: MacOSChecks.additionalMacOS26RuleIDs))
        for rule in rules {
            let check = CISCheck(id: rule, category: "macos", description: "Fixture", ruleID: rule)
            let result = MacOSChecks.runTahoe(check: check, osMajorVersion: 25, readPreference: { _, _ in nil })
            #expect(result.status == "manual")
            #expect(result.details.contains("targets macOS 26"))
        }
    }

    @Test func auditEvidenceBatchPassesCompliantMetadataAndAclFixtures() throws {
        let fixture = try AuditFixture()
        defer { fixture.cleanup() }

        for rule in AuditFixture.auditRules {
            let result = fixture.result(rule)
            #expect(result.status == "pass", "\(rule): \(result.details)")
            #expect(!result.details.contains("private-audit-event.log"))
        }
    }

    @Test func auditEvidenceMetadataRulesFailOnKnownMismatches() throws {
        let fixture = try AuditFixture()
        defer { fixture.cleanup() }

        let nonRootUID: uid_t = getuid() == 0 ? 1 : 0
        let nonWheelGID: gid_t = getgid() == 0 ? 1 : 0
        #expect(fixture.result("audit_files_owner_configure", expectedRootUID: nonRootUID).status == "fail")
        #expect(fixture.result("audit_files_group_configure", expectedWheelGID: nonWheelGID).status == "fail")
        #expect(fixture.result("audit_folder_owner_configure", expectedRootUID: nonRootUID).status == "fail")
        #expect(fixture.result("audit_folder_group_configure", expectedWheelGID: nonWheelGID).status == "fail")

        #expect(chmod(fixture.auditDirectory.path, 0o750) == 0)
        #expect(fixture.result("audit_folders_mode_configure").status == "fail")
        #expect(chmod(fixture.auditDirectory.path, 0o700) == 0)

        #expect(chmod(fixture.auditFile.path, 0o640) == 0)
        #expect(fixture.result("audit_files_mode_configure").status == "fail")
    }

    @Test func auditEvidenceAclRulesFailWhenAnAclIsPresent() throws {
        let fixture = try AuditFixture()
        defer { fixture.cleanup() }

        try fixture.addACL(to: fixture.configuration)
        #expect(fixture.result("audit_control_acls_configure").status == "fail")
        try fixture.removeACL(from: fixture.configuration)

        try fixture.addACL(to: fixture.auditDirectory)
        #expect(fixture.result("audit_acls_folders_configure").status == "fail")
        try fixture.removeACL(from: fixture.auditDirectory)

        try fixture.addACL(to: fixture.auditFile)
        #expect(fixture.result("audit_acls_files_configure").status == "fail")
    }

    @Test func auditEvidenceMissingPermissionDeniedAndMalformedInputsStayManual() throws {
        let fixture = try AuditFixture()
        defer { fixture.cleanup() }

        let missingConfig = fixture.root.appendingPathComponent("missing-audit-control")
        #expect(fixture.result("audit_files_mode_configure", configuration: missingConfig).status == "manual")

        try Data("dir:\(fixture.auditDirectory.path)\ndir:\(fixture.auditDirectory.path)\n".utf8).write(to: fixture.configuration)
        #expect(fixture.result("audit_files_owner_configure").status == "manual")
        try fixture.writeConfiguration()

        try Data("dir:/tmp/../tmp\n".utf8).write(to: fixture.configuration)
        #expect(fixture.result("audit_folders_mode_configure").status == "manual")
        try fixture.writeConfiguration()

        #expect(chmod(fixture.configuration.path, 0) == 0)
        let denied = fixture.result("audit_control_acls_configure")
        #expect(denied.status == "manual")
        #expect(denied.details.contains("Permission was denied"))
        #expect(chmod(fixture.configuration.path, 0o600) == 0)

        #expect(chmod(fixture.auditFile.path, 0) == 0)
        let deniedACL = fixture.result("audit_acls_files_configure")
        #expect(deniedACL.status == "manual")
        #expect(deniedACL.details.contains("Permission was denied"))
        #expect(chmod(fixture.auditFile.path, 0o400) == 0)
    }

    @Test func auditEvidenceSymlinksAreNeverFollowed() throws {
        let fixture = try AuditFixture()
        defer { fixture.cleanup() }

        let linkedConfig = fixture.root.appendingPathComponent("linked-audit-control")
        try FileManager.default.createSymbolicLink(at: linkedConfig, withDestinationURL: fixture.configuration)
        let linkedConfigResult = fixture.result("audit_control_acls_configure", configuration: linkedConfig)
        #expect(linkedConfigResult.status == "manual")
        #expect(linkedConfigResult.details.contains("symlink"))

        let linkedFile = fixture.auditDirectory.appendingPathComponent("linked-event")
        try FileManager.default.createSymbolicLink(at: linkedFile, withDestinationURL: fixture.auditFile)
        let linkedFileResult = fixture.result("audit_files_mode_configure")
        #expect(linkedFileResult.status == "manual")
        #expect(linkedFileResult.details.contains("symlink"))
        #expect(!linkedFileResult.details.contains("private-audit-event.log"))
    }
}

private struct AuditFixture {
    static let auditRules: [String] = [
        "audit_files_owner_configure", "audit_files_group_configure", "audit_files_mode_configure",
        "audit_folder_owner_configure", "audit_folder_group_configure", "audit_folders_mode_configure",
        "audit_acls_files_configure", "audit_acls_folders_configure", "audit_control_acls_configure"
    ]

    let root: URL
    let configuration: URL
    let auditDirectory: URL
    let auditFile: URL

    init() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        configuration = root.appendingPathComponent("audit_control")
        auditDirectory = root.appendingPathComponent("audit", isDirectory: true)
        auditFile = auditDirectory.appendingPathComponent("private-audit-event.log")
        try FileManager.default.createDirectory(at: auditDirectory, withIntermediateDirectories: true)
        try Data("fixture audit record".utf8).write(to: auditFile)
        try writeConfiguration()
        guard chmod(auditDirectory.path, 0o700) == 0, chmod(auditFile.path, 0o400) == 0,
              chmod(configuration.path, 0o600) == 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
    }

    func writeConfiguration() throws {
        try Data("dir:\(auditDirectory.path)\n".utf8).write(to: configuration)
        guard chmod(configuration.path, 0o600) == 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
    }

    func result(
        _ rule: String,
        configuration url: URL? = nil,
        expectedRootUID: uid_t = getuid(),
        expectedWheelGID: gid_t = getgid()
    ) -> CheckResult {
        let check = CISCheck(id: rule, category: "macos", description: "Fixture", ruleID: rule)
        return MacOSChecks.runAuditEvidenceCheck(
            check: check,
            configurationURL: url ?? configuration,
            expectedRootUID: expectedRootUID,
            expectedWheelGID: expectedWheelGID
        )
    }

    func addACL(to url: URL) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/chmod")
        process.arguments = ["+a", "everyone deny delete", url.path]
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw NSError(domain: "AuditFixture", code: Int(process.terminationStatus), userInfo: [NSLocalizedDescriptionKey: "Could not add a temporary fixture ACL."])
        }
    }

    func removeACL(from url: URL) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/chmod")
        process.arguments = ["-N", url.path]
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw NSError(domain: "AuditFixture", code: Int(process.terminationStatus), userInfo: [NSLocalizedDescriptionKey: "Could not remove a temporary fixture ACL."])
        }
    }

    func cleanup() {
        let removeACLs = Process()
        removeACLs.executableURL = URL(fileURLWithPath: "/bin/chmod")
        removeACLs.arguments = ["-RN", root.path]
        try? removeACLs.run()
        removeACLs.waitUntilExit()
        _ = chmod(auditDirectory.path, 0o700)
        _ = chmod(auditFile.path, 0o600)
        _ = chmod(configuration.path, 0o600)
        try? FileManager.default.removeItem(at: root)
    }
}
