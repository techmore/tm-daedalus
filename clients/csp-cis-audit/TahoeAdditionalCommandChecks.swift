import Foundation
import Darwin
import CoreFoundation

extension MacOSChecks {
    // Static, read-only checks derived from NIST mSCP Tahoe rev3, commit
    // beceac1d21baf9d924c2780f2e248577435bbfb1 (CC BY 4.0).
    // The server supplies a rule ID; every executable and argument stays bundled.
    static let additionalMacOS26CommandRuleIDs: Set<String> = [
        "os_internal_apfs_volumes_encrypted", "audit_auditd_enabled", "os_anti_virus_installed", "os_guest_folder_removed", "os_nfsd_disable", "os_power_nap_disable",
        "system_settings_wake_network_access_disable", "os_time_server_enabled",
        "system_settings_guest_access_smb_disable",
        "os_safari_advertising_privacy_protection_enable",
        "os_safari_open_safe_downloads_disable",
        "os_safari_prevent_cross-site_tracking_enable",
        "os_safari_show_full_website_address_enable",
        "os_safari_show_status_bar_enabled",
        "os_safari_warn_fraudulent_website_enable",
        "audit_control_owner_configure", "audit_control_group_configure",
        "audit_control_mode_configure"
    ]

    static let additionalMacOS26AuditEvidenceRuleIDs: Set<String> = [
        "audit_files_owner_configure",
        "audit_files_group_configure", "audit_files_mode_configure",
        "audit_folder_owner_configure", "audit_folder_group_configure",
        "audit_folders_mode_configure", "audit_acls_files_configure",
        "audit_acls_folders_configure", "audit_control_acls_configure"
    ]

    static let additionalMacOS26RuleIDs = additionalMacOS26CommandRuleIDs
        .union(additionalMacOS26AuditEvidenceRuleIDs)

    static func runAdditionalTahoeCommand(
        check: CISCheck,
        command: (String, [String]) -> CommandEvidence
    ) -> CheckResult {
        func result(_ status: String, _ detail: String) -> CheckResult {
            CheckResult(check: check, status: status, details: "Pinned NIST mSCP Tahoe read-only check for \(check.ruleID ?? check.id). " + detail)
        }
        func usable(_ evidence: CommandEvidence, exits: Set<Int32> = [0]) -> Bool {
            evidence.unavailable == nil && exits.contains(evidence.exitCode)
                && evidence.error.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        }
        let rule = check.ruleID ?? ""
        switch rule {
        case "os_safari_advertising_privacy_protection_enable",
             "os_safari_open_safe_downloads_disable",
             "os_safari_prevent_cross-site_tracking_enable",
             "os_safari_show_full_website_address_enable",
             "os_safari_show_status_bar_enabled",
             "os_safari_warn_fraudulent_website_enable":
            return runManagedProfileSettingCheck(check: check, command: command)

        case "os_internal_apfs_volumes_encrypted":
            return checkInternalAPFSEncryption(check: check, command: command)

        case "audit_auditd_enabled":
            return checkAuditServiceEnabled(check: check, command: command)

        case "system_settings_guest_access_smb_disable":
            let evidence = command("/usr/sbin/sysadminctl", ["-smbGuestAccess", "status"])
            guard evidence.unavailable == nil, evidence.exitCode == 0 else {
                return result("manual", "SMB guest-access state could not be read unambiguously.")
            }
            let status = evidence.output + "\n" + evidence.error
            let disabled = status.contains("SMB guest access disabled")
            let enabled = status.contains("SMB guest access enabled")
            if disabled && !enabled {
                return result("pass", "sysadminctl explicitly reports SMB guest access disabled.")
            }
            if enabled && !disabled {
                return result("fail", "sysadminctl explicitly reports SMB guest access enabled.")
            }
            return result("manual", "sysadminctl did not report one unambiguous SMB guest-access state.")

        case "os_guest_folder_removed":
            // The pinned mSCP check searches the /Users directory listing for
            // the case-sensitive substring "Guest". Inspect only that
            // directory level and never include entry names in uploaded detail.
            let evidence = command("/bin/ls", ["-1", "/Users"])
            guard usable(evidence), !evidence.output.isEmpty else {
                return result("manual", "The /Users directory listing was unavailable or empty; no absence was inferred.")
            }
            var entries = evidence.output.components(separatedBy: "\n")
            if entries.last == "" { entries.removeLast() }
            guard !entries.isEmpty, entries.allSatisfy({ entry in
                !entry.isEmpty && !entry.contains("/")
                    && entry.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) })
            }) else {
                return result("manual", "The /Users directory listing was malformed or ambiguous.")
            }
            if entries.contains(where: { $0.contains("Guest") }) {
                return result("fail", "A directory entry matching the pinned Guest-folder rule is present.")
            }
            return result("pass", "No directory entry matching the pinned Guest-folder rule was observed.")

        case "os_anti_virus_installed":
            let evidence = command("/usr/bin/xprotect", ["status"])
            guard usable(evidence) else { return result("manual", "XProtect status is unavailable; no enabled protection was inferred.") }
            var flags: [String: Bool] = [:]
            for line in evidence.output.components(separatedBy: .newlines) {
                let parts = line.trimmingCharacters(in: .whitespaces).components(separatedBy: ":")
                guard parts.count == 2, ["launch scans", "background scans"].contains(parts[0]) else { continue }
                let value = parts[1].trimmingCharacters(in: .whitespaces)
                guard flags[parts[0]] == nil, ["enabled", "disabled"].contains(value) else {
                    return result("manual", "XProtect returned ambiguous scan-mode evidence.")
                }
                flags[parts[0]] = value == "enabled"
            }
            if flags.values.contains(false) { return result("fail", "At least one XProtect scan mode is explicitly disabled.") }
            guard flags.count == 2 else { return result("manual", "Both launch and background scan-mode settings were not reported.") }
            return result("pass", "XProtect launch scans and background scans are explicitly enabled.")

        case "os_nfsd_disable":
            let state = command("/sbin/nfsd", ["status"])
            guard usable(state, exits: [0, 1]) else { return result("manual", "NFS service status is unavailable or permission limited.") }
            let lines = state.output.components(separatedBy: .newlines).map { $0.trimmingCharacters(in: .whitespaces) }
            let disabled = lines.filter { $0 == "nfsd service is disabled" }.count
            let enabled = lines.filter { $0 == "nfsd service is enabled" }.count
            if enabled == 1 && disabled == 0 { return result("fail", "The NFS service is explicitly enabled.") }
            guard disabled == 1 && enabled == 0 else { return result("manual", "No unambiguous disabled NFS service state was reported.") }
            let running = command("/usr/bin/pgrep", ["nfsd"])
            guard usable(running, exits: [0, 1]) else { return result("manual", "The NFS process check is unavailable or permission limited.") }
            let pids = running.output.components(separatedBy: .whitespacesAndNewlines).filter { !$0.isEmpty }
            if running.exitCode == 1 && pids.isEmpty { return result("pass", "The NFS service is disabled and no matching nfsd process was observed.") }
            if running.exitCode == 0 && !pids.isEmpty && pids.allSatisfy({ Int($0).map { $0 > 0 } ?? false }) {
                return result("fail", "A matching nfsd process is running despite the disabled service setting.")
            }
            return result("manual", "The NFS process check returned ambiguous evidence.")

        case "os_power_nap_disable", "system_settings_wake_network_access_disable":
            let evidence = command("/usr/bin/pmset", ["-g", "custom"])
            guard usable(evidence) else { return result("manual", "Power-management settings could not be read.") }
            let key = rule == "os_power_nap_disable" ? "powernap" : "womp"
            var values: [Int] = []
            var sectionCounts: [Int] = []
            var currentCount = 0
            var sawSection = false
            for line in evidence.output.components(separatedBy: .newlines) {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if ["Battery Power:", "AC Power:", "UPS Power:"].contains(trimmed) {
                    if sawSection { sectionCounts.append(currentCount) }
                    sawSection = true
                    currentCount = 0
                    continue
                }
                let fields = line.components(separatedBy: .whitespaces).filter { !$0.isEmpty }
                guard fields.first == key else { continue }
                currentCount += 1
                guard fields.count == 2, let value = Int(fields[1]), [0, 1].contains(value) else {
                    return result("manual", "A reported \(key) value had an unsupported format.")
                }
                values.append(value)
            }
            if values.contains(1) { return result("fail", "At least one reported \(key) setting is explicitly enabled.") }
            if sawSection {
                sectionCounts.append(currentCount)
                guard sectionCounts.allSatisfy({ $0 == 1 }) else { return result("manual", "Each reported power-source section must contain exactly one \(key) setting.") }
            } else if currentCount != 1 {
                return result("manual", "Power-source settings were missing or duplicated without identifiable sections.")
            }
            guard !values.isEmpty else { return result("manual", "This hardware or OS did not report \(key); absence is not proof that it is disabled.") }
            return result(values.allSatisfy { $0 == 0 } ? "pass" : "fail", "\(key) was checked across all \(values.count) reported power-source settings; every value must be zero.")

        case "os_time_server_enabled":
            let evidence = command("/bin/launchctl", ["print", "system/com.apple.timed"])
            guard evidence.unavailable == nil else { return result("manual", "The timed service query was unavailable.") }
            if evidence.exitCode != 0 && evidence.error.contains("Could not find service") && evidence.error.contains("com.apple.timed") {
                return result("fail", "The required com.apple.timed service was not found in the system launchd domain.")
            }
            guard usable(evidence), evidence.output.range(of: "(?m)^system/com\\.apple\\.timed\\s*=\\s*\\{", options: .regularExpression) != nil else {
                return result("manual", "The system launchd domain did not provide unambiguous timed service evidence.")
            }
            return result("pass", "The required com.apple.timed service is present in the system launchd domain; this does not attest time synchronization quality.")

        case "audit_control_owner_configure", "audit_control_group_configure", "audit_control_mode_configure":
            let evidence = command("/usr/bin/stat", ["-f", "%HT:%u:%g:%Lp", "/etc/security/audit_control"])
            guard usable(evidence) else { return result("manual", "audit_control metadata is absent or inaccessible; permissions were not inferred.") }
            let fields = evidence.output.trimmingCharacters(in: .whitespacesAndNewlines).components(separatedBy: ":")
            guard fields.count == 4, fields[0] == "Regular File",
                  let owner = Int(fields[1]), owner >= 0,
                  let group = Int(fields[2]), group >= 0,
                  !fields[3].isEmpty, fields[3].allSatisfy({ "01234567".contains($0) }),
                  let mode = Int(fields[3], radix: 8) else {
                return result("manual", "audit_control metadata had an unsupported format.")
            }
            switch rule {
            case "audit_control_owner_configure":
                return result(owner == 0 ? "pass" : "fail", "audit_control must be owned by UID zero.")
            case "audit_control_group_configure":
                return result(group == 0 ? "pass" : "fail", "audit_control must have GID zero.")
            default:
                return result([0o400, 0o440].contains(mode) ? "pass" : "fail", "audit_control permissions must be exactly 0400 or 0440, matching the pinned source's owner/group read-only modes.")
            }
        case "audit_files_owner_configure", "audit_files_group_configure", "audit_files_mode_configure",
             "audit_folder_owner_configure", "audit_folder_group_configure", "audit_folders_mode_configure",
             "audit_acls_files_configure", "audit_acls_folders_configure", "audit_control_acls_configure":
            return runAuditEvidenceCheck(check: check)
        default:
            return result("manual", "No additional bundled command check is available for this rule.")
        }
    }

    // Shared with the legacy CSP auditing check; never infer success from an error mentioning auditd.
    static func checkInternalAPFSEncryption(
        check: CISCheck,
        command: (String, [String]) -> CommandEvidence,
        clock: () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }
    ) -> CheckResult {
        func result(_ status: String, _ detail: String) -> CheckResult {
            CheckResult(check: check, status: status, details: "Pinned Tahoe internal APFS encryption check. " + detail)
        }
        func plist(_ evidence: CommandEvidence) -> [String: Any]? {
            guard evidence.unavailable == nil, evidence.exitCode == 0,
                  evidence.error.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                  !evidence.output.isEmpty, evidence.output.utf8.count <= 65536,
                  let value = try? PropertyListSerialization.propertyList(from: Data(evidence.output.utf8), options: [], format: nil) as? [String: Any] else { return nil }
            return value
        }
        let started = clock()
        guard let inventory = plist(command("/usr/sbin/diskutil", ["list", "-plist", "internal"])),
              let disks = inventory["AllDisksAndPartitions"] as? [[String: Any]], !disks.isEmpty, disks.count <= 32 else {
            return result("manual", "Internal disk inventory is missing, unsupported or unavailable.")
        }
        var identifiers: [String] = []
        for disk in disks {
            guard let rawVolumes = disk["APFSVolumes"] else {
                if disk["Content"] as? String == "Apple_APFS" {
                    return result("manual", "An internal APFS container did not include volume evidence.")
                }
                continue
            }
            guard let volumes = rawVolumes as? [[String: Any]], !volumes.isEmpty else {
                return result("manual", "Internal APFS volume enumeration was incomplete.")
            }
            for volume in volumes {
                guard let identifier = volume["DeviceIdentifier"] as? String,
                      identifier.utf8.count <= 32,
                      identifier.range(of: "^disk[0-9]+s[0-9]+$", options: .regularExpression) != nil,
                      !identifiers.contains(identifier), identifiers.count < 32 else {
                    return result("manual", "Volume identifiers were missing, duplicated, unsupported or exceeded the collection bound.")
                }
                identifiers.append(identifier)
            }
        }
        guard !identifiers.isEmpty else { return result("manual", "No internal APFS volumes were captured; encryption was not inferred.") }
        var eligible = 0
        for identifier in identifiers {
            guard clock() - started < 6 else { return result("manual", "Volume inspection reached its bounded collection deadline.") }
            guard let info = plist(command("/usr/sbin/diskutil", ["info", "-plist", identifier])),
                  info["DeviceIdentifier"] as? String == identifier,
                  (info["FilesystemType"] as? String)?.lowercased() == "apfs",
                  let internalFlag = info["Internal"] as? NSNumber,
                  CFGetTypeID(internalFlag) == CFBooleanGetTypeID(), internalFlag.boolValue,
                  let name = info["VolumeName"] as? String, !name.isEmpty else {
                return result("manual", "An internal volume's identity or metadata could not be verified.")
            }
            // Same named exclusions as the pinned mSCP rule; names stay local.
            if ["Preboot", "Recovery", "VM"].contains(name) { continue }
            eligible += 1
            guard let encrypted = info["FileVault"] as? NSNumber, CFGetTypeID(encrypted) == CFBooleanGetTypeID() else {
                return result("manual", "An eligible internal volume did not report an explicit encryption state.")
            }
            if !encrypted.boolValue {
                return result("fail", "An eligible internal APFS volume explicitly reports FileVault disabled; other volumes may remain unassessed.")
            }
        }
        guard eligible > 0 else { return result("manual", "Only excluded infrastructure volumes were observed; user-storage coverage is unconfirmed.") }
        return result("pass", "All " + String(eligible) + " captured eligible internal APFS volumes explicitly report FileVault enabled.")
    }

    static func checkAuditServiceEnabled(
        check: CISCheck,
        command: (String, [String]) -> CommandEvidence = readCommand
    ) -> CheckResult {
        func result(_ status: String, _ detail: String) -> CheckResult {
            CheckResult(check: check, status: status, details: "Read-only auditing evidence. " + detail)
        }
        func usable(_ evidence: CommandEvidence) -> Bool {
            evidence.unavailable == nil && evidence.exitCode == 0
                && evidence.error.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        }
        let service = command("/bin/launchctl", ["print", "system/com.apple.auditd"])
        guard service.unavailable == nil else {
            return result("manual", "The audit service query was unavailable.")
        }
        if service.exitCode != 0 && service.error.contains("Could not find service")
            && service.error.contains("com.apple.auditd") {
            return result("fail", "The required audit service was not found in the system launchd domain.")
        }
        guard usable(service), service.output.range(
            of: "(?m)^system/com\\.apple\\.auditd\\s*=\\s*\\{", options: .regularExpression
        ) != nil else {
            return result("manual", "The system domain did not provide unambiguous audit service evidence.")
        }
        let metadata = command("/usr/bin/stat", ["-f", "%HT", "/etc/security/audit_control"])
        guard usable(metadata), metadata.output.trimmingCharacters(in: .whitespacesAndNewlines) == "Regular File" else {
            return result("manual", "audit_control is absent, inaccessible or not a regular file; auditing was not inferred.")
        }
        let condition = command("/usr/sbin/audit", ["-c"])
        guard usable(condition) else {
            return result("manual", "The kernel audit condition could not be read with current permissions.")
        }
        var value = condition.output.trimmingCharacters(in: .whitespacesAndNewlines)
        if value.hasPrefix("audit condition: ") {
            value = String(value.dropFirst("audit condition: ".count))
        }
        if value == "AUC_AUDITING" {
            return result("pass", "The audit service and regular audit_control file are present, and the kernel explicitly reports auditing enabled.")
        }
        if ["AUC_NOAUDIT", "AUC_DISABLED"].contains(value) {
            return result("fail", "The kernel explicitly reports auditing disabled.")
        }
        return result("manual", "The kernel audit condition was unrecognized or ambiguous.")

    }
    // The pinned Tahoe source checks these values in installed configuration
    // profiles. Keep the allowed keys, values, and command local to the client;
    // never upload the profile dump or echo arbitrary settings in report details.
    static func runManagedProfileSettingCheck(
        check: CISCheck,
        command: (String, [String]) -> CommandEvidence
    ) -> CheckResult {
        func result(_ status: String, _ detail: String) -> CheckResult {
            CheckResult(check: check, status: status, details: "Pinned NIST mSCP Tahoe read-only check for \(check.ruleID ?? check.id). " + detail)
        }

        let rule = check.ruleID ?? ""
        let requiredSettings: [String: (expected: String, allowedValues: Set<String>)]
        switch rule {
        case "os_safari_advertising_privacy_protection_enable":
            requiredSettings = ["WebKitPreferences.privateClickMeasurementEnabled": (expected: "1", allowedValues: ["0", "1"])]
        case "os_safari_open_safe_downloads_disable":
            requiredSettings = ["AutoOpenSafeDownloads": (expected: "0", allowedValues: ["0", "1"])]
        case "os_safari_prevent_cross-site_tracking_enable":
            requiredSettings = [
                "WebKitPreferences.storageBlockingPolicy": (expected: "1", allowedValues: ["0", "1"]),
                "WebKitStorageBlockingPolicy": (expected: "1", allowedValues: ["0", "1"]),
                "BlockStoragePolicy": (expected: "2", allowedValues: ["1", "2"])
            ]
        case "os_safari_show_full_website_address_enable":
            requiredSettings = ["ShowFullURLInSmartSearchField": (expected: "1", allowedValues: ["0", "1"])]
        case "os_safari_show_status_bar_enabled":
            requiredSettings = ["ShowOverlayStatusBar": (expected: "1", allowedValues: ["0", "1"])]
        case "os_safari_warn_fraudulent_website_enable":
            requiredSettings = ["WarnAboutFraudulentWebsites": (expected: "1", allowedValues: ["0", "1"])]
        default:
            return result("manual", "No bundled managed-profile setting check is available for this rule.")
        }

        let evidence = command("/usr/bin/profiles", ["-P", "-o", "stdout"])
        guard evidence.unavailable == nil, evidence.exitCode == 0,
              evidence.error.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return result("manual", "Installed configuration profiles could not be read completely; no Safari setting was inferred.")
        }

        var observedCount = 0
        var expectedCount = 0
        var unexpectedCount = 0
        for line in evidence.output.components(separatedBy: .newlines) {
            for (key, requirement) in requiredSettings where line.contains(key) {
                let escapedKey = NSRegularExpression.escapedPattern(for: key)
                let pattern = "(?<![A-Za-z0-9_.])\"?\(escapedKey)\"?\\s*=\\s*([0-9]+)(?![A-Za-z0-9])"
                guard let expression = try? NSRegularExpression(pattern: pattern) else {
                    return result("manual", "The bundled managed-profile setting matcher is invalid.")
                }
                let lineRange = NSRange(line.startIndex..., in: line)
                let matches = expression.matches(in: line, range: lineRange)
                guard !matches.isEmpty else {
                    return result("manual", "A Safari profile setting had an unsupported format.")
                }
                for match in matches {
                    guard let valueRange = Range(match.range(at: 1), in: line) else {
                        return result("manual", "A Safari profile setting had an unsupported format.")
                    }
                    let value = String(line[valueRange])
                    guard requirement.allowedValues.contains(value) else {
                        return result("manual", "A Safari profile setting had an unsupported value format.")
                    }
                    observedCount += 1
                    if value == requirement.expected { expectedCount += 1 }
                    else { unexpectedCount += 1 }
                }
            }
        }

        guard observedCount > 0 else {
            return result("fail", "No installed configuration profile contained the required Safari setting.")
        }
        if expectedCount > 0 && unexpectedCount > 0 {
            return result("manual", "Installed configuration profiles contain conflicting Safari setting values.")
        }
        if unexpectedCount > 0 {
            return result("fail", "Installed configuration profiles do not contain the required Safari setting value.")
        }
        return result("pass", "Installed configuration profiles explicitly contain the required Safari setting.")
    }

    // Audit checks inspect metadata only. The configured log directory comes
    // from a bounded, no-follow read of audit_control; no shell command or
    // server-provided path is executed. File names and audit contents are not
    // copied into the report.
    static func runAuditEvidenceCheck(
        check: CISCheck,
        configurationURL: URL = URL(fileURLWithPath: "/etc/security/audit_control"),
        expectedRootUID: uid_t = 0,
        expectedWheelGID: gid_t? = nil
    ) -> CheckResult {
        func result(_ status: String, _ detail: String) -> CheckResult {
            CheckResult(check: check, status: status, details: "Pinned NIST mSCP Tahoe read-only check for \(check.ruleID ?? check.id). " + detail)
        }

        let rule = check.ruleID ?? ""
        if rule == "audit_control_acls_configure" {
            switch inspectControlACL(at: configurationURL) {
            case .present:
                return result("fail", "audit_control has an extended ACL.")
            case .absent:
                return result("pass", "audit_control has no extended ACL.")
            case .problem(let message):
                return result("manual", message)
            }
        }

        let groupRules: Set<String> = ["audit_folder_group_configure", "audit_files_group_configure"]
        let wheelGID: gid_t?
        if !groupRules.contains(rule) {
            wheelGID = nil
        } else if let expectedWheelGID {
            wheelGID = expectedWheelGID
        } else if let wheel = "wheel".withCString({ getgrnam($0) }) {
            wheelGID = wheel.pointee.gr_gid
        } else {
            return result("manual", "The wheel group ID could not be resolved; audit ownership was not inferred.")
        }

        guard let directoryPath = configuredAuditDirectory(at: configurationURL) else {
            return result("manual", "The audit_control configuration is missing, inaccessible, malformed, or ambiguous; the audit directory was not inferred.")
        }

        let folderRules: Set<String> = [
            "audit_folder_owner_configure", "audit_folder_group_configure", "audit_folders_mode_configure"
        ]
        if folderRules.contains(rule) {
            guard let directory = inspectDirectoryMetadata(at: directoryPath) else {
                return result("manual", "The configured audit directory is missing, inaccessible, a symlink, or not a directory.")
            }
            switch rule {
            case "audit_folder_owner_configure":
                return result(directory.uid == expectedRootUID ? "pass" : "fail", "The configured audit directory must be owned by root.")
            case "audit_folder_group_configure":
                guard let wheelGID else { return result("manual", "The wheel group ID is unavailable.") }
                return result(directory.gid == wheelGID ? "pass" : "fail", "The configured audit directory must belong to wheel.")
            default:
                return result(directory.mode == 0o700 ? "pass" : "fail", "The pinned check requires the configured audit directory mode to be exactly 0700.")
            }
        }

        if rule == "audit_acls_folders_configure" {
            switch inspectDirectoryACL(at: directoryPath) {
            case .present:
                return result("fail", "The configured audit directory has an extended ACL.")
            case .absent:
                return result("pass", "The configured audit directory has no extended ACL.")
            case .problem(let message):
                return result("manual", message)
            }
        }

        let needsACLs = rule == "audit_acls_files_configure"
        let scan = scanAuditFiles(at: directoryPath, inspectACLs: needsACLs)
        let expectedFiles = scan.files.count
        guard expectedFiles > 0 || !scan.problems.isEmpty else {
            return result("manual", "The configured audit directory contained no file evidence.")
        }

        if needsACLs {
            if scan.files.contains(where: { $0.hasExtendedACL == true }) {
                return result("fail", "At least one configured audit log file has an extended ACL.")
            }
            if let issue = scan.problems.first {
                return result("manual", issue.message)
            }
            guard expectedFiles > 0 else {
                return result("manual", "The configured audit directory contained no file evidence.")
            }
            return result("pass", "No extended ACL was found on any of the \(expectedFiles) directly configured audit log files.")
        }

        var mismatches = 0
        for file in scan.files {
            switch rule {
            case "audit_files_owner_configure":
                if file.uid != expectedRootUID { mismatches += 1 }
            case "audit_files_group_configure":
                if let wheelGID, file.gid != wheelGID { mismatches += 1 }
            case "audit_files_mode_configure":
                // Matches the pinned rule's -r--[r-]----- permission pattern.
                if file.mode != 0o400 && file.mode != 0o440 { mismatches += 1 }
            default:
                return result("manual", "No bundled audit evidence check is available for this rule.")
            }
        }
        if mismatches > 0 {
            let criterion: String
            switch rule {
            case "audit_files_owner_configure": criterion = "root ownership"
            case "audit_files_group_configure": criterion = "wheel group ownership"
            default: criterion = "mode 0400 or 0440"
            }
            return result("fail", "\(mismatches) of \(expectedFiles) audit log files did not meet the \(criterion) requirement.")
        }
        if let issue = scan.problems.first {
            return result("manual", issue.message)
        }
        guard expectedFiles > 0 else {
            return result("manual", "The configured audit directory contained no file evidence.")
        }
        let summary: String
        switch rule {
        case "audit_files_owner_configure": summary = "All \(expectedFiles) directly configured audit log files are owned by root."
        case "audit_files_group_configure": summary = "All \(expectedFiles) directly configured audit log files belong to wheel."
        default: summary = "All \(expectedFiles) directly configured audit log files have mode 0400 or 0440."
        }
        return result("pass", summary)
    }

    static let auditControlMaximumBytes = 65_536
    private static let auditFileMaximumCount = 4_096

    private struct AuditMetadata {
        let uid: uid_t
        let gid: gid_t
        let mode: mode_t
        let type: mode_t
        var hasExtendedACL: Bool? = nil

        init(_ metadata: stat, hasExtendedACL: Bool? = nil) {
            uid = metadata.st_uid
            gid = metadata.st_gid
            mode = metadata.st_mode & mode_t(0o7777)
            type = metadata.st_mode & mode_t(S_IFMT)
            self.hasExtendedACL = hasExtendedACL
        }
    }

    private enum AuditACLObservation {
        case present
        case absent
        case problem(String)
    }

    private struct AuditScan {
        var files: [AuditMetadata] = []
        var problems: [AuditProblem] = []
    }

    private enum AuditProblem {
        case missing
        case permissionDenied
        case symlink
        case ambiguous

        var message: String {
            switch self {
            case .missing: return "Required audit evidence is missing; no pass or fail was inferred."
            case .permissionDenied: return "Permission was denied while reading required audit evidence; the result is manual."
            case .symlink: return "A symlink was encountered in required audit evidence; it was not followed."
            case .ambiguous: return "Audit evidence was malformed, unsupported, or incomplete; the result is manual."
            }
        }

        static func fromErrno(_ code: Int32) -> AuditProblem {
            switch code {
            case ENOENT, ENOTDIR: return .missing
            case EACCES, EPERM: return .permissionDenied
            case ELOOP: return .symlink
            default: return .ambiguous
            }
        }
    }

    private static func configuredAuditDirectory(at configurationURL: URL) -> String? {
        guard let data = readAuditControl(at: configurationURL),
              let text = String(data: data, encoding: .utf8),
              !text.unicodeScalars.contains(where: { $0.value == 0 }) else { return nil }
        let directoryLines = text.split(whereSeparator: \.isNewline).filter { $0.hasPrefix("dir:") }
        guard directoryLines.count == 1 else { return nil }
        let value = String(directoryLines[0].dropFirst(4))
        guard !value.isEmpty, value.utf8.count <= 1_024,
              value.hasPrefix("/"), value != "/",
              !value.contains(":"),
              value.unicodeScalars.allSatisfy({ $0.value >= 0x21 && $0.value != 0x7f }),
              !value.split(separator: "/", omittingEmptySubsequences: false).contains(where: { $0 == "." || $0 == ".." }),
              URL(fileURLWithPath: value).standardizedFileURL.path == value else { return nil }
        return value
    }

    static func readAuditControl(at url: URL) -> Data? {
        let descriptor = url.path.withCString { open($0, O_RDONLY | O_NONBLOCK | O_NOFOLLOW) }
        guard descriptor >= 0 else { return nil }
        defer { _ = close(descriptor) }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              metadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              metadata.st_size >= 0,
              metadata.st_size <= auditControlMaximumBytes else { return nil }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 8_192)
        while true {
            let count = buffer.withUnsafeMutableBytes { bytes in
                read(descriptor, bytes.baseAddress, bytes.count)
            }
            if count == 0 { break }
            if count < 0 {
                if errno == EINTR { continue }
                return nil
            }
            guard data.count + count <= auditControlMaximumBytes else { return nil }
            data.append(contentsOf: buffer.prefix(count))
        }
        return data
    }

    private static func inspectDirectoryMetadata(at path: String) -> AuditMetadata? {
        var metadata = stat()
        let status = path.withCString { lstat($0, &metadata) }
        guard status == 0, metadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR) else { return nil }
        return AuditMetadata(metadata)
    }

    private static func inspectControlACL(at url: URL) -> AuditACLObservation {
        let descriptor = url.path.withCString { open($0, O_RDONLY | O_NONBLOCK | O_NOFOLLOW) }
        guard descriptor >= 0 else { return .problem(AuditProblem.fromErrno(errno).message) }
        defer { _ = close(descriptor) }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              metadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              metadata.st_size >= 0, metadata.st_size <= auditControlMaximumBytes else {
            return .problem("audit_control is missing, oversized, a symlink, or not a regular file.")
        }
        return inspectExtendedACL(descriptor)
    }

    private static func inspectDirectoryACL(at path: String) -> AuditACLObservation {
        let descriptor = path.withCString { open($0, O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW) }
        guard descriptor >= 0 else { return .problem(AuditProblem.fromErrno(errno).message) }
        defer { _ = close(descriptor) }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              metadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR) else {
            return .problem("The configured audit directory could not be safely identified.")
        }
        return inspectExtendedACL(descriptor)
    }

    private static func inspectExtendedACL(_ descriptor: Int32) -> AuditACLObservation {
        errno = 0
        guard let acl = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else {
            let code = errno
            // Darwin reports ENOENT for a valid file descriptor with no
            // extended ACL. Other errors are not evidence of ACL absence.
            if code == ENOENT { return .absent }
            return .problem(AuditProblem.fromErrno(code).message)
        }
        _ = acl_free(UnsafeMutableRawPointer(acl))
        return .present
    }

    private static func scanAuditFiles(at path: String, inspectACLs: Bool) -> AuditScan {
        var scan = AuditScan()
        let descriptor = path.withCString { open($0, O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW) }
        guard descriptor >= 0 else {
            scan.problems.append(.fromErrno(errno))
            return scan
        }
        defer { _ = close(descriptor) }
        var directoryMetadata = stat()
        guard fstat(descriptor, &directoryMetadata) == 0,
              directoryMetadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR) else {
            scan.problems.append(.ambiguous)
            return scan
        }
        let listingDescriptor = dup(descriptor)
        guard listingDescriptor >= 0, let directory = fdopendir(listingDescriptor) else {
            if listingDescriptor >= 0 { _ = close(listingDescriptor) }
            scan.problems.append(.fromErrno(errno))
            return scan
        }
        defer { _ = closedir(directory) }

        var seen = 0
        while true {
            errno = 0
            guard let entry = readdir(directory) else {
                if errno != 0 { scan.problems.append(.fromErrno(errno)) }
                break
            }
            let name = withUnsafePointer(to: entry.pointee.d_name) {
                $0.withMemoryRebound(to: CChar.self, capacity: Int(entry.pointee.d_namlen) + 1) {
                    String(cString: $0)
                }
            }
            if name == "." || name == ".." { continue }
            seen += 1
            guard seen <= auditFileMaximumCount else {
                scan.problems.append(.ambiguous)
                break
            }
            var fileMetadata = stat()
            let status = name.withCString { fstatat(descriptor, $0, &fileMetadata, AT_SYMLINK_NOFOLLOW) }
            guard status == 0 else {
                scan.problems.append(.fromErrno(errno))
                continue
            }
            let type = fileMetadata.st_mode & mode_t(S_IFMT)
            guard type == mode_t(S_IFREG) else {
                scan.problems.append(type == mode_t(S_IFLNK) ? .symlink : .ambiguous)
                continue
            }
            var observed = AuditMetadata(fileMetadata)
            if inspectACLs {
                let child = name.withCString { openat(descriptor, $0, O_RDONLY | O_NONBLOCK | O_NOFOLLOW) }
                guard child >= 0 else {
                    scan.problems.append(.fromErrno(errno))
                    continue
                }
                defer { _ = close(child) }
                var openedMetadata = stat()
                guard fstat(child, &openedMetadata) == 0,
                      openedMetadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
                      openedMetadata.st_dev == fileMetadata.st_dev,
                      openedMetadata.st_ino == fileMetadata.st_ino else {
                    scan.problems.append(.ambiguous)
                    continue
                }
                switch inspectExtendedACL(child) {
                case .present: observed.hasExtendedACL = true
                case .absent: observed.hasExtendedACL = false
                case .problem(let message):
                    scan.problems.append(message.contains("Permission was denied") ? .permissionDenied : .ambiguous)
                }
            }
            scan.files.append(observed)
        }
        if seen == 0 { scan.problems.append(.missing) }
        return scan
    }
}
