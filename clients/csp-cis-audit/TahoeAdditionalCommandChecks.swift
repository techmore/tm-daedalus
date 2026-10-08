import Foundation
import Darwin
import CoreFoundation

private final class AuthorizationKeyValidator: NSObject, XMLParserDelegate {
    var dictionaries = [Set<String>]()
    var key: String? = nil
    var valid = true
    var depth = 0
    func parser(_ parser: XMLParser, didStartElement elementName: String, namespaceURI: String?, qualifiedName qName: String?, attributes attributeDict: [String: String] = [:]) {
        depth += 1
        if depth > 32 || key != nil { valid = false; parser.abortParsing(); return }
        if elementName == "dict" { dictionaries.append([]) }
        if elementName == "key" {
            guard !dictionaries.isEmpty else { valid = false; parser.abortParsing(); return }
            key = ""
        }
    }
    func parser(_ parser: XMLParser, foundCharacters string: String) {
        if key != nil { key! += string; if key!.utf8.count > 256 { valid = false; parser.abortParsing() } }
    }
    func parser(_ parser: XMLParser, foundCDATA CDATABlock: Data) {
        guard let string = String(data: CDATABlock, encoding: .utf8) else { valid = false; parser.abortParsing(); return }
        self.parser(parser, foundCharacters: string)
    }
    func parser(_ parser: XMLParser, didEndElement elementName: String, namespaceURI: String?, qualifiedName qName: String?) {
        if elementName == "key", let value = key {
            if dictionaries.isEmpty || !dictionaries[dictionaries.count - 1].insert(value).inserted { valid = false; parser.abortParsing() }
            key = nil
        }
        if elementName == "dict", !dictionaries.isEmpty { dictionaries.removeLast() }
        depth -= 1
    }
}

extension MacOSChecks {
    // Static, read-only checks derived from NIST mSCP Tahoe rev3, commit
    // beceac1d21baf9d924c2780f2e248577435bbfb1 (CC BY 4.0).
    // The server supplies a rule ID; every executable and argument stays bundled.
    static let additionalMacOS26CommandRuleIDs: Set<String> = [
        "os_system_wide_applications_configure",
        "os_sudo_timeout_configure", "os_sudo_log_enforce", "os_sudoers_timestamp_type_configure",
        "pwpolicy_account_lockout_enforce", "pwpolicy_account_lockout_timeout_enforce", "pwpolicy_max_lifetime_enforce", "pwpolicy_minimum_length_enforce", "pwpolicy_history_enforce", "pwpolicy_alpha_numeric_enforce", "pwpolicy_special_character_enforce", "system_settings_system_wide_preferences_configure", "os_unlock_active_user_session_disable", "os_password_hint_remove", "os_home_folders_secure", "os_internal_apfs_volumes_encrypted", "audit_auditd_enabled", "os_anti_virus_installed", "os_guest_folder_removed", "os_nfsd_disable", "os_power_nap_disable",
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

    static let tahoeAuditFlagRequirements = [
        "audit_flags_aa_configure": "aa", "audit_flags_ad_configure": "ad",
        "audit_flags_lo_configure": "lo", "audit_flags_ex_configure": "-ex",
        "audit_flags_fm_failed_configure": "-fm", "audit_flags_fr_configure": "-fr",
        "audit_flags_fw_configure": "-fw"
    ]
    static let additionalMacOS26PolicyRuleIDs: Set<String> = Set(tahoeAuditFlagRequirements.keys).union(["audit_retention_configure"])

    static let additionalMacOS26RuleIDs = additionalMacOS26CommandRuleIDs
        .union(additionalMacOS26AuditEvidenceRuleIDs)
        .union(additionalMacOS26PolicyRuleIDs)

    static func authorizationPolicy(_ output: String) -> [String: Any]? {
        guard output.utf8.count <= 65536, !output.contains("<!ENTITY") else { return nil }
        let data = Data(output.utf8)
        let validator = AuthorizationKeyValidator()
        let parser = XMLParser(data: data)
        parser.shouldResolveExternalEntities = false
        parser.delegate = validator
        guard parser.parse(), validator.valid, validator.depth == 0, validator.dictionaries.isEmpty,
              let object = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
              let dictionary = object as? [String: Any] else { return nil }
        return dictionary
    }

    static func runAdditionalTahoeCommand(
        check: CISCheck,
        command: (String, [String]) -> CommandEvidence,
        legacyPasswordCriteria: Bool = false
    ) -> CheckResult {
        func result(_ status: String, _ detail: String) -> CheckResult {
            let prefix = legacyPasswordCriteria ? "Legacy CSP read-only account-policy check. " : "Pinned NIST mSCP Tahoe read-only check for \(check.ruleID ?? check.id). "
            return CheckResult(check: check, status: status, details: prefix + detail)
        }
        func usable(_ evidence: CommandEvidence, exits: Set<Int32> = [0]) -> Bool {
            evidence.unavailable == nil && exits.contains(evidence.exitCode)
                && evidence.error.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        }
        let rule = check.ruleID ?? ""
        switch rule {
        case "os_system_wide_applications_configure":
            // Match the pinned /Applications directory criterion without a
            // shell, following symlinks, collecting names or changing modes.
            // Fixed markers verify an actual directory root and all matches;
            // stderr/nonzero/timeout evidence never becomes a clean pass.
            let evidence = command("/usr/bin/find", ["-P", "/Applications",
                "(", "-path", "/Applications", "-type", "d", "-exec", "/usr/bin/printf", "root-directory\n", ";", ")",
                "-o", "(", "-iname", "*.app", "-type", "d", "-perm", "-2", "-exec", "/usr/bin/printf", "world-writable-application\n", ";", ")"])
            guard usable(evidence), evidence.output.utf8.count <= 65536,
                  evidence.output.hasSuffix("\n") else {
                return result("manual", "Application-directory traversal was unavailable, unsuccessful or incomplete. Application names were not collected into the report.")
            }
            let lines = evidence.output.components(separatedBy: "\n").dropLast()
            guard lines.filter({ $0 == "root-directory" }).count == 1,
                  lines.allSatisfy({ $0 == "root-directory" || $0 == "world-writable-application" }) else {
                return result("manual", "Application-directory evidence lacked a unique directory root or contained unsupported output. No clean permission result was inferred.")
            }
            let mismatches = lines.filter { $0 == "world-writable-application" }.count
            return result(mismatches == 0 ? "pass" : "fail", mismatches == 0
                ? "Completed bounded traversal found no world-writable application bundle directories under /Applications. Symlinks were not followed."
                : "Completed bounded traversal found \(mismatches) world-writable application bundle directory match(es) under /Applications. Names remain local; no permissions were changed.")

        case "os_sudo_timeout_configure", "os_sudo_log_enforce", "os_sudoers_timestamp_type_configure":
            // Version mode never executes a command or asks for a password.
            // Full effective policy is available only when the caller already
            // has the privileges sudo requires; the client does not elevate.
            let evidence = command("/usr/bin/sudo", ["-V"])
            guard usable(evidence), evidence.output.utf8.count <= 65536,
                  !evidence.output.unicodeScalars.contains(where: { $0.value == 0 || $0.value == 127 }) else {
                return result("manual", "Effective sudo policy was unavailable, unsuccessful or exceeded its capture limit. No privilege escalation was attempted.")
            }
            let lines = evidence.output.components(separatedBy: .newlines)
            let versions = lines.filter { $0.hasPrefix("Sudo version ") }
            let timeouts = lines.filter { $0.hasPrefix("Authentication timestamp timeout:") }
            let timestampTypes = lines.filter { $0.hasPrefix("Type of authentication timestamp record:") }
            guard versions.count == 1, versions[0].range(of: "^Sudo version [0-9]+(?:\\.[0-9]+){1,3}(?:p[0-9]+)?$", options: .regularExpression) != nil,
                  timeouts.count == 1, timestampTypes.count == 1,
                  timeouts[0].range(of: "^Authentication timestamp timeout: -?(?:0|[1-9][0-9]*)(?:\\.[0-9]+)? minutes$", options: .regularExpression) != nil else {
                return result("manual", "Complete supported effective sudo policy fields were not available. Version-only output, missing permissions or ambiguous fields require review.")
            }
            let timeoutText = timeouts[0].dropFirst("Authentication timestamp timeout: ".count).dropLast(" minutes".count)
            let timestampType = String(timestampTypes[0].dropFirst("Type of authentication timestamp record: ".count))
            guard let timeout = Double(timeoutText), timeout.isFinite,
                  ["tty", "global", "ppid", "kernel"].contains(timestampType) else {
                return result("manual", "Effective sudo policy contains an unsupported timeout or timestamp type; no compliance result was inferred.")
            }
            if rule == "os_sudo_timeout_configure" {
                return result(timeout == 0 ? "pass" : "fail", timeout == 0
                    ? "Effective authentication timeout matches the pinned zero-minute criterion."
                    : "Effective authentication timeout differs from the pinned zero-minute criterion.")
            }
            if rule == "os_sudoers_timestamp_type_configure" {
                return result(timestampType == "tty" ? "pass" : "fail", timestampType == "tty"
                    ? "Effective authentication timestamp record type matches the pinned tty criterion."
                    : "Effective authentication timestamp record type differs from the pinned tty criterion.")
            }
            let logging = lines.filter { $0 == "Log when a command is allowed by sudoers" }
            guard logging.count <= 1 else {
                return result("manual", "Effective sudo logging evidence is duplicated or ambiguous.")
            }
            return result(logging.count == 1 ? "pass" : "fail", logging.count == 1
                ? "Complete captured effective sudo policy explicitly enables allowed-command logging. Actual event delivery is not assessed."
                : "Complete captured effective sudo policy lacks the allowed-command logging flag required by the pinned check.")

        case "os_safari_advertising_privacy_protection_enable",
             "os_safari_open_safe_downloads_disable",
             "os_safari_prevent_cross-site_tracking_enable",
             "os_safari_show_full_website_address_enable",
             "os_safari_show_status_bar_enabled",
             "os_safari_warn_fraudulent_website_enable":
            return runManagedProfileSettingCheck(check: check, command: command)

        case "pwpolicy_alpha_numeric_enforce", "pwpolicy_special_character_enforce", "pwpolicy_history_enforce", "pwpolicy_minimum_length_enforce", "pwpolicy_max_lifetime_enforce", "pwpolicy_account_lockout_enforce", "pwpolicy_account_lockout_timeout_enforce":
            let evidence = command("/usr/bin/pwpolicy", ["-getaccountpolicies"])
            guard usable(evidence), evidence.output.utf8.count <= 65536 else {
                return result("manual", "Account-policy evidence was unavailable or exceeded its limit.")
            }
            var xml = evidence.output.trimmingCharacters(in: .whitespacesAndNewlines)
            if !xml.hasPrefix("<?xml") {
                let lines = xml.components(separatedBy: .newlines)
                guard lines.count > 1, lines[0] == "Getting global account policies" else {
                    return result("manual", "Account-policy output has an unsupported format.")
                }
                xml = lines.dropFirst().joined(separator: "\n")
            }
            guard let policy = authorizationPolicy(xml) else {
                return result("manual", "Account-policy XML could not be read unambiguously.")
            }
            if rule == "pwpolicy_alpha_numeric_enforce" {
                var identifiers = [String]()
                var invalid = false
                func visit(_ object: Any) {
                    if let dictionary = object as? [String: Any] {
                        if let raw = dictionary["policyIdentifier"] {
                            if let value = raw as? String, !value.isEmpty, value.utf8.count <= 4096 {
                                identifiers.append(value)
                            } else { invalid = true }
                        }
                        for value in dictionary.values { visit(value) }
                    } else if let values = object as? [Any] { values.forEach(visit) }
                }
                visit(policy)
                guard !invalid, !identifiers.isEmpty, identifiers.count <= 100 else {
                    return result("manual", "Typed bounded policy identifiers were absent or unsupported.")
                }
                let candidates = identifiers.filter { $0.contains("requireAlphanumeric") }
                guard candidates.count <= 1, candidates.allSatisfy({ $0 == "requireAlphanumeric" || $0.hasSuffix(".requireAlphanumeric") }) else {
                    return result("manual", "Numeric-character policy identifiers were duplicate or ambiguous.")
                }
                return result(candidates.count == 1 ? "pass" : "fail", "Captured the pinned numeric-character policy identifier criterion. This is identifier evidence, not a password-creation attempt or external directory enforcement claim. Raw policy is omitted.")
            }
            if rule == "pwpolicy_special_character_enforce" {
                guard let entries = policy["policyCategoryPasswordContent"] as? [[String: Any]],
                      !entries.isEmpty, entries.count <= 100 else {
                    return result("manual", "Explicit password-content policy entries were absent or unsupported.")
                }
                let expression = try! NSRegularExpression(pattern: #"^policyAttributePassword matches '\(\.\*\[\^a-zA-Z0-9\]\.\*\)\{(0|[1-9][0-9]{0,3}),?\}'$"#)
                var minima = [Int]()
                for entry in entries {
                    guard let content = entry["policyContent"] as? String, content.utf8.count <= 4096 else {
                        return result("manual", "Password-content policy was absent or wrongly typed.")
                    }
                    guard content.contains("[^a-zA-Z0-9]") else { continue }
                    let value = content.trimmingCharacters(in: .whitespacesAndNewlines)
                    let range = NSRange(value.startIndex..<value.endIndex, in: value)
                    guard let match = expression.firstMatch(in: value, range: range), match.range == range,
                          let capture = Range(match.range(at: 1), in: value), let minimum = Int(value[capture]) else {
                        return result("manual", "Special-character condition uses an unsupported or compound predicate.")
                    }
                    minima.append(minimum)
                }
                guard minima.count == 1 else {
                    return result("manual", "Exactly one explicit special-character condition was not available.")
                }
                return result(minima[0] >= 1 ? "pass" : "fail", "Captured one explicit special-character minimum of " + String(minima[0]) + "; pinned Level 2 minimum is 1. This is local policy evidence, not a password-creation attempt or external directory assessment. Raw policy is omitted.")
            }
            if rule == "pwpolicy_minimum_length_enforce" {
                guard let entries = policy["policyCategoryPasswordContent"] as? [[String: Any]],
                      !entries.isEmpty, entries.count <= 100 else {
                    return result("manual", "Explicit password-content policy entries were absent or unsupported.")
                }
                let expression = try! NSRegularExpression(pattern: #"^policyAttributePassword matches '\.\{(0|[1-9][0-9]{0,3}),\}'$"#)
                var lengths = [Int]()
                for entry in entries {
                    guard let content = entry["policyContent"] as? String,
                          content.utf8.count <= 4096 else {
                        return result("manual", "Password-content policy was absent or wrongly typed.")
                    }
                    let value = content.trimmingCharacters(in: .whitespacesAndNewlines)
                    let range = NSRange(value.startIndex..<value.endIndex, in: value)
                    guard let match = expression.firstMatch(in: value, range: range),
                          match.range == range, let capture = Range(match.range(at: 1), in: value),
                          let minimum = Int(value[capture]) else {
                        return result("manual", "Password-content policy uses an unsupported condition. Compound predicates were not inferred.")
                    }
                    lengths.append(minimum)
                }
                let maximum = lengths.max()!
                let threshold = legacyPasswordCriteria ? 8 : 15
                return result(maximum >= threshold ? "pass" : "fail", "Captured " + String(lengths.count) + " explicit minimum-length condition(s); strongest minimum " + String(maximum) + ", bundled threshold " + String(threshold) + ". This is local policy evidence, not a password-creation attempt or external directory assessment. Raw policy is omitted.")
            }
            if rule == "pwpolicy_account_lockout_enforce" || rule == "pwpolicy_account_lockout_timeout_enforce" {
                let attempts = rule == "pwpolicy_account_lockout_enforce"
                let key = attempts ? "policyAttributeMaximumFailedAuthentications" : "autoEnableInSeconds"
                var values = [Int]()
                var invalid = false
                func visit(_ object: Any) {
                    if let dictionary = object as? [String: Any] {
                        if let raw = dictionary[key] {
                            guard let number = raw as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
                                  number.doubleValue.isFinite, number.doubleValue >= 0,
                                  number.doubleValue <= 31536000, number.doubleValue == Double(number.intValue),
                                  !attempts || number.intValue > 0 else { invalid = true; return }
                            values.append(number.intValue)
                        }
                        for value in dictionary.values { visit(value) }
                    } else if let array = object as? [Any] { for value in array { visit(value) } }
                }
                visit(policy)
                guard !invalid, !values.isEmpty else {
                    return result("manual", "Explicit supported lockout policy values were absent or wrongly typed. Disabled or unavailable attempt limits were not inferred as enforced.")
                }
                let matches = attempts ? values.allSatisfy { $0 <= 5 } : values.allSatisfy { $0 >= 900 }
                return result(matches ? "pass" : "fail", "Captured " + String(values.count) + " lockout value(s), range " + String(values.min()!) + "–" + String(values.max()!) + (attempts ? " attempts; bundled maximum 5." : " seconds; pinned minimum 900 (15 minutes).") + " This is local policy evidence, not a failed-login attempt or external directory assessment. Raw policy is omitted.")
            }
            if rule == "pwpolicy_max_lifetime_enforce" {
                var ages = [Double]()
                var invalid = false
                func visit(_ object: Any) {
                    if let dictionary = object as? [String: Any] {
                        if let raw = dictionary["policyAttributeExpiresEveryNDays"] {
                            guard let number = raw as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
                                  number.doubleValue.isFinite, number.doubleValue > 0, number.doubleValue <= 10000 else { invalid = true; return }
                            ages.append(number.doubleValue)
                        }
                        for value in dictionary.values { visit(value) }
                    } else if let array = object as? [Any] { for value in array { visit(value) } }
                }
                visit(policy)
                guard !invalid, !ages.isEmpty else {
                    return result("manual", "Explicit supported positive password-lifetime values were absent or wrongly typed. A zero value was not interpreted as an enforced lifetime.")
                }
                let maximum = ages.max()!, threshold = legacyPasswordCriteria ? 90.0 : 365.0
                return result(maximum <= threshold ? "pass" : "fail", "Captured " + String(ages.count) + " lifetime value(s); longest " + String(maximum) + " days, bundled maximum " + String(threshold) + ". This is captured local policy evidence, not a recommendation to change password-rotation policy or an external directory assessment. Raw policy is omitted.")
            }
            var depths = [Int]()
            var invalid = false
            func visit(_ object: Any) {
                if let dictionary = object as? [String: Any] {
                    if let raw = dictionary["policyAttributePasswordHistoryDepth"] {
                        guard let number = raw as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
                              number.doubleValue.isFinite, number.doubleValue >= 0,
                              number.doubleValue <= 10000, number.doubleValue == Double(number.intValue) else { invalid = true; return }
                        depths.append(number.intValue)
                    }
                    for value in dictionary.values { visit(value) }
                } else if let array = object as? [Any] { for value in array { visit(value) } }
            }
            visit(policy)
            guard !invalid, !depths.isEmpty else {
                return result("manual", "Explicit supported password-history depths were absent or wrongly typed.")
            }
            let threshold = legacyPasswordCriteria ? 5 : 24
            return result(depths.allSatisfy { $0 >= threshold } ? "pass" : "fail",
                "Captured " + String(depths.count) + " history-depth value(s); minimum " + String(depths.min()!) + ", bundled threshold " + String(threshold) + ". This is global local-account policy evidence, not a password-reuse attempt or external directory assessment. Raw policy is omitted.")

        case "system_settings_system_wide_preferences_configure":
            let rights = ["system.preferences", "system.preferences.energysaver", "system.preferences.network", "system.preferences.printing", "system.preferences.sharing", "system.preferences.softwareupdate", "system.preferences.startupdisk", "system.preferences.timemachine"]
            let deadline = Date().addingTimeInterval(6)
            var unavailable = 0
            var mismatches = 0
            for (index, right) in rights.enumerated() {
                guard Date() < deadline else { unavailable += rights.count - index; break }
                let evidence = command("/usr/bin/security", ["-q", "authorizationdb", "read", right])
                guard usable(evidence), let policy = authorizationPolicy(evidence.output),
                      let shared = policy["shared"] as? NSNumber, CFGetTypeID(shared) == CFBooleanGetTypeID(),
                      let authenticate = policy["authenticate-user"] as? NSNumber, CFGetTypeID(authenticate) == CFBooleanGetTypeID(),
                      let owner = policy["session-owner"] as? NSNumber, CFGetTypeID(owner) == CFBooleanGetTypeID(),
                      let group = policy["group"] as? String else { unavailable += 1; continue }
                if shared.boolValue || !authenticate.boolValue || owner.boolValue || group != "admin" { mismatches += 1 }
            }
            if mismatches > 0 { return result("fail", "Explicit authorization policy mismatches were observed for " + String(mismatches) + " system-preference rights. Unavailable evidence count: " + String(unavailable) + ". No policy was changed.") }
            if unavailable > 0 { return result("manual", "Complete typed authorization evidence for all eight system-preference rights was unavailable. No successful policy was inferred.") }
            return result("pass", "All eight captured system-preference rights require authentication by the admin group with shared and session-owner authorization disabled. This is policy evidence, not a live interaction test.")

        case "os_unlock_active_user_session_disable":
            func rules(_ right: String) -> [String]? {
                let evidence = command("/usr/bin/security", ["-q", "authorizationdb", "read", right])
                guard usable(evidence), let dictionary = authorizationPolicy(evidence.output),
                      let values = dictionary["rule"] as? [String], values.count == 1,
                      let value = values.first, !value.isEmpty, value.utf8.count <= 128 else { return nil }
                return values
            }
            guard let initial = rules("system.login.screensaver")?.first else {
                return result("manual", "The screensaver authorization rule could not be read unambiguously.")
            }
            let selected: String
            if initial == "psso-screensaver" || initial == "psso-screensaver-mscp" {
                guard let nested = rules(initial)?.first else {
                    return result("manual", "The supported PSSO authorization rule could not be read unambiguously.")
                }
                selected = nested
            } else { selected = initial }
            if selected == "authenticate-session-owner" {
                return result("pass", "The captured authorization rule requires the session owner. This is policy evidence, not a live unlock test or complete smartcard/PSSO applicability assessment.")
            }
            if selected == "authenticate-session-owner-or-admin" {
                return result("fail", "The captured authorization rule permits the session owner or an administrator. No authorization settings were changed.")
            }
            return result("manual", "The captured authorization mechanism is unsupported; its policy was not inferred and its name is omitted.")

        case "os_password_hint_remove":
            let evidence = command("/usr/bin/dscl", [".", "-list", "/Users", "hint"])
            guard usable(evidence) else { return result("manual", "Local account hint enumeration was unavailable; no hint content is uploaded.") }
            let lines = evidence.output.components(separatedBy: .newlines).filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
            guard !lines.isEmpty, lines.count <= 10000 else { return result("manual", "Local account enumeration was empty or exceeded the account limit.") }
            var accounts = Set<String>()
            var hints = 0
            for line in lines {
                let parts = line.split(whereSeparator: { $0.isWhitespace })
                guard let name = parts.first,
                      name.range(of: "^[A-Za-z0-9_.-]+$", options: .regularExpression) != nil,
                      accounts.insert(String(name)).inserted else {
                    return result("manual", "Local account enumeration was ambiguous or unsupported; no account names or hints are uploaded.")
                }
                if parts.count > 1 { hints += 1 }
            }
            return result(hints == 0 ? "pass" : "fail", "Enumerated " + String(accounts.count) + " local account records; " + String(hints) + " contain hint text. This does not establish external directory account policy. Account names and hint text are omitted.")

        case "os_home_folders_secure":
            let evidence = command("/usr/bin/find", ["/System/Volumes/Data/Users", "-mindepth", "1", "-maxdepth", "1", "-type", "d", "!", "-name", "*Shared*", "!", "-name", "*Guest*", "-exec", "/usr/bin/stat", "-f", "%HT:%Lp", "{}", "+"])
            guard usable(evidence), evidence.output.utf8.count <= 65536 else {
                return result("manual", "Home-directory metadata was inaccessible, incomplete or exceeded its limit.")
            }
            let lines = evidence.output.components(separatedBy: .newlines).filter { !$0.isEmpty }
            guard !lines.isEmpty, lines.count <= 10000 else {
                return result("manual", "No eligible home directories were captured, or enumeration exceeded its limit.")
            }
            var mismatches = 0
            for line in lines {
                let parts = line.components(separatedBy: ":")
                guard parts.count == 2, parts[0] == "Directory",
                      parts[1].range(of: "^[0-7]{3,4}$", options: .regularExpression) != nil,
                      let mode = UInt16(parts[1], radix: 8) else {
                    return result("manual", "Captured home-directory metadata was malformed or unsupported.")
                }
                if mode != 0o700 && mode != 0o711 { mismatches += 1 }
            }
            return result(mismatches == 0 ? "pass" : "fail", "Captured " + String(lines.count) + " eligible direct user directories; " + String(mismatches) + " differ from pinned modes 0700/0711. Shared/Guest-name exclusions follow the pinned procedure. This does not assess ACLs, directory accounts or home contents. Directory names remain local.")

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

    static func checkTahoeAuditFlag(check: CISCheck, readControl: (URL) -> Data? = readAuditControl) -> CheckResult {
        func result(_ status: String, _ detail: String) -> CheckResult {
            CheckResult(check: check, status: status, details: "Pinned Tahoe audit flag configuration. " + detail + " This does not verify active kernel auditing or retained events. Raw configuration remains local.")
        }
        guard let required = tahoeAuditFlagRequirements[check.ruleID ?? ""],
              let data = readControl(URL(fileURLWithPath: "/etc/security/audit_control")),
              data.count <= auditControlMaximumBytes,
              let text = String(data: data, encoding: .utf8), !text.contains("\0") else {
            return result("manual", "Required policy evidence is missing, inaccessible or unsupported.")
        }
        let lines = text.components(separatedBy: .newlines).map { $0.components(separatedBy: "#")[0].trimmingCharacters(in: .whitespaces) }
        guard !lines.contains(where: { $0.range(of: "^flags(?:[ \t]|$)", options: .regularExpression) != nil }),
              let field = MacOSSystemChecks.auditPolicyField("flags", readControl: { _ in data }) else {
            return result("manual", "The flags field is missing, malformed or duplicated.")
        }
        let tokens = field.components(separatedBy: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        let known: Set<String> = ["no", "fr", "fw", "fa", "fm", "fc", "fd", "cl", "pc", "nt", "ip", "na", "ad", "lo", "aa", "ap", "res", "io", "ex", "ot"]
        var classes = Set<String>()
        for token in tokens {
            let name = token.hasPrefix("-") || token.hasPrefix("+") ? String(token.dropFirst()) : token
            guard known.contains(name), classes.insert(name).inserted else {
                return result("manual", "Unknown, duplicate, conflicting or combined selections require review.")
            }
        }
        if tokens.contains(required) { return result("pass", "The exact bundled selection is present.") }
        if required.hasPrefix("-"), tokens.contains(String(required.dropFirst())) {
            return result("manual", "A broader event selection is present; the pinned failure-only selection needs review.")
        }
        return result("fail", "The required bundled event selection is absent from the captured explicit flags.")
    }

    // Shared with the legacy CSP auditing check; never infer success from an error mentioning auditd.
    static func checkTahoeAuditRetention(
        check: CISCheck,
        readControl: (URL) -> Data? = readAuditControl
    ) -> CheckResult {
        func result(_ status: String, _ detail: String) -> CheckResult {
            CheckResult(check: check, status: status, details: "Pinned CIS Tahoe retention policy check. " + detail)
        }
        guard let value = MacOSSystemChecks.auditPolicyField("expire-after", readControl: readControl) else {
            return result("manual", "Audit expiration is missing, duplicated or inaccessible; no duration was inferred.")
        }
        if value == "30d" {
            return result("pass", "The age-only expiration matches the pinned CIS value of 30d. This does not verify retained records or central storage.")
        }
        guard value.range(of: "^[0-9]{1,12}[shdy]$", options: .regularExpression) != nil,
              let number = Double(value.dropLast()), let unit = value.last else {
            return result("manual", "The policy is combined, unsupported or noncanonical and needs review against the pinned 30d value.")
        }
        let units: [Character: Double] = ["s":1, "h":3600, "d":86400, "y":31536000]
        let days = number * (units[unit] ?? 0) / 86400
        if days < 30 {
            return result("fail", "The explicit age-only expiration is shorter than the pinned 30-day CIS value. Central retention exceptions require separate review.")
        }
        return result("manual", "This age-only policy differs from the pinned literal 30d value; review the alternative retention policy. No shortened retention was inferred.")
    }

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
