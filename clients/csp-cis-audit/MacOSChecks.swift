import Foundation
import Darwin
import CoreFoundation

// Main coordinator for macOS checks that delegates to specialized modules
struct MacOSChecks {
    static func run(check: CISCheck) -> CheckResult {
        guard check.ruleID != nil else { return runLegacy(check: check) }
        return runTahoe(check: check, osMajorVersion: ProcessInfo.processInfo.operatingSystemVersion.majorVersion) {
            suite, key in UserDefaults(suiteName: suite)?.object(forKey: key)
        }
    }

    static func legacyBooleanPreference(
        check: CISCheck, domain: String, key: String, expected: Bool,
        command: (String, [String]) -> CommandEvidence = readCommand
    ) -> CheckResult {
        let evidence = command("/usr/bin/defaults", ["read", domain, key])
        let value = evidence.output.trimmingCharacters(in: .whitespacesAndNewlines)
        guard evidence.unavailable == nil, evidence.exitCode == 0,
              evidence.error.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              value == "0" || value == "1" else {
            return CheckResult.unavailablePreference(check: check, detail: "An explicit macOS Boolean preference could not be read for " + key + ".")
        }
        let observed = value == "1"
        return CheckResult(check: check, status: observed == expected ? "pass" : "fail",
            details: key + " explicitly reads " + (observed ? "enabled" : "disabled") + ". This check expects " + (expected ? "enabled" : "disabled") + ". This is local preference evidence; managed enforcement for every user was not established.")
    }

    enum PreferenceValue {
        case boolean(Bool)
        case integer(Int)
        case integerExcluding(Int)
        case integerRange(ClosedRange<Int>)
        case numberRange(ClosedRange<Double>)
        case string(String)
        case dateAgeDays(Int)
    }

    struct PreferenceExpectation {
        let suite: String
        let key: String
        let value: PreferenceValue
        var currentHost = false
        var systemPath: String? = nil

        init(_ suite: String, _ key: String, _ expected: Bool) {
            self.suite = suite; self.key = key; self.value = .boolean(expected)
        }
        init(_ suite: String, _ key: String, integer: Int) {
            self.suite = suite; self.key = key; self.value = .integer(integer)
        }
        init(_ suite: String, _ key: String, range: ClosedRange<Double>) {
            self.suite = suite; self.key = key; self.value = .numberRange(range)
        }
        init(_ suite: String, _ key: String, string: String) {
            self.suite = suite; self.key = key; self.value = .string(string)
        }
        init(_ suite: String, _ key: String, integerExcluding: Int) {
            self.suite = suite; self.key = key; self.value = .integerExcluding(integerExcluding)
        }
        init(_ suite: String, _ key: String, integerRange: ClosedRange<Int>) {
            self.suite = suite; self.key = key; self.value = .integerRange(integerRange)
        }
        init(_ suite: String, _ key: String, hostBoolean: Bool) {
            self.suite = suite; self.key = key; self.value = .boolean(hostBoolean); self.currentHost = true
        }
        init(systemPath: String, key: String, boolean: Bool) {
            self.suite = systemPath; self.key = key; self.value = .boolean(boolean); self.systemPath = systemPath
        }
        init(systemPath: String, key: String, maximumAgeDays: Int) {
            self.suite = systemPath; self.key = key; self.value = .dateAgeDays(maximumAgeDays); self.systemPath = systemPath
        }
    }

    // Static read-only expectations derived from NIST mSCP Tahoe rev3, commit
    // beceac1d21baf9d924c2780f2e248577435bbfb1 (CC BY 4.0).
    // These match the source NSUserDefaults suite/key checks. Remote profiles
    // select a known rule ID; they cannot supply executable code or preferences.
    static let macOS26PreferenceRules: [String: [PreferenceExpectation]] = [
        "system_settings_location_services_menu_enforce": [.init(systemPath: "/Library/Preferences/com.apple.locationmenu.plist", key: "ShowSystemServices", boolean: true)],
        "system_settings_softwareupdate_current": [.init(systemPath: "/Library/Preferences/com.apple.SoftwareUpdate.plist", key: "LastFullSuccessfulDate", maximumAgeDays: 30)],
        // Apple documents idleTime=0 as never activating. The source discussion
        // requires activation within 900 seconds; a disabled timer cannot satisfy it.
        // https://developer.apple.com/documentation/devicemanagement/screensaveruser
        "system_settings_screensaver_timeout_enforce": [.init("com.apple.screensaver", "idleTime", integerRange: 1...900)],
        "system_settings_hot_corners_secure": [
            .init("com.apple.dock", "wvous-bl-corner", integerExcluding: 6),
            .init("com.apple.dock", "wvous-tl-corner", integerExcluding: 6),
            .init("com.apple.dock", "wvous-tr-corner", integerExcluding: 6),
            .init("com.apple.dock", "wvous-br-corner", integerExcluding: 6)
        ],
        "os_on_device_dictation_enforce": [.init("com.apple.applicationaccess", "forceOnDeviceOnlyDictation", true)],
        "system_settings_bluetooth_sharing_disable": [.init("com.apple.Bluetooth", "PrefKeyServicesEnabled", hostBoolean: false)],
        "system_settings_improve_search_disable": [.init("com.apple.assistant.support", "Search Queries Data Sharing Status", integer: 2)],
        "system_settings_improve_siri_dictation_disable": [.init("com.apple.assistant.support", "Siri Data Sharing Opt-In Status", integer: 2)],
        "system_settings_time_server_enforce": [.init("com.apple.timed", "TMAutomaticTimeOnlyEnabled", true)],
        "icloud_sync_disable": [.init("com.apple.applicationaccess", "allowCloudDesktopAndDocuments", false)],
        "os_bonjour_disable": [.init("com.apple.mDNSResponder", "NoMulticastAdvertisements", true)],
        "system_settings_content_caching_disable": [.init("com.apple.applicationaccess", "allowContentCaching", false)],
        "system_settings_media_sharing_disabled": [
            .init("com.apple.applicationaccess", "allowMediaSharing", false),
            .init("com.apple.applicationaccess", "allowMediaSharingModification", false)
        ],
        "system_settings_time_machine_auto_backup_enable": [.init("com.apple.TimeMachine", "AutoBackup", true)],
        // Pinned source ODV cis_lvl1 and cis_lvl2 agree for these three rules.
        "system_settings_time_server_configure": [.init("com.apple.MCX", "timeServer", string: "time.apple.com")],
        "system_settings_screensaver_ask_for_password_delay_enforce": [.init("com.apple.screensaver", "askForPasswordDelay", range: 0...5)],
        "os_software_update_deferral": [.init("com.apple.applicationaccess", "enforcedSoftwareUpdateDelay", range: 0...30)],
        "os_config_data_install_enforce": [.init("com.apple.SoftwareUpdate", "ConfigDataInstall", true)],
        "os_mail_summary_disable": [.init("com.apple.applicationaccess", "allowMailSummary", false)],
        "os_notes_transcription_disable": [.init("com.apple.applicationaccess", "allowNotesTranscription", false)],
        "os_notes_transcription_summary_disable": [.init("com.apple.applicationaccess", "allowNotesTranscriptionSummary", false)],
        "os_writing_tools_disable": [.init("com.apple.applicationaccess", "allowWritingTools", false)],
        "system_settings_external_intelligence_disable": [.init("com.apple.applicationaccess", "allowExternalIntelligenceIntegrations", false)],
        "system_settings_external_intelligence_sign_in_disable": [.init("com.apple.applicationaccess", "allowExternalIntelligenceIntegrationsSignIn", false)],
        "system_settings_personalized_advertising_disable": [.init("com.apple.applicationaccess", "allowApplePersonalizedAdvertising", false)],
        "system_settings_improve_assistive_voice_disable": [.init("com.apple.Accessibility", "AXSAudioDonationSiriImprovementEnabled", false)],
        "system_settings_loginwindow_prompt_username_password_enforce": [.init("com.apple.loginwindow", "SHOWFULLNAME", true)],
        "os_airdrop_disable": [.init("com.apple.applicationaccess", "allowAirDrop", false)],
        "os_gatekeeper_enable": [.init("com.apple.systempolicy.control", "EnableAssessment", true)],
        "os_terminal_secure_keyboard_enable": [.init("com.apple.Terminal", "SecureKeyboardEntry", true)],
        "os_software_update_app_update_enforce": [.init("com.apple.SoftwareUpdate", "AutomaticallyInstallAppUpdates", true)],
        "system_settings_airplay_receiver_disable": [.init("com.apple.applicationaccess", "allowAirPlayIncomingRequests", false)],
        "system_settings_automatic_login_disable": [.init("com.apple.loginwindow", "com.apple.login.mcx.DisableAutoLoginClient", true)],
        "system_settings_critical_update_install_enforce": [.init("com.apple.SoftwareUpdate", "CriticalUpdateInstall", true)],
        "system_settings_diagnostics_reports_disable": [
            .init("com.apple.SubmitDiagInfo", "AutoSubmit", false),
            .init("com.apple.applicationaccess", "allowDiagnosticSubmission", false)
        ],
        "system_settings_firewall_enable": [.init("com.apple.security.firewall", "EnableFirewall", true)],
        "system_settings_firewall_stealth_mode_enable": [.init("com.apple.security.firewall", "EnableStealthMode", true)],
        "system_settings_guest_account_disable": [
            .init("com.apple.MCX", "DisableGuestAccount", true),
            .init("com.apple.MCX", "EnableGuestAccount", false)
        ],
        "system_settings_install_macos_updates_enforce": [.init("com.apple.SoftwareUpdate", "AutomaticallyInstallMacOSUpdates", true)],
        "system_settings_internet_sharing_disable": [.init("com.apple.MCX", "forceInternetSharingOff", true)],
        "system_settings_password_hints_disable": [.init("com.apple.loginwindow", "RetriesUntilHint", integer: 0)],
        "system_settings_screensaver_password_enforce": [.init("com.apple.screensaver", "askForPassword", true)],
        "system_settings_siri_disable": [.init("com.apple.applicationaccess", "allowAssistant", false)],
        "system_settings_software_update_download_enforce": [.init("com.apple.SoftwareUpdate", "AutomaticDownload", true)]
    ]

    // ARM-native binaries establish Apple Silicon applicability. Intel or Rosetta
    // builds do not establish the underlying hardware, so keep those manual.
    static var localAppleSiliconEvidence: Bool? {
        #if arch(arm64)
        return true
        #else
        return nil
        #endif
    }

    static func readCurrentHostPreference(_ suite: String, _ key: String) -> Any? {
        CFPreferencesCopyValue(key as CFString, suite as CFString, kCFPreferencesCurrentUser, kCFPreferencesCurrentHost)
    }

    // Only the bundled fixed paths above use this reader. Bound the file before
    // parsing; inaccessible, oversized and invalid plists supply no evidence.
    static func readSystemPlistPreference(_ path: String, _ key: String) -> Any? {
        let descriptor = Darwin.open(path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW)
        guard descriptor >= 0 else { return nil }
        let file = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        defer { try? file.close() }
        var metadata = stat()
        guard Darwin.fstat(descriptor, &metadata) == 0,
              metadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              metadata.st_size >= 0, metadata.st_size <= 1_048_576 else { return nil }
        guard let data = try? file.read(upToCount: 1_048_577), data.count <= 1_048_576,
              let dictionary = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any] else { return nil }
        return dictionary[key]
    }

    static var auditCalendar: Calendar {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = .current
        return calendar
    }

    static func datePreference(_ raw: Any?) -> Date? {
        if let date = raw as? Date { return date }
        guard let text = raw as? String, text.utf8.count <= 40 else { return nil }
        // defaults prints NSDate as the first format. Also accept explicit ISO
        // timestamps or a strict date-only value, never arbitrary date guesses.
        let formats = [
            ("^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} [+-][0-9]{4}$", "yyyy-MM-dd HH:mm:ss Z"),
            ("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$", "yyyy-MM-dd'T'HH:mm:ss'Z'"),
            ("^[0-9]{4}-[0-9]{2}-[0-9]{2}$", "yyyy-MM-dd")
        ]
        for (pattern, format) in formats where text.range(of: pattern, options: .regularExpression) != nil {
            let formatter = DateFormatter()
            formatter.locale = Locale(identifier: "en_US_POSIX")
            formatter.calendar = Calendar(identifier: .gregorian)
            formatter.timeZone = TimeZone(secondsFromGMT: 0)
            formatter.dateFormat = format; formatter.isLenient = false
            return formatter.date(from: text)
        }
        return nil
    }

    // Injectable evidence lets tests validate outcomes without inspecting this Mac.
    static func runTahoe(
        check: CISCheck,
        osMajorVersion: Int,
        command: (String, [String]) -> CommandEvidence = readCommand,
        appleSilicon: Bool? = localAppleSiliconEvidence,
        readHostPreference: (String, String) -> Any? = readCurrentHostPreference,
        readSystemPreference: (String, String) -> Any? = readSystemPlistPreference,
        readAuditPolicy: (URL) -> Data? = readAuditControl,
        now: Date = Date(),
        calendar: Calendar = auditCalendar,
        readPreference: (String, String) -> Any?
    ) -> CheckResult {
        guard osMajorVersion == 26 else {
            return CheckResult(check: check, status: "manual", details: "This profile targets macOS 26.0; the local CSP check was not run on this OS version.")
        }
        if check.ruleID == "audit_retention_configure" {
            return checkTahoeAuditRetention(check: check, readControl: readAuditPolicy)
        }
        if let ruleID = check.ruleID, additionalMacOS26RuleIDs.contains(ruleID) {
            return runAdditionalTahoeCommand(check: check, command: command)
        }
        if let ruleID = check.ruleID, macOS26CommandRuleIDs.contains(ruleID) {
            return runTahoeCommand(check: check, readPreference: readPreference, command: command)
        }
        guard let ruleID = check.ruleID, let expectations = macOS26PreferenceRules[ruleID] else {
            return CheckResult(check: check, status: "manual", details: "No validated bundled read-only CSP implementation is available for mSCP rule \(check.ruleID ?? check.id).")
        }
        if ruleID == "os_on_device_dictation_enforce", appleSilicon != true {
            return CheckResult(check: check, status: "manual", details: "Pinned NIST rule applies only to Apple Silicon. Hardware applicability is absent or does not match; no preference was inspected.")
        }
        var evidence: [String] = []
        var unavailable: [String] = []
        var mismatches: [String] = []
        for expectation in expectations {
            let label = "\(expectation.suite)/\(expectation.key)"
            let raw: Any?
            if let path = expectation.systemPath { raw = readSystemPreference(path, expectation.key) }
            else if expectation.currentHost { raw = readHostPreference(expectation.suite, expectation.key) }
            else { raw = readPreference(expectation.suite, expectation.key) }
            var matches: Bool
            switch expectation.value {
            case .string(let expected):
                guard let actual = raw as? String else { unavailable.append(label); continue }
                matches = actual == expected
                // Do not copy arbitrary preference text into an uploaded report.
                evidence.append("\(label) matches bundled expected string=\(matches)")
            case .boolean(let expected):
                guard let number = raw as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() else {
                    unavailable.append(label); continue
                }
                matches = number.boolValue == expected
                evidence.append("\(label)=\(number.boolValue)")
            case .integer(let expected):
                guard let number = raw as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
                      number.doubleValue.isFinite, number.doubleValue == Double(number.intValue) else {
                    unavailable.append(label); continue
                }
                matches = number.intValue == expected
                evidence.append("\(label)=\(number.intValue)")
            case .integerExcluding(let excluded):
                guard let number = raw as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
                      number.doubleValue.isFinite, number.doubleValue == Double(number.intValue), number.intValue >= 0 else {
                    unavailable.append(label); continue
                }
                matches = number.intValue != excluded
                evidence.append("\(label)=\(number.intValue), prohibited \(excluded)")
            case .integerRange(let range):
                guard let number = raw as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
                      number.doubleValue.isFinite, number.doubleValue == Double(number.intValue) else {
                    unavailable.append(label); continue
                }
                matches = range.contains(number.intValue)
                evidence.append("\(label)=\(number.intValue), required \(range.lowerBound)...\(range.upperBound)")
            case .dateAgeDays(let maximum):
                guard let date = datePreference(raw), date.timeIntervalSince1970.isFinite,
                      date <= now, let age = calendar.dateComponents([.day], from: calendar.startOfDay(for: date), to: calendar.startOfDay(for: now)).day, age >= 0 else {
                    unavailable.append(label); continue
                }
                matches = age <= maximum
                evidence.append("\(label) is \(age) calendar days old; pinned CIS maximum \(maximum) days. This is recorded update-check evidence, not proof that every available patch was installed.")
            case .numberRange(let range):
                guard let number = raw as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(), number.doubleValue.isFinite else {
                    unavailable.append(label); continue
                }
                matches = range.contains(number.doubleValue)
                evidence.append("\(label)=\(number.doubleValue), required \(range.lowerBound)...\(range.upperBound)")
            }
            if !matches { mismatches.append(label) }
        }
        let prefix = "Pinned NIST mSCP Tahoe preference check for \(ruleID). "
        // A known mismatch fails even when another required value is unavailable.
        if !mismatches.isEmpty {
            return CheckResult(check: check, status: "fail", details: prefix + "Expected preference value differs: " + mismatches.joined(separator: ", ") + ". " + evidence.joined(separator: "; "))
        }
        if !unavailable.isEmpty {
            return CheckResult(check: check, status: "manual", details: prefix + "Required preference evidence is absent or has an unsupported type: " + unavailable.joined(separator: ", ") + ". Review the managed settings and effective user scope.")
        }
        return CheckResult(check: check, status: "pass", details: prefix + "All required values match in the current client user scope. " + evidence.joined(separator: "; "))
    }

    struct CommandEvidence {
        let output: String
        let error: String
        let exitCode: Int32
        let unavailable: String?
        init(output: String = "", error: String = "", exitCode: Int32 = 0, unavailable: String? = nil) {
            self.output = output; self.error = error; self.exitCode = exitCode; self.unavailable = unavailable
        }
    }

    // A profile selects these bundled IDs, never a path or command supplied by a server.
    static let macOS26CommandRuleIDs: Set<String> = [
        "os_sip_enable", "os_authenticated_root_enable", "os_mobile_file_integrity_enable",
        "os_root_disable", "system_settings_filevault_enforce", "system_settings_printer_sharing_disable",
        "system_settings_remote_management_disable", "system_settings_smbd_disable", "system_settings_rae_disable",
        "system_settings_screen_sharing_disable", "system_settings_ssh_disable", "os_tftpd_disable",
        "os_uucp_disable", "os_httpd_disable"
    ]

    private final class CommandOutputBuffer: @unchecked Sendable {
        private let lock = NSLock()
        private var streams = [Data(), Data()]
        private var exceeded = false
        func append(_ chunk: Data, stream: Int) -> Bool {
            lock.lock(); defer { lock.unlock() }
            let remaining = max(0, 65536 - streams[stream].count)
            streams[stream].append(chunk.prefix(remaining))
            if chunk.count > remaining { exceeded = true }
            return exceeded
        }
        func snapshot() -> (String, String, Bool) {
            lock.lock(); defer { lock.unlock() }
            return (String(decoding: streams[0], as: UTF8.self), String(decoding: streams[1], as: UTF8.self), exceeded)
        }
    }

    // No shell, no sudo, bounded output and wall time. stdout/stderr stay distinct so
    // permission errors cannot be mistaken for an absent setting or disabled service.
    static let commandTimeoutSeconds: Double = 3

    static func readCommand(_ path: String, _ arguments: [String]) -> CommandEvidence {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: path); task.arguments = arguments
        let stdout = Pipe(); let stderr = Pipe()
        task.standardOutput = stdout; task.standardError = stderr
        task.standardInput = FileHandle.nullDevice
        task.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"]
        let completed = DispatchSemaphore(value: 0)
        task.terminationHandler = { _ in completed.signal() }
        do { try task.run() } catch {
            return CommandEvidence(unavailable: "Bundled system tool could not be started: \(error.localizedDescription)")
        }
        let buffer = CommandOutputBuffer(); let readers = DispatchGroup()
        for (index, pipe) in [stdout, stderr].enumerated() {
            readers.enter()
            DispatchQueue.global(qos: .utility).async {
                defer { readers.leave() }
                while let chunk = try? pipe.fileHandleForReading.read(upToCount: 4096), !chunk.isEmpty {
                    if buffer.append(chunk, stream: index) {
                        if task.isRunning { Darwin.kill(task.processIdentifier, SIGKILL) }
                        break
                    }
                }
            }
        }
        let timedOut = completed.wait(timeout: .now() + commandTimeoutSeconds) == .timedOut
        if timedOut {
            task.terminate()
            if completed.wait(timeout: .now() + 0.5) == .timedOut {
                Darwin.kill(task.processIdentifier, SIGKILL)
                _ = completed.wait(timeout: .now() + 0.5)
            }
        }
        let drained = readers.wait(timeout: .now() + 1) == .success
        if !drained {
            try? stdout.fileHandleForReading.close(); try? stderr.fileHandleForReading.close()
        }
        let (output, error, outputExceeded) = buffer.snapshot()
        if timedOut || !drained || outputExceeded {
            return CommandEvidence(output: output, error: error, unavailable: "System tool exceeded the time or output limit; evidence is incomplete.")
        }
        return CommandEvidence(output: output, error: error, exitCode: task.terminationStatus)
    }

    static func runTahoeCommand(
        check: CISCheck, readPreference: (String, String) -> Any?,
        command: (String, [String]) -> CommandEvidence
    ) -> CheckResult {
        func result(_ status: String, _ detail: String) -> CheckResult {
            CheckResult(check: check, status: status, details: "Pinned NIST mSCP Tahoe read-only check for \(check.ruleID ?? check.id). " + detail)
        }
        func usable(_ evidence: CommandEvidence) -> Bool {
            evidence.unavailable == nil && evidence.exitCode == 0 && evidence.error.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        }
        func unavailable(_ evidence: CommandEvidence) -> CheckResult {
            result("manual", evidence.unavailable ?? "System tool did not provide successful, unambiguous evidence (exit \(evidence.exitCode)). Permissions, tool availability, or unexpected output require review.")
        }
        let rule = check.ruleID ?? ""
        switch rule {
        case "os_sip_enable":
            let evidence = command("/usr/bin/csrutil", ["status"])
            guard usable(evidence) else { return unavailable(evidence) }
            let text = evidence.output.trimmingCharacters(in: .whitespacesAndNewlines)
            if text == "System Integrity Protection status: enabled." { return result("pass", text) }
            if text.hasPrefix("System Integrity Protection status: disabled.") || text.hasPrefix("System Integrity Protection status: unknown (Custom Configuration).") {
                return result("fail", "SIP is disabled or configured with exceptions; the source requires the fully enabled status.")
            }
            return result("manual", "Unrecognized csrutil status output.")
        case "os_authenticated_root_enable":
            let evidence = command("/sbin/mount", [])
            guard usable(evidence) else { return unavailable(evidence) }
            let roots = evidence.output.components(separatedBy: .newlines).filter { $0.contains(" on / (") }
            guard roots.count == 1, let root = roots.first, root.hasSuffix(")") else { return result("manual", "Exactly one root filesystem mount could not be identified.") }
            let flags = root.components(separatedBy: " on / (")[1].dropLast().split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
            return result(flags.contains("sealed") ? "pass" : "fail", "Root mount flags: " + flags.joined(separator: ", "))
        case "os_mobile_file_integrity_enable":
            let evidence = command("/usr/sbin/nvram", ["-p"])
            guard usable(evidence) else { return unavailable(evidence) }
            guard !evidence.output.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return result("manual", "No NVRAM enumeration evidence was returned.") }
            return result(evidence.output.contains("amfi_get_out_of_my_way=1") ? "fail" : "pass", "The NIST source checks the NVRAM AMFI bypass marker; this does not attest to all runtime code-integrity protections.")
        case "os_root_disable":
            let evidence = command("/usr/bin/dscl", ["/Local/Default", "read", "/Users/root", "AuthenticationAuthority"])
            if evidence.unavailable == nil && evidence.output.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && evidence.error.trimmingCharacters(in: .whitespacesAndNewlines) == "No such key: AuthenticationAuthority" {
                return result("pass", "The root record has no AuthenticationAuthority attribute.")
            }
            guard usable(evidence) else { return unavailable(evidence) }
            guard evidence.output.hasPrefix("AuthenticationAuthority:") else { return result("manual", "Unrecognized directory record output.") }
            return result("fail", "The root record has an AuthenticationAuthority attribute.")
        case "system_settings_filevault_enforce":
            let pref = readPreference("com.apple.MCX", "dontAllowFDEDisable") as? NSNumber
            let known = pref.map { CFGetTypeID($0) == CFBooleanGetTypeID() } ?? false
            let evidence = command("/usr/bin/fdesetup", ["status"])
            if known && pref?.boolValue == false { return result("fail", "dontAllowFDEDisable is explicitly false; FileVault disabling is not prohibited.") }
            guard usable(evidence) else { return unavailable(evidence) }
            let lines = evidence.output.components(separatedBy: .newlines)
            if lines.contains("FileVault is Off.") { return result("fail", "FileVault is Off.") }
            guard lines.contains("FileVault is On."), known else { return result("manual", "FileVault status or the required dontAllowFDEDisable managed Boolean is unavailable; conversion in progress needs review.") }
            return result("pass", "FileVault is On and dontAllowFDEDisable is explicitly true.")
        case "system_settings_printer_sharing_disable":
            let evidence = command("/usr/sbin/cupsctl", [])
            guard usable(evidence) else { return unavailable(evidence) }
            let values = evidence.output.components(separatedBy: .newlines).filter { $0.hasPrefix("_share_printers=") }
            guard values.count == 1 else { return result("manual", "Printer sharing evidence is absent or ambiguous.") }
            if values[0] == "_share_printers=0" { return result("pass", "CUPS printer sharing is disabled.") }
            if values[0] == "_share_printers=1" { return result("fail", "CUPS printer sharing is enabled.") }
            return result("manual", "Unrecognized CUPS printer sharing value.")
        case "system_settings_remote_management_disable":
            let evidence = command("/usr/libexec/mdmclient", ["QuerySecurityInfo"])
            guard usable(evidence) else { return unavailable(evidence) }
            let values = evidence.output.components(separatedBy: .newlines).map { $0.trimmingCharacters(in: .whitespaces) }.filter { $0.hasPrefix("RemoteDesktopEnabled = ") }
            guard values.count == 1 else { return result("manual", "RemoteDesktopEnabled security information is absent or ambiguous.") }
            if values[0] == "RemoteDesktopEnabled = 0;" { return result("pass", "Remote desktop is disabled in local security information.") }
            if values[0] == "RemoteDesktopEnabled = 1;" { return result("fail", "Remote desktop is enabled in local security information.") }
            return result("manual", "Unrecognized remote desktop security information.")
        default:
            let disabledRules = ["system_settings_smbd_disable": "com.apple.smbd", "system_settings_rae_disable": "com.apple.AEServer"]
            let inactiveRules = ["system_settings_screen_sharing_disable": "com.apple.screensharing", "system_settings_ssh_disable": "com.openssh.sshd", "os_tftpd_disable": "com.apple.tftpd", "os_uucp_disable": "com.apple.uucp", "os_httpd_disable": "org.apache.httpd"]
            guard let label = disabledRules[rule] ?? inactiveRules[rule] else { return result("manual", "No bundled command implementation for this rule.") }
            let listing = command("/bin/launchctl", ["print-disabled", "system"])
            guard usable(listing), listing.output.contains("disabled services = {"), listing.output.contains("}") else { return unavailable(listing) }
            let entries = listing.output.components(separatedBy: .newlines).map { $0.trimmingCharacters(in: .whitespaces) }.filter { $0.hasPrefix("\"\(label)\" => ") }
            guard entries.count <= 1 else { return result("manual", "Duplicate launch service state evidence.") }
            if let entry = entries.first, entry != "\"\(label)\" => disabled" && entry != "\"\(label)\" => enabled" {
                return result("manual", "Unrecognized launch service state.")
            }
            if disabledRules[rule] != nil {
                return result(entries.first == "\"\(label)\" => disabled" ? "pass" : "fail", "The source requires an explicit disabled service override for \(label).")
            }
            if entries.first == "\"\(label)\" => enabled" { return result("fail", "\(label) has an explicit enabled override.") }
            let running = command("/bin/launchctl", ["print", "system/\(label)"])
            if usable(running), !running.output.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return result("fail", "\(label) is loaded in the system launch domain.") }
            if running.unavailable == nil && running.exitCode == 113 && running.output.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && running.error.contains("Could not find service \"\(label)\" in domain for system") {
                return result("pass", "\(label) is not loaded and has no explicit enabled override.")
            }
            return unavailable(running)
        }
    }

    private static func runLegacy(check: CISCheck) -> CheckResult {
        switch check.description {
        // Installation, Updates, and Patches
        case let desc where desc.contains("all Apple-provided software is current"):
            return MacOSUpdateChecks.checkAppleSoftwareCurrent(check: check)
        case let desc where desc.contains("Auto Update is enabled"):
            return MacOSUpdateChecks.checkAutoUpdate(check: check)
        case let desc where desc.contains("Download New Updates When Available is enabled"):
            return MacOSUpdateChecks.checkDownloadNewUpdates(check: check)
        case let desc where desc.contains("Install of macOS Updates is enabled"):
            return MacOSUpdateChecks.checkInstallMacOSUpdates(check: check)
        case let desc where desc.contains("Install Application Updates from the App Store is enabled"):
            return MacOSUpdateChecks.checkInstallAppStoreUpdates(check: check)
        case let desc where desc.contains("Install Security Responses and System Files is enabled"):
            return MacOSUpdateChecks.checkInstallSecurityResponses(check: check)
        case let desc where desc.contains("Software Update Deferment is 30 days or less"):
            return MacOSUpdateChecks.checkSoftwareUpdateDeferment(check: check)
            
        // System Preferences and Security
        case let desc where desc.contains("Gatekeeper is enabled"):
            return MacOSSystemChecks.checkGatekeeperEnabled(check: check)
        case let desc where desc.contains("FileVault is enabled"):
            return MacOSSystemChecks.checkFileVaultEnabled(check: check)
        case let desc where desc.contains("System Integrity Protection is enabled"):
            return MacOSSystemChecks.checkSIPEnabled(check: check)
        case let desc where desc.contains("Apple Mobile File Integrity is enabled"):
            return MacOSSystemChecks.checkAMFIEnabled(check: check)
        case let desc where desc.contains("Sealed System Volume is enabled"):
            return MacOSSystemChecks.checkSSVEnabled(check: check)
        case let desc where desc.contains("Secure Keyboard Entry in Terminal.app is enabled"):
            return MacOSSystemChecks.checkSecureKeyboardEntry(check: check)
        case let desc where desc.contains("Secure Empty Trash is enabled"):
            return MacOSSystemChecks.checkSecureEmptyTrash(check: check)
        case let desc where desc.contains("login items are not added"):
            return MacOSSystemChecks.checkLoginItemsNotAdded(check: check)
        case let desc where desc.contains("security auditing is enabled"):
            return MacOSSystemChecks.checkSecurityAuditingEnabled(check: check)
        case let desc where desc.contains("security auditing retention is configured"):
            return MacOSSystemChecks.checkAuditRetention(check: check)
        case let desc where desc.contains("security auditing flags are configured for startup and time changes"):
            return MacOSSystemChecks.checkAuditFlagsStartup(check: check)
        case let desc where desc.contains("security auditing flags are configured for system-wide settings"):
            return MacOSSystemChecks.checkAuditFlagsSystemWide(check: check)
        case let desc where desc.contains("security auditing flags are configured for authentication and authorization"):
            return MacOSSystemChecks.checkAuditFlagsAuth(check: check)
        case let desc where desc.contains("security auditing flags are configured for file system events"):
            return MacOSSystemChecks.checkAuditFlagsFileSystem(check: check)
        case let desc where desc.contains("security auditing flags are configured for user events"):
            return MacOSSystemChecks.checkAuditFlagsUserEvents(check: check)
        case let desc where desc.contains("security auditing flags are configured for network events"):
            return MacOSSystemChecks.checkAuditFlagsNetworkEvents(check: check)
        case let desc where desc.contains("security auditing flags are configured for process events"):
            return MacOSSystemChecks.checkAuditFlagsProcessEvents(check: check)
            
        // Password Policies
        case let desc where desc.contains("password account lockout threshold is configured"):
            return MacOSPasswordChecks.checkPasswordLockoutThreshold(check: check)
        case let desc where desc.contains("password minimum length is configured"):
            return MacOSPasswordChecks.checkPasswordMinLength(check: check)
        case let desc where desc.contains("password complexity is configured"):
            return MacOSPasswordChecks.checkPasswordComplexity(check: check)
        case let desc where desc.contains("password history is configured"):
            return MacOSPasswordChecks.checkPasswordHistory(check: check)
        case let desc where desc.contains("password maximum age is configured"):
            return MacOSPasswordChecks.checkPasswordMaxAge(check: check)
        case let desc where desc.contains("password minimum age is configured"):
            return MacOSPasswordChecks.checkPasswordMinAge(check: check)
        case let desc where desc.contains("login keychain is locked when system sleeps"):
            return MacOSPasswordChecks.checkLoginKeychainLocked(check: check)
            
        // File Permissions
        case let desc where desc.contains("users' home directories permissions are 750"):
            return MacOSPasswordChecks.checkHomeDirectoryPermissions(check: check)
        case let desc where desc.contains("users' dot-files permissions are 750"):
            return MacOSPasswordChecks.checkDotFilePermissions(check: check)
        case let desc where desc.contains("users' .ssh directory permissions are 700"):
            return MacOSPasswordChecks.checkSSHDirectoryPermissions(check: check)
        case let desc where desc.contains("users' .ssh/config permissions are 600"):
            return MacOSPasswordChecks.checkSSHConfigPermissions(check: check)
        case let desc where desc.contains("users' .ssh/authorized_keys permissions are 600"):
            return MacOSPasswordChecks.checkSSHAuthorizedKeysPermissions(check: check)
            
        // Firewall Settings
        case let desc where desc.contains("Firewall is enabled"):
            return MacOSNetworkChecks.checkFirewall(check: check)
        case let desc where desc.contains("Firewall Stealth Mode is enabled"):
            return MacOSNetworkChecks.checkFirewallStealthMode(check: check)
        case let desc where desc.contains("Firewall is configured to block all incoming connections"):
            return MacOSNetworkChecks.checkFirewallBlockAll(check: check)
            
        // User and Login Settings
        case let desc where desc.contains("Automatic Login is disabled"):
            return MacOSUserChecks.checkAutomaticLoginDisabled(check: check)
        case let desc where desc.contains("Guest account is disabled"):
            return MacOSUserChecks.checkGuestAccountDisabled(check: check)
        case let desc where desc.contains("Guest access to shared folders is disabled"):
            return MacOSUserChecks.checkGuestSharingDisabled(check: check)
        case let desc where desc.contains("Fast User Switching is disabled"):
            return MacOSUserChecks.checkFastUserSwitchingDisabled(check: check)
        case let desc where desc.contains("Show All Users on Login Screen is disabled"):
            return MacOSUserChecks.checkShowAllUsersDisabled(check: check)
        case let desc where desc.contains("Show password hints is disabled"):
            return MacOSUserChecks.checkPasswordHintsDisabled(check: check)
        case let desc where desc.contains("the screensaver is enabled and set to begin after 20 minutes or less"):
            return MacOSUserChecks.checkScreensaverTimeout(check: check)
        case let desc where desc.contains("screensaver requires a password"):
            return MacOSUserChecks.checkScreensaverPasswordRequired(check: check)
        case let desc where desc.contains("password screensaver grace period is set to 5 seconds or less"):
            return MacOSUserChecks.checkScreensaverGracePeriod(check: check)
        case let desc where desc.contains("root account is disabled"):
            return MacOSUserChecks.checkRootAccountDisabled(check: check)
            
        // Network and Sharing
        case let desc where desc.contains("Set Time and Date Automatically is enabled"):
            return MacOSNetworkChecks.checkTimeAndDateAutomatically(check: check)
        case let desc where desc.contains("NTP servers are configured properly"):
            return MacOSNetworkChecks.checkNTPServers(check: check)
        case let desc where desc.contains("Remote Login is disabled"):
            return MacOSNetworkChecks.checkRemoteLoginDisabled(check: check)
        case let desc where desc.contains("Remote Management is disabled"):
            return MacOSNetworkChecks.checkRemoteManagementDisabled(check: check)
        case let desc where desc.contains("Remote Apple Events is disabled"):
            return MacOSNetworkChecks.checkRemoteAppleEventsDisabled(check: check)
        case let desc where desc.contains("Internet Sharing is disabled"):
            return MacOSNetworkChecks.checkInternetSharingDisabled(check: check)
        case let desc where desc.contains("Media Sharing is disabled"):
            return MacOSNetworkChecks.checkMediaSharingDisabled(check: check)
        case let desc where desc.contains("DVD/CD Sharing is disabled"):
            return MacOSNetworkChecks.checkDVDSharingDisabled(check: check)
        case let desc where desc.contains("Screen Sharing is disabled"):
            return MacOSNetworkChecks.checkScreenSharingDisabled(check: check)
        case let desc where desc.contains("File Sharing is disabled"):
            return MacOSNetworkChecks.checkFileSharingDisabled(check: check)
        case let desc where desc.contains("Printer Sharing is disabled"):
            return MacOSNetworkChecks.checkPrinterSharingDisabled(check: check)
        case let desc where desc.contains("Content Caching is disabled"):
            return MacOSNetworkChecks.checkContentCachingDisabled(check: check)
        case let desc where desc.contains("Bluetooth Sharing is disabled"):
            return MacOSNetworkChecks.checkBluetoothSharingDisabled(check: check)
        case let desc where desc.contains("AirDrop is disabled"):
            return MacOSNetworkChecks.checkAirDropDisabled(check: check)
        case let desc where desc.contains("AirPlay Receiver is disabled"):
            return MacOSNetworkChecks.checkAirPlayReceiverDisabled(check: check)
            
        // Privacy and Security
        case let desc where desc.contains("Location Services is disabled"):
            return MacOSPrivacyChecks.checkLocationServicesDisabled(check: check)
        case let desc where desc.contains("Sending diagnostic and usage data to Apple is disabled"):
            return MacOSPrivacyChecks.checkDiagnosticDataDisabled(check: check)
            
        // Hardware and Peripheral Security
        case let desc where desc.contains("Bluetooth is disabled when not needed"):
            return MacOSHardwareChecks.checkBluetoothDisabled(check: check)
        case let desc where desc.contains("Camera access is limited to approved apps"):
            return MacOSHardwareChecks.checkCameraAccess(check: check)
        case let desc where desc.contains("Microphone access is limited to approved apps"):
            return MacOSHardwareChecks.checkMicrophoneAccess(check: check)
        case let desc where desc.contains("Full Disk Access is limited to approved apps"):
            return MacOSHardwareChecks.checkFullDiskAccess(check: check)
        case let desc where desc.contains("Screen Recording access is limited to approved apps"):
            return MacOSHardwareChecks.checkScreenRecordingAccess(check: check)
        case let desc where desc.contains("Automation access is limited to approved apps"):
            return MacOSHardwareChecks.checkAutomationAccess(check: check)
        case let desc where desc.contains("USB restricted mode is enabled"):
            return MacOSHardwareChecks.checkUSBRestrictedMode(check: check)
        case let desc where desc.contains("Limit Ad Tracking is enabled"):
            return MacOSPrivacyChecks.checkLimitAdTracking(check: check)
        case let desc where desc.contains("Siri is disabled"):
            return MacOSPrivacyChecks.checkSiriDisabled(check: check)
        case let desc where desc.contains("Dictation is disabled"):
            return MacOSPrivacyChecks.checkDictationDisabled(check: check)
        case let desc where desc.contains("Spotlight Suggestions are disabled"):
            return MacOSPrivacyChecks.checkSpotlightSuggestionsDisabled(check: check)
        case let desc where desc.contains("Safari Spotlight Suggestions are disabled"):
            return MacOSPrivacyChecks.checkSafariSpotlightSuggestionsDisabled(check: check)
        case let desc where desc.contains("Safari Prevent cross-site tracking is enabled"):
            return MacOSPrivacyChecks.checkSafariPreventCrossSiteTracking(check: check)
        case let desc where desc.contains("Safari Block all cookies is enabled"):
            return MacOSPrivacyChecks.checkSafariBlockAllCookies(check: check)
        case let desc where desc.contains("Safari Web Content is set to deny without user prompt"):
            return MacOSPrivacyChecks.checkSafariWebContentDeny(check: check)
            
        // Application Security
        case let desc where desc.contains("Gatekeeper is configured to only allow code signed by Apple"):
            return MacOSAppSecurityChecks.checkGatekeeperStrictConfig(check: check)
        case let desc where desc.contains("Automatic Opening of Safe Files in Safari is disabled"):
            return MacOSAppSecurityChecks.checkSafariAutoOpenSafeFiles(check: check)
        case let desc where desc.contains("Automatic Execution of JavaScript is disabled in downloaded files"):
            return MacOSAppSecurityChecks.checkJavaScriptAutoExecDisabled(check: check)
        case let desc where desc.contains("Automatic Execution of Java Applets is disabled"):
            return MacOSAppSecurityChecks.checkJavaAppletsDisabled(check: check)
        case let desc where desc.contains("Automatic Execution of Plugins is disabled"):
            return MacOSAppSecurityChecks.checkPluginsDisabled(check: check)
        case let desc where desc.contains("Quarantine of Downloaded Files is enabled"):
            return MacOSAppSecurityChecks.checkQuarantineEnabled(check: check)
        case let desc where desc.contains("XProtect Updater is enabled"):
            return MacOSAppSecurityChecks.checkXProtectEnabled(check: check)
        case let desc where desc.contains("XProtect Signatures are updated regularly"):
            return MacOSAppSecurityChecks.checkXProtectSignatures(check: check)
        case let desc where desc.contains("MRT.app is enabled"):
            return MacOSAppSecurityChecks.checkMRTEnabled(check: check)
            
        // Hardware and Peripheral Security
        case let desc where desc.contains("Camera access is limited to approved apps"):
            return MacOSAppSecurityChecks.checkCameraAccess(check: check)
        case let desc where desc.contains("Microphone access is limited to approved apps"):
            return MacOSAppSecurityChecks.checkMicrophoneAccess(check: check)
        case let desc where desc.contains("Full Disk Access is limited to approved apps"):
            return MacOSAppSecurityChecks.checkFullDiskAccess(check: check)
            
        default:
            return CheckResult(check: check, status: "manual", details: "Not yet implemented")
        }
    }

    private static func checkFirewall(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/libexec/ApplicationFirewall/socketfilterfw"
        process.arguments = ["--getglobalstate"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to run firewall check: \(error)")
        }
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        if output.contains("State = 1") {
            return CheckResult(check: check, status: "pass", details: "Firewall is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Firewall is NOT enabled.")
        }
    }

    private static func checkAutoUpdate(check: CISCheck) -> CheckResult {
        // Check if automatic software updates are enabled using 'defaults' for com.apple.SoftwareUpdate
        let process = Process()
        process.launchPath = "/usr/bin/defaults"
        process.arguments = ["read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to run auto update check: \(error)")
        }
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if output == "1" {
            return CheckResult(check: check, status: "pass", details: "Auto Update is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Auto Update is NOT enabled.")
        }
    }

    private static func checkTimeAndDateAutomatically(check: CISCheck) -> CheckResult {
        // Check if time and date are set automatically
        let process = Process()
        process.launchPath = "/usr/sbin/systemsetup"
        process.arguments = ["-getusingnetworktime"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check time and date setting: \(error)")
        }
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if output.contains("On") {
            return CheckResult(check: check, status: "pass", details: "Set Time and Date Automatically is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Set Time and Date Automatically is NOT enabled.")
        }
    }

    private static func checkDownloadNewUpdates(check: CISCheck) -> CheckResult {
        // Check if 'AutomaticDownload' is enabled in com.apple.SoftwareUpdate
        let process = Process()
        process.launchPath = "/usr/bin/defaults"
        process.arguments = ["read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticDownload"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check AutomaticDownload: \(error)")
        }
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if output == "1" {
            return CheckResult(check: check, status: "pass", details: "Download New Updates When Available is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Download New Updates When Available is NOT enabled.")
        }
    }

    private static func checkInstallMacOSUpdates(check: CISCheck) -> CheckResult {
        // Check if 'AutomaticallyInstallMacOSUpdates' is enabled in com.apple.SoftwareUpdate
        let process = Process()
        process.launchPath = "/usr/bin/defaults"
        process.arguments = ["read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticallyInstallMacOSUpdates"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check AutomaticallyInstallMacOSUpdates: \(error)")
        }
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if output == "1" {
            return CheckResult(check: check, status: "pass", details: "Install of macOS Updates is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Install of macOS Updates is NOT enabled.")
        }
    }

    private static func checkFirewallStealthMode(check: CISCheck) -> CheckResult {
        // Use /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode
        let process = Process()
        process.launchPath = "/usr/libexec/ApplicationFirewall/socketfilterfw"
        process.arguments = ["--getstealthmode"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to run firewall stealth mode check: \(error)")
        }
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        if output.contains("enabled") {
            return CheckResult(check: check, status: "pass", details: "Firewall Stealth Mode is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Firewall Stealth Mode is NOT enabled.")
        }
    }

    private static func checkInstallAppStoreUpdates(check: CISCheck) -> CheckResult {
        // Check if 'AutoUpdate' is enabled in com.apple.commerce
        let process = Process()
        process.launchPath = "/usr/bin/defaults"
        process.arguments = ["read", "/Library/Preferences/com.apple.commerce", "AutoUpdate"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check App Store auto updates: \(error)")
        }
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if output == "1" {
            return CheckResult(check: check, status: "pass", details: "Install Application Updates from the App Store is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Install Application Updates from the App Store is NOT enabled.")
        }
    }

    private static func checkContentCachingDisabled(check: CISCheck) -> CheckResult {
        // Use AssetCacheManagerUtil to check if content caching is disabled
        let process = Process()
        process.launchPath = "/usr/bin/AssetCacheManagerUtil"
        process.arguments = ["status"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check content caching: \(error)")
        }
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        if output.contains("Activated: false") {
            return CheckResult(check: check, status: "pass", details: "Content Caching is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Content Caching is ENABLED.")
        }
    }

    private static func checkBluetoothSharingDisabled(check: CISCheck) -> CheckResult {
        // Check if Bluetooth Sharing is disabled via launchctl
        let process = Process()
        process.launchPath = "/bin/launchctl"
        process.arguments = ["print-disabled", "system"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check Bluetooth Sharing: \(error)")
        }
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        if output.contains("com.apple.bluetoothd"), output.contains("true") {
            return CheckResult(check: check, status: "pass", details: "Bluetooth Sharing is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Bluetooth Sharing is ENABLED.")
        }
    }
    
    private static func checkRemoteLoginDisabled(check: CISCheck) -> CheckResult {
        // Check if Remote Login (SSH) is disabled
        let process = Process()
        process.launchPath = "/usr/sbin/systemsetup"
        process.arguments = ["-getremotelogin"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check Remote Login: \(error)")
        }
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        if output.contains("Remote Login: Off") {
            return CheckResult(check: check, status: "pass", details: "Remote Login is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Remote Login is ENABLED.")
        }
    }
    
    private static func checkRemoteManagementDisabled(check: CISCheck) -> CheckResult {
        // Check if Remote Management (ARD) is disabled
        let process = Process()
        process.launchPath = "/usr/bin/defaults"
        process.arguments = ["read", "/Library/Preferences/com.apple.RemoteManagement", "ARD_AllLocalUsers"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            // If the command fails, it likely means ARD is not configured, which is good
            return CheckResult(check: check, status: "pass", details: "Remote Management appears to be disabled.")
        }
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        if output.contains("0") || output.isEmpty {
            return CheckResult(check: check, status: "pass", details: "Remote Management is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Remote Management is ENABLED.")
        }
    }
    
    private static func checkRemoteAppleEventsDisabled(check: CISCheck) -> CheckResult {
        // Check if Remote Apple Events are disabled
        let process = Process()
        process.launchPath = "/usr/sbin/systemsetup"
        process.arguments = ["-getremoteappleevents"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check Remote Apple Events: \(error)")
        }
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        if output.contains("Remote Apple Events: Off") {
            return CheckResult(check: check, status: "pass", details: "Remote Apple Events are disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Remote Apple Events are ENABLED.")
        }
    }
    
    private static func checkInternetSharingDisabled(check: CISCheck) -> CheckResult {
        // Check if Internet Sharing is disabled
        let process = Process()
        process.launchPath = "/usr/bin/defaults"
        process.arguments = ["read", "/Library/Preferences/SystemConfiguration/com.apple.nat", "Enabled"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            // If the command fails, it likely means Internet Sharing is not configured, which is good
            return CheckResult(check: check, status: "pass", details: "Internet Sharing appears to be disabled.")
        }
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        if output.contains("0") || output.isEmpty {
            return CheckResult(check: check, status: "pass", details: "Internet Sharing is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Internet Sharing is ENABLED.")
        }
    }
    
    private static func checkMediaSharingDisabled(check: CISCheck) -> CheckResult {
        // Check if Media Sharing is disabled
        let process = Process()
        process.launchPath = "/usr/bin/defaults"
        process.arguments = ["read", "com.apple.amp.mediasharingd", "home-sharing-enabled"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            // If the command fails, it likely means Media Sharing is not configured, which is good
            return CheckResult(check: check, status: "pass", details: "Media Sharing appears to be disabled.")
        }
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        if output.contains("0") || output.isEmpty {
            return CheckResult(check: check, status: "pass", details: "Media Sharing is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Media Sharing is ENABLED.")
        }
    }
    
    private static func checkDVDSharingDisabled(check: CISCheck) -> CheckResult {
        // Check if DVD/CD Sharing is disabled by checking if the service is running
        let process = Process()
        process.launchPath = "/bin/launchctl"
        process.arguments = ["list", "com.apple.ODSAgent"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check DVD/CD Sharing: \(error)")
        }
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        if output.isEmpty || !output.contains("com.apple.ODSAgent") {
            return CheckResult(check: check, status: "pass", details: "DVD/CD Sharing is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "DVD/CD Sharing is ENABLED.")
        }
    }
    
    private static func checkScreenSharingDisabled(check: CISCheck) -> CheckResult {
        // Check if Screen Sharing is disabled
        let process = Process()
        process.launchPath = "/bin/launchctl"
        process.arguments = ["list", "com.apple.screensharing"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check Screen Sharing: \(error)")
        }
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        if output.isEmpty || !output.contains("com.apple.screensharing") {
            return CheckResult(check: check, status: "pass", details: "Screen Sharing is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Screen Sharing is ENABLED.")
        }
    }
    
    private static func checkFileSharingDisabled(check: CISCheck) -> CheckResult {
        // Check if File Sharing is disabled
        let process = Process()
        process.launchPath = "/bin/launchctl"
        process.arguments = ["list", "com.apple.smbd"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check File Sharing: \(error)")
        }
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        if output.isEmpty || !output.contains("com.apple.smbd") {
            return CheckResult(check: check, status: "pass", details: "File Sharing is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "File Sharing is ENABLED.")
        }
    }
    
    private static func checkPrinterSharingDisabled(check: CISCheck) -> CheckResult {
        // Check if Printer Sharing is disabled using system_profiler instead of cupsctl
        let process = Process()
        process.launchPath = "/usr/sbin/system_profiler"
        process.arguments = ["SPPrintersDataType"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check Printer Sharing: \(error)")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        if !output.contains("Shared: Yes") {
            return CheckResult(check: check, status: "pass", details: "Printer Sharing is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Printer Sharing is ENABLED.")
        }
    }
    
    // Check if FileVault is enabled
    private static func checkFileVaultEnabled(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/fdesetup"
        process.arguments = ["status"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check FileVault status: \(error)")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        if output.contains("FileVault is On") {
            return CheckResult(check: check, status: "pass", details: "FileVault is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "FileVault is NOT enabled.")
        }
    }
    
    // Check if Gatekeeper is enabled
    private static func checkGatekeeperEnabled(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/sbin/spctl"
        process.arguments = ["--status"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check Gatekeeper status: \(error)")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        if output.contains("assessments enabled") {
            return CheckResult(check: check, status: "pass", details: "Gatekeeper is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Gatekeeper is NOT enabled.")
        }
    }
    
    // Check if System Integrity Protection is enabled
    private static func checkSIPEnabled(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/csrutil"
        process.arguments = ["status"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CheckResult(check: check, status: "error", details: "Failed to check System Integrity Protection status: \(error)")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        if output.contains("System Integrity Protection status: enabled") {
            return CheckResult(check: check, status: "pass", details: "System Integrity Protection is enabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "System Integrity Protection is NOT enabled.")
        }
    }
    
    // Check if Guest account is disabled
    private static func checkGuestAccountDisabled(check: CISCheck) -> CheckResult {
        let process = Process()
        process.launchPath = "/usr/bin/defaults"
        process.arguments = ["read", "/Library/Preferences/com.apple.loginwindow", "GuestEnabled"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            // If the command fails, it likely means the setting doesn't exist, which is good (default is disabled)
            return CheckResult(check: check, status: "pass", details: "Guest account appears to be disabled.")
        }
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if output == "0" || output.isEmpty {
            return CheckResult(check: check, status: "pass", details: "Guest account is disabled.")
        } else {
            return CheckResult(check: check, status: "fail", details: "Guest account is ENABLED.")
        }
    }
    
    // Check if Automatic Login is disabled
    private static func checkAutomaticLoginDisabled(check: CISCheck) -> CheckResult {
        MacOSUserChecks.checkAutomaticLoginDisabled(check: check)
    }
}
