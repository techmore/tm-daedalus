import Foundation

struct MacOSHardwareChecks {
    static func checkBluetoothDisabled(check: CISCheck, command: (String, [String]) -> MacOSChecks.CommandEvidence = MacOSChecks.readCommand) -> CheckResult {
        MacOSChecks.legacyBooleanPreference(check: check, domain: "/Library/Preferences/com.apple.Bluetooth", key: "ControllerPowerState", expected: false, command: command)
    }

    private static func permissionReview(check: CISCheck, permission: String) -> CheckResult {
        CheckResult(check: check, status: "manual", details: "Review " + permission + " grants in Privacy & Security against the organization's approved applications. This client did not collect a complete supported permission inventory or an approval list. An empty or failed query and the number of applications do not establish approved access. No permission was reset or changed.")
    }

    static func checkCameraAccess(check: CISCheck) -> CheckResult {
        permissionReview(check: check, permission: "Camera")
    }
    static func checkMicrophoneAccess(check: CISCheck) -> CheckResult {
        permissionReview(check: check, permission: "Microphone")
    }
    static func checkScreenRecordingAccess(check: CISCheck) -> CheckResult {
        permissionReview(check: check, permission: "Screen Recording")
    }
    static func checkAutomationAccess(check: CISCheck) -> CheckResult {
        permissionReview(check: check, permission: "Automation")
    }
    static func checkFullDiskAccess(check: CISCheck) -> CheckResult {
        permissionReview(check: check, permission: "Full Disk Access")
    }

    static func checkUSBRestrictedMode(check: CISCheck) -> CheckResult {
        CheckResult(check: check, status: "manual", details: "Review effective wired-accessory approval settings and hardware applicability. A smartcard DisabledTokens preference does not establish USB restricted mode. This client did not collect supported accessory-policy evidence; no accessory or smartcard setting was changed.")
    }
}
