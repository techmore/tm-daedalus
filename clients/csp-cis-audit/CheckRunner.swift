import Foundation

protocol CheckExecutable {
    var check: CISCheck { get }
    func run() -> CheckResult
}

struct CheckResult: Codable {
    let check: CISCheck
    let status: String  // "pass", "fail", "manual", "error"
    let details: String
}

struct CheckRunner {
    static func runAll(checks: [CISCheck]) -> [CheckResult] {
        checks.map { check in
            // Dispatch to category-specific implementation
            switch check.category {
            case "macos":
                return MacOSChecks.run(check: check)
            case "chrome":
                return ChromeChecks.run(check: check)
            case "safari":
                return SafariChecks.run(check: check)
            default:
                return CheckResult(check: check, status: "manual", details: "Unknown category")
            }
        }
    }
}

