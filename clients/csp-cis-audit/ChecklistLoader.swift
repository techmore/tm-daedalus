import Foundation
import Yams

// Model for a single check, matching the YAML and OpenAPI structure
struct Checklist: Codable {
    let macos: [String]?
    let chrome: [String]?
    let safari: [String]?
}

struct CISCheck: Codable {
    let id: String
    let category: String // "macos", "chrome", "safari"
    let description: String
    let ruleID: String?
    let benchmarkIDs: [String]?
    let expectedLoginMessage: String?

    enum CodingKeys: String, CodingKey {
        case id
        case category
        case description
        case ruleID = "rule_id"
        case benchmarkIDs = "benchmark_ids"
        case expectedLoginMessage = "expected_login_message"
    }

    init(
        id: String,
        category: String,
        description: String,
        ruleID: String? = nil,
        benchmarkIDs: [String]? = nil,
        expectedLoginMessage: String? = nil
    ) {
        self.id = id
        self.category = category
        self.description = description
        self.ruleID = ruleID
        self.benchmarkIDs = benchmarkIDs
        self.expectedLoginMessage = expectedLoginMessage
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        id = try values.decode(String.self, forKey: .id)
        category = try values.decode(String.self, forKey: .category)
        description = try values.decode(String.self, forKey: .description)
        ruleID = try values.decodeIfPresent(String.self, forKey: .ruleID)
        benchmarkIDs = try values.decodeIfPresent([String].self, forKey: .benchmarkIDs)
        expectedLoginMessage = try values.decodeIfPresent(String.self, forKey: .expectedLoginMessage)
    }

    func encode(to encoder: Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(id, forKey: .id)
        try values.encode(category, forKey: .category)
        try values.encode(description, forKey: .description)
        try values.encodeIfPresent(ruleID, forKey: .ruleID)
        try values.encodeIfPresent(benchmarkIDs, forKey: .benchmarkIDs)
        try values.encodeIfPresent(expectedLoginMessage, forKey: .expectedLoginMessage)
    }
}

class ChecklistLoader {
    static func load(from filename: String = "checklist.yaml") -> [CISCheck] {
        print("Loading checklist from: \(filename) in app bundle...")

        guard let bundlePath = Bundle.main.path(forResource: filename.replacingOccurrences(of: ".yaml", with: ""), ofType: "yaml") else {
            print("Error: \(filename) not found in the app bundle.")
            return []
        }

        // Check if file exists
        let fileManager = FileManager.default
        guard fileManager.fileExists(atPath: bundlePath) else {
            print("Error: File does not exist at bundle path: \(bundlePath)")
            return []
        }

        // Read file with error handling
        var yamlString: String
        do {
            yamlString = try String(contentsOfFile: bundlePath, encoding: .utf8)
            print("Successfully read YAML file, content length: \(yamlString.count) characters")
            print("YAML content preview: \(yamlString.prefix(100))...")
        } catch {
            print("Error reading YAML file: \(error)")
            return []
        }

        // Decode with detailed error handling
        var checklist: Checklist
        do {
            checklist = try YAMLDecoder().decode(Checklist.self, from: yamlString)
            print("Successfully decoded YAML to Checklist")
            print("Found \(checklist.macos?.count ?? 0) macOS checks")
            print("Found \(checklist.chrome?.count ?? 0) Chrome checks")
            print("Found \(checklist.safari?.count ?? 0) Safari checks")
        } catch {
            print("YAML decoding error: \(error)")
            return []
        }

        var checks: [CISCheck] = []
        if let macos = checklist.macos {
            for (idx, desc) in macos.enumerated() {
                checks.append(CISCheck(id: "macos_\(idx+1)", category: "macos", description: desc))
            }
        }
        if let chrome = checklist.chrome {
            for (idx, desc) in chrome.enumerated() {
                checks.append(CISCheck(id: "chrome_\(idx+1)", category: "chrome", description: desc))
            }
        }
        if let safari = checklist.safari {
            for (idx, desc) in safari.enumerated() {
                checks.append(CISCheck(id: "safari_\(idx+1)", category: "safari", description: desc))
            }
        }
        return checks
    }
}
