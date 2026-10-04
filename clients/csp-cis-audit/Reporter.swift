import Foundation

struct SystemInfo: Codable {
    let hostname: String
    let ipAddresses: [String]
    let osVersion: String
    let cpuInfo: String
    let cpuCores: String
    let cpuThreads: String
    let ramTotal: String
    let ramUsed: String
    let diskTotal: String
    let diskUsed: String
    let diskFree: String
    let hardwareModel: String
    let serialNumber: String
    let bootTime: String
    let installedApps: [(name: String, version: String)]
    let securitySettings: [String: String]
    
    // Standard initializer
    init(hostname: String, ipAddresses: [String], osVersion: String, cpuInfo: String,
         cpuCores: String, cpuThreads: String, ramTotal: String, ramUsed: String,
         diskTotal: String, diskUsed: String, diskFree: String, hardwareModel: String,
         serialNumber: String, bootTime: String, installedApps: [(name: String, version: String)],
         securitySettings: [String: String]) {
        self.hostname = hostname
        self.ipAddresses = ipAddresses
        self.osVersion = osVersion
        self.cpuInfo = cpuInfo
        self.cpuCores = cpuCores
        self.cpuThreads = cpuThreads
        self.ramTotal = ramTotal
        self.ramUsed = ramUsed
        self.diskTotal = diskTotal
        self.diskUsed = diskUsed
        self.diskFree = diskFree
        self.hardwareModel = hardwareModel
        self.serialNumber = serialNumber
        self.bootTime = bootTime
        self.installedApps = installedApps
        self.securitySettings = securitySettings
    }
    
    enum CodingKeys: String, CodingKey {
        case hostname, ipAddresses, osVersion, cpuInfo, cpuCores, cpuThreads
        case ramTotal, ramUsed, diskTotal, diskUsed, diskFree
        case hardwareModel, serialNumber, bootTime, installedApps, securitySettings
    }
    
    // Custom encoding for the tuple array
    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(hostname, forKey: .hostname)
        try container.encode(ipAddresses, forKey: .ipAddresses)
        try container.encode(osVersion, forKey: .osVersion)
        try container.encode(cpuInfo, forKey: .cpuInfo)
        try container.encode(cpuCores, forKey: .cpuCores)
        try container.encode(cpuThreads, forKey: .cpuThreads)
        try container.encode(ramTotal, forKey: .ramTotal)
        try container.encode(ramUsed, forKey: .ramUsed)
        try container.encode(diskTotal, forKey: .diskTotal)
        try container.encode(diskUsed, forKey: .diskUsed)
        try container.encode(diskFree, forKey: .diskFree)
        try container.encode(hardwareModel, forKey: .hardwareModel)
        try container.encode(serialNumber, forKey: .serialNumber)
        try container.encode(bootTime, forKey: .bootTime)
        
        // Encode the array of tuples as an array of dictionaries
        let appDicts = installedApps.map { ["name": $0.name, "version": $0.version] }
        try container.encode(appDicts, forKey: .installedApps)
        try container.encode(securitySettings, forKey: .securitySettings)
    }
    
    // Custom decoding for the tuple array
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        hostname = try container.decode(String.self, forKey: .hostname)
        ipAddresses = try container.decode([String].self, forKey: .ipAddresses)
        osVersion = try container.decode(String.self, forKey: .osVersion)
        cpuInfo = try container.decode(String.self, forKey: .cpuInfo)
        cpuCores = try container.decode(String.self, forKey: .cpuCores)
        cpuThreads = try container.decode(String.self, forKey: .cpuThreads)
        ramTotal = try container.decode(String.self, forKey: .ramTotal)
        ramUsed = try container.decode(String.self, forKey: .ramUsed)
        diskTotal = try container.decode(String.self, forKey: .diskTotal)
        diskUsed = try container.decode(String.self, forKey: .diskUsed)
        diskFree = try container.decode(String.self, forKey: .diskFree)
        hardwareModel = try container.decode(String.self, forKey: .hardwareModel)
        serialNumber = try container.decode(String.self, forKey: .serialNumber)
        bootTime = try container.decode(String.self, forKey: .bootTime)
        
        // Decode the array of dictionaries back to an array of tuples
        let appDicts = try container.decode([[String: String]].self, forKey: .installedApps)
        installedApps = appDicts.compactMap { dict in
            if let name = dict["name"], let version = dict["version"] {
                return (name: name, version: version)
            }
            return nil
        }
        securitySettings = try container.decode([String: String].self, forKey: .securitySettings)
    }
}

struct CheckReport: Codable {
    let results: [CheckResult]
    let timestamp: String // ISO8601
    let systemInfo: SystemInfo
    let summary: ReportSummary
}

struct ReportSummary: Codable {
    let totalChecks: Int
    let passedChecks: Int
    let failedChecks: Int
    let manualChecks: Int
    let errorChecks: Int
    let complianceScore: Double // Percentage of passed checks
    
    // Category-specific summaries
    let macOSChecks: CategorySummary
    let chromeChecks: CategorySummary
    let safariChecks: CategorySummary
}

struct CategorySummary: Codable {
    let total: Int
    let passed: Int
    let failed: Int
    let manual: Int
    let error: Int
    let score: Double // Percentage of passed checks
}

class Reporter {
    static func report(results: [CheckResult], to endpoint: String) {
        print("\n[DEBUG] Starting enhanced reporting process...")
        
        // Collect system information
        print("[DEBUG] Collecting system information...")
        let systemInfo = collectSystemInfo()
        
        // Generate report summary
        print("[DEBUG] Generating report summary...")
        let summary = generateReportSummary(results: results)
        
        // Print a summary of the results to the console
        print("[DEBUG] Printing detailed results summary...")
        printResultsSummary(results, summary: summary, systemInfo: systemInfo)
        
        // Create the report object
        let timestamp = ISO8601DateFormatter().string(from: Date())
        print("[DEBUG] Creating report object with timestamp: \(timestamp)")
        let report = CheckReport(results: results, timestamp: timestamp, systemInfo: systemInfo, summary: summary)
        
        // Encode the report to JSON
        guard let data = try? JSONEncoder().encode(report) else {
            print("Failed to encode report")
            return
        }
        
        // Save the report locally
        saveReportLocally(data: data, timestamp: timestamp)
        
        // Send the report to the endpoint
        sendReportToEndpoint(data: data, endpoint: endpoint)
    }
    
    private static func collectSystemInfo() -> SystemInfo {
        // Get hostname
        let hostname = ProcessInfo.processInfo.hostName
        
        // Get IP addresses
        let ipAddresses = getIPAddresses()
        
        // Get OS version
        let osVersion = ProcessInfo.processInfo.operatingSystemVersionString
        
        // Get CPU info
        let cpuInfo = getCPUInfo()
        
        // Get CPU cores
        let cpuCores = "Unknown"
        
        // Get CPU threads
        let cpuThreads = "Unknown"
        
        // Get RAM info
        let (ramTotal, ramUsed) = getRAMInfo()
        
        // Get disk space info
        let (diskTotal, diskUsed, diskFree) = getDiskSpaceInfo()
        
        // Get hardware model
        let hardwareModel = "Unknown"
        
        // Get serial number (redacted for privacy)
        let serialNumber = "Redacted"
        
        // Get boot time
        let bootTime = "Unknown"
        
        // Empty apps list and security settings
        let installedApps: [(name: String, version: String)] = []
        let securitySettings: [String: String] = [:]
        
        return SystemInfo(
            hostname: hostname,
            ipAddresses: ipAddresses,
            osVersion: osVersion,
            cpuInfo: cpuInfo,
            cpuCores: cpuCores,
            cpuThreads: cpuThreads,
            ramTotal: ramTotal,
            ramUsed: ramUsed,
            diskTotal: diskTotal,
            diskUsed: diskUsed,
            diskFree: diskFree,
            hardwareModel: hardwareModel,
            serialNumber: serialNumber,
            bootTime: bootTime,
            installedApps: installedApps,
            securitySettings: securitySettings
        )
    }
    
    private static func getIPAddresses() -> [String] {
        var addresses = [String]()
        
        // Run ifconfig command to get network interfaces
        let process = Process()
        process.launchPath = "/sbin/ifconfig"
        let pipe = Pipe()
        process.standardOutput = pipe
        
        do {
            try process.run()
            process.waitUntilExit()
            
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            if let output = String(data: data, encoding: .utf8) {
                // Parse the output to find IP addresses
                let pattern = "inet \\d+\\.\\d+\\.\\d+\\.\\d+"
                if let regex = try? NSRegularExpression(pattern: pattern, options: []) {
                    let matches = regex.matches(in: output, options: [], range: NSRange(output.startIndex..., in: output))
                    for match in matches {
                        if let range = Range(match.range, in: output) {
                            let ipLine = output[range]
                            let components = ipLine.split(separator: " ")
                            if components.count >= 2 {
                                addresses.append(String(components[1]))
                            }
                        }
                    }
                }
            }
        } catch {
            print("Error getting IP addresses: \(error)")
        }
        
        return addresses
    }
    
    private static func getCPUInfo() -> String {
        let process = Process()
        process.launchPath = "/usr/sbin/sysctl"
        process.arguments = ["-n", "machdep.cpu.brand_string"]
        let pipe = Pipe()
        process.standardOutput = pipe
        
        do {
            try process.run()
            process.waitUntilExit()
            
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            if let output = String(data: data, encoding: .utf8) {
                return output.trimmingCharacters(in: .whitespacesAndNewlines)
            }
        } catch {
            print("Error getting CPU info: \(error)")
        }
        
        return "Unknown CPU"
    }
    
    private static func getRAMInfo() -> (String, String) {
        let process = Process()
        process.launchPath = "/usr/bin/vm_stat"
        let pipe = Pipe()
        process.standardOutput = pipe
        
        do {
            try process.run()
            process.waitUntilExit()
            
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            if let output = String(data: data, encoding: .utf8) {
                // Total RAM
                let totalRAM = ProcessInfo.processInfo.physicalMemory
                let totalRAMGB = String(format: "%.2f GB", Double(totalRAM) / 1_073_741_824)
                
                // Used RAM calculation from vm_stat
                var _freePages = 0
                var activePages = 0
                var _inactivePages = 0
                var wiredPages = 0
                
                let lines = output.components(separatedBy: "\n")
                for line in lines {
                    if line.contains("Pages free") {
                        let components = line.components(separatedBy: ":")
                        if components.count >= 2 {
                            let valueStr = components[1].trimmingCharacters(in: .whitespacesAndNewlines).replacingOccurrences(of: ".", with: "")
                            _freePages = Int(valueStr) ?? 0
                        }
                    } else if line.contains("Pages active") {
                        let components = line.components(separatedBy: ":")
                        if components.count >= 2 {
                            let valueStr = components[1].trimmingCharacters(in: .whitespacesAndNewlines).replacingOccurrences(of: ".", with: "")
                            activePages = Int(valueStr) ?? 0
                        }
                    } else if line.contains("Pages inactive") {
                        let components = line.components(separatedBy: ":")
                        if components.count >= 2 {
                            let valueStr = components[1].trimmingCharacters(in: .whitespacesAndNewlines).replacingOccurrences(of: ".", with: "")
                            _inactivePages = Int(valueStr) ?? 0
                        }
                    } else if line.contains("Pages wired down") {
                        let components = line.components(separatedBy: ":")
                        if components.count >= 2 {
                            let valueStr = components[1].trimmingCharacters(in: .whitespacesAndNewlines).replacingOccurrences(of: ".", with: "")
                            wiredPages = Int(valueStr) ?? 0
                        }
                    }
                }
                
                // Calculate used memory (active + wired)
                let pageSize = 4096 // 4KB
                let usedMemory = (activePages + wiredPages) * pageSize
                let usedMemoryGB = String(format: "%.2f GB", Double(usedMemory) / 1_073_741_824)
                
                return (totalRAMGB, usedMemoryGB)
            }
        } catch {
            print("Error getting RAM info: \(error)")
        }
        
        return ("Unknown", "Unknown")
    }
    
    private static func getDiskSpaceInfo() -> (String, String, String) {
        let fileManager = FileManager.default
        do {
            let systemAttributes = try fileManager.attributesOfFileSystem(forPath: "/")
            if let totalSize = systemAttributes[.systemSize] as? NSNumber,
               let freeSize = systemAttributes[.systemFreeSize] as? NSNumber {
                
                let totalGB = String(format: "%.2f GB", Double(totalSize.int64Value) / 1_073_741_824)
                let freeGB = String(format: "%.2f GB", Double(freeSize.int64Value) / 1_073_741_824)
                let usedGB = String(format: "%.2f GB", Double(totalSize.int64Value - freeSize.int64Value) / 1_073_741_824)
                
                return (totalGB, usedGB, freeGB)
            }
        } catch {
            print("Error getting disk space info: \(error)")
        }
        
        return ("Unknown", "Unknown", "Unknown")
    }
    
    private static func generateReportSummary(results: [CheckResult]) -> ReportSummary {
        // Count overall results by status
        var passCount = 0
        var failCount = 0
        var manualCount = 0
        var errorCount = 0
        
        for result in results {
            switch result.status {
            case "pass": passCount += 1
            case "fail": failCount += 1
            case "manual": manualCount += 1
            case "error": errorCount += 1
            default: break
            }
        }
        
        // Calculate overall compliance score
        let totalChecks = results.count
        let complianceScore = totalChecks > 0 ? (Double(passCount) / Double(totalChecks)) * 100.0 : 0.0
        
        // Generate category-specific summaries
        let macOSResults = results.filter { $0.check.category == "macos" }
        let chromeResults = results.filter { $0.check.category == "chrome" }
        let safariResults = results.filter { $0.check.category == "safari" }
        
        let macOSSummary = generateCategorySummary(results: macOSResults)
        let chromeSummary = generateCategorySummary(results: chromeResults)
        let safariSummary = generateCategorySummary(results: safariResults)
        
        return ReportSummary(
            totalChecks: totalChecks,
            passedChecks: passCount,
            failedChecks: failCount,
            manualChecks: manualCount,
            errorChecks: errorCount,
            complianceScore: complianceScore,
            macOSChecks: macOSSummary,
            chromeChecks: chromeSummary,
            safariChecks: safariSummary
        )
    }
    
    private static func generateCategorySummary(results: [CheckResult]) -> CategorySummary {
        var passCount = 0
        var failCount = 0
        var manualCount = 0
        var errorCount = 0
        
        for result in results {
            switch result.status {
            case "pass": passCount += 1
            case "fail": failCount += 1
            case "manual": manualCount += 1
            case "error": errorCount += 1
            default: break
            }
        }
        
        let totalChecks = results.count
        let score = totalChecks > 0 ? (Double(passCount) / Double(totalChecks)) * 100.0 : 0.0
        
        return CategorySummary(
            total: totalChecks,
            passed: passCount,
            failed: failCount,
            manual: manualCount,
            error: errorCount,
            score: score
        )
    }
    
    private static func saveReportLocally(data: Data, timestamp: String) {
        // Create a formatted timestamp for the filename
        let dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "yyyy-MM-dd_HH-mm-ss"
        let dateString = dateFormatter.string(from: Date())
        
        // Get the Documents directory
        let documentsDirectory = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        
        // Create a reports directory if it doesn't exist
        let reportsDirectory = documentsDirectory.appendingPathComponent("CISReports")
        do {
            try FileManager.default.createDirectory(at: reportsDirectory, withIntermediateDirectories: true)
        } catch {
            print("Failed to create reports directory: \(error)")
            return
        }
        
        // Create the report file
        let reportFile = reportsDirectory.appendingPathComponent("cis_report_\(dateString).json")
        
        do {
            try data.write(to: reportFile)
            print("Report saved locally to: \(reportFile.path)")
        } catch {
            print("Failed to save report locally: \(error)")
        }
    }
    
    private static func sendReportToEndpoint(data: Data, endpoint: String) {
        // Validate the endpoint URL
        guard let url = URL(string: endpoint) else {
            print("Invalid endpoint URL: \(endpoint)")
            // Just print a completion message and don't try to send
            print("\n[COMPLETE] CIS benchmark check completed. Report saved locally.")
            return
        }
        
        // Set up the HTTP request
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = data
        
        print("\n[INFO] Attempting to send report to \(endpoint)...")
        print("[INFO] If the server is not running, this will time out after 5 seconds.")
        
        // Create a semaphore to make the network request synchronous
        let semaphore = DispatchSemaphore(value: 0)
        
        // Send the report with a timeout
        let task = URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                print("[ERROR] Failed to send report to \(endpoint): \(error)")
            } else if let response = response as? HTTPURLResponse, !(200...299).contains(response.statusCode) {
                print("[ERROR] Server returned status code: \(response.statusCode)")
                if let responseData = data, let responseString = String(data: responseData, encoding: .utf8) {
                    print("[ERROR] Response: \(responseString)")
                }
            } else {
                print("[SUCCESS] Report sent successfully to \(endpoint)")
            }
            
            // Signal completion
            semaphore.signal()
        }
        task.resume()
        
        // Wait for the network request to complete with a timeout
        let result = semaphore.wait(timeout: .now() + 5.0) // 5 second timeout
        
        if result == .timedOut {
            print("[WARNING] Network request timed out. The server at \(endpoint) may not be running.")
        }
        
        print("\n[COMPLETE] CIS benchmark check completed. Report saved locally.")
    }
    
    private static func printResultsSummary(_ results: [CheckResult], summary: ReportSummary, systemInfo: SystemInfo) {
        // Get current date and time
        let dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        let currentDateTime = dateFormatter.string(from: Date())
        
        // Print system information
        print("\n============= SYSTEM INFORMATION =============")
        print("Timestamp: \(currentDateTime)")
        print("Hostname: \(systemInfo.hostname)")
        print("IP Addresses: \(systemInfo.ipAddresses.joined(separator: ", "))")
        print("OS Version: \(systemInfo.osVersion)")
        print("CPU: \(systemInfo.cpuInfo)")
        print("RAM: \(systemInfo.ramUsed) used of \(systemInfo.ramTotal)")
        print("Disk: \(systemInfo.diskUsed) used, \(systemInfo.diskFree) free of \(systemInfo.diskTotal)")
        print("============================================\n")
        
        // Print overall summary
        print("============= CIS BENCHMARK RESULTS =============")
        print("Overall Compliance Score: \(String(format: "%.2f%%", summary.complianceScore))")
        print("Total Checks: \(summary.totalChecks)")
        print("Passed: \(summary.passedChecks) (\(String(format: "%.2f%%", Double(summary.passedChecks) / Double(summary.totalChecks) * 100.0)))")
        print("Failed: \(summary.failedChecks) (\(String(format: "%.2f%%", Double(summary.failedChecks) / Double(summary.totalChecks) * 100.0)))")
        print("Manual: \(summary.manualChecks) (\(String(format: "%.2f%%", Double(summary.manualChecks) / Double(summary.totalChecks) * 100.0)))")
        print("Errors: \(summary.errorChecks) (\(String(format: "%.2f%%", Double(summary.errorChecks) / Double(summary.totalChecks) * 100.0)))")
        print("================================================\n")
        
        // Print category-specific summaries
        print("============= CATEGORY SUMMARIES =============")
        print("macOS: \(String(format: "%.2f%%", summary.macOSChecks.score)) (\(summary.macOSChecks.passed)/\(summary.macOSChecks.total) passed)")
        print("Chrome: \(String(format: "%.2f%%", summary.chromeChecks.score)) (\(summary.chromeChecks.passed)/\(summary.chromeChecks.total) passed)")
        print("Safari: \(String(format: "%.2f%%", summary.safariChecks.score)) (\(summary.safariChecks.passed)/\(summary.safariChecks.total) passed)")
        print("==============================================\n")
        
        // Print detailed results for each category
        printCategoryResults("macOS", results: results.filter { $0.check.category == "macos" })
        printCategoryResults("Chrome", results: results.filter { $0.check.category == "chrome" })
        printCategoryResults("Safari", results: results.filter { $0.check.category == "safari" })
    }
    
    private static func printCategoryResults(_ category: String, results: [CheckResult]) {
        print("\n============= \(category.uppercased()) CHECKS =============")
        
        // Group results by status
        let passedChecks = results.filter { $0.status == "pass" }
        let failedChecks = results.filter { $0.status == "fail" }
        let manualChecks = results.filter { $0.status == "manual" }
        let errorChecks = results.filter { $0.status == "error" }
        
        // Print failed checks first (most important)
        if !failedChecks.isEmpty {
            print("\nFAILED CHECKS (\(failedChecks.count)):")
            for result in failedChecks {
                print("❌ [\(result.check.id)] \(result.check.description)")
                print("   Details: \(result.details)")
            }
        }
        
        // Print error checks
        if !errorChecks.isEmpty {
            print("\nCHECKS WITH ERRORS (\(errorChecks.count)):")
            for result in errorChecks {
                print("⚠️ [\(result.check.id)] \(result.check.description)")
                print("   Error: \(result.details)")
            }
        }
        
        // Print manual checks
        if !manualChecks.isEmpty {
            print("\nMANUAL CHECKS (\(manualChecks.count)):")
            for result in manualChecks {
                print("🔍 [\(result.check.id)] \(result.check.description)")
                print("   Note: \(result.details)")
            }
        }
        
        // Print passed checks
        if !passedChecks.isEmpty {
            print("\nPASSED CHECKS (\(passedChecks.count)):")
            for result in passedChecks {
                print("✅ [\(result.check.id)] \(result.check.description)")
            }
        }
        
        print("==============================================\n")
    }
}
