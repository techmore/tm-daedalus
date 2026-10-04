import Foundation
import Dispatch

enum CISClientPaths {
    private static let deviceIdentityQueue = DispatchQueue(label: "org.cybersecuritypilot.daedalus.device-identity")

    static var applicationSupportDirectory: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support")
        return base.appendingPathComponent("Daedalus", isDirectory: true)
    }

    static func reportsDirectory() throws -> URL {
        try privateDirectory(named: "reports")
    }

    static func logsDirectory() throws -> URL {
        try privateDirectory(named: "logs")
    }

    static func deviceIdentifier() throws -> String {
        try deviceIdentityQueue.sync {
            let stateDirectory = try privateDirectory(named: "state")
            let identifierURL = stateDirectory.appendingPathComponent("device-id")

            if let stored = try? String(contentsOf: identifierURL, encoding: .utf8),
               let identifier = UUID(uuidString: stored.trimmingCharacters(in: .whitespacesAndNewlines)) {
                try FileManager.default.setAttributes(
                    [.posixPermissions: 0o600],
                    ofItemAtPath: identifierURL.path
                )
                return identifier.uuidString.lowercased()
            }

            let identifier = UUID().uuidString.lowercased()
            try Data(identifier.utf8).write(to: identifierURL, options: .atomic)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600],
                ofItemAtPath: identifierURL.path
            )
            return identifier
        }
    }

    static func ensurePrivateDirectory(_ url: URL) throws {
        try FileManager.default.createDirectory(
            at: url,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: url.path)
    }

    static func privateDirectory(named name: String) throws -> URL {
        let clientRoot = applicationSupportDirectory.appendingPathComponent("CIS Client", isDirectory: true)
        try ensurePrivateDirectory(applicationSupportDirectory)
        try ensurePrivateDirectory(clientRoot)
        let url = clientRoot.appendingPathComponent(name, isDirectory: true)
        try ensurePrivateDirectory(url)
        return url
    }
}
