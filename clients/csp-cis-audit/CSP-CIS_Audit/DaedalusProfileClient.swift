import Foundation

struct DaedalusProfilesResponse: Decodable {
    let domain: String
    let profiles: [DaedalusPublishedProfile]
}

struct DaedalusBenchmark: Decodable {
    let name: String?
    let version: String?
    let level: String?
    let osVersion: String?

    enum CodingKeys: String, CodingKey {
        case name
        case version
        case level
        case osVersion = "os_version"
    }
}

struct DaedalusPublishedProfile: Decodable {
    let slug: String
    let name: String
    let version: String
    let platform: String
    let description: String
    let checks: [CISCheck]
    let benchmark: DaedalusBenchmark?
}

enum DaedalusProfileClientError: Error, LocalizedError {
    case invalidEndpoint
    case insecureEndpoint
    case noCompatibleProfile
    case requestedProfileNotPublished(String)
    case invalidResponse

    var errorDescription: String? {
        switch self {
        case .invalidEndpoint:
            return "The Daedalus profile endpoint is invalid."
        case .insecureEndpoint:
            return "Profiles require HTTPS, except for a loopback development server."
        case .noCompatibleProfile:
            return "Daedalus has no published macOS or multi-platform CIS profile."
        case .requestedProfileNotPublished(let slug):
            return "The configured Daedalus profile '\(slug)' is not published for macOS."
        case .invalidResponse:
            return "Daedalus returned an invalid profile catalog."
        }
    }
}

enum DaedalusProfileClient {
    /// Returns a reason when a profile declares a target macOS major version
    /// that does not match the host. Profiles without an OS target remain
    /// usable across supported macOS versions.
    static func incompatibilityReason(
        for profile: DaedalusPublishedProfile,
        osMajorVersion: Int
    ) -> String? {
        guard let target = profile.benchmark?.osVersion,
              let targetMajor = target.split(separator: ".").first.flatMap({ Int($0) }) else {
            return nil
        }
        guard targetMajor == osMajorVersion else {
            return "This profile targets macOS \(target); the current host is macOS \(osMajorVersion)."
        }
        return nil
    }

    static func protectedSession() -> URLSession {
        URLSession(configuration: .ephemeral, delegate: DaedalusOriginRedirectGuard(), delegateQueue: nil)
    }

    static func profileEndpoint(configuredEndpoint: String, reportEndpoint: String) -> String? {
        let configured = configuredEndpoint.trimmingCharacters(in: .whitespacesAndNewlines)
        if !configured.isEmpty {
            return configured
        }

        guard var components = URLComponents(string: reportEndpoint),
              components.path.hasSuffix("/api/cis/report") else {
            return nil
        }
        components.path = String(components.path.dropLast("/api/cis/report".count))
            + "/api/cis/client/profiles"
        return components.url?.absoluteString
    }

    static func fetch(
        endpoint: String,
        apiKey: String,
        preferredSlug: String = ""
    ) -> DaedalusPublishedProfile? {
        guard !apiKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            print("[INFO] No CIS API key is configured; using the bundled checklist.")
            return nil
        }
        guard let url = URL(string: endpoint),
              Config.isAllowedReportingEndpoint(endpoint) else {
            print("[WARNING] Daedalus profile endpoint is invalid; using the bundled checklist.")
            return nil
        }

        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.timeoutInterval = 12
        request.setValue(apiKey, forHTTPHeaderField: "X-API-Key")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("no-cache", forHTTPHeaderField: "Cache-Control")

        let semaphore = DispatchSemaphore(value: 0)
        var responseData: Data?
        var responseStatus: Int?
        var requestError: Error?
        let session = protectedSession()
        defer { session.invalidateAndCancel() }
        session.dataTask(with: request) { data, response, error in
            responseData = data
            responseStatus = (response as? HTTPURLResponse)?.statusCode
            requestError = error
            semaphore.signal()
        }.resume()

        guard semaphore.wait(timeout: .now() + 14) == .success else {
            print("[WARNING] Daedalus profile fetch timed out; using the bundled checklist.")
            return nil
        }
        if requestError != nil {
            print("[WARNING] Daedalus profile fetch failed; using the bundled checklist.")
            return nil
        }
        guard responseStatus.map({ (200..<300).contains($0) }) == true,
              let responseData else {
            print("[WARNING] Daedalus profile endpoint returned HTTP \(responseStatus ?? 0); using the bundled checklist.")
            return nil
        }

        do {
            let profile = try selectProfile(from: responseData, preferredSlug: preferredSlug)
            print("[INFO] Using Daedalus profile \(profile.name) v\(profile.version) (\(profile.checks.count) checks).")
            return profile
        } catch {
            print("[WARNING] \(error.localizedDescription) Using the bundled checklist.")
            return nil
        }
    }

    static func selectProfile(
        from data: Data,
        preferredSlug: String = ""
    ) throws -> DaedalusPublishedProfile {
        let catalog: DaedalusProfilesResponse
        do {
            catalog = try JSONDecoder().decode(DaedalusProfilesResponse.self, from: data)
        } catch {
            throw DaedalusProfileClientError.invalidResponse
        }

        let compatible = catalog.profiles.filter {
            let platform = $0.platform.lowercased()
            return platform == "macos" || platform == "multi"
        }
        let requested = preferredSlug.trimmingCharacters(in: .whitespacesAndNewlines)
        let selected: DaedalusPublishedProfile?
        if requested.isEmpty {
            selected = compatible.first
            if compatible.count > 1 {
                print("[WARNING] Multiple Daedalus macOS profiles are published; using the newest. Set profile_slug in the imported client config to pin one.")
            }
        } else {
            selected = compatible.first {
                $0.slug.caseInsensitiveCompare(requested) == .orderedSame
            }
        }

        guard let selected, !selected.checks.isEmpty else {
            if !requested.isEmpty {
                throw DaedalusProfileClientError.requestedProfileNotPublished(requested)
            }
            throw DaedalusProfileClientError.noCompatibleProfile
        }
        return selected
    }
}

// Authenticated requests cannot redirect credentials to another origin or
// downgrade HTTPS. Same-origin canonical route redirects remain supported.
final class DaedalusOriginRedirectGuard: NSObject, URLSessionTaskDelegate {
    static func allowsRedirect(from source: URL, to destination: URL) -> Bool {
        func port(_ url: URL) -> Int? { url.port ?? (url.scheme == "https" ? 443 : url.scheme == "http" ? 80 : nil) }
        return source.scheme?.lowercased() == destination.scheme?.lowercased()
            && source.host?.lowercased() == destination.host?.lowercased()
            && port(source) == port(destination)
            && destination.user == nil && destination.password == nil
    }

    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        guard let source = task.originalRequest?.url, let destination = request.url,
              Self.allowsRedirect(from: source, to: destination) else {
            completionHandler(nil)
            return
        }
        completionHandler(request)
    }
}
