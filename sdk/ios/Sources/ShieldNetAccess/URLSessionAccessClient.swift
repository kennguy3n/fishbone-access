//
// URLSessionAccessClient.swift — production URLSession-backed `AccessClient`.
//
// Each method builds a real `URLRequest` against the control plane, attaches a
// bearer token from the caller-supplied async provider, unwraps the handler's
// single-key JSON envelope (`{"request": ...}`, `{"requests": [...]}`,
// `{"grant": ...}`, `{"history": [...]}`), and decodes into the typed models.
//
// Depends only on `Foundation` — no Combine, no third-party HTTP libraries.
// Host apps can substitute their own `URLSession` (e.g. with certificate
// pinning or a background configuration) via the initializer.
//

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Production HTTP client conforming to ``AccessClient``.
///
/// Construct once per app launch. `baseURL` is the control-plane root with or
/// without the `/api/v1` suffix. `authTokenProvider` returns a current
/// iam-core bearer token; it is invoked on every request so token refresh and
/// step-up re-auth stay the caller's responsibility.
public final class URLSessionAccessClient: AccessClient, @unchecked Sendable {
    private let apiBase: URL
    private let session: URLSession
    private let authTokenProvider: @Sendable () async throws -> String

    public init(
        baseURL: URL,
        session: URLSession = .shared,
        authTokenProvider: @Sendable @escaping () async throws -> String
    ) {
        // Normalise to a `<root>/api/v1` base exactly once so callers may pass
        // either form. Strip ALL trailing slashes (matching the Android SDK's
        // `trimEnd('/')`) so a base like `https://host//` doesn't yield a
        // double slash before `/api/v1`.
        let trimmed = baseURL.absoluteString.trimmingCharacters(in: .whitespaces)
        var noSlash = trimmed
        while noSlash.hasSuffix("/") { noSlash.removeLast() }
        let normalized = noSlash.hasSuffix("/api/v1") ? noSlash : noSlash + "/api/v1"
        self.apiBase = URL(string: normalized) ?? baseURL
        self.session = session
        self.authTokenProvider = authTokenProvider
    }

    // MARK: - AccessClient conformance

    public func me() async throws -> Identity {
        try await get(path: "/me")
    }

    public func createRequest(_ input: CreateAccessRequest) async throws -> RequestSubmission {
        guard !input.targetUserID.trimmingCharacters(in: .whitespaces).isEmpty else {
            throw AccessSDKError.invalidInput("target_user_id is required")
        }
        guard !input.resourceRef.trimmingCharacters(in: .whitespaces).isEmpty else {
            throw AccessSDKError.invalidInput("resource_ref is required")
        }
        let env: CreateEnvelope = try await post(path: "/access-requests", body: input)
        return RequestSubmission(request: env.request, workflow: env.workflow)
    }

    public func listRequests() async throws -> [AccessRequest] {
        let env: RequestsEnvelope = try await get(path: "/access-requests")
        return env.requests
    }

    public func getRequest(id: String) async throws -> AccessRequest {
        let env: RequestEnvelope = try await get(path: "/access-requests/\(try idPath(id))")
        return env.request
    }

    public func getRequestDetail(id: String) async throws -> AccessRequestDetail {
        let env: DetailEnvelope = try await get(path: "/access-requests/\(try idPath(id))")
        return AccessRequestDetail(request: env.request, risk: env.risk, anomalies: env.anomalies)
    }

    public func requestHistory(id: String) async throws -> [StateHistoryEntry] {
        let env: HistoryEnvelope = try await get(path: "/access-requests/\(try idPath(id))/history")
        return env.history
    }

    public func approveRequest(id: String, reason: String?) async throws -> AccessRequest {
        try await transition(id: id, action: "approve", reason: reason)
    }

    public func denyRequest(id: String, reason: String) async throws -> AccessRequest {
        guard !reason.trimmingCharacters(in: .whitespaces).isEmpty else {
            throw AccessSDKError.invalidInput("deny requires a reason")
        }
        return try await transition(id: id, action: "deny", reason: reason)
    }

    public func cancelRequest(id: String, reason: String?) async throws -> AccessRequest {
        try await transition(id: id, action: "cancel", reason: reason)
    }

    public func provisionRequest(id: String) async throws -> AccessGrant {
        let env: GrantEnvelope = try await post(
            path: "/access-requests/\(try idPath(id))/provision",
            body: EmptyBody()
        )
        return env.grant
    }

    public func revokeGrant(id: String, reason: String?) async throws {
        let _: EmptyResponse = try await post(
            path: "/grants/\(try idPath(id))/revoke",
            body: DecisionBody(reason: reason),
            allowEmptyBody: true
        )
    }

    public func emergencyOffboard(userExternalID: String, reason: String?) async throws -> LeaverResult {
        let trimmed = userExternalID.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else {
            throw AccessSDKError.invalidInput("user_external_id is required")
        }
        do {
            let env: LeaverEnvelope = try await post(
                path: "/emergency-offboard",
                body: OffboardBody(userExternalID: trimmed, reason: reason)
            )
            return env.leaver
        } catch let AccessSDKError.http(statusCode, body) {
            // A partial failure is HTTP 500 carrying the SAME { leaver }
            // breakdown (workflows.go); recover it so the host can render which
            // layers failed instead of only a generic message.
            if let body, let data = body.data(using: .utf8),
               let env = try? Self.decoder().decode(LeaverEnvelope.self, from: data) {
                return env.leaver
            }
            throw AccessSDKError.http(statusCode: statusCode, body: body)
        }
    }

    private func transition(id: String, action: String, reason: String?) async throws -> AccessRequest {
        let env: RequestEnvelope = try await post(
            path: "/access-requests/\(try idPath(id))/\(action)",
            body: DecisionBody(reason: reason)
        )
        return env.request
    }

    // MARK: - Envelopes & helper bodies

    private struct EmptyBody: Encodable {}
    private struct EmptyResponse: Decodable { init() {}; init(from _: Decoder) throws {} }
    private struct DecisionBody: Encodable {
        let reason: String?
        func encode(to encoder: Encoder) throws {
            var c = encoder.container(keyedBy: CodingKeys.self)
            try c.encodeIfPresent(reason, forKey: .reason)
        }
        enum CodingKeys: String, CodingKey { case reason }
    }
    private struct RequestEnvelope: Decodable { let request: AccessRequest }
    private struct GrantEnvelope: Decodable { let grant: AccessGrant }
    private struct LeaverEnvelope: Decodable { let leaver: LeaverResult }

    private struct OffboardBody: Encodable {
        let userExternalID: String
        let reason: String?
        func encode(to encoder: Encoder) throws {
            var c = encoder.container(keyedBy: CodingKeys.self)
            try c.encode(userExternalID, forKey: .userExternalID)
            try c.encodeIfPresent(reason, forKey: .reason)
        }
        enum CodingKeys: String, CodingKey {
            case userExternalID = "user_external_id"
            case reason
        }
    }

    // The detail envelope reads the same `{request}` the request endpoint
    // returns plus the optional `risk` verdict and the `anomalies` array,
    // tolerating a missing/`null` array (parity with the list envelopes).
    private struct DetailEnvelope: Decodable {
        let request: AccessRequest
        let risk: RiskVerdict?
        let anomalies: [AnomalyFlag]
        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            request = try c.decode(AccessRequest.self, forKey: .request)
            risk = try c.decodeIfPresent(RiskVerdict.self, forKey: .risk)
            anomalies = try c.decodeIfPresent([AnomalyFlag].self, forKey: .anomalies) ?? []
        }
        enum CodingKeys: String, CodingKey { case request, risk, anomalies }
    }

    // The list envelopes decode a JSON `null` or a missing key to an empty
    // array rather than throwing. The current server always emits `[]` (GORM's
    // Find initialises the slice), but this keeps the iOS SDK as resilient as
    // the Android SDK, whose `optJSONArray` path already tolerates `null`.
    private struct RequestsEnvelope: Decodable {
        let requests: [AccessRequest]
        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            requests = try c.decodeIfPresent([AccessRequest].self, forKey: .requests) ?? []
        }
        enum CodingKeys: String, CodingKey { case requests }
    }
    private struct HistoryEnvelope: Decodable {
        let history: [StateHistoryEntry]
        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            history = try c.decodeIfPresent([StateHistoryEntry].self, forKey: .history) ?? []
        }
        enum CodingKeys: String, CodingKey { case history }
    }
    private struct CreateEnvelope: Decodable {
        let request: AccessRequest
        let workflow: WorkflowDecision?
    }

    private func idPath(_ id: String) throws -> String {
        let trimmed = id.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { throw AccessSDKError.invalidInput("id is required") }
        return trimmed
    }

    // MARK: - Transport primitives

    private func get<T: Decodable>(path: String) async throws -> T {
        var request = URLRequest(url: apiBase.appendingPathComponent(path.trimmingFirstSlash()))
        request.httpMethod = "GET"
        try await attachAuth(&request)
        return try await dispatch(request, allowEmptyBody: false)
    }

    private func post<T: Decodable, B: Encodable>(
        path: String,
        body: B,
        allowEmptyBody: Bool = false
    ) async throws -> T {
        var request = URLRequest(url: apiBase.appendingPathComponent(path.trimmingFirstSlash()))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        try await attachAuth(&request)
        do {
            request.httpBody = try JSONEncoder().encode(body)
        } catch {
            throw AccessSDKError.invalidInput("encode body: \(error)")
        }
        return try await dispatch(request, allowEmptyBody: allowEmptyBody)
    }

    private func attachAuth(_ request: inout URLRequest) async throws {
        let token: String
        do {
            token = try await authTokenProvider()
        } catch {
            throw AccessSDKError.unauthenticated
        }
        // Reject empty *and* whitespace-only tokens (parity with the Android
        // SDK's `isBlank()` check) so we fail closed locally instead of sending
        // a `Bearer    ` header and burning a round-trip on a guaranteed 401.
        guard !token.trimmingCharacters(in: .whitespaces).isEmpty else {
            throw AccessSDKError.unauthenticated
        }
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
    }

    private func dispatch<T: Decodable>(_ request: URLRequest, allowEmptyBody: Bool) async throws -> T {
        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await self.data(for: request)
        } catch {
            throw AccessSDKError.transport(String(describing: error))
        }
        guard let http = response as? HTTPURLResponse else {
            throw AccessSDKError.transport("non-HTTP response")
        }
        let body = String(data: data, encoding: .utf8)
        switch http.statusCode {
        case 401:
            throw AccessSDKError.unauthenticated
        case 403 where isStepUp(body):
            throw AccessSDKError.stepUpRequired(body)
        case 200..<300:
            break
        default:
            throw AccessSDKError.http(statusCode: http.statusCode, body: body)
        }

        if data.isEmpty, allowEmptyBody {
            if let empty = try? Self.decoder().decode(T.self, from: Data("{}".utf8)) {
                return empty
            }
        }
        do {
            return try Self.decoder().decode(T.self, from: data)
        } catch {
            throw AccessSDKError.decoding(String(describing: error))
        }
    }

    /// Portable `async` wrapper over `dataTask`. We do not use
    /// `URLSession.data(for:)` because it is unavailable in
    /// swift-corelibs-foundation on Linux; the continuation form behaves
    /// identically on Apple platforms and on Linux/CI.
    private func data(for request: URLRequest) async throws -> (Data, URLResponse) {
        try await withCheckedThrowingContinuation { continuation in
            let task = session.dataTask(with: request) { data, response, error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                guard let data, let response else {
                    continuation.resume(throwing: URLError(.badServerResponse))
                    return
                }
                continuation.resume(returning: (data, response))
            }
            task.resume()
        }
    }

    // A 403 is a step-up gate only when the canonical `{"error": "..."}`
    // envelope carries the RequireMFA marker; other 403s stay generic.
    private func isStepUp(_ body: String?) -> Bool {
        guard let body, !body.isEmpty else { return false }
        let message: String
        if let data = body.data(using: .utf8),
           let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let err = obj["error"] as? String {
            message = err
        } else {
            message = body
        }
        return message.lowercased().contains("step-up mfa")
    }

    /// JSON decoder configured to parse the RFC3339 timestamps the Go control
    /// plane emits, tolerating both fractional-second and whole-second forms.
    private static func decoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .custom { d in
            let raw = try d.singleValueContainer().decode(String.self)
            if let date = iso8601Fractional.date(from: raw) ?? iso8601Plain.date(from: raw) {
                return date
            }
            throw DecodingError.dataCorrupted(
                .init(codingPath: d.codingPath, debugDescription: "invalid RFC3339 timestamp: \(raw)")
            )
        }
        return decoder
    }

    private static let iso8601Fractional: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    private static let iso8601Plain: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f
    }()
}

private extension String {
    /// `appendingPathComponent` already inserts a separator, so strip our
    /// leading "/" to avoid an empty path segment.
    func trimmingFirstSlash() -> String {
        hasPrefix("/") ? String(dropFirst()) : self
    }
}
