//
// AccessClient.swift — ShieldNet Access mobile SDK contract (iOS).
//
// A thin, well-typed REST client over the ShieldNet Access control-plane
// `/api/v1` surface. Every method maps 1:1 to an endpoint registered in
// `internal/handlers/lifecycle.go` / `router.go` and documented in
// `docs/openapi.yaml`. This protocol mirrors the Kotlin `AccessClient`
// interface in `sdk/android` method-for-method.
//
// Endpoint mapping:
//   me               → GET    /api/v1/me
//   createRequest    → POST   /api/v1/access-requests
//   listRequests     → GET    /api/v1/access-requests
//   getRequest       → GET    /api/v1/access-requests/:id
//   requestHistory   → GET    /api/v1/access-requests/:id/history
//   approveRequest   → POST   /api/v1/access-requests/:id/approve
//   denyRequest      → POST   /api/v1/access-requests/:id/deny
//   cancelRequest    → POST   /api/v1/access-requests/:id/cancel
//   provisionRequest → POST   /api/v1/access-requests/:id/provision
//   revokeGrant      → POST   /api/v1/grants/:id/revoke
//
// There is NO on-device inference. AI risk review (WS5) is server-side; the
// SDK only reads the resulting `AccessRequest.riskLevel` / `riskFactors` and
// the `WorkflowDecision`.
//

import Foundation

/// Typed error surface for SDK consumers. Concrete clients throw these so host
/// applications can branch on them in a type-safe way (e.g. drive a step-up
/// flow on ``stepUpRequired(_:)``, retry on ``transport(_:)``).
public enum AccessSDKError: Error, Sendable, Equatable {
    /// Network / transport failure (timeouts, DNS, TLS).
    case transport(String)

    /// Non-2xx HTTP response. `body` is the raw response body if present
    /// (the canonical `{"error": "..."}` envelope from the Gin handlers).
    /// 401 and step-up-403 are surfaced as the dedicated cases below.
    case http(statusCode: Int, body: String?)

    /// Response body could not be decoded into the expected model.
    case decoding(String)

    /// Caller-side invariant violation (e.g. blank request id).
    case invalidInput(String)

    /// The caller is not authenticated (HTTP 401, or no token available).
    case unauthenticated

    /// The action requires a step-up-MFA-satisfied token but the current one
    /// does not carry it (HTTP 403 "step-up MFA required"). The host should
    /// drive an iam-core step-up (WebAuthn / OTP), obtain a fresh token, and
    /// retry. The associated value is the raw server error body.
    case stepUpRequired(String?)

    /// The host application has not configured the SDK (base URL / token).
    case notConfigured
}

/// Async REST surface for the ShieldNet Access control plane.
///
/// Concrete implementations (e.g. ``URLSessionAccessClient``) bind to
/// `URLSession` and serialize / deserialize the `Models.swift` types.
public protocol AccessClient: Sendable {
    /// Resolve the caller's identity and tenant (`GET /me`). Use
    /// ``Identity/mfaSatisfied`` to decide up-front whether a step-up will be
    /// needed for a high-risk action.
    func me() async throws -> Identity

    /// Submit an access / elevation request (`POST /access-requests`). The
    /// server runs risk-based routing and returns both the persisted request
    /// and the ``WorkflowDecision``.
    func createRequest(_ input: CreateAccessRequest) async throws -> RequestSubmission

    /// List the access requests visible in the caller's workspace
    /// (`GET /access-requests`).
    func listRequests() async throws -> [AccessRequest]

    /// Fetch a single request by id (`GET /access-requests/:id`) — used to
    /// poll status and read the lease countdown via `expiresAt`.
    func getRequest(id: String) async throws -> AccessRequest

    /// Fetch the immutable state-transition history of a request
    /// (`GET /access-requests/:id/history`).
    func requestHistory(id: String) async throws -> [StateHistoryEntry]

    /// Approve a pending request as an approver. The returned row surfaces the
    /// server's AI risk verdict via `riskLevel` / `riskFactors`.
    /// (`POST /access-requests/:id/approve`, optional `{ reason }`.)
    func approveRequest(id: String, reason: String?) async throws -> AccessRequest

    /// Deny a pending request with an approver-supplied reason
    /// (`POST /access-requests/:id/deny`, `{ reason }`).
    func denyRequest(id: String, reason: String) async throws -> AccessRequest

    /// Cancel one's own pending request
    /// (`POST /access-requests/:id/cancel`, optional `{ reason }`).
    func cancelRequest(id: String, reason: String?) async throws -> AccessRequest

    /// Provision an approved request, materialising the JIT lease (the
    /// returned ``AccessGrant``). `POST /access-requests/:id/provision`.
    func provisionRequest(id: String) async throws -> AccessGrant

    /// Revoke a grant (end the JIT lease early; idempotent server-side).
    /// `POST /grants/:id/revoke`, optional `{ reason }`.
    func revokeGrant(id: String, reason: String?) async throws
}

// Default-argument conveniences so callers can omit `reason`.
public extension AccessClient {
    func approveRequest(id: String) async throws -> AccessRequest {
        try await approveRequest(id: id, reason: nil)
    }

    func cancelRequest(id: String) async throws -> AccessRequest {
        try await cancelRequest(id: id, reason: nil)
    }

    func revokeGrant(id: String) async throws {
        try await revokeGrant(id: id, reason: nil)
    }
}
