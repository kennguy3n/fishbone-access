//
// Models.swift — typed wire models for the ShieldNet Access mobile SDK (iOS).
//
// These `Codable` value types mirror the JSON the ShieldNet Access control
// plane (`cmd/ztna-api`) emits on its `/api/v1` surface, and are kept
// byte-for-byte compatible with the Kotlin models in
// `sdk/android/src/main/kotlin/com/shieldnet/access/Models.kt`. Field names
// follow the Go GORM models in `internal/models/models.go` and the canonical
// `docs/openapi.yaml`.
//
// There is NO on-device inference in this SDK. No `import CoreML`, no
// `import MLX`, no bundled model files (`.mlmodel`, `.tflite`, `.onnx`,
// `.gguf`). The "AI risk verdict" the approver sees is computed server-side
// (the access-ai-agent, WS5) and surfaced here only as the persisted
// `AccessRequest.riskLevel` / `riskFactors` fields and the `WorkflowDecision`.
//

import Foundation

/// Lifecycle state of an ``AccessRequest``. Values mirror the Go-side
/// constants in `internal/services/lifecycle/state_machine.go`.
public enum AccessRequestState: String, Codable, CaseIterable, Sendable {
    case requested
    case approved
    case denied
    case cancelled
    case provisioning
    case provisioned
    case provisionFailed = "provision_failed"
    case active
    case revoked
    case expired
}

/// Coarse risk bucket carried on an ``AccessRequest``. Mirrors the
/// `risk_level` enum understood by the router in
/// `internal/services/lifecycle/workflow_service.go`. Populated server-side
/// by the access-ai-agent risk review (WS5); the SDK only reads it.
public enum RiskLevel: String, Codable, CaseIterable, Sendable {
    case low
    case medium
    case high
}

/// Workflow lane a freshly-created request is routed into — the
/// human-readable surface of the server-side risk verdict. Mirrors the
/// `step_type` enum in `lifecycle.WorkflowDecision`.
public enum WorkflowStep: String, Codable, CaseIterable, Sendable {
    case autoApprove = "auto_approve"
    case managerApproval = "manager_approval"
    case securityReview = "security_review"
}

/// Lifecycle state of an ``AccessGrant`` (a JIT lease). Mirrors the
/// `GrantState*` constants in `internal/services/lifecycle/provisioning_service.go`.
public enum GrantState: String, Codable, CaseIterable, Sendable {
    case active
    case revoked
    case expired
}

/// Resolved identity + tenant for the bearer token, returned by `GET /me`.
/// Tenancy is derived solely from the validated iam-core token claim.
///
/// `mfaSatisfied` reflects whether the session behind the token completed
/// step-up MFA / WebAuthn at iam-core (the `amr`/`mfa` claim). High-risk,
/// data-plane-mutating routes require it; see ``AccessSDKError/stepUpRequired(_:)``.
public struct Identity: Codable, Sendable, Equatable {
    public let userID: String
    public let tenantID: String
    public let roles: [String]
    public let scopes: [String]
    public let mfaSatisfied: Bool

    enum CodingKeys: String, CodingKey {
        case userID = "user_id"
        case tenantID = "tenant_id"
        case roles
        case scopes
        case mfaSatisfied = "mfa_satisfied"
    }

    public init(
        userID: String,
        tenantID: String,
        roles: [String] = [],
        scopes: [String] = [],
        mfaSatisfied: Bool = false
    ) {
        self.userID = userID
        self.tenantID = tenantID
        self.roles = roles
        self.scopes = scopes
        self.mfaSatisfied = mfaSatisfied
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        userID = try c.decode(String.self, forKey: .userID)
        tenantID = try c.decodeIfPresent(String.self, forKey: .tenantID) ?? ""
        roles = try c.decodeIfPresent([String].self, forKey: .roles) ?? []
        scopes = try c.decodeIfPresent([String].self, forKey: .scopes) ?? []
        mfaSatisfied = try c.decodeIfPresent(Bool.self, forKey: .mfaSatisfied) ?? false
    }
}

/// Input for ``AccessClient/createRequest(_:)``. Mirrors the
/// `CreateAccessRequest` schema. The actor (requester) and workspace are
/// derived server-side from the validated token + tenant context and must
/// NOT be supplied here.
public struct CreateAccessRequest: Codable, Sendable, Equatable {
    public let targetUserID: String
    public let resourceRef: String
    public let connectorID: String?
    public let role: String?
    public let justification: String?
    public let riskLevel: RiskLevel?
    public let riskFactors: [String]

    enum CodingKeys: String, CodingKey {
        case targetUserID = "target_user_id"
        case resourceRef = "resource_ref"
        case connectorID = "connector_id"
        case role
        case justification
        case riskLevel = "risk_level"
        case riskFactors = "risk_factors"
    }

    public init(
        targetUserID: String,
        resourceRef: String,
        connectorID: String? = nil,
        role: String? = nil,
        justification: String? = nil,
        riskLevel: RiskLevel? = nil,
        riskFactors: [String] = []
    ) {
        self.targetUserID = targetUserID
        self.resourceRef = resourceRef
        self.connectorID = connectorID
        self.role = role
        self.justification = justification
        self.riskLevel = riskLevel
        self.riskFactors = riskFactors
    }

    /// Encode omitting empty optionals / arrays so the wire payload matches
    /// the Go handler's `binding` expectations (no empty `risk_factors`).
    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(targetUserID, forKey: .targetUserID)
        try c.encode(resourceRef, forKey: .resourceRef)
        try c.encodeIfPresent(connectorID, forKey: .connectorID)
        try c.encodeIfPresent(role, forKey: .role)
        try c.encodeIfPresent(justification, forKey: .justification)
        try c.encodeIfPresent(riskLevel, forKey: .riskLevel)
        if !riskFactors.isEmpty {
            try c.encode(riskFactors, forKey: .riskFactors)
        }
    }
}

/// Persisted access/elevation request. Mirrors `models.AccessRequest`.
public struct AccessRequest: Codable, Identifiable, Sendable, Equatable {
    public let id: String
    public let workspaceID: String
    public let requesterID: String
    public let targetUserID: String?
    public let connectorID: String?
    public let resourceRef: String
    public let role: String?
    public let justification: String?
    public let state: AccessRequestState
    public let riskLevel: RiskLevel?
    public let riskFactors: [String]
    public let expiresAt: Date?
    public let createdAt: Date
    public let updatedAt: Date?

    enum CodingKeys: String, CodingKey {
        case id
        case workspaceID = "workspace_id"
        case requesterID = "requester_id"
        case targetUserID = "target_user_id"
        case connectorID = "connector_id"
        case resourceRef = "resource_ref"
        case role
        case justification
        case state
        case riskLevel = "risk_level"
        case riskFactors = "risk_factors"
        case expiresAt = "expires_at"
        case createdAt = "created_at"
        case updatedAt = "updated_at"
    }

    public init(
        id: String,
        workspaceID: String,
        requesterID: String,
        targetUserID: String? = nil,
        connectorID: String? = nil,
        resourceRef: String,
        role: String? = nil,
        justification: String? = nil,
        state: AccessRequestState,
        riskLevel: RiskLevel? = nil,
        riskFactors: [String] = [],
        expiresAt: Date? = nil,
        createdAt: Date,
        updatedAt: Date? = nil
    ) {
        self.id = id
        self.workspaceID = workspaceID
        self.requesterID = requesterID
        self.targetUserID = targetUserID
        self.connectorID = connectorID
        self.resourceRef = resourceRef
        self.role = role
        self.justification = justification
        self.state = state
        self.riskLevel = riskLevel
        self.riskFactors = riskFactors
        self.expiresAt = expiresAt
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        workspaceID = try c.decode(String.self, forKey: .workspaceID)
        requesterID = try c.decode(String.self, forKey: .requesterID)
        targetUserID = try c.decodeIfPresent(String.self, forKey: .targetUserID)
        connectorID = try c.decodeIfPresent(String.self, forKey: .connectorID)
        resourceRef = try c.decode(String.self, forKey: .resourceRef)
        role = try c.decodeIfPresent(String.self, forKey: .role)
        justification = try c.decodeIfPresent(String.self, forKey: .justification)
        state = try c.decode(AccessRequestState.self, forKey: .state)
        riskLevel = try c.decodeIfPresent(RiskLevel.self, forKey: .riskLevel)
        riskFactors = try c.decodeIfPresent([String].self, forKey: .riskFactors) ?? []
        expiresAt = try c.decodeIfPresent(Date.self, forKey: .expiresAt)
        createdAt = try c.decode(Date.self, forKey: .createdAt)
        updatedAt = try c.decodeIfPresent(Date.self, forKey: .updatedAt)
    }
}

/// Risk-based routing outcome returned alongside a newly-created request.
/// Mirrors `lifecycle.WorkflowDecision`.
public struct WorkflowDecision: Codable, Sendable, Equatable {
    public let stepType: WorkflowStep
    public let reason: String
    public let approved: Bool

    enum CodingKeys: String, CodingKey {
        case stepType = "step_type"
        case reason
        case approved
    }

    public init(stepType: WorkflowStep, reason: String, approved: Bool) {
        self.stepType = stepType
        self.reason = reason
        self.approved = approved
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        stepType = try c.decode(WorkflowStep.self, forKey: .stepType)
        reason = try c.decodeIfPresent(String.self, forKey: .reason) ?? ""
        approved = try c.decodeIfPresent(Bool.self, forKey: .approved) ?? false
    }
}

/// Result of ``AccessClient/createRequest(_:)``: the persisted `request`
/// plus the `workflow` routing decision (`nil` only if the server omitted it).
public struct RequestSubmission: Sendable, Equatable {
    public let request: AccessRequest
    public let workflow: WorkflowDecision?

    public init(request: AccessRequest, workflow: WorkflowDecision? = nil) {
        self.request = request
        self.workflow = workflow
    }
}

/// One immutable state-transition record for a request. Mirrors
/// `models.AccessRequestStateHistory`.
public struct StateHistoryEntry: Codable, Identifiable, Sendable, Equatable {
    public let id: String
    public let requestID: String
    public let fromState: String
    public let toState: String
    public let actor: String?
    public let reason: String?
    public let createdAt: Date

    enum CodingKeys: String, CodingKey {
        case id
        case requestID = "request_id"
        case fromState = "from_state"
        case toState = "to_state"
        case actor
        case reason
        case createdAt = "created_at"
    }

    public init(
        id: String,
        requestID: String,
        fromState: String,
        toState: String,
        actor: String? = nil,
        reason: String? = nil,
        createdAt: Date
    ) {
        self.id = id
        self.requestID = requestID
        self.fromState = fromState
        self.toState = toState
        self.actor = actor
        self.reason = reason
        self.createdAt = createdAt
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        requestID = try c.decode(String.self, forKey: .requestID)
        fromState = try c.decodeIfPresent(String.self, forKey: .fromState) ?? ""
        toState = try c.decode(String.self, forKey: .toState)
        actor = try c.decodeIfPresent(String.self, forKey: .actor)
        reason = try c.decodeIfPresent(String.self, forKey: .reason)
        createdAt = try c.decode(Date.self, forKey: .createdAt)
    }
}

/// An active upstream grant — the JIT lease (WS4) materialised when an
/// approved request is provisioned. Mirrors `models.AccessGrant`.
public struct AccessGrant: Codable, Identifiable, Sendable, Equatable {
    public let id: String
    public let workspaceID: String
    public let requestID: String?
    public let connectorID: String?
    public let iamCoreUserID: String
    public let resourceRef: String
    public let role: String?
    public let state: GrantState
    public let grantedAt: Date?
    public let expiresAt: Date?
    public let revokedAt: Date?

    enum CodingKeys: String, CodingKey {
        case id
        case workspaceID = "workspace_id"
        case requestID = "request_id"
        case connectorID = "connector_id"
        case iamCoreUserID = "iam_core_user_id"
        case resourceRef = "resource_ref"
        case role
        case state
        case grantedAt = "granted_at"
        case expiresAt = "expires_at"
        case revokedAt = "revoked_at"
    }

    public init(
        id: String,
        workspaceID: String,
        requestID: String? = nil,
        connectorID: String? = nil,
        iamCoreUserID: String,
        resourceRef: String,
        role: String? = nil,
        state: GrantState,
        grantedAt: Date? = nil,
        expiresAt: Date? = nil,
        revokedAt: Date? = nil
    ) {
        self.id = id
        self.workspaceID = workspaceID
        self.requestID = requestID
        self.connectorID = connectorID
        self.iamCoreUserID = iamCoreUserID
        self.resourceRef = resourceRef
        self.role = role
        self.state = state
        self.grantedAt = grantedAt
        self.expiresAt = expiresAt
        self.revokedAt = revokedAt
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        workspaceID = try c.decode(String.self, forKey: .workspaceID)
        requestID = try c.decodeIfPresent(String.self, forKey: .requestID)
        connectorID = try c.decodeIfPresent(String.self, forKey: .connectorID)
        iamCoreUserID = try c.decode(String.self, forKey: .iamCoreUserID)
        resourceRef = try c.decode(String.self, forKey: .resourceRef)
        role = try c.decodeIfPresent(String.self, forKey: .role)
        state = try c.decode(GrantState.self, forKey: .state)
        grantedAt = try c.decodeIfPresent(Date.self, forKey: .grantedAt)
        expiresAt = try c.decodeIfPresent(Date.self, forKey: .expiresAt)
        revokedAt = try c.decodeIfPresent(Date.self, forKey: .revokedAt)
    }

    /// Seconds left on the lease relative to `now`, never negative. Returns
    /// `nil` for a non-expiring grant; returns `0` once the lease has lapsed.
    /// Pure clock arithmetic — it does not re-check `state` against the server.
    public func remaining(now: Date = Date()) -> TimeInterval? {
        guard let expiresAt else { return nil }
        return max(0, expiresAt.timeIntervalSince(now))
    }

    /// True when the grant is `.active` and either has no expiry or has not
    /// yet lapsed at `now`. Fail-closed: a revoked grant is never active even
    /// if its `expiresAt` is in the future.
    public func isActive(now: Date = Date()) -> Bool {
        guard state == .active else { return false }
        guard let expiresAt else { return true }
        return now < expiresAt
    }
}
