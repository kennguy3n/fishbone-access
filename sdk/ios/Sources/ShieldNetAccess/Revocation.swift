//
// Revocation.swift — one-tap revoke models + step-up planning (iOS, WS5).
//
// Two server-side revoke paths exist, both reachable through ``AccessClient``:
//
//   - Grant revoke  — `POST /api/v1/grants/:id/revoke` ends a single JIT lease
//     early. Permission-gated only (`PermGrantRevoke`); NOT step-up-gated
//     server-side, so the *client* is responsible for requiring step-up on a
//     high-risk revoke (see ``Revocation/plan(_:)-detail``).
//   - Kill switch   — `POST /api/v1/emergency-offboard` runs the six-layer
//     leaver kill switch for one identity. Step-up-MFA-gated server-side
//     (`RequireMFA`): a token without a satisfied MFA claim is rejected with
//     403 and surfaces as ``AccessSDKError/stepUpRequired(_:)``.
//
// `LeaverResult` mirrors `lifecycle.LeaverResult` / the `LeaverResult` schema
// in `docs/openapi.yaml`; `Revocation` is a pure helper that decides whether a
// revoke should be gated behind step-up MFA so the UX is consistent with the
// web console and Android. Kept byte-for-byte compatible with
// `sdk/android/.../Revocation.kt`.
//

import Foundation

/// One of the six ordered layers the leaver kill switch attempts. Mirrors the
/// `layer` enum in the `LeaverResult` schema (`docs/openapi.yaml`).
public enum KillSwitchLayer: String, Codable, CaseIterable, Sendable {
    case grantRevoke = "grant_revoke"
    case teamRemove = "team_remove"
    case iamCoreDisable = "iam_core_disable"
    case sessionRevoke = "session_revoke"
    case scimDeprovision = "scim_deprovision"
    case identityDisable = "identity_disable"
}

/// Per-layer outcome of the kill switch.
public enum KillSwitchLayerStatus: String, Codable, CaseIterable, Sendable {
    case done
    case skipped
    case failed
}

/// Outcome of a single kill-switch layer; `detail` explains a skip/failure.
public struct KillSwitchLayerResult: Codable, Sendable, Equatable {
    public let layer: KillSwitchLayer
    public let status: KillSwitchLayerStatus
    public let detail: String?

    enum CodingKeys: String, CodingKey {
        case layer
        case status
        case detail
    }

    public init(layer: KillSwitchLayer, status: KillSwitchLayerStatus, detail: String? = nil) {
        self.layer = layer
        self.status = status
        self.detail = detail
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        layer = try c.decode(KillSwitchLayer.self, forKey: .layer)
        status = try c.decode(KillSwitchLayerStatus.self, forKey: .status)
        detail = try c.decodeIfPresent(String.self, forKey: .detail)
    }
}

/// Aggregated outcome of the six-layer leaver kill switch
/// (``AccessClient/emergencyOffboard(userExternalID:reason:)``). Every layer is
/// attempted even if an earlier one fails; `errored` is true when any layer
/// reported ``KillSwitchLayerStatus/failed``. The server returns the SAME
/// breakdown on a partial failure (HTTP 500), so the host can always render
/// per-layer detail.
public struct LeaverResult: Codable, Sendable, Equatable {
    public let userExternalID: String
    public let errored: Bool
    public let layers: [KillSwitchLayerResult]

    enum CodingKeys: String, CodingKey {
        case userExternalID = "user_external_id"
        case errored
        case layers
    }

    public init(userExternalID: String, errored: Bool, layers: [KillSwitchLayerResult] = []) {
        self.userExternalID = userExternalID
        self.errored = errored
        self.layers = layers
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        userExternalID = try c.decode(String.self, forKey: .userExternalID)
        errored = try c.decodeIfPresent(Bool.self, forKey: .errored) ?? false
        layers = try c.decodeIfPresent([KillSwitchLayerResult].self, forKey: .layers) ?? []
    }

    /// Layers that failed — the actionable subset for an operator to retry.
    public var failedLayers: [KillSwitchLayerResult] {
        layers.filter { $0.status == .failed }
    }
}

/// The decision of how to drive a revoke from the client.
///
/// - `requiresStepUp` — the host must ensure the session has satisfied step-up
///   MFA (via ``Identity/mfaSatisfied`` / an iam-core re-auth) BEFORE calling
///   the revoke, mirroring the web console which disables the control until MFA
///   is satisfied. The kill-switch path is additionally enforced server-side.
/// - `advisory` — the risk summary that drove the decision.
public struct RevocationPlan: Sendable, Equatable {
    public let requiresStepUp: Bool
    public let advisory: RiskAdvisory

    public init(requiresStepUp: Bool, advisory: RiskAdvisory) {
        self.requiresStepUp = requiresStepUp
        self.advisory = advisory
    }
}

/// Pure step-up planning for a revoke. The SDK never performs MFA itself; this
/// just tells the host whether to gate the revoke so high-risk revocations get
/// the same step-up treatment on every platform.
///
/// A high-risk revoke (``RiskAdvisory/isHighRisk``) requires step-up. The
/// authoritative gate still lives on the server for the kill switch — even if
/// a host skips this check,
/// ``AccessClient/emergencyOffboard(userExternalID:reason:)`` surfaces
/// ``AccessSDKError/stepUpRequired(_:)`` when the token lacks the MFA claim.
public enum Revocation {
    /// Plan a revoke from a full ``AccessRequestDetail``.
    public static func plan(_ detail: AccessRequestDetail) -> RevocationPlan {
        plan(RiskAssessment.evaluate(detail))
    }

    /// Plan a revoke from a pre-computed ``RiskAdvisory``.
    public static func plan(_ advisory: RiskAdvisory) -> RevocationPlan {
        RevocationPlan(requiresStepUp: advisory.isHighRisk, advisory: advisory)
    }
}
