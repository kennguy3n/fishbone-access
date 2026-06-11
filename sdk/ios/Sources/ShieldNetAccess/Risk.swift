//
// Risk.swift — risky-access awareness models + classification (iOS, WS5).
//
// The ShieldNet Access control plane already computes an AI risk verdict and
// advisory anomaly flags server-side (there is NO on-device inference). The
// request-detail endpoint surfaces them:
//
//   GET /api/v1/access-requests/:id  ->  { request, risk, anomalies }
//
// These `Codable` value types mirror `AccessRiskVerdict` /
// `AccessRequestAnomalyFlag` in `docs/openapi.yaml` (and
// `internal/models/risk.go`) and are kept byte-for-byte compatible with the
// Kotlin models in `sdk/android/.../Risk.kt`.
//
// `RiskAssessment` turns those raw signals into a single, host-renderable
// `RiskAdvisory` so an SME app can surface anomalous / high-risk *active*
// access and offer a one-tap revoke. The classification is a pure function
// (no I/O), so it is identical across iOS and Android.
//

import Foundation

/// Routing-facing verdict produced by the server-side risk review. Mirrors the
/// `recommendation` enum in `docs/openapi.yaml`.
public enum RiskRecommendation: String, Codable, CaseIterable, Sendable {
    case autoApproveEligible = "auto_approve_eligible"
    case needsReview = "needs_review"
    case highRisk = "high_risk"
}

/// One immutable AI risk assessment of a request, persisted for audit. Mirrors
/// `models.AccessRiskVerdict`. `degraded` is true when the AI agent was
/// unreachable and the fail-open fallback supplied the verdict (which is never
/// ``RiskRecommendation/autoApproveEligible``).
public struct RiskVerdict: Codable, Identifiable, Sendable, Equatable {
    public let id: String
    public let requestID: String
    public let score: RiskLevel
    public let recommendation: RiskRecommendation
    public let factors: [String]
    public let rationale: String?
    public let source: String?
    public let degraded: Bool
    public let createdAt: Date?

    enum CodingKeys: String, CodingKey {
        case id
        case requestID = "request_id"
        case score
        case recommendation
        case factors
        case rationale
        case source
        case degraded
        case createdAt = "created_at"
    }

    public init(
        id: String,
        requestID: String,
        score: RiskLevel,
        recommendation: RiskRecommendation,
        factors: [String] = [],
        rationale: String? = nil,
        source: String? = nil,
        degraded: Bool = false,
        createdAt: Date? = nil
    ) {
        self.id = id
        self.requestID = requestID
        self.score = score
        self.recommendation = recommendation
        self.factors = factors
        self.rationale = rationale
        self.source = source
        self.degraded = degraded
        self.createdAt = createdAt
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        requestID = try c.decode(String.self, forKey: .requestID)
        score = try c.decode(RiskLevel.self, forKey: .score)
        recommendation = try c.decode(RiskRecommendation.self, forKey: .recommendation)
        factors = try c.decodeIfPresent([String].self, forKey: .factors) ?? []
        rationale = try c.decodeIfPresent(String.self, forKey: .rationale)
        source = try c.decodeIfPresent(String.self, forKey: .source)
        degraded = try c.decodeIfPresent(Bool.self, forKey: .degraded) ?? false
        createdAt = try c.decodeIfPresent(Date.self, forKey: .createdAt)
    }
}

/// One advisory anomaly observation surfaced against an approved elevation.
/// Mirrors `models.AccessRequestAnomalyFlag`. Anomaly detection is advisory —
/// a flag never changes the request's state — so these are signals for a human
/// reviewer, not an enforcement gate. `severity` is a free-form server string
/// (`low` / `medium` / `high` / `critical`); use ``isElevated`` for a
/// forward-compatible "high or critical" check rather than matching literals.
public struct AnomalyFlag: Codable, Identifiable, Sendable, Equatable {
    public let id: String
    public let requestID: String
    public let grantID: String?
    public let kind: String
    public let severity: String?
    public let reason: String?
    public let confidence: Double?
    public let createdAt: Date?

    enum CodingKeys: String, CodingKey {
        case id
        case requestID = "request_id"
        case grantID = "grant_id"
        case kind
        case severity
        case reason
        case confidence
        case createdAt = "created_at"
    }

    public init(
        id: String,
        requestID: String,
        grantID: String? = nil,
        kind: String,
        severity: String? = nil,
        reason: String? = nil,
        confidence: Double? = nil,
        createdAt: Date? = nil
    ) {
        self.id = id
        self.requestID = requestID
        self.grantID = grantID
        self.kind = kind
        self.severity = severity
        self.reason = reason
        self.confidence = confidence
        self.createdAt = createdAt
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        requestID = try c.decode(String.self, forKey: .requestID)
        grantID = try c.decodeIfPresent(String.self, forKey: .grantID)
        kind = try c.decode(String.self, forKey: .kind)
        severity = try c.decodeIfPresent(String.self, forKey: .severity)
        reason = try c.decodeIfPresent(String.self, forKey: .reason)
        confidence = try c.decodeIfPresent(Double.self, forKey: .confidence)
        createdAt = try c.decodeIfPresent(Date.self, forKey: .createdAt)
    }

    /// True when the flag is a `high`/`critical` severity (case-insensitive).
    public var isElevated: Bool {
        guard let severity = severity?.lowercased() else { return false }
        return severity == "high" || severity == "critical"
    }
}

/// The full risk picture for one request, returned by
/// `GET /api/v1/access-requests/:id` (`{ request, risk, anomalies }`). `risk`
/// is nil until the request has been scored; `anomalies` is empty until an
/// approved elevation has been analysed.
public struct AccessRequestDetail: Sendable, Equatable {
    public let request: AccessRequest
    public let risk: RiskVerdict?
    public let anomalies: [AnomalyFlag]

    public init(request: AccessRequest, risk: RiskVerdict? = nil, anomalies: [AnomalyFlag] = []) {
        self.request = request
        self.risk = risk
        self.anomalies = anomalies
    }
}

/// A host-renderable risk summary for a piece of access, derived purely from
/// the server's signals by ``RiskAssessment``.
///
/// - `isHighRisk` — the access warrants a step-up-gated, urgent revoke.
/// - `isElevated` — worth surfacing for awareness even if not yet high-risk.
/// - `reasons` — short, human-readable justifications for a banner / toast.
/// - `anomalyCount` — number of advisory anomaly flags backing this summary.
public struct RiskAdvisory: Sendable, Equatable {
    public let isHighRisk: Bool
    public let isElevated: Bool
    public let reasons: [String]
    public let anomalyCount: Int

    public init(isHighRisk: Bool, isElevated: Bool, reasons: [String], anomalyCount: Int) {
        self.isHighRisk = isHighRisk
        self.isElevated = isElevated
        self.reasons = reasons
        self.anomalyCount = anomalyCount
    }
}

/// Pure classification of the server's risk signals into a ``RiskAdvisory``.
///
/// Severity is the union of three independent signals so a host never has to
/// combine them itself: the request's coarse band, the latest AI verdict
/// (score band + routing recommendation), and any advisory anomaly flags.
/// "High risk" is fail-safe: ANY one high signal is enough. This is the
/// cross-platform source of truth for which active access to surface and which
/// revokes to gate behind step-up MFA (see ``Revocation``).
public enum RiskAssessment {
    /// Evaluate a full ``AccessRequestDetail``.
    public static func evaluate(_ detail: AccessRequestDetail) -> RiskAdvisory {
        evaluate(request: detail.request, verdict: detail.risk, anomalies: detail.anomalies)
    }

    /// Evaluate the raw signals directly (request band + verdict + anomalies).
    public static func evaluate(
        request: AccessRequest,
        verdict: RiskVerdict?,
        anomalies: [AnomalyFlag] = []
    ) -> RiskAdvisory {
        var reasons: [String] = []

        // 1. Coarse request band.
        switch request.riskLevel {
        case .high: reasons.append("AI risk band: high")
        case .medium: reasons.append("AI risk band: medium")
        default: break
        }

        // 2. Latest AI verdict (band + routing recommendation).
        if let verdict {
            if verdict.score == .high && request.riskLevel != .high {
                reasons.append("AI verdict score: high")
            } else if verdict.score == .medium && request.riskLevel != .medium {
                // A medium verdict score is an `isElevated` trigger, so it must
                // contribute a reason — otherwise an elevated advisory could
                // render with an empty justification ("Risky active access — .").
                reasons.append("AI verdict score: medium")
            }
            switch verdict.recommendation {
            case .highRisk: reasons.append("Recommendation: high risk")
            case .needsReview: reasons.append("Recommendation: needs review")
            case .autoApproveEligible: break
            }
            if verdict.degraded { reasons.append("AI scoring degraded (fail-open)") }
        }

        // 3. Advisory anomaly flags.
        let elevatedAnomalies = anomalies.filter { $0.isElevated }.count
        if elevatedAnomalies > 0 {
            reasons.append("Anomalies (high): \(elevatedAnomalies)")
        } else if !anomalies.isEmpty {
            reasons.append("Anomalies: \(anomalies.count)")
        }

        let isHighRisk =
            request.riskLevel == .high ||
            verdict?.score == .high ||
            verdict?.recommendation == .highRisk ||
            elevatedAnomalies > 0

        let isElevated =
            isHighRisk ||
            request.riskLevel == .medium ||
            verdict?.score == .medium ||
            verdict?.recommendation == .needsReview ||
            !anomalies.isEmpty

        return RiskAdvisory(
            isHighRisk: isHighRisk,
            isElevated: isElevated,
            reasons: reasons,
            anomalyCount: anomalies.count
        )
    }
}
