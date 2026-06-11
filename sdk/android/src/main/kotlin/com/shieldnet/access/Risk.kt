/*
 * Risk.kt — risky-access awareness models + classification (Android, WS5).
 *
 * The ShieldNet Access control plane already computes an AI risk verdict and
 * advisory anomaly flags server-side (there is NO on-device inference). The
 * request-detail endpoint surfaces them:
 *
 *   GET /api/v1/access-requests/:id  ->  { request, risk, anomalies }
 *
 * These types mirror `AccessRiskVerdict` / `AccessRequestAnomalyFlag` in
 * `docs/openapi.yaml` (and `internal/models/risk.go`) and are kept
 * byte-for-byte compatible with the Swift models in
 * `sdk/ios/Sources/ShieldNetAccess/Risk.swift`.
 *
 * [RiskAssessment] turns those raw signals into a single, host-renderable
 * [RiskAdvisory] so an SME app can surface anomalous / high-risk *active*
 * access and offer a one-tap revoke — without re-deriving the severity logic
 * at every call site. The classification is a pure function (no I/O), so it is
 * trivially unit-tested and identical across Android and iOS.
 */
package com.shieldnet.access

import java.time.Instant

/**
 * Routing-facing verdict produced by the server-side risk review. Mirrors the
 * `recommendation` enum in `docs/openapi.yaml`
 * (`auto_approve_eligible` / `needs_review` / `high_risk`).
 */
enum class RiskRecommendation(val wireValue: String) {
    AUTO_APPROVE_ELIGIBLE("auto_approve_eligible"),
    NEEDS_REVIEW("needs_review"),
    HIGH_RISK("high_risk");

    companion object {
        @JvmStatic
        fun fromWire(value: String): RiskRecommendation =
            entries.firstOrNull { it.wireValue == value }
                ?: throw AccessSDKException.Decoding("unknown risk recommendation: $value")
    }
}

/**
 * One immutable AI risk assessment of a request, persisted for audit. Mirrors
 * `models.AccessRiskVerdict`. [degraded] is true when the AI agent was
 * unreachable and the fail-open fallback supplied the verdict (which is never
 * [RiskRecommendation.AUTO_APPROVE_ELIGIBLE]) — surface it so an operator can
 * tell an AI-derived score from a degraded one.
 */
data class RiskVerdict(
    val id: String,
    val requestId: String,
    val score: RiskLevel,
    val recommendation: RiskRecommendation,
    val factors: List<String> = emptyList(),
    val rationale: String? = null,
    val source: String? = null,
    val degraded: Boolean = false,
    val createdAt: Instant? = null,
)

/**
 * One advisory anomaly observation surfaced against an approved elevation.
 * Mirrors `models.AccessRequestAnomalyFlag`. Anomaly detection is advisory —
 * a flag never changes the request's state — so these are signals for a human
 * reviewer, not an enforcement gate. [severity] is a free-form server string
 * (`low` / `medium` / `high` / `critical`); use [isElevated] for a
 * forward-compatible "high or critical" check rather than matching literals.
 */
data class AnomalyFlag(
    val id: String,
    val requestId: String,
    val grantId: String? = null,
    val kind: String,
    val severity: String? = null,
    val reason: String? = null,
    val confidence: Double? = null,
    val createdAt: Instant? = null,
) {
    /** True when the flag is a `high`/`critical` severity (case-insensitive). */
    val isElevated: Boolean
        get() = severity?.lowercase()?.let { it == "high" || it == "critical" } ?: false
}

/**
 * The full risk picture for one request, returned by
 * `GET /api/v1/access-requests/:id` (`{ request, risk, anomalies }`). [risk]
 * is null until the request has been scored; [anomalies] is empty until an
 * approved elevation has been analysed.
 */
data class AccessRequestDetail(
    val request: AccessRequest,
    val risk: RiskVerdict? = null,
    val anomalies: List<AnomalyFlag> = emptyList(),
)

/**
 * A host-renderable risk summary for a piece of access, derived purely from
 * the server's signals by [RiskAssessment].
 *
 * - [isHighRisk] — the access warrants a step-up-gated, urgent revoke (HIGH AI
 *   band, a `high_risk` recommendation, or a high/critical anomaly).
 * - [isElevated] — worth surfacing for awareness (medium-or-above, a
 *   `needs_review` recommendation, or any anomaly) even if not yet high-risk.
 * - [reasons] — short, human-readable justifications for a banner / toast.
 * - [anomalyCount] — number of advisory anomaly flags backing this summary.
 */
data class RiskAdvisory(
    val isHighRisk: Boolean,
    val isElevated: Boolean,
    val reasons: List<String>,
    val anomalyCount: Int,
)

/**
 * Pure classification of the server's risk signals into a [RiskAdvisory].
 *
 * Severity is the union of three independent signals so a host never has to
 * combine them itself:
 *   1. the request's coarse [AccessRequest.riskLevel] band,
 *   2. the latest AI [RiskVerdict] (score band + routing recommendation), and
 *   3. any advisory [AnomalyFlag]s.
 *
 * "High risk" is fail-safe: ANY one high signal is enough. This is the
 * cross-platform source of truth for which active access to surface and which
 * revokes to gate behind step-up MFA (see [Revocation]).
 */
object RiskAssessment {
    /** Evaluate a full [AccessRequestDetail]. */
    @JvmStatic
    fun evaluate(detail: AccessRequestDetail): RiskAdvisory =
        evaluate(detail.request, detail.risk, detail.anomalies)

    /** Evaluate the raw signals directly (request band + verdict + anomalies). */
    @JvmStatic
    fun evaluate(
        request: AccessRequest,
        verdict: RiskVerdict?,
        anomalies: List<AnomalyFlag> = emptyList(),
    ): RiskAdvisory {
        val reasons = mutableListOf<String>()

        // 1. Coarse request band.
        when (request.riskLevel) {
            RiskLevel.HIGH -> reasons += "AI risk band: high"
            RiskLevel.MEDIUM -> reasons += "AI risk band: medium"
            else -> {}
        }

        // 2. Latest AI verdict (band + routing recommendation).
        verdict?.let { v ->
            if (v.score == RiskLevel.HIGH && request.riskLevel != RiskLevel.HIGH) {
                reasons += "AI verdict score: high"
            } else if (v.score == RiskLevel.MEDIUM && request.riskLevel != RiskLevel.MEDIUM) {
                // A medium verdict score is an `isElevated` trigger, so it must
                // contribute a reason — otherwise an elevated advisory could
                // render with an empty justification ("Risky active access — .").
                reasons += "AI verdict score: medium"
            }
            when (v.recommendation) {
                RiskRecommendation.HIGH_RISK -> reasons += "Recommendation: high risk"
                RiskRecommendation.NEEDS_REVIEW -> reasons += "Recommendation: needs review"
                RiskRecommendation.AUTO_APPROVE_ELIGIBLE -> {}
            }
            if (v.degraded) reasons += "AI scoring degraded (fail-open)"
        }

        // 3. Advisory anomaly flags.
        val elevatedAnomalies = anomalies.count { it.isElevated }
        if (elevatedAnomalies > 0) {
            reasons += "Anomalies (high): $elevatedAnomalies"
        } else if (anomalies.isNotEmpty()) {
            reasons += "Anomalies: ${anomalies.size}"
        }

        val isHighRisk =
            request.riskLevel == RiskLevel.HIGH ||
                verdict?.score == RiskLevel.HIGH ||
                verdict?.recommendation == RiskRecommendation.HIGH_RISK ||
                elevatedAnomalies > 0

        val isElevated =
            isHighRisk ||
                request.riskLevel == RiskLevel.MEDIUM ||
                verdict?.score == RiskLevel.MEDIUM ||
                verdict?.recommendation == RiskRecommendation.NEEDS_REVIEW ||
                anomalies.isNotEmpty()

        return RiskAdvisory(
            isHighRisk = isHighRisk,
            isElevated = isElevated,
            reasons = reasons.toList(),
            anomalyCount = anomalies.size,
        )
    }
}
