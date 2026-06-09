/*
 * Models.kt — typed wire models for the ShieldNet Access mobile SDK (Android).
 *
 * These types mirror the JSON payloads the ShieldNet Access control plane
 * (`cmd/ztna-api`) emits on its `/api/v1` surface. They are the source of
 * truth for the Kotlin contract and are kept byte-for-byte compatible with
 * the Swift models in `sdk/ios/Sources/ShieldNetAccess/Models.swift`.
 *
 * Wire field names follow the Go GORM models in `internal/models/models.go`
 * and the canonical `docs/openapi.yaml`. The handlers in
 * `internal/handlers/lifecycle.go` wrap every payload in a single-key
 * envelope (`{"request": ...}`, `{"requests": [...]}`, `{"grant": ...}`,
 * `{"history": [...]}`); the concrete client unwraps these envelopes.
 *
 * There is NO on-device inference in this SDK. The "AI risk verdict" the
 * approver sees is computed server-side (the access-ai-agent, WS5) and
 * surfaced here only as the persisted [AccessRequest.riskLevel] /
 * [AccessRequest.riskFactors] fields plus the [WorkflowDecision] routing
 * outcome. The SDK never imports a model runtime and ships no model files.
 *
 * The SDK is deliberately free of any JSON-serialization dependency in its
 * public types: host apps may pick Moshi / kotlinx.serialization / Gson and
 * adapt via the `wireValue` accessors. The bundled [OkHttpAccessClient] uses
 * the platform `org.json` parser internally.
 */
package com.shieldnet.access

import java.time.Duration
import java.time.Instant

/**
 * Lifecycle state of an [AccessRequest]. Values mirror the Go-side constants
 * in `internal/services/lifecycle/state_machine.go` and the `state` enum in
 * `docs/openapi.yaml`.
 */
enum class AccessRequestState(val wireValue: String) {
    REQUESTED("requested"),
    APPROVED("approved"),
    DENIED("denied"),
    CANCELLED("cancelled"),
    PROVISIONING("provisioning"),
    PROVISIONED("provisioned"),
    PROVISION_FAILED("provision_failed"),
    ACTIVE("active"),
    REVOKED("revoked"),
    EXPIRED("expired");

    companion object {
        /**
         * Parse a server-supplied wire string. Throws
         * [AccessSDKException.Decoding] for an unrecognised value so a
         * malformed payload fails loud rather than silently mapping to a
         * default — the server enum is fixed in `docs/openapi.yaml`.
         */
        @JvmStatic
        fun fromWire(value: String): AccessRequestState =
            entries.firstOrNull { it.wireValue == value }
                ?: throw AccessSDKException.Decoding("unknown access request state: $value")
    }
}

/**
 * Coarse risk bucket carried on an [AccessRequest]. Mirrors the
 * `risk_level` enum (`low` / `medium` / `high`) understood by the
 * risk-based router in `internal/services/lifecycle/workflow_service.go`.
 *
 * The bucket is populated server-side by the access-ai-agent risk review
 * (WS5); the SDK only reads it.
 */
enum class RiskLevel(val wireValue: String) {
    LOW("low"),
    MEDIUM("medium"),
    HIGH("high");

    companion object {
        @JvmStatic
        fun fromWire(value: String): RiskLevel =
            entries.firstOrNull { it.wireValue == value }
                ?: throw AccessSDKException.Decoding("unknown risk level: $value")
    }
}

/**
 * Workflow lane a freshly-created request is routed into. Mirrors the
 * `step_type` enum in `WorkflowDecision` (`internal/services/lifecycle/
 * workflow_service.go`). This is the human-readable surface of the
 * server-side risk verdict.
 */
enum class WorkflowStep(val wireValue: String) {
    AUTO_APPROVE("auto_approve"),
    MANAGER_APPROVAL("manager_approval"),
    SECURITY_REVIEW("security_review");

    companion object {
        @JvmStatic
        fun fromWire(value: String): WorkflowStep =
            entries.firstOrNull { it.wireValue == value }
                ?: throw AccessSDKException.Decoding("unknown workflow step: $value")
    }
}

/**
 * Lifecycle state of an [AccessGrant] (a JIT lease). Mirrors the
 * `GrantState*` constants in `internal/services/lifecycle/
 * provisioning_service.go`.
 */
enum class GrantState(val wireValue: String) {
    ACTIVE("active"),
    REVOKED("revoked"),
    EXPIRED("expired");

    companion object {
        @JvmStatic
        fun fromWire(value: String): GrantState =
            entries.firstOrNull { it.wireValue == value }
                ?: throw AccessSDKException.Decoding("unknown grant state: $value")
    }
}

/**
 * Resolved identity + tenant for the bearer token, returned by
 * `GET /api/v1/me`. Tenancy is derived solely from the validated iam-core
 * token claim (never from client input), so this is the authoritative view
 * of who the caller is and which workspace they act within.
 *
 * [mfaSatisfied] reflects whether the session behind the token completed
 * step-up MFA / WebAuthn at iam-core (the `amr`/`mfa` claim). High-risk,
 * data-plane-mutating routes require it; see [AccessSDKException.StepUpRequired].
 */
data class Identity(
    val userId: String,
    val tenantId: String,
    val roles: List<String> = emptyList(),
    val scopes: List<String> = emptyList(),
    val mfaSatisfied: Boolean = false,
)

/**
 * Input for [AccessClient.createRequest]. Mirrors the `CreateAccessRequest`
 * schema. The actor (requester) and workspace are derived server-side from
 * the validated token + tenant context and must NOT be supplied here.
 */
data class CreateAccessRequest(
    val targetUserId: String,
    val resourceRef: String,
    val connectorId: String? = null,
    val role: String? = null,
    val justification: String? = null,
    val riskLevel: RiskLevel? = null,
    val riskFactors: List<String> = emptyList(),
)

/**
 * Persisted access/elevation request. Mirrors `models.AccessRequest`.
 * Returned (inside a `{"request": ...}` envelope) by create / get /
 * approve / deny / cancel.
 */
data class AccessRequest(
    val id: String,
    val workspaceId: String,
    val requesterId: String,
    val targetUserId: String? = null,
    val connectorId: String? = null,
    val resourceRef: String,
    val role: String? = null,
    val justification: String? = null,
    val state: AccessRequestState,
    val riskLevel: RiskLevel? = null,
    val riskFactors: List<String> = emptyList(),
    val expiresAt: Instant? = null,
    val createdAt: Instant,
    val updatedAt: Instant? = null,
)

/**
 * Risk-based routing outcome returned alongside a newly-created request
 * (the `{"workflow": ...}` envelope key). Mirrors
 * `lifecycle.WorkflowDecision`. This is the approver-facing surface of the
 * server-side AI risk verdict: [stepType] is the lane the request landed in
 * and [reason] is the human-readable justification.
 */
data class WorkflowDecision(
    val stepType: WorkflowStep,
    val reason: String,
    val approved: Boolean,
)

/**
 * Result of [AccessClient.createRequest]: the persisted [request] plus the
 * [workflow] routing decision. [workflow] is null only if the server omitted
 * it (e.g. a best-effort routing failure that still created the request).
 */
data class RequestSubmission(
    val request: AccessRequest,
    val workflow: WorkflowDecision? = null,
)

/**
 * One immutable state-transition record for a request, returned by
 * `GET /api/v1/access-requests/:id/history`. Mirrors
 * `models.AccessRequestStateHistory`.
 */
data class StateHistoryEntry(
    val id: String,
    val requestId: String,
    val fromState: String,
    val toState: String,
    val actor: String? = null,
    val reason: String? = null,
    val createdAt: Instant,
)

/**
 * An active upstream grant — the JIT lease (WS4) materialised when an
 * approved request is provisioned. Mirrors `models.AccessGrant`. The lease
 * "countdown" is [expiresAt]; use [remaining] / [isActive] to drive a UI
 * timer without re-deriving the arithmetic per call site.
 */
data class AccessGrant(
    val id: String,
    val workspaceId: String,
    val requestId: String? = null,
    val connectorId: String? = null,
    val iamCoreUserId: String,
    val resourceRef: String,
    val role: String? = null,
    val state: GrantState,
    val grantedAt: Instant? = null,
    val expiresAt: Instant? = null,
    val revokedAt: Instant? = null,
) {
    /**
     * Time left on the lease relative to [now], never negative. Returns
     * null for a non-expiring grant (no [expiresAt]); returns
     * [Duration.ZERO] once the lease has lapsed. This is a pure clock
     * computation — it does not re-check [state] against the server.
     */
    fun remaining(now: Instant = Instant.now()): Duration? {
        val exp = expiresAt ?: return null
        val left = Duration.between(now, exp)
        return if (left.isNegative) Duration.ZERO else left
    }

    /**
     * True when the grant is in [GrantState.ACTIVE] and either has no
     * expiry or has not yet lapsed at [now]. Fail-closed: a revoked grant
     * is never active even if its [expiresAt] is in the future.
     */
    fun isActive(now: Instant = Instant.now()): Boolean {
        if (state != GrantState.ACTIVE) return false
        val exp = expiresAt ?: return true
        return now.isBefore(exp)
    }
}
