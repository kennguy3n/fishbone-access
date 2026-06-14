/*
 * Revocation.kt — one-tap revoke models + step-up planning (Android).
 *
 * Two server-side revoke paths exist, both reachable through [AccessClient]:
 *
 *   - Grant revoke  — `POST /api/v1/grants/:id/revoke` ends a single JIT lease
 *     early. Permission-gated only (`PermGrantRevoke`); NOT step-up-gated
 *     server-side, so the *client* is responsible for requiring step-up on a
 *     high-risk revoke (see [Revocation.plan]).
 *   - Kill switch   — `POST /api/v1/emergency-offboard` runs the six-layer
 *     leaver kill switch for one identity. Step-up-MFA-gated server-side
 *     (`RequireMFA`): a token without a satisfied MFA claim is rejected with
 *     403 and surfaces as [AccessSDKException.StepUpRequired].
 *
 * [LeaverResult] mirrors `lifecycle.LeaverResult` / the `LeaverResult` schema
 * in `docs/openapi.yaml`; [Revocation] is a pure helper that decides whether a
 * revoke should be gated behind step-up MFA so the UX is consistent with the
 * web console and iOS. Kept byte-for-byte compatible with
 * `sdk/ios/Sources/ShieldNetAccess/Revocation.swift`.
 */
package com.shieldnet.access

/**
 * One of the six ordered layers the leaver kill switch attempts. Mirrors the
 * `layer` enum in the `LeaverResult` schema (`docs/openapi.yaml`).
 */
enum class KillSwitchLayer(val wireValue: String) {
    GRANT_REVOKE("grant_revoke"),
    TEAM_REMOVE("team_remove"),
    IAM_CORE_DISABLE("iam_core_disable"),
    SESSION_REVOKE("session_revoke"),
    SCIM_DEPROVISION("scim_deprovision"),
    IDENTITY_DISABLE("identity_disable");

    companion object {
        @JvmStatic
        fun fromWire(value: String): KillSwitchLayer =
            entries.firstOrNull { it.wireValue == value }
                ?: throw AccessSDKException.Decoding("unknown kill-switch layer: $value")
    }
}

/** Per-layer outcome of the kill switch. */
enum class KillSwitchLayerStatus(val wireValue: String) {
    DONE("done"),
    SKIPPED("skipped"),
    FAILED("failed");

    companion object {
        @JvmStatic
        fun fromWire(value: String): KillSwitchLayerStatus =
            entries.firstOrNull { it.wireValue == value }
                ?: throw AccessSDKException.Decoding("unknown kill-switch layer status: $value")
    }
}

/** Outcome of a single kill-switch layer; [detail] explains a skip/failure. */
data class KillSwitchLayerResult(
    val layer: KillSwitchLayer,
    val status: KillSwitchLayerStatus,
    val detail: String? = null,
)

/**
 * Aggregated outcome of the six-layer leaver kill switch
 * ([AccessClient.emergencyOffboard]). Every layer is attempted even if an
 * earlier one fails; [errored] is true when any layer reported
 * [KillSwitchLayerStatus.FAILED]. The server returns the SAME breakdown on a
 * partial failure (HTTP 500), so the host can always render per-layer detail.
 */
data class LeaverResult(
    val userExternalId: String,
    val errored: Boolean,
    val layers: List<KillSwitchLayerResult> = emptyList(),
) {
    /** Layers that failed — the actionable subset for an operator to retry. */
    val failedLayers: List<KillSwitchLayerResult>
        get() = layers.filter { it.status == KillSwitchLayerStatus.FAILED }
}

/**
 * The decision of how to drive a revoke from the client.
 *
 * - [requiresStepUp] — the host must ensure the session has satisfied step-up
 *   MFA (via [Identity.mfaSatisfied] / an iam-core re-auth) BEFORE calling the
 *   revoke, mirroring the web console which disables the control until MFA is
 *   satisfied. The kill-switch path is additionally enforced server-side.
 * - [advisory] — the risk summary that drove the decision, for the
 *   confirmation UI.
 */
data class RevocationPlan(
    val requiresStepUp: Boolean,
    val advisory: RiskAdvisory,
)

/**
 * Pure step-up planning for a revoke. The SDK never performs MFA itself; this
 * just tells the host whether to gate the revoke so high-risk revocations get
 * the same step-up treatment on every platform.
 *
 * A high-risk revoke ([RiskAdvisory.isHighRisk]) requires step-up. The
 * authoritative gate still lives on the server for the kill switch — even if a
 * host skips this check, [AccessClient.emergencyOffboard] surfaces
 * [AccessSDKException.StepUpRequired] when the token lacks the MFA claim.
 */
object Revocation {
    /** Plan a revoke from a full [AccessRequestDetail]. */
    @JvmStatic
    fun plan(detail: AccessRequestDetail): RevocationPlan =
        plan(RiskAssessment.evaluate(detail))

    /** Plan a revoke from a pre-computed [RiskAdvisory]. */
    @JvmStatic
    fun plan(advisory: RiskAdvisory): RevocationPlan =
        RevocationPlan(requiresStepUp = advisory.isHighRisk, advisory = advisory)
}
