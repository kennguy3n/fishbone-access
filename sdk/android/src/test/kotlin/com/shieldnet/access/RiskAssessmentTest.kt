/*
 * RiskAssessmentTest.kt — pure-function coverage for the WS5 risky-access
 * classifier ([RiskAssessment]) and the step-up revocation planner
 * ([Revocation]). No network: these assert the cross-platform severity logic
 * that both the Android and iOS SDKs (and, by mirroring, the web console) use
 * to decide which access to surface and which revokes to gate behind MFA.
 */
package com.shieldnet.access

import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RiskAssessmentTest {
    private fun request(level: RiskLevel? = null) = AccessRequest(
        id = "r1",
        workspaceId = "ws1",
        requesterId = "u1",
        resourceRef = "projects/foo",
        state = AccessRequestState.ACTIVE,
        riskLevel = level,
        createdAt = Instant.EPOCH,
    )

    private fun verdict(
        score: RiskLevel,
        rec: RiskRecommendation,
        degraded: Boolean = false,
    ) = RiskVerdict(id = "rv1", requestId = "r1", score = score, recommendation = rec, degraded = degraded)

    private fun anomaly(severity: String?) =
        AnomalyFlag(id = "af1", requestId = "r1", kind = "impossible_travel", severity = severity)

    @Test
    fun `high AI band alone is high-risk and requires step-up`() {
        val advisory = RiskAssessment.evaluate(request(RiskLevel.HIGH), verdict = null)
        assertTrue(advisory.isHighRisk)
        assertTrue(advisory.isElevated)
        assertTrue(advisory.reasons.any { it.contains("high", ignoreCase = true) })
        assertTrue(Revocation.plan(advisory).requiresStepUp)
    }

    @Test
    fun `high_risk recommendation drives high-risk even when band is low`() {
        val advisory = RiskAssessment.evaluate(
            request(RiskLevel.LOW),
            verdict(RiskLevel.LOW, RiskRecommendation.HIGH_RISK),
        )
        assertTrue(advisory.isHighRisk)
        assertTrue(advisory.reasons.any { it.contains("high risk", ignoreCase = true) })
    }

    @Test
    fun `an elevated anomaly is high-risk regardless of the AI band`() {
        val advisory = RiskAssessment.evaluate(
            request(RiskLevel.LOW),
            verdict(RiskLevel.LOW, RiskRecommendation.AUTO_APPROVE_ELIGIBLE),
            listOf(anomaly("critical")),
        )
        assertTrue(advisory.isHighRisk)
        assertEquals(1, advisory.anomalyCount)
        assertTrue(advisory.reasons.any { it.contains("Anomalies (high)") })
    }

    @Test
    fun `medium signals are elevated but not high-risk`() {
        val advisory = RiskAssessment.evaluate(
            request(RiskLevel.MEDIUM),
            verdict(RiskLevel.MEDIUM, RiskRecommendation.NEEDS_REVIEW),
        )
        assertFalse(advisory.isHighRisk)
        assertTrue(advisory.isElevated)
        assertFalse(Revocation.plan(advisory).requiresStepUp)
    }

    @Test
    fun `a low-severity anomaly raises awareness but not the step-up gate`() {
        val advisory = RiskAssessment.evaluate(
            request(RiskLevel.LOW),
            verdict(RiskLevel.LOW, RiskRecommendation.AUTO_APPROVE_ELIGIBLE),
            listOf(anomaly("low")),
        )
        assertFalse(advisory.isHighRisk)
        assertTrue(advisory.isElevated)
        assertTrue(advisory.reasons.any { it.startsWith("Anomalies:") })
    }

    @Test
    fun `low and unscored access is neither elevated nor high-risk`() {
        val none = RiskAssessment.evaluate(request(RiskLevel.LOW), verdict = null)
        assertFalse(none.isElevated)
        assertFalse(none.isHighRisk)
        assertTrue(none.reasons.isEmpty())

        val unscored = RiskAssessment.evaluate(request(null), verdict = null)
        assertFalse(unscored.isElevated)
    }

    @Test
    fun `a degraded verdict is called out for the operator`() {
        val advisory = RiskAssessment.evaluate(
            request(RiskLevel.MEDIUM),
            verdict(RiskLevel.MEDIUM, RiskRecommendation.NEEDS_REVIEW, degraded = true),
        )
        assertTrue(advisory.reasons.any { it.contains("degraded", ignoreCase = true) })
    }

    @Test
    fun `evaluate via detail matches evaluate via raw signals`() {
        val req = request(RiskLevel.HIGH)
        val v = verdict(RiskLevel.HIGH, RiskRecommendation.HIGH_RISK)
        val flags = listOf(anomaly("high"))
        val detail = AccessRequestDetail(request = req, risk = v, anomalies = flags)
        assertEquals(
            RiskAssessment.evaluate(req, v, flags),
            RiskAssessment.evaluate(detail),
        )
        assertTrue(Revocation.plan(detail).requiresStepUp)
    }
}
