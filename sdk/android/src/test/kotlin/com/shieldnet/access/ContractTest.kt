/*
 * ContractTest.kt — compile-time + behavioural conformance of [AccessClient].
 *
 * The SDK ships an interface plus a bundled OkHttp implementation. This test
 * asserts the interface is implementable end-to-end with an in-memory fake:
 * if a method signature changes in a breaking way the fake stops compiling
 * and the target fails to build. It also exercises the typed error surface
 * and the enum wire mappings, which are the SDK's external contract.
 */
package com.shieldnet.access

import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

/** In-memory fake exercising every method on the interface. */
private class FakeAccessClient : AccessClient {
    override suspend fun me(): Identity = Identity(
        userId = "user_1",
        tenantId = "tenant_1",
        roles = listOf("approver"),
        scopes = listOf("access:write"),
        mfaSatisfied = true,
    )

    override suspend fun createRequest(input: CreateAccessRequest): RequestSubmission = RequestSubmission(
        request = sampleRequest(AccessRequestState.REQUESTED).copy(
            resourceRef = input.resourceRef,
            targetUserId = input.targetUserId,
            riskLevel = input.riskLevel,
            riskFactors = input.riskFactors,
        ),
        workflow = WorkflowDecision(WorkflowStep.MANAGER_APPROVAL, "risk=medium → manager_approval", approved = false),
    )

    override suspend fun listRequests(): List<AccessRequest> = listOf(sampleRequest(AccessRequestState.ACTIVE))

    override suspend fun getRequest(id: String): AccessRequest = sampleRequest(AccessRequestState.ACTIVE).copy(id = id)

    override suspend fun getRequestDetail(id: String): AccessRequestDetail = AccessRequestDetail(
        request = sampleRequest(AccessRequestState.ACTIVE).copy(id = id, riskLevel = RiskLevel.HIGH),
        risk = RiskVerdict(
            id = "rv_1",
            requestId = id,
            score = RiskLevel.HIGH,
            recommendation = RiskRecommendation.HIGH_RISK,
            factors = listOf("sensitive_resource"),
            degraded = false,
        ),
        anomalies = listOf(
            AnomalyFlag(id = "af_1", requestId = id, kind = "impossible_travel", severity = "high"),
        ),
    )

    override suspend fun requestHistory(id: String): List<StateHistoryEntry> = listOf(
        StateHistoryEntry("h1", id, "requested", "approved", actor = "user_2", reason = "ok", createdAt = Instant.EPOCH),
    )

    override suspend fun approveRequest(id: String, reason: String?): AccessRequest =
        sampleRequest(AccessRequestState.APPROVED).copy(id = id)

    override suspend fun denyRequest(id: String, reason: String): AccessRequest =
        sampleRequest(AccessRequestState.DENIED).copy(id = id)

    override suspend fun cancelRequest(id: String, reason: String?): AccessRequest =
        sampleRequest(AccessRequestState.CANCELLED).copy(id = id)

    override suspend fun provisionRequest(id: String): AccessGrant = AccessGrant(
        id = "grant_$id",
        workspaceId = "ws_1",
        requestId = id,
        connectorId = "conn_1",
        iamCoreUserId = "user_1",
        resourceRef = "projects/foo",
        role = "viewer",
        state = GrantState.ACTIVE,
        grantedAt = Instant.EPOCH,
        expiresAt = Instant.EPOCH.plusSeconds(3600),
    )

    override suspend fun revokeGrant(id: String, reason: String?) = Unit

    override suspend fun emergencyOffboard(userExternalId: String, reason: String?): LeaverResult = LeaverResult(
        userExternalId = userExternalId,
        errored = false,
        layers = KillSwitchLayer.entries.map {
            KillSwitchLayerResult(layer = it, status = KillSwitchLayerStatus.DONE)
        },
    )

    private fun sampleRequest(state: AccessRequestState) = AccessRequest(
        id = "req_1",
        workspaceId = "ws_1",
        requesterId = "user_1",
        targetUserId = "user_1",
        connectorId = "conn_1",
        resourceRef = "projects/foo",
        role = "viewer",
        justification = "ci",
        state = state,
        createdAt = Instant.EPOCH,
    )
}

class ContractTest {
    @Test
    fun `fake satisfies AccessClient and can be exercised end-to-end`() = runBlocking {
        val client: AccessClient = FakeAccessClient()

        val me = client.me()
        assertEquals("tenant_1", me.tenantId)
        assertTrue(me.mfaSatisfied)

        val submission = client.createRequest(
            CreateAccessRequest(
                targetUserId = "user_1",
                resourceRef = "projects/foo",
                role = "viewer",
                justification = "ci",
                riskLevel = RiskLevel.MEDIUM,
            ),
        )
        assertEquals(AccessRequestState.REQUESTED, submission.request.state)
        assertEquals(WorkflowStep.MANAGER_APPROVAL, submission.workflow?.stepType)
        assertEquals(RiskLevel.MEDIUM, submission.request.riskLevel)

        assertEquals(1, client.listRequests().size)
        assertEquals("req_42", client.getRequest("req_42").id)
        assertEquals("approved", client.requestHistory("req_1").first().toState)

        assertEquals(AccessRequestState.APPROVED, client.approveRequest("req_1").state)
        assertEquals(AccessRequestState.DENIED, client.denyRequest("req_1", "nope").state)
        assertEquals(AccessRequestState.CANCELLED, client.cancelRequest("req_1").state)

        val grant = client.provisionRequest("req_1")
        assertEquals(GrantState.ACTIVE, grant.state)
        assertTrue(grant.isActive(Instant.EPOCH))

        client.revokeGrant(grant.id, "done")

        val detail = client.getRequestDetail("req_1")
        assertEquals(RiskRecommendation.HIGH_RISK, detail.risk?.recommendation)
        assertEquals(1, detail.anomalies.size)

        val leaver = client.emergencyOffboard("user_1", "left the company")
        assertEquals("user_1", leaver.userExternalId)
        assertTrue(!leaver.errored)
        assertEquals(KillSwitchLayer.entries.size, leaver.layers.size)
    }

    @Test
    fun `typed errors carry structured context`() {
        val http = AccessSDKException.Http(statusCode = 409, body = "{\"error\":\"conflict\"}")
        assertEquals(409, http.statusCode)
        assertTrue(http.message!!.contains("HTTP 409"))

        val stepUp = AccessSDKException.StepUpRequired("{\"error\":\"step-up MFA required\"}")
        assertTrue(stepUp.message!!.contains("step-up MFA"))

        assertFailsWith<AccessSDKException.Unauthenticated> { throw AccessSDKException.Unauthenticated() }
    }

    @Test
    fun `enum wire values match the server contract`() {
        assertEquals("provision_failed", AccessRequestState.PROVISION_FAILED.wireValue)
        assertEquals(AccessRequestState.ACTIVE, AccessRequestState.fromWire("active"))
        assertEquals(RiskLevel.HIGH, RiskLevel.fromWire("high"))
        assertEquals(WorkflowStep.SECURITY_REVIEW, WorkflowStep.fromWire("security_review"))
        assertEquals(GrantState.REVOKED, GrantState.fromWire("revoked"))

        assertEquals(RiskRecommendation.HIGH_RISK, RiskRecommendation.fromWire("high_risk"))
        assertEquals("auto_approve_eligible", RiskRecommendation.AUTO_APPROVE_ELIGIBLE.wireValue)
        assertEquals(KillSwitchLayer.SCIM_DEPROVISION, KillSwitchLayer.fromWire("scim_deprovision"))
        assertEquals(KillSwitchLayerStatus.FAILED, KillSwitchLayerStatus.fromWire("failed"))

        assertFailsWith<AccessSDKException.Decoding> { AccessRequestState.fromWire("nope") }
        assertFailsWith<AccessSDKException.Decoding> { GrantState.fromWire("pending") }
        assertFailsWith<AccessSDKException.Decoding> { RiskRecommendation.fromWire("maybe") }
        assertFailsWith<AccessSDKException.Decoding> { KillSwitchLayer.fromWire("nuke") }
    }

    @Test
    fun `grant lease countdown is clamped and respects state`() {
        val base = Instant.parse("2025-01-01T00:00:00Z")
        val active = AccessGrant(
            id = "g1", workspaceId = "ws", iamCoreUserId = "u", resourceRef = "r",
            state = GrantState.ACTIVE, grantedAt = base, expiresAt = base.plusSeconds(600),
        )
        assertEquals(600, active.remaining(base)!!.seconds)
        assertEquals(0, active.remaining(base.plusSeconds(900))!!.seconds)
        assertTrue(active.isActive(base))
        assertTrue(!active.isActive(base.plusSeconds(900)))

        val nonExpiring = active.copy(expiresAt = null)
        assertNull(nonExpiring.remaining(base))
        assertTrue(nonExpiring.isActive(base))

        val revoked = active.copy(state = GrantState.REVOKED)
        assertTrue(!revoked.isActive(base)) // fail-closed even with a future expiry
    }
}
