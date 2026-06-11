/*
 * OkHttpAccessClientTest.kt — real HTTP round-trips against MockWebServer.
 *
 * These are NOT mocks of OkHttp: the SDK drives a fully-real OkHttpClient
 * (request construction, headers, dispatch) against an in-process HTTP server
 * returning canned responses. We assert the request the SDK produced (path,
 * method, Authorization header, body) and that the response is unwrapped from
 * the handler envelope into the typed model. A network server is impractical
 * to stand up per test, so MockWebServer stands in for `ztna-api` — the only
 * mock in the suite, and only at the socket boundary.
 */
package com.shieldnet.access

import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

class OkHttpAccessClientTest {
    private lateinit var server: MockWebServer
    private lateinit var client: OkHttpAccessClient

    @BeforeTest
    fun setUp() {
        server = MockWebServer()
        server.start()
        // baseUrl WITHOUT /api/v1 — the client must append the prefix.
        client = OkHttpAccessClient(
            baseUrl = server.url("/").toString().trimEnd('/'),
            authTokenProvider = { "tok_123" },
        )
    }

    @AfterTest
    fun tearDown() {
        server.shutdown()
    }

    @Test
    fun `me parses identity and sends bearer token`() = runBlocking {
        server.enqueue(
            MockResponse().setBody(
                """{"user_id":"u1","tenant_id":"t1","roles":["approver","admin"],
                   "scopes":["access:write"],"mfa_satisfied":true}""",
            ),
        )
        val me = client.me()
        assertEquals("u1", me.userId)
        assertEquals("t1", me.tenantId)
        assertEquals(listOf("approver", "admin"), me.roles)
        assertTrue(me.mfaSatisfied)

        val recorded = server.takeRequest()
        assertEquals("/api/v1/me", recorded.path)
        assertEquals("Bearer tok_123", recorded.getHeader("Authorization"))
        assertEquals("GET", recorded.method)
    }

    @Test
    fun `createRequest posts body and unwraps request plus workflow`() = runBlocking {
        server.enqueue(
            MockResponse().setResponseCode(201).setBody(
                """{"request":{"id":"r1","workspace_id":"ws1","requester_id":"u1",
                     "target_user_id":"u2","resource_ref":"projects/foo","role":"viewer",
                     "state":"requested","risk_level":"high","risk_factors":["sensitive_resource"],
                     "created_at":"2025-01-01T00:00:00Z"},
                   "workflow":{"step_type":"security_review","reason":"risk=high","approved":false}}""",
            ),
        )
        val submission = client.createRequest(
            CreateAccessRequest(
                targetUserId = "u2",
                resourceRef = "projects/foo",
                role = "viewer",
                justification = "deploy",
                riskLevel = RiskLevel.HIGH,
                riskFactors = listOf("sensitive_resource"),
            ),
        )
        assertEquals("r1", submission.request.id)
        assertEquals(AccessRequestState.REQUESTED, submission.request.state)
        assertEquals(RiskLevel.HIGH, submission.request.riskLevel)
        assertEquals(listOf("sensitive_resource"), submission.request.riskFactors)
        assertEquals(WorkflowStep.SECURITY_REVIEW, submission.workflow?.stepType)

        val recorded = server.takeRequest()
        assertEquals("/api/v1/access-requests", recorded.path)
        assertEquals("POST", recorded.method)
        val sent = recorded.body.readUtf8()
        assertTrue(sent.contains("\"target_user_id\":\"u2\""))
        assertTrue(sent.contains("\"resource_ref\":\"projects\\/foo\"") || sent.contains("\"resource_ref\":\"projects/foo\""))
        assertTrue(sent.contains("\"risk_level\":\"high\""))
        assertTrue(sent.contains("sensitive_resource"))
    }

    @Test
    fun `listRequests unwraps the requests array`() = runBlocking {
        server.enqueue(
            MockResponse().setBody(
                """{"requests":[
                     {"id":"r1","workspace_id":"ws1","requester_id":"u1","resource_ref":"a","state":"active","created_at":"2025-01-01T00:00:00Z"},
                     {"id":"r2","workspace_id":"ws1","requester_id":"u1","resource_ref":"b","state":"denied","created_at":"2025-01-02T00:00:00Z"}
                   ]}""",
            ),
        )
        val rows = client.listRequests()
        assertEquals(2, rows.size)
        assertEquals(AccessRequestState.ACTIVE, rows[0].state)
        assertEquals("r2", rows[1].id)
        assertEquals("/api/v1/access-requests", server.takeRequest().path)
    }

    @Test
    fun `getRequest reads expiry for lease countdown`() = runBlocking {
        server.enqueue(
            MockResponse().setBody(
                """{"request":{"id":"r1","workspace_id":"ws1","requester_id":"u1","resource_ref":"a",
                     "state":"active","expires_at":"2025-01-01T01:00:00Z","created_at":"2025-01-01T00:00:00Z"}}""",
            ),
        )
        val req = client.getRequest("r1")
        assertEquals(AccessRequestState.ACTIVE, req.state)
        assertEquals("2025-01-01T01:00:00Z", req.expiresAt.toString())
        assertEquals("/api/v1/access-requests/r1", server.takeRequest().path)
    }

    @Test
    fun `requestHistory unwraps the history array`() = runBlocking {
        server.enqueue(
            MockResponse().setBody(
                """{"history":[{"id":"h1","request_id":"r1","from_state":"requested","to_state":"approved",
                     "actor":"u2","reason":"ok","created_at":"2025-01-01T00:00:00Z"}]}""",
            ),
        )
        val hist = client.requestHistory("r1")
        assertEquals(1, hist.size)
        assertEquals("approved", hist[0].toState)
        assertEquals("/api/v1/access-requests/r1/history", server.takeRequest().path)
    }

    @Test
    fun `approve and deny hit the right paths and bodies`() = runBlocking {
        server.enqueue(
            MockResponse().setBody(
                """{"request":{"id":"r1","workspace_id":"ws1","requester_id":"u1","resource_ref":"a",
                     "state":"approved","risk_level":"medium","created_at":"2025-01-01T00:00:00Z"}}""",
            ),
        )
        val approved = client.approveRequest("r1", reason = "looks good")
        assertEquals(AccessRequestState.APPROVED, approved.state)
        assertEquals(RiskLevel.MEDIUM, approved.riskLevel) // server AI risk verdict surfaced
        val approveReq = server.takeRequest()
        assertEquals("/api/v1/access-requests/r1/approve", approveReq.path)
        assertTrue(approveReq.body.readUtf8().contains("\"reason\":\"looks good\""))

        server.enqueue(
            MockResponse().setBody(
                """{"request":{"id":"r1","workspace_id":"ws1","requester_id":"u1","resource_ref":"a",
                     "state":"denied","created_at":"2025-01-01T00:00:00Z"}}""",
            ),
        )
        val denied = client.denyRequest("r1", reason = "too broad")
        assertEquals(AccessRequestState.DENIED, denied.state)
        assertEquals("/api/v1/access-requests/r1/deny", server.takeRequest().path)
    }

    @Test
    fun `provision returns the grant and computes remaining lease`() = runBlocking {
        server.enqueue(
            MockResponse().setBody(
                """{"grant":{"id":"g1","workspace_id":"ws1","request_id":"r1","connector_id":"c1",
                     "iam_core_user_id":"u1","resource_ref":"projects/foo","role":"viewer","state":"active",
                     "granted_at":"2025-01-01T00:00:00Z","expires_at":"2025-01-01T02:00:00Z"}}""",
            ),
        )
        val grant = client.provisionRequest("r1")
        assertEquals(GrantState.ACTIVE, grant.state)
        assertEquals("g1", grant.id)
        val now = java.time.Instant.parse("2025-01-01T00:30:00Z")
        assertEquals(90 * 60L, grant.remaining(now)!!.seconds)
        assertTrue(grant.isActive(now))
        assertEquals("/api/v1/access-requests/r1/provision", server.takeRequest().path)
    }

    @Test
    fun `revokeGrant accepts the server's status body`() = runBlocking {
        // The real handler returns {"status":"revoked"}; revokeGrant ignores the
        // body and simply succeeds on 2xx.
        server.enqueue(MockResponse().setResponseCode(200).setBody("""{"status":"revoked"}"""))
        client.revokeGrant("g1", reason = "done")
        val recorded = server.takeRequest()
        assertEquals("/api/v1/grants/g1/revoke", recorded.path)
        assertTrue(recorded.body.readUtf8().contains("\"reason\":\"done\""))
    }

    @Test
    fun `revokeGrant tolerates an empty body`() = runBlocking {
        // Defensive: even if a future/proxy response omits the body, a 2xx still
        // counts as success (allowEmpty = true).
        server.enqueue(MockResponse().setResponseCode(200).setBody(""))
        client.revokeGrant("g1", reason = "done")
        val recorded = server.takeRequest()
        assertEquals("/api/v1/grants/g1/revoke", recorded.path)
        assertTrue(recorded.body.readUtf8().contains("\"reason\":\"done\""))
    }

    @Test
    fun `401 maps to Unauthenticated`() {
        server.enqueue(MockResponse().setResponseCode(401).setBody("""{"error":"invalid token"}"""))
        assertFailsWith<AccessSDKException.Unauthenticated> { runBlocking { client.me() } }
    }

    @Test
    fun `403 step-up gate maps to StepUpRequired`() {
        server.enqueue(MockResponse().setResponseCode(403).setBody("""{"error":"step-up MFA required"}"""))
        val ex = assertFailsWith<AccessSDKException.StepUpRequired> {
            runBlocking { client.provisionRequest("r1") }
        }
        assertTrue(ex.body!!.contains("step-up MFA required"))
    }

    @Test
    fun `other 403 stays a generic Http error`() {
        server.enqueue(MockResponse().setResponseCode(403).setBody("""{"error":"tenant mismatch"}"""))
        val ex = assertFailsWith<AccessSDKException.Http> { runBlocking { client.listRequests() } }
        assertEquals(403, ex.statusCode)
    }

    @Test
    fun `5xx maps to Http with status and body`() {
        server.enqueue(MockResponse().setResponseCode(500).setBody("""{"error":"boom"}"""))
        val ex = assertFailsWith<AccessSDKException.Http> { runBlocking { client.me() } }
        assertEquals(500, ex.statusCode)
        assertTrue(ex.body!!.contains("boom"))
    }

    @Test
    fun `malformed JSON maps to Decoding`() {
        server.enqueue(MockResponse().setBody("not-json"))
        assertFailsWith<AccessSDKException.Decoding> { runBlocking { client.me() } }
    }

    @Test
    fun `missing required field maps to Decoding`() {
        server.enqueue(MockResponse().setBody("""{"request":{"id":"r1"}}"""))
        assertFailsWith<AccessSDKException.Decoding> { runBlocking { client.getRequest("r1") } }
    }

    @Test
    fun `client-side validation rejects bad input before any network call`() {
        assertFailsWith<AccessSDKException.InvalidInput> {
            runBlocking { client.createRequest(CreateAccessRequest(targetUserId = "", resourceRef = "x")) }
        }
        assertFailsWith<AccessSDKException.InvalidInput> {
            runBlocking { client.denyRequest("r1", reason = "  ") }
        }
        assertFailsWith<AccessSDKException.InvalidInput> {
            runBlocking { client.getRequest("  ") }
        }
        // No request should have been dispatched.
        assertEquals(0, server.requestCount)
    }

    @Test
    fun `blank token maps to Unauthenticated without a network call`() {
        val noTokenClient = OkHttpAccessClient(
            baseUrl = server.url("/api/v1").toString(),
            authTokenProvider = { "" },
        )
        assertFailsWith<AccessSDKException.Unauthenticated> { runBlocking { noTokenClient.me() } }
        assertEquals(0, server.requestCount)
    }

    @Test
    fun `malformed baseUrl on a POST surfaces typed InvalidInput`() {
        // A non-HTTP(S) base produces an unparseable URL. Both GET and POST must
        // fail closed with AccessSDKException.InvalidInput rather than leaking
        // OkHttp's raw IllegalArgumentException.
        val badClient = OkHttpAccessClient(
            baseUrl = "ftp://example.com",
            authTokenProvider = { "tok" },
        )
        assertFailsWith<AccessSDKException.InvalidInput> {
            runBlocking {
                badClient.createRequest(CreateAccessRequest(targetUserId = "u1", resourceRef = "res"))
            }
        }
        assertFailsWith<AccessSDKException.InvalidInput> {
            runBlocking { badClient.me() }
        }
    }

    @Test
    fun `baseUrl already carrying api v1 is not doubled`() = runBlocking {
        val prefixed = OkHttpAccessClient(
            baseUrl = server.url("/api/v1").toString(),
            authTokenProvider = { "tok" },
        )
        server.enqueue(MockResponse().setBody("""{"user_id":"u1","tenant_id":"t1"}"""))
        prefixed.me()
        assertEquals("/api/v1/me", server.takeRequest().path)
    }

    @Test
    fun `optional fields tolerate absence`() = runBlocking {
        server.enqueue(MockResponse().setBody("""{"user_id":"u1"}"""))
        val me = client.me()
        assertEquals("", me.tenantId)
        assertTrue(me.roles.isEmpty())
        assertTrue(!me.mfaSatisfied)
    }

    @Test
    fun `getRequestDetail unwraps request, risk verdict and anomalies`() = runBlocking {
        server.enqueue(
            MockResponse().setBody(
                """{"request":{"id":"r1","workspace_id":"ws1","requester_id":"u1",
                     "resource_ref":"projects/foo","state":"active","risk_level":"high",
                     "created_at":"2025-01-01T00:00:00Z"},
                   "risk":{"id":"rv1","request_id":"r1","score":"high","recommendation":"high_risk",
                     "factors":["sensitive_resource","off_hours"],"rationale":"sensitive prod access",
                     "source":"ai_agent","degraded":false,"created_at":"2025-01-01T00:00:00Z"},
                   "anomalies":[{"id":"af1","request_id":"r1","grant_id":"g1","kind":"impossible_travel",
                     "severity":"high","reason":"two geos in 5m","confidence":0.92,
                     "created_at":"2025-01-01T00:05:00Z"}]}""",
            ),
        )
        val detail = client.getRequestDetail("r1")
        assertEquals("/api/v1/access-requests/r1", server.takeRequest().path)
        assertEquals(AccessRequestState.ACTIVE, detail.request.state)
        assertEquals(RiskLevel.HIGH, detail.risk?.score)
        assertEquals(RiskRecommendation.HIGH_RISK, detail.risk?.recommendation)
        assertEquals(listOf("sensitive_resource", "off_hours"), detail.risk?.factors)
        assertEquals(1, detail.anomalies.size)
        assertEquals("impossible_travel", detail.anomalies.first().kind)
        assertEquals(0.92, detail.anomalies.first().confidence)
        assertTrue(detail.anomalies.first().isElevated)
    }

    @Test
    fun `getRequestDetail tolerates a request with no risk or anomalies`() = runBlocking {
        server.enqueue(
            MockResponse().setBody(
                """{"request":{"id":"r1","workspace_id":"ws1","requester_id":"u1",
                     "resource_ref":"projects/foo","state":"requested",
                     "created_at":"2025-01-01T00:00:00Z"}}""",
            ),
        )
        val detail = client.getRequestDetail("r1")
        assertEquals(AccessRequestState.REQUESTED, detail.request.state)
        assertEquals(null, detail.risk)
        assertTrue(detail.anomalies.isEmpty())
    }

    @Test
    fun `emergencyOffboard posts identity and parses the per-layer breakdown`() = runBlocking {
        server.enqueue(
            MockResponse().setBody(
                """{"leaver":{"user_external_id":"ext-1","errored":false,"layers":[
                     {"layer":"grant_revoke","status":"done"},
                     {"layer":"team_remove","status":"done"},
                     {"layer":"iam_core_disable","status":"done"},
                     {"layer":"session_revoke","status":"done"},
                     {"layer":"scim_deprovision","status":"skipped","detail":"no scim connector"},
                     {"layer":"identity_disable","status":"done"}]}}""",
            ),
        )
        val result = client.emergencyOffboard("ext-1", reason = "left the company")
        val recorded = server.takeRequest()
        assertEquals("/api/v1/emergency-offboard", recorded.path)
        val sent = recorded.body.readUtf8()
        assertTrue(sent.contains("\"user_external_id\":\"ext-1\""))
        assertTrue(sent.contains("\"reason\":\"left the company\""))
        assertEquals("ext-1", result.userExternalId)
        assertTrue(!result.errored)
        assertEquals(6, result.layers.size)
        assertEquals(KillSwitchLayerStatus.SKIPPED, result.layers[4].status)
        assertTrue(result.failedLayers.isEmpty())
    }

    @Test
    fun `emergencyOffboard recovers the breakdown from a 500 partial failure`() = runBlocking {
        // The server returns 500 carrying the SAME {leaver} breakdown when a
        // layer fails; the SDK must surface it rather than only a generic Http.
        server.enqueue(
            MockResponse().setResponseCode(500).setBody(
                """{"error":"one or more layers failed","leaver":{"user_external_id":"ext-1",
                     "errored":true,"layers":[
                     {"layer":"grant_revoke","status":"done"},
                     {"layer":"iam_core_disable","status":"failed","detail":"idp timeout"}]}}""",
            ),
        )
        val result = client.emergencyOffboard("ext-1")
        assertTrue(result.errored)
        assertEquals(1, result.failedLayers.size)
        assertEquals(KillSwitchLayer.IAM_CORE_DISABLE, result.failedLayers.first().layer)
        assertEquals("idp timeout", result.failedLayers.first().detail)
    }

    @Test
    fun `emergencyOffboard surfaces the step-up MFA gate`() {
        server.enqueue(MockResponse().setResponseCode(403).setBody("""{"error":"step-up MFA required"}"""))
        val ex = assertFailsWith<AccessSDKException.StepUpRequired> {
            runBlocking { client.emergencyOffboard("ext-1") }
        }
        assertTrue(ex.body!!.contains("step-up MFA required"))
    }

    @Test
    fun `emergencyOffboard rejects a blank identity before any network call`() {
        assertFailsWith<AccessSDKException.InvalidInput> {
            runBlocking { client.emergencyOffboard("  ") }
        }
        assertEquals(0, server.requestCount)
    }

    @Test
    fun `emergencyOffboard without a breakdown rethrows the Http error`() {
        // A 500 that does NOT carry a {leaver} body (e.g. a gateway error) must
        // stay a typed Http error, not silently become an empty result.
        server.enqueue(MockResponse().setResponseCode(500).setBody("""{"error":"upstream unavailable"}"""))
        val ex = assertFailsWith<AccessSDKException.Http> {
            runBlocking { client.emergencyOffboard("ext-1") }
        }
        assertEquals(500, ex.statusCode)
    }

    @Test
    fun `emergencyOffboard with a malformed breakdown rethrows the original Http error`() {
        // A 500 whose {leaver} is present but malformed (missing the required
        // user_external_id) must fall through to the original Http error, not a
        // decode error — preserving the transport context (matches iOS `try?`).
        server.enqueue(
            MockResponse().setResponseCode(500).setBody(
                """{"error":"one or more layers failed","leaver":{"errored":true}}""",
            ),
        )
        val ex = assertFailsWith<AccessSDKException.Http> {
            runBlocking { client.emergencyOffboard("ext-1") }
        }
        assertEquals(500, ex.statusCode)
        assertTrue(ex.body!!.contains("one or more layers failed"))
    }
}
