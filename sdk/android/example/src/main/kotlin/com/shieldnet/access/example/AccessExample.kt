/*
 * AccessExample.kt — end-to-end usage of the ShieldNet Access Android SDK.
 *
 * Run with:
 *   ACCESS_BASE_URL=https://access.example.com \
 *   ACCESS_TOKEN=<iam-core bearer token> \
 *   ./gradlew :example:run
 *
 * On Android the same code runs inside a coroutine scope (e.g. a
 * `viewModelScope`); here we use `runBlocking` for a console program.
 */
package com.shieldnet.access.example

import com.shieldnet.access.AccessRequestState
import com.shieldnet.access.AccessSDKException
import com.shieldnet.access.CreateAccessRequest
import com.shieldnet.access.OkHttpAccessClient
import com.shieldnet.access.RiskLevel
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    val baseUrl = System.getenv("ACCESS_BASE_URL") ?: "https://access.example.com"
    val token = System.getenv("ACCESS_TOKEN")
        ?: error("set ACCESS_TOKEN to an iam-core bearer token")

    // The token provider is invoked before every call, so refreshing the
    // token (or supplying a stepped-up one) stays the host app's concern.
    val client = OkHttpAccessClient(baseUrl = baseUrl, authTokenProvider = { token })

    // 1. Who am I, and has my session already satisfied step-up MFA?
    val me = client.me()
    println("acting as ${me.userId} in tenant ${me.tenantId}; mfaSatisfied=${me.mfaSatisfied}")

    // 2. Submit an elevation request. The server runs risk-based routing
    //    (the AI risk verdict, WS5) and tells us which lane it landed in.
    val submission = client.createRequest(
        CreateAccessRequest(
            targetUserId = me.userId,
            resourceRef = "projects/payments-prod",
            role = "deployer",
            justification = "ship hotfix 1.2.3",
            riskLevel = RiskLevel.HIGH,
            riskFactors = listOf("sensitive_resource"),
        ),
    )
    val req = submission.request
    println("request ${req.id} → state=${req.state}, lane=${submission.workflow?.stepType}, why=${submission.workflow?.reason}")

    // 3. Poll until the request leaves the pending states (approved/denied).
    var current = client.getRequest(req.id)
    while (current.state == AccessRequestState.REQUESTED) {
        current = client.getRequest(req.id)
        break // single poll for the example; real apps loop with backoff
    }

    // 4. As an approver, approve it (surfacing the server AI risk verdict).
    if (current.state == AccessRequestState.REQUESTED) {
        val approved = client.approveRequest(req.id, reason = "reviewed, low blast radius")
        println("approved → state=${approved.state}, risk=${approved.riskLevel}")
    }

    // 5. Provision the approved request → JIT lease, and read its countdown.
    try {
        val grant = client.provisionRequest(req.id)
        println("lease ${grant.id} active=${grant.isActive()} remaining=${grant.remaining()}")
    } catch (e: AccessSDKException.StepUpRequired) {
        // High-risk gate: drive an iam-core step-up (WebAuthn) in the host,
        // obtain a fresh token, then retry. The provider above would return
        // the stepped-up token on the next attempt.
        println("step-up MFA required before provisioning: ${e.body}")
    }
}
