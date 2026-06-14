/*
 * AccessClient.kt — ShieldNet Access mobile SDK contract (Android).
 *
 * A thin, well-typed REST client over the ShieldNet Access control-plane
 * `/api/v1` surface. Every method maps 1:1 to an endpoint registered in
 * `internal/handlers/lifecycle.go` / `router.go` and documented in
 * `docs/openapi.yaml`. An SME's own Android app embeds this to drive access
 * flows without re-implementing the wire contract.
 *
 * Endpoint mapping:
 *   me               → GET    /api/v1/me
 *   createRequest    → POST   /api/v1/access-requests
 *   listRequests     → GET    /api/v1/access-requests
 *   getRequest       → GET    /api/v1/access-requests/:id
 *   getRequestDetail → GET    /api/v1/access-requests/:id  (+ risk, anomalies)
 *   requestHistory   → GET    /api/v1/access-requests/:id/history
 *   approveRequest   → POST   /api/v1/access-requests/:id/approve
 *   denyRequest      → POST   /api/v1/access-requests/:id/deny
 *   cancelRequest    → POST   /api/v1/access-requests/:id/cancel
 *   provisionRequest → POST   /api/v1/access-requests/:id/provision
 *   revokeGrant      → POST   /api/v1/grants/:id/revoke
 *   emergencyOffboard→ POST   /api/v1/emergency-offboard
 *
 * Authentication is a bearer access token issued by iam-core (OAuth2/OIDC).
 * The SDK never performs MFA itself: step-up MFA / WebAuthn happens at
 * iam-core and is reflected in the token's `amr`/`mfa` claim. When the
 * server gates a high-risk action on step-up the SDK surfaces
 * [AccessSDKException.StepUpRequired] so the host can drive an iam-core
 * step-up and retry with a fresh token. See [Identity.mfaSatisfied].
 *
 * There is NO on-device inference. AI risk review is server-side; the
 * SDK only reads the resulting [AccessRequest.riskLevel] /
 * [AccessRequest.riskFactors] and the [WorkflowDecision].
 */
package com.shieldnet.access

/**
 * Typed error surface for SDK consumers. Concrete clients throw these so host
 * applications can branch on them in a type-safe way (e.g. drive a step-up
 * flow on [StepUpRequired], surface a retry on [Transport]).
 */
sealed class AccessSDKException(message: String, cause: Throwable? = null) : Exception(message, cause) {
    /** Network / transport failure (timeouts, DNS, TLS). */
    class Transport(message: String, cause: Throwable? = null) : AccessSDKException(message, cause)

    /**
     * Non-2xx HTTP response from the control plane. [body] is the raw
     * response body if present (the canonical `{"error": "..."}` envelope
     * produced by the Gin handlers). 401 and step-up-403 are surfaced as the
     * dedicated subtypes below rather than this generic case.
     */
    class Http(val statusCode: Int, val body: String?) :
        AccessSDKException("HTTP $statusCode${body?.let { ": $it" } ?: ""}")

    /** Response body could not be decoded into the expected model. */
    class Decoding(message: String, cause: Throwable? = null) : AccessSDKException(message, cause)

    /** Caller-side invariant violation (e.g. blank request id). */
    class InvalidInput(message: String) : AccessSDKException(message)

    /** The caller is not authenticated (HTTP 401, or no token available). */
    class Unauthenticated : AccessSDKException("unauthenticated")

    /**
     * The action requires a step-up-MFA-satisfied token but the current
     * token does not carry one (HTTP 403 "step-up MFA required"). The host
     * should drive an iam-core step-up (WebAuthn / OTP), obtain a fresh
     * token, and retry the call. [body] carries the raw server error.
     */
    class StepUpRequired(val body: String?) :
        AccessSDKException("step-up MFA required${body?.let { ": $it" } ?: ""}")

    /** The host application has not configured the SDK (base URL / token). */
    class NotConfigured : AccessSDKException("SDK not configured")
}

/**
 * Async REST surface for the ShieldNet Access control plane.
 *
 * Methods are `suspend` so concrete implementations (e.g. [OkHttpAccessClient])
 * can run I/O on a coroutine dispatcher supplied by the host. Errors are
 * surfaced as [AccessSDKException].
 */
interface AccessClient {
    /**
     * Resolve the caller's identity and tenant.
     *
     * `GET /api/v1/me`. Use [Identity.mfaSatisfied] to decide up-front
     * whether a step-up will be needed for a high-risk action.
     */
    suspend fun me(): Identity

    /**
     * Submit an access / elevation request.
     *
     * `POST /api/v1/access-requests`. The server creates the request, runs
     * risk-based workflow routing (auto-approve / manager / security review),
     * and returns both the persisted [AccessRequest] and the
     * [WorkflowDecision]. Low-risk requests may already be `approved` in the
     * returned row.
     */
    suspend fun createRequest(input: CreateAccessRequest): RequestSubmission

    /**
     * List the access requests visible in the caller's workspace.
     *
     * `GET /api/v1/access-requests`.
     */
    suspend fun listRequests(): List<AccessRequest>

    /**
     * Fetch a single request by id — used to poll / observe status and, once
     * provisioned, to read the lease countdown via [AccessRequest.expiresAt].
     *
     * `GET /api/v1/access-requests/:id`.
     */
    suspend fun getRequest(id: String): AccessRequest

    /**
     * Fetch a request together with its risky-access signals: the latest AI
     * [RiskVerdict] and any advisory [AnomalyFlag]s. This is the same endpoint
     * as [getRequest] but reads the `risk` / `anomalies` envelope keys the
     * server already returns, so a host can surface high-risk / anomalous
     * active access and offer a one-tap revoke. Feed the result to
     * [RiskAssessment.evaluate] for a ready-to-render [RiskAdvisory].
     *
     * `GET /api/v1/access-requests/:id`.
     */
    suspend fun getRequestDetail(id: String): AccessRequestDetail

    /**
     * Fetch the immutable state-transition history of a request.
     *
     * `GET /api/v1/access-requests/:id/history`.
     */
    suspend fun requestHistory(id: String): List<StateHistoryEntry>

    /**
     * Approve a pending request as an approver. The returned row surfaces the
     * server's AI risk verdict via [AccessRequest.riskLevel] /
     * [AccessRequest.riskFactors].
     *
     * `POST /api/v1/access-requests/:id/approve` — optional `{ reason }`.
     */
    suspend fun approveRequest(id: String, reason: String? = null): AccessRequest

    /**
     * Deny a pending request with an approver-supplied reason.
     *
     * `POST /api/v1/access-requests/:id/deny` — `{ reason }`.
     */
    suspend fun denyRequest(id: String, reason: String): AccessRequest

    /**
     * Cancel one's own pending request.
     *
     * `POST /api/v1/access-requests/:id/cancel` — optional `{ reason }`.
     */
    suspend fun cancelRequest(id: String, reason: String? = null): AccessRequest

    /**
     * Provision an approved request, materialising the JIT lease (the
     * returned [AccessGrant], whose [AccessGrant.expiresAt] is the lease
     * countdown).
     *
     * `POST /api/v1/access-requests/:id/provision`.
     */
    suspend fun provisionRequest(id: String): AccessGrant

    /**
     * Revoke a grant (end the JIT lease early). Idempotent server-side.
     *
     * `POST /api/v1/grants/:id/revoke` — optional `{ reason }`.
     *
     * Permission-gated only; not step-up-gated server-side. For a high-risk
     * revoke, gate the call behind step-up MFA on the client first — see
     * [Revocation.plan].
     */
    suspend fun revokeGrant(id: String, reason: String? = null)

    /**
     * Run the six-layer leaver kill switch for one identity as an emergency
     * offboard — the "revoke everything for this user" path. Step-up-MFA-gated
     * server-side: a token without a satisfied MFA claim is rejected and
     * surfaces as [AccessSDKException.StepUpRequired], so the host can drive an
     * iam-core step-up and retry. Returns the per-layer [LeaverResult]; a
     * partial failure ([LeaverResult.errored]) still returns the full
     * breakdown rather than throwing.
     *
     * `POST /api/v1/emergency-offboard` — `{ user_external_id, reason? }`.
     */
    suspend fun emergencyOffboard(userExternalId: String, reason: String? = null): LeaverResult
}
