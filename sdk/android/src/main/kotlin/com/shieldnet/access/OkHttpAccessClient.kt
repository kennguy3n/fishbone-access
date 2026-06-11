/*
 * OkHttpAccessClient.kt — production OkHttp-backed [AccessClient].
 *
 * Each suspend method builds a real okhttp3.Request, runs it on the IO
 * dispatcher, unwraps the handler's single-key JSON envelope, and parses the
 * payload with the platform `org.json` parser. The SDK is deliberately free
 * of a JSON-serialization dependency in its public types — host apps already
 * ship OkHttp and we don't force a Moshi / kotlinx.serialization / Gson
 * choice on them.
 *
 * `authTokenProvider` is invoked before every request so token refresh (and
 * step-up re-authentication) stays the caller's responsibility: after the SDK
 * raises [AccessSDKException.StepUpRequired], the host drives an iam-core
 * step-up and the next call picks up the fresh token from the provider.
 */
package com.shieldnet.access

import java.io.IOException
import java.time.Instant
import java.time.format.DateTimeParseException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject

private val JSON_MEDIA = "application/json".toMediaType()

// The exact server error string for a step-up gate (internal/middleware/
// auth.go RequireMFA). Matched case-insensitively against the `error` field.
private const val STEP_UP_MARKER = "step-up mfa"

/**
 * Production HTTP implementation of [AccessClient].
 *
 * Construct once per app launch. [baseUrl] is the control-plane root with or
 * without the `/api/v1` suffix and with or without a trailing slash (e.g.
 * `https://access.example.com` or `https://access.example.com/api/v1`).
 * [authTokenProvider] returns a current iam-core bearer token.
 */
class OkHttpAccessClient(
    baseUrl: String,
    private val client: OkHttpClient = OkHttpClient(),
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val authTokenProvider: suspend () -> String,
) : AccessClient {

    // Normalise to a `<root>/api/v1` prefix exactly once so callers may pass
    // either form. Trailing slashes are trimmed to keep path joins clean.
    private val apiBase: String = run {
        val trimmed = baseUrl.trim().trimEnd('/')
        if (trimmed.endsWith("/api/v1")) trimmed else "$trimmed/api/v1"
    }

    override suspend fun me(): Identity {
        val obj = getObject("/me")
        return Identity(
            userId = obj.requireString("user_id"),
            tenantId = obj.optStringOrNull("tenant_id") ?: "",
            roles = obj.stringList("roles"),
            scopes = obj.stringList("scopes"),
            mfaSatisfied = obj.optBoolean("mfa_satisfied", false),
        )
    }

    override suspend fun createRequest(input: CreateAccessRequest): RequestSubmission {
        if (input.targetUserId.isBlank()) {
            throw AccessSDKException.InvalidInput("target_user_id is required")
        }
        if (input.resourceRef.isBlank()) {
            throw AccessSDKException.InvalidInput("resource_ref is required")
        }
        val body = JSONObject().apply {
            put("target_user_id", input.targetUserId)
            put("resource_ref", input.resourceRef)
            input.connectorId?.let { put("connector_id", it) }
            input.role?.let { put("role", it) }
            input.justification?.let { put("justification", it) }
            input.riskLevel?.let { put("risk_level", it.wireValue) }
            if (input.riskFactors.isNotEmpty()) {
                put("risk_factors", JSONArray(input.riskFactors))
            }
        }
        val env = parseObject(post("/access-requests", body.toString()))
        val request = env.requireObject("request").toAccessRequest()
        val workflow = env.optJSONObject("workflow")?.takeIf { it.length() > 0 }?.toWorkflowDecision()
        return RequestSubmission(request = request, workflow = workflow)
    }

    override suspend fun listRequests(): List<AccessRequest> {
        val env = getObject("/access-requests")
        return env.objectArray("requests").map { it.toAccessRequest() }
    }

    override suspend fun getRequest(id: String): AccessRequest {
        val env = getObject("/access-requests/${id.requireId()}")
        return env.requireObject("request").toAccessRequest()
    }

    override suspend fun getRequestDetail(id: String): AccessRequestDetail {
        val env = getObject("/access-requests/${id.requireId()}")
        return AccessRequestDetail(
            request = env.requireObject("request").toAccessRequest(),
            risk = env.optJSONObject("risk")?.takeIf { it.length() > 0 }?.toRiskVerdict(),
            anomalies = env.objectArray("anomalies").map { it.toAnomalyFlag() },
        )
    }

    override suspend fun requestHistory(id: String): List<StateHistoryEntry> {
        val env = getObject("/access-requests/${id.requireId()}/history")
        return env.objectArray("history").map { it.toStateHistoryEntry() }
    }

    override suspend fun approveRequest(id: String, reason: String?): AccessRequest =
        transition(id, "approve", reason)

    override suspend fun denyRequest(id: String, reason: String): AccessRequest {
        if (reason.isBlank()) throw AccessSDKException.InvalidInput("deny requires a reason")
        return transition(id, "deny", reason)
    }

    override suspend fun cancelRequest(id: String, reason: String?): AccessRequest =
        transition(id, "cancel", reason)

    override suspend fun provisionRequest(id: String): AccessGrant {
        val env = parseObject(post("/access-requests/${id.requireId()}/provision", "{}"))
        return env.requireObject("grant").toAccessGrant()
    }

    override suspend fun revokeGrant(id: String, reason: String?) {
        post("/grants/${id.requireId()}/revoke", decisionBody(reason), allowEmpty = true)
    }

    override suspend fun emergencyOffboard(userExternalId: String, reason: String?): LeaverResult {
        val externalId = userExternalId.trim()
        if (externalId.isBlank()) {
            throw AccessSDKException.InvalidInput("user_external_id is required")
        }
        val body = JSONObject().apply {
            put("user_external_id", externalId)
            reason?.let { put("reason", it) }
        }
        // A partial failure is HTTP 500 carrying the SAME { leaver } breakdown
        // (workflows.go); recover it from the typed Http error so the host can
        // render which layers failed instead of only a generic message. If the
        // body is absent, unparseable, or the leaver is malformed, fall through
        // to rethrow the original HTTP error rather than masking it with a
        // decode error (matches URLSessionAccessClient's `try?`).
        val raw = try {
            post("/emergency-offboard", body.toString())
        } catch (e: AccessSDKException.Http) {
            val recovered = e.body?.let { errBody ->
                runCatching { parseObject(errBody).requireObject("leaver").toLeaverResult() }
                    .getOrNull()
            }
            if (recovered != null) return recovered
            throw e
        }
        return parseObject(raw).requireObject("leaver").toLeaverResult()
    }

    private suspend fun transition(id: String, action: String, reason: String?): AccessRequest {
        val env = parseObject(post("/access-requests/${id.requireId()}/$action", decisionBody(reason)))
        return env.requireObject("request").toAccessRequest()
    }

    private fun decisionBody(reason: String?): String =
        JSONObject().apply { reason?.let { put("reason", it) } }.toString()

    // ----------------------------- Transport -----------------------------

    private suspend fun getObject(path: String): JSONObject = parseObject(get(path))

    private suspend fun get(path: String): String {
        val req = newRequest(path)
            .get()
            .build()
        return execute(req, allowEmpty = false)
    }

    private suspend fun post(path: String, body: String, allowEmpty: Boolean = false): String {
        val req = newRequest(path)
            .post(body.toRequestBody(JSON_MEDIA))
            .build()
        return execute(req, allowEmpty)
    }

    // Build a request with the bearer token attached, validating the URL up
    // front so a misconfigured baseUrl surfaces as a typed
    // AccessSDKException.InvalidInput on every verb (GET and POST alike) rather
    // than OkHttp's raw IllegalArgumentException.
    private suspend fun newRequest(path: String): Request.Builder {
        val url = (apiBase + path).toHttpUrlOrNull()
            ?: throw AccessSDKException.InvalidInput("invalid URL for path $path")
        return Request.Builder()
            .url(url)
            .header("Accept", "application/json")
            .header("Authorization", "Bearer ${fetchToken()}")
    }

    private suspend fun fetchToken(): String =
        try {
            authTokenProvider().also { if (it.isBlank()) throw AccessSDKException.Unauthenticated() }
        } catch (e: AccessSDKException) {
            throw e
        } catch (e: Throwable) {
            throw AccessSDKException.Unauthenticated()
        }

    private suspend fun execute(req: Request, allowEmpty: Boolean): String =
        withContext(ioDispatcher) {
            val response = try {
                client.newCall(req).execute()
            } catch (e: IOException) {
                throw AccessSDKException.Transport(e.message ?: "transport failure", e)
            }
            response.use { res ->
                val raw = res.body?.string() ?: ""
                when {
                    res.code == 401 -> throw AccessSDKException.Unauthenticated()
                    res.code == 403 && isStepUp(raw) -> throw AccessSDKException.StepUpRequired(raw.ifBlank { null })
                    res.code !in 200..299 -> throw AccessSDKException.Http(res.code, raw.ifBlank { null })
                    raw.isBlank() && !allowEmpty ->
                        throw AccessSDKException.Decoding("empty response body for ${req.url}")
                    else -> raw
                }
            }
        }

    // A 403 is a step-up gate only when the canonical `{"error": "..."}`
    // envelope carries the RequireMFA marker; other 403s (tenant mismatch,
    // no workspace) stay generic Http errors so callers don't mis-handle them.
    private fun isStepUp(raw: String): Boolean {
        if (raw.isBlank()) return false
        val msg = try {
            JSONObject(raw).optString("error", "")
        } catch (_: JSONException) {
            raw
        }
        return msg.lowercase().contains(STEP_UP_MARKER)
    }

    // ----------------------------- Parsing -----------------------------

    private fun parseObject(json: String): JSONObject =
        try {
            JSONObject(json)
        } catch (e: JSONException) {
            throw AccessSDKException.Decoding("expected JSON object: ${e.message}", e)
        }
}

// --- JSONObject extension helpers (kept private to the file) ---

private fun String.requireId(): String =
    trim().ifBlank { throw AccessSDKException.InvalidInput("id is required") }

private fun JSONObject.requireString(key: String): String {
    if (!has(key) || isNull(key)) throw AccessSDKException.Decoding("missing field: $key")
    return getString(key)
}

private fun JSONObject.optStringOrNull(key: String): String? =
    if (!has(key) || isNull(key)) null else optString(key, "").takeIf { it.isNotEmpty() }

private fun JSONObject.requireObject(key: String): JSONObject {
    if (!has(key) || isNull(key)) throw AccessSDKException.Decoding("missing object field: $key")
    return try {
        getJSONObject(key)
    } catch (e: JSONException) {
        throw AccessSDKException.Decoding("field $key is not an object", e)
    }
}

private fun JSONObject.stringList(key: String): List<String> {
    val arr = optJSONArray(key) ?: return emptyList()
    return (0 until arr.length()).map { arr.getString(it) }
}

private fun JSONObject.objectArray(key: String): List<JSONObject> {
    val arr = optJSONArray(key) ?: return emptyList()
    return (0 until arr.length()).map {
        try {
            arr.getJSONObject(it)
        } catch (e: JSONException) {
            throw AccessSDKException.Decoding("element $it of $key is not an object", e)
        }
    }
}

private fun parseInstant(value: String, field: String): Instant =
    try {
        Instant.parse(value)
    } catch (e: DateTimeParseException) {
        throw AccessSDKException.Decoding("field $field is not an RFC3339 timestamp: $value", e)
    }

private fun JSONObject.requireInstant(key: String): Instant = parseInstant(requireString(key), key)

private fun JSONObject.optInstant(key: String): Instant? =
    optStringOrNull(key)?.let { parseInstant(it, key) }

private fun JSONObject.toAccessRequest(): AccessRequest = AccessRequest(
    id = requireString("id"),
    workspaceId = requireString("workspace_id"),
    requesterId = requireString("requester_id"),
    targetUserId = optStringOrNull("target_user_id"),
    connectorId = optStringOrNull("connector_id"),
    resourceRef = requireString("resource_ref"),
    role = optStringOrNull("role"),
    justification = optStringOrNull("justification"),
    state = AccessRequestState.fromWire(requireString("state")),
    riskLevel = optStringOrNull("risk_level")?.let(RiskLevel::fromWire),
    riskFactors = stringList("risk_factors"),
    expiresAt = optInstant("expires_at"),
    createdAt = requireInstant("created_at"),
    updatedAt = optInstant("updated_at"),
)

private fun JSONObject.toWorkflowDecision(): WorkflowDecision = WorkflowDecision(
    stepType = WorkflowStep.fromWire(requireString("step_type")),
    reason = optString("reason", ""),
    approved = optBoolean("approved", false),
)

private fun JSONObject.toStateHistoryEntry(): StateHistoryEntry = StateHistoryEntry(
    id = requireString("id"),
    requestId = requireString("request_id"),
    fromState = optString("from_state", ""),
    toState = requireString("to_state"),
    actor = optStringOrNull("actor"),
    reason = optStringOrNull("reason"),
    createdAt = requireInstant("created_at"),
)

private fun JSONObject.toAccessGrant(): AccessGrant = AccessGrant(
    id = requireString("id"),
    workspaceId = requireString("workspace_id"),
    requestId = optStringOrNull("request_id"),
    connectorId = optStringOrNull("connector_id"),
    iamCoreUserId = requireString("iam_core_user_id"),
    resourceRef = requireString("resource_ref"),
    role = optStringOrNull("role"),
    state = GrantState.fromWire(requireString("state")),
    grantedAt = optInstant("granted_at"),
    expiresAt = optInstant("expires_at"),
    revokedAt = optInstant("revoked_at"),
)

private fun JSONObject.optDoubleOrNull(key: String): Double? =
    if (!has(key) || isNull(key)) null else optDouble(key).takeIf { !it.isNaN() }

private fun JSONObject.toRiskVerdict(): RiskVerdict = RiskVerdict(
    id = requireString("id"),
    requestId = requireString("request_id"),
    score = RiskLevel.fromWire(requireString("score")),
    recommendation = RiskRecommendation.fromWire(requireString("recommendation")),
    factors = stringList("factors"),
    rationale = optStringOrNull("rationale"),
    source = optStringOrNull("source"),
    degraded = optBoolean("degraded", false),
    createdAt = optInstant("created_at"),
)

private fun JSONObject.toAnomalyFlag(): AnomalyFlag = AnomalyFlag(
    id = requireString("id"),
    requestId = requireString("request_id"),
    grantId = optStringOrNull("grant_id"),
    kind = requireString("kind"),
    severity = optStringOrNull("severity"),
    reason = optStringOrNull("reason"),
    confidence = optDoubleOrNull("confidence"),
    createdAt = optInstant("created_at"),
)

private fun JSONObject.toLeaverResult(): LeaverResult = LeaverResult(
    userExternalId = requireString("user_external_id"),
    errored = optBoolean("errored", false),
    layers = objectArray("layers").map { it.toKillSwitchLayerResult() },
)

private fun JSONObject.toKillSwitchLayerResult(): KillSwitchLayerResult = KillSwitchLayerResult(
    layer = KillSwitchLayer.fromWire(requireString("layer")),
    status = KillSwitchLayerStatus.fromWire(requireString("status")),
    detail = optStringOrNull("detail"),
)
