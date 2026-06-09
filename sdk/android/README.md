# ShieldNet Access SDK — Android

A thin, well-typed Kotlin client over the ShieldNet Access control-plane
`/api/v1` surface. An SME embeds it in their own Android app to drive access /
elevation flows — submit requests, observe AI-driven risk routing, approve or
deny as an approver, handle step-up MFA, and activate / watch JIT leases —
without re-implementing the wire contract.

> **No on-device inference.** This SDK ships no model files and imports no ML
> runtime. "AI-initiated" means the SDK calls the server endpoint that triggers
> the server-side `access-ai-agent` (WS5). The risk verdict is read from the
> persisted request fields and the workflow routing decision.

The Swift package under [`sdk/ios`](../ios) mirrors this contract method-for-method.

## Install

The module is plain Kotlin/JVM (no Android Gradle Plugin) so it builds on a
stock JDK. Consume the published Maven artifact:

```kotlin
dependencies {
    implementation("com.shieldnet.access:access-sdk:0.1.0")
}
```

Runtime requirements: OkHttp 4.x, kotlinx-coroutines 1.8.x, and `org.json`
(part of the Android platform; pulled from Maven for JVM tests).

## Quick start

```kotlin
import com.shieldnet.access.*

val client = OkHttpAccessClient(
    baseUrl = "https://access.example.com",   // with or without the /api/v1 suffix
    authTokenProvider = { tokenStore.currentIamCoreToken() }, // called per request
)

// Identity + tenant; check whether the session already satisfied step-up MFA.
val me = client.me()

// Submit an elevation request — the server runs risk-based routing.
val submission = client.createRequest(
    CreateAccessRequest(
        targetUserId = me.userId,
        resourceRef = "projects/payments-prod",
        role = "deployer",
        justification = "ship hotfix 1.2.3",
        riskLevel = RiskLevel.HIGH,
    ),
)
println(submission.workflow?.stepType)   // AUTO_APPROVE | MANAGER_APPROVAL | SECURITY_REVIEW

// Approve as an approver; the returned row carries the server's AI risk verdict.
val approved = client.approveRequest(submission.request.id, reason = "low blast radius")
println(approved.riskLevel)              // LOW | MEDIUM | HIGH

// Provision → JIT lease, then read the countdown.
val grant = client.provisionRequest(submission.request.id)
println(grant.remaining())               // Duration until the lease expires
```

All methods are `suspend`; call them from a coroutine scope the host controls
(`viewModelScope`, `lifecycleScope`, …). I/O runs on `Dispatchers.IO` by
default — override via the `ioDispatcher` constructor parameter.

## Capabilities

| Capability | Method | Endpoint |
| --- | --- | --- |
| Identity / tenant | `me()` | `GET /me` |
| Submit request | `createRequest(...)` | `POST /access-requests` |
| List requests | `listRequests()` | `GET /access-requests` |
| Poll / observe status | `getRequest(id)` | `GET /access-requests/:id` |
| State history | `requestHistory(id)` | `GET /access-requests/:id/history` |
| Approve (with reason) | `approveRequest(id, reason)` | `POST /access-requests/:id/approve` |
| Deny (with reason) | `denyRequest(id, reason)` | `POST /access-requests/:id/deny` |
| Cancel own request | `cancelRequest(id, reason)` | `POST /access-requests/:id/cancel` |
| Activate JIT lease | `provisionRequest(id)` | `POST /access-requests/:id/provision` |
| Revoke lease early | `revokeGrant(id, reason)` | `POST /grants/:id/revoke` |

### Step-up MFA / WebAuthn

ShieldNet Access delegates identity and MFA to **iam-core** (OAuth2/OIDC). The
SDK does not perform MFA itself. Instead:

- `me().mfaSatisfied` reports whether the current token's session already
  cleared step-up (the `amr` / `mfa` claim).
- When the server gates a high-risk, data-plane-mutating action on step-up, the
  call throws `AccessSDKException.StepUpRequired`. The host then drives an
  iam-core step-up (WebAuthn / passkey via Credential Manager, or OTP), obtains
  a fresh token, and retries — the `authTokenProvider` returns the stepped-up
  token on the next call.

```kotlin
try {
    client.provisionRequest(id)
} catch (e: AccessSDKException.StepUpRequired) {
    val steppedUp = iamCore.stepUpWithWebAuthn()   // host-driven, out of band
    tokenStore.replace(steppedUp)
    client.provisionRequest(id)                    // retry with the fresh token
}
```

### JIT lease countdown

`provisionRequest` returns the `AccessGrant` (the lease). Read its live state
with the pure helpers — no extra round-trips:

```kotlin
grant.isActive()         // active AND not yet expired (fail-closed on revoke)
grant.remaining()        // Duration left, clamped to zero, null if non-expiring
```

To refresh the countdown against the server, re-fetch the originating request
with `getRequest(id)` and read `state` / `expiresAt`.

## Error handling

Every failure is an `AccessSDKException`:

| Subtype | Meaning |
| --- | --- |
| `Transport` | network / TLS / timeout |
| `Unauthenticated` | HTTP 401, or no token available |
| `StepUpRequired` | HTTP 403 "step-up MFA required" — drive step-up and retry |
| `Http` | any other non-2xx (status + raw body) |
| `Decoding` | response body did not match the model |
| `InvalidInput` | caller-side invariant (e.g. blank id / reason) — no network call made |
| `NotConfigured` | SDK not configured |

## Build & test

```bash
cd sdk/android
./gradlew build      # compile + unit/contract tests + example
./gradlew test       # tests only
./gradlew :example:run   # run the console example (needs ACCESS_BASE_URL + ACCESS_TOKEN)
```

Tests use OkHttp's `MockWebServer` for real HTTP round-trips (request/response
at the socket boundary) plus an in-memory fake that proves the `AccessClient`
interface is implementable end-to-end.

## Design notes

- **Thin client.** Types and field names mirror `docs/openapi.yaml` and the Go
  models in `internal/models/models.go`. Handler envelopes
  (`{"request": …}`, `{"requests": […]}`, `{"grant": …}`, `{"history": […]}`)
  are unwrapped by the client.
- **No serialization dependency in public types.** Host apps keep their own
  Moshi / kotlinx.serialization / Gson choice; the bundled client parses with
  `org.json`.
- **Token refresh is the host's job.** `authTokenProvider` is invoked per
  request, keeping refresh and step-up re-auth outside the SDK.
- **Multi-tenant & fail-closed.** Actor and workspace are derived server-side
  from the validated token + tenant claim; the SDK never sends them, so a
  client cannot act for another tenant or spoof an actor.
