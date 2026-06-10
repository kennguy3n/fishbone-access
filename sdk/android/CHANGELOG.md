# ShieldNet Access SDK (Android) — Changelog

The SDK is versioned independently of the backend. Tags follow
`sdk-android-vMAJOR.MINOR.PATCH`. See `PUBLISHING.md` for the release flow.

## 0.2.0 — cross-platform revoke UX (WS5)

- Adds two methods to the `AccessClient` interface (now 12 methods):
  - `getRequestDetail(id)` reads the same `GET /access-requests/:id` endpoint
    but unwraps the `risk` (AI `RiskVerdict`) and `anomalies` (`AnomalyFlag`)
    envelope keys the server already returns, so a host can surface high-risk /
    anomalous active access and offer a one-tap revoke.
  - `emergencyOffboard(userExternalId, reason?)` drives the six-layer leaver
    kill switch (`POST /emergency-offboard`) for a single identity. The call is
    step-up-MFA-gated server-side: a token without a satisfied MFA claim throws
    `AccessSDKException.StepUpRequired`. A partial failure (HTTP 500) still
    returns the full per-layer `LeaverResult` breakdown rather than throwing.
- Ships new value types in `Risk.kt`: `RiskVerdict`, `RiskRecommendation`,
  `AnomalyFlag`, `AccessRequestDetail`, `RiskAdvisory`; and in `Revocation.kt`:
  `LeaverResult`, `KillSwitchLayer`/`KillSwitchLayerStatus`/`KillSwitchLayerResult`,
  `RevocationPlan`.
- Ships the pure cross-platform classifier `RiskAssessment.evaluate(...)` →
  `RiskAdvisory` (`isElevated` / `isHighRisk` + human-readable `reasons`) and the
  step-up planner `Revocation.plan(...)` → `RevocationPlan`. High-risk is a
  fail-safe union of the request risk band, the AI recommendation, the verdict
  score, and any elevated anomaly; `Revocation.plan` gates a high-risk revoke
  behind step-up MFA so the UX matches the web console and iOS SDK.
- No new dependencies; identical logic and wire mapping to the iOS SDK.

## 0.1.0 — initial publishable cut

- First public Maven artifact (`com.shieldnet.access:access-sdk:0.1.0`).
- Ships the `AccessClient` Kotlin interface with all 10 REST methods mapping to
  the fishbone-access `/api/v1` surface: `me`, `createRequest`, `listRequests`,
  `getRequest`, `requestHistory`, `approveRequest`, `denyRequest`,
  `cancelRequest`, `provisionRequest`, `revokeGrant`.
- Ships the `OkHttpAccessClient` concrete implementation backed by `OkHttpClient`
  + manual `org.json` parsing (no JSON-serialization dependency leaked into the
  public types), coroutine-based with a host-overridable IO dispatcher and a
  per-request `authTokenProvider`.
- Ships the typed-exception sealed class `AccessSDKException` with `Transport`,
  `Http`, `Decoding`, `InvalidInput`, `Unauthenticated`, `StepUpRequired`, and
  `NotConfigured` subclasses. `StepUpRequired` surfaces the server's high-risk
  step-up-MFA gate so the host can drive WebAuthn and retry.
- Surfaces the server-side AI risk verdict (WS5) via `AccessRequest.riskLevel` /
  `riskFactors` and the `WorkflowDecision` routing lane. No on-device inference.
- Models JIT leases (WS4) as `AccessGrant` with fail-closed `isActive()` /
  `remaining()` countdown helpers.
- Ships a Kotlin JVM sample under `sdk/android/example/`.
