# ShieldNet Access SDK (iOS) — Changelog

The SDK is versioned independently of the backend. Tags follow
`sdk-ios-vMAJOR.MINOR.PATCH`. See `PUBLISHING.md` for the release flow.

## 0.2.0 — cross-platform revoke UX (WS5)

- Adds two methods to the `AccessClient` protocol (now 12 methods):
  - `getRequestDetail(id:)` reads the same `GET /access-requests/:id` endpoint
    but unwraps the `risk` (AI `RiskVerdict`) and `anomalies` (`AnomalyFlag`)
    envelope keys the server already returns, so a host can surface high-risk /
    anomalous active access and offer a one-tap revoke.
  - `emergencyOffboard(userExternalID:reason:)` drives the six-layer leaver kill
    switch (`POST /emergency-offboard`) for a single identity. The call is
    step-up-MFA-gated server-side: a token without a satisfied MFA claim throws
    `AccessSDKError.stepUpRequired`. A partial failure (HTTP 500) still returns
    the full per-layer `LeaverResult` breakdown rather than throwing.
- Ships new value types in `Risk.swift`: `RiskVerdict`, `RiskRecommendation`,
  `AnomalyFlag`, `AccessRequestDetail`, `RiskAdvisory`; and in
  `Revocation.swift`: `LeaverResult`,
  `KillSwitchLayer`/`KillSwitchLayerStatus`/`KillSwitchLayerResult`,
  `RevocationPlan`.
- Ships the pure cross-platform classifier `RiskAssessment.evaluate(...)` →
  `RiskAdvisory` (`isElevated` / `isHighRisk` + human-readable `reasons`) and the
  step-up planner `Revocation.plan(...)` → `RevocationPlan`. High-risk is a
  fail-safe union of the request risk band, the AI recommendation, the verdict
  score, and any elevated anomaly; `Revocation.plan` gates a high-risk revoke
  behind step-up MFA so the UX matches the web console and Android SDK.
- No new dependencies (Foundation-only); identical logic and wire mapping to the
  Android SDK.
- `RiskAssessment.evaluate` now emits an `"AI verdict score: medium"` reason when
  a medium verdict score diverges from the request band, so an `isElevated`
  advisory never renders with an empty justification. Matches the Android/web
  classifiers byte-for-byte.
- Adds the missing `AccessRequestState.aiReviewed` (`ai_reviewed`) case so a
  request observed in that real intermediate state (`requested → ai_reviewed →
  approved/denied`) decodes instead of throwing `DecodingError`.
  `getRequestDetail(id:)` makes this state reachable from the SDK, so the enum
  now matches the server state machine and `docs/openapi.yaml` exactly.

## 0.1.0 — initial publishable cut

- First Swift Package release of `ShieldNetAccess` (iOS 15+, macOS 12+).
- Ships the `AccessClient` protocol with all 10 async methods mapping to the
  fishbone-access `/api/v1` surface: `me`, `createRequest`, `listRequests`,
  `getRequest`, `requestHistory`, `approveRequest`, `denyRequest`,
  `cancelRequest`, `provisionRequest`, `revokeGrant` — mirroring the Android
  SDK method-for-method.
- Ships `URLSessionAccessClient`, a `URLSession`-backed implementation
  (Foundation-only; portable across Apple platforms and Linux/CI via a
  `dataTask` continuation wrapper), with a per-request async `authTokenProvider`
  and RFC3339 timestamp decoding (with/without fractional seconds).
- Ships the typed `AccessSDKError` enum: `transport`, `http`, `decoding`,
  `invalidInput`, `unauthenticated`, `stepUpRequired`, `notConfigured`.
  `stepUpRequired` surfaces the server's high-risk step-up-MFA gate.
- Surfaces the server-side AI risk verdict (WS5) via `AccessRequest.riskLevel` /
  `riskFactors` and the `WorkflowDecision`. No on-device inference (no CoreML /
  MLX / bundled model files).
- Models JIT leases (WS4) as `AccessGrant` with fail-closed `isActive()` /
  `remaining()` helpers.
- Ships a compiled console sample under `sdk/ios/Example/` (`swift run AccessExample`).
