# ShieldNet Access SDK (Android) — Changelog

The SDK is versioned independently of the backend. Tags follow
`sdk-android-vMAJOR.MINOR.PATCH`. See `PUBLISHING.md` for the release flow.

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
