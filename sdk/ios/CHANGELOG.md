# ShieldNet Access SDK (iOS) — Changelog

The SDK is versioned independently of the backend. Tags follow
`sdk-ios-vMAJOR.MINOR.PATCH`. See `PUBLISHING.md` for the release flow.

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
