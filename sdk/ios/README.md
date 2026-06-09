# ShieldNet Access SDK — iOS (Swift Package)

A thin, well-typed Swift client over the ShieldNet Access control-plane
`/api/v1` surface. An SME embeds it in their own iOS app to drive access /
elevation flows — submit requests, observe AI-driven risk routing, approve or
deny as an approver, handle step-up MFA, and activate / watch JIT leases.

It mirrors the Kotlin SDK under [`sdk/android`](../android) method-for-method,
using `async/await` and `URLSession`.

> **No on-device inference.** This package imports only `Foundation` — no
> `CoreML`, no `MLX`, no bundled model files. "AI-initiated" means the SDK
> calls the server endpoint that triggers the server-side `access-ai-agent`
> (WS5); the risk verdict is read from the persisted request fields and the
> workflow routing decision.

## Requirements

- iOS 15+ / macOS 12+ (async/await, `ISO8601DateFormatter.withFractionalSeconds`).
- Swift 5.7+ toolchain.

## Install (Swift Package Manager)

```swift
dependencies: [
    .package(url: "https://github.com/kennguy3n/fishbone-access.git", from: "0.1.0"),
],
targets: [
    .target(name: "MyApp", dependencies: [
        .product(name: "ShieldNetAccess", package: "fishbone-access"),
    ]),
]
```

(Or point Xcode at the `sdk/ios` directory directly for local development.)

## Quick start

```swift
import ShieldNetAccess

let client = URLSessionAccessClient(
    baseURL: URL(string: "https://access.example.com")!,   // with or without /api/v1
    authTokenProvider: { await tokenStore.currentIamCoreToken() } // awaited per request
)

// Identity + tenant; check whether the session already satisfied step-up MFA.
let me = try await client.me()

// Submit an elevation request — the server runs risk-based routing.
let submission = try await client.createRequest(
    CreateAccessRequest(
        targetUserID: me.userID,
        resourceRef: "projects/payments-prod",
        role: "deployer",
        justification: "ship hotfix 1.2.3",
        riskLevel: .high
    )
)
print(submission.workflow?.stepType ?? .autoApprove)  // autoApprove | managerApproval | securityReview

// Approve as an approver; the returned row carries the server's AI risk verdict.
let approved = try await client.approveRequest(id: submission.request.id, reason: "low blast radius")
print(approved.riskLevel ?? .low)                     // low | medium | high

// Provision → JIT lease, then read the countdown.
let grant = try await client.provisionRequest(id: submission.request.id)
print(grant.remaining() ?? 0)                         // seconds until the lease expires
```

## Capabilities

| Capability | Method | Endpoint |
| --- | --- | --- |
| Identity / tenant | `me()` | `GET /me` |
| Submit request | `createRequest(_:)` | `POST /access-requests` |
| List requests | `listRequests()` | `GET /access-requests` |
| Poll / observe status | `getRequest(id:)` | `GET /access-requests/:id` |
| State history | `requestHistory(id:)` | `GET /access-requests/:id/history` |
| Approve (with reason) | `approveRequest(id:reason:)` | `POST /access-requests/:id/approve` |
| Deny (with reason) | `denyRequest(id:reason:)` | `POST /access-requests/:id/deny` |
| Cancel own request | `cancelRequest(id:reason:)` | `POST /access-requests/:id/cancel` |
| Activate JIT lease | `provisionRequest(id:)` | `POST /access-requests/:id/provision` |
| Revoke lease early | `revokeGrant(id:reason:)` | `POST /grants/:id/revoke` |

### Step-up MFA / WebAuthn

ShieldNet Access delegates identity and MFA to **iam-core** (OAuth2/OIDC). The
SDK does not perform MFA itself:

- `me().mfaSatisfied` reports whether the current token's session already
  cleared step-up.
- When the server gates a high-risk action on step-up, the call throws
  `AccessSDKError.stepUpRequired`. The host drives an iam-core step-up
  (WebAuthn / passkey via `ASAuthorizationController`, or OTP), obtains a fresh
  token, and retries — `authTokenProvider` returns the stepped-up token next.

```swift
do {
    _ = try await client.provisionRequest(id: id)
} catch AccessSDKError.stepUpRequired {
    let steppedUp = try await iamCore.stepUpWithPasskey()  // host-driven
    await tokenStore.replace(steppedUp)
    _ = try await client.provisionRequest(id: id)          // retry
}
```

### JIT lease countdown

`provisionRequest` returns the `AccessGrant`. Read its live state with the pure
helpers — no extra round-trips:

```swift
grant.isActive()    // active AND not expired (fail-closed on revoke)
grant.remaining()   // TimeInterval left, clamped to zero, nil if non-expiring
```

## Error handling

Every failure is an `AccessSDKError`: `.transport`, `.unauthenticated`,
`.stepUpRequired(body)`, `.http(statusCode:body:)`, `.decoding`,
`.invalidInput`, `.notConfigured`.

## Build & test

```bash
cd sdk/ios
swift build                       # compile the library + example
swift test                        # run unit + contract tests
swift run AccessExample           # run the console example (needs ACCESS_BASE_URL + ACCESS_TOKEN)
```

The package depends only on `Foundation`, so the **non-UI core compiles and the
full XCTest suite runs on Linux** via swift-corelibs-foundation, as well as on
macOS. There is no SwiftUI/UIKit code in this package.

> **macOS / CI note.** This SDK is UI-free and has no UIKit/SwiftUI
> dependency, so `swift build` / `swift test` are authoritative on both Linux
> and macOS. If a host app wraps it in a SwiftUI screen, that app's view tests
> must run on macOS with Xcode (`xcodebuild -scheme … -destination 'platform=iOS Simulator,…'`).

## Design notes

- **Thin client.** Types and field names mirror `docs/openapi.yaml`, the Go
  models in `internal/models/models.go`, and the Android SDK. Handler envelopes
  (`{"request": …}`, `{"requests": […]}`, `{"grant": …}`, `{"history": […]}`)
  are unwrapped by the client.
- **Token refresh is the host's job.** `authTokenProvider` is awaited per
  request, keeping refresh and step-up re-auth outside the SDK.
- **Multi-tenant & fail-closed.** Actor and workspace are derived server-side
  from the validated token + tenant claim; the SDK never sends them.
- **Timestamps.** RFC3339 with or without fractional seconds are both decoded.
