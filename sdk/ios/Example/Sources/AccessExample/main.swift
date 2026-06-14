//
// main.swift — end-to-end usage of the ShieldNetAccess iOS SDK.
//
// A tiny command-line program (not an app target) kept as a compiled
// executable target so `swift build` validates the example against the real
// SDK API. In a SwiftUI app the same calls run from an `async` task / view
// model; here we use the top-level `await` of an async `@main`-style entry.
//
// Run:
//   ACCESS_BASE_URL=https://access.example.com ACCESS_TOKEN=<token> \
//   swift run AccessExample
//

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import ShieldNetAccess

func runExample() async {
    let baseURLString = ProcessInfo.processInfo.environment["ACCESS_BASE_URL"] ?? "https://access.example.com"
    guard let baseURL = URL(string: baseURLString) else {
        print("invalid ACCESS_BASE_URL: \(baseURLString)")
        return
    }
    guard let token = ProcessInfo.processInfo.environment["ACCESS_TOKEN"] else {
        print("set ACCESS_TOKEN to an iam-core bearer token")
        return
    }

    // The token provider is awaited before every call, so refreshing or
    // supplying a stepped-up token stays the host app's concern.
    let client = URLSessionAccessClient(baseURL: baseURL, authTokenProvider: { token })

    do {
        // 1. Who am I, and did this session already satisfy step-up MFA?
        let me = try await client.me()
        print("acting as \(me.userID) in tenant \(me.tenantID); mfaSatisfied=\(me.mfaSatisfied)")

        // 2. Submit an elevation request; the server runs risk-based routing.
        let submission = try await client.createRequest(
            CreateAccessRequest(
                targetUserID: me.userID,
                resourceRef: "projects/payments-prod",
                role: "deployer",
                justification: "ship hotfix 1.2.3",
                riskLevel: .high,
                riskFactors: ["sensitive_resource"]
            )
        )
        let request = submission.request
        print("request \(request.id) → state=\(request.state.rawValue), lane=\(submission.workflow?.stepType.rawValue ?? "n/a")")

        // 3. Approve as an approver (surfacing the server AI risk verdict).
        if request.state == .requested {
            let approved = try await client.approveRequest(id: request.id, reason: "reviewed, low blast radius")
            print("approved → state=\(approved.state.rawValue), risk=\(approved.riskLevel?.rawValue ?? "n/a")")
        }

        // 4. Provision → JIT lease, and read its countdown.
        let grant = try await client.provisionRequest(id: request.id)
        print("lease \(grant.id) active=\(grant.isActive()) remaining=\(grant.remaining().map { "\(Int($0))s" } ?? "n/a")")

        // 5. Risky-access awareness: read the AI risk verdict + anomaly
        //    signals and classify them with the cross-platform pure helper.
        let detail = try await client.getRequestDetail(id: request.id)
        let advisory = RiskAssessment.evaluate(detail)
        if advisory.isElevated {
            print("⚠️ elevated access \(detail.request.id): \(advisory.reasons.joined(separator: "; "))")
        }

        // 6. One-tap revoke. For a high-risk revoke the SDK tells the host
        //    to gate behind step-up MFA first — the same decision on every
        //    platform. The grant-revoke endpoint itself is permission-gated.
        let plan = Revocation.plan(advisory)
        if plan.requiresStepUp && !me.mfaSatisfied {
            print("revoke of \(grant.id) needs step-up MFA — driving WebAuthn before revoke")
        } else {
            try await client.revokeGrant(id: grant.id, reason: "risk review: ending lease early")
            print("revoked lease \(grant.id)")
        }

        // 7. Emergency offboard: the "revoke everything for this user"
        //    kill switch. Step-up-gated server-side; a partial failure still
        //    returns the per-layer breakdown so the operator can retry.
        //    NOTE: emergencyOffboard takes the EXTERNAL identity id (the value
        //    your IdP/directory knows the leaver by). We reuse me.userID here
        //    purely to keep the example self-contained — a real host resolves
        //    the external id from its directory, not the caller's iam-core id.
        let leaver = try await client.emergencyOffboard(userExternalID: me.userID, reason: "offboarding")
        print("offboard \(leaver.userExternalID): errored=\(leaver.errored), failed layers=\(leaver.failedLayers.map { $0.layer.rawValue })")
    } catch let AccessSDKError.stepUpRequired(body) {
        // High-risk gate: drive an iam-core step-up (WebAuthn) in the host,
        // obtain a fresh token, then retry the gated call.
        print("step-up MFA required: \(body ?? "")")
    } catch {
        print("access flow failed: \(error)")
    }
}

await runExample()
