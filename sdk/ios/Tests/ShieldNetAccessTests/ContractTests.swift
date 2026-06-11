//
// ContractTests.swift — compile-time + behavioural conformance of `AccessClient`.
//
// Asserts the protocol is implementable end-to-end with an in-memory fake (a
// breaking signature change stops the fake compiling and fails the target),
// and exercises the typed error surface, enum wire mappings, and the JIT
// lease countdown helpers — the SDK's external contract.
//

import XCTest
@testable import ShieldNetAccess

/// In-memory fake exercising every method on the protocol.
private actor FakeAccessClient: AccessClient {
    func me() async throws -> Identity {
        Identity(userID: "user_1", tenantID: "tenant_1", roles: ["approver"], scopes: ["access:write"], mfaSatisfied: true)
    }

    func createRequest(_ input: CreateAccessRequest) async throws -> RequestSubmission {
        RequestSubmission(
            request: sample(.requested, resource: input.resourceRef, risk: input.riskLevel),
            workflow: WorkflowDecision(stepType: .managerApproval, reason: "risk=medium → manager_approval", approved: false)
        )
    }

    func listRequests() async throws -> [AccessRequest] { [sample(.active)] }

    func getRequest(id: String) async throws -> AccessRequest { sample(.active, id: id) }

    func getRequestDetail(id: String) async throws -> AccessRequestDetail {
        AccessRequestDetail(
            request: sample(.active, id: id, risk: .high),
            risk: RiskVerdict(id: "rv_1", requestID: id, score: .high, recommendation: .highRisk, factors: ["sensitive_resource"]),
            anomalies: [AnomalyFlag(id: "af_1", requestID: id, kind: "impossible_travel", severity: "high")]
        )
    }

    func requestHistory(id: String) async throws -> [StateHistoryEntry] {
        [StateHistoryEntry(id: "h1", requestID: id, fromState: "requested", toState: "approved", actor: "user_2", reason: "ok", createdAt: Date(timeIntervalSince1970: 0))]
    }

    func approveRequest(id: String, reason: String?) async throws -> AccessRequest { sample(.approved, id: id) }
    func denyRequest(id: String, reason: String) async throws -> AccessRequest { sample(.denied, id: id) }
    func cancelRequest(id: String, reason: String?) async throws -> AccessRequest { sample(.cancelled, id: id) }

    func provisionRequest(id: String) async throws -> AccessGrant {
        AccessGrant(
            id: "grant_\(id)", workspaceID: "ws_1", requestID: id, connectorID: "conn_1",
            iamCoreUserID: "user_1", resourceRef: "projects/foo", role: "viewer", state: .active,
            grantedAt: Date(timeIntervalSince1970: 0), expiresAt: Date(timeIntervalSince1970: 3600)
        )
    }

    func revokeGrant(id: String, reason: String?) async throws {}

    func emergencyOffboard(userExternalID: String, reason: String?) async throws -> LeaverResult {
        LeaverResult(
            userExternalID: userExternalID,
            errored: false,
            layers: KillSwitchLayer.allCases.map { KillSwitchLayerResult(layer: $0, status: .done) }
        )
    }

    private func sample(_ state: AccessRequestState, id: String = "req_1", resource: String = "projects/foo", risk: RiskLevel? = nil) -> AccessRequest {
        AccessRequest(
            id: id, workspaceID: "ws_1", requesterID: "user_1", targetUserID: "user_1",
            connectorID: "conn_1", resourceRef: resource, role: "viewer", justification: "ci",
            state: state, riskLevel: risk, createdAt: Date(timeIntervalSince1970: 0)
        )
    }
}

final class ContractTests: XCTestCase {
    func testFakeSatisfiesProtocolEndToEnd() async throws {
        let client: AccessClient = FakeAccessClient()

        let me = try await client.me()
        XCTAssertEqual(me.tenantID, "tenant_1")
        XCTAssertTrue(me.mfaSatisfied)

        let submission = try await client.createRequest(
            CreateAccessRequest(targetUserID: "user_1", resourceRef: "projects/foo", role: "viewer", riskLevel: .medium)
        )
        XCTAssertEqual(submission.request.state, .requested)
        XCTAssertEqual(submission.workflow?.stepType, .managerApproval)
        XCTAssertEqual(submission.request.riskLevel, .medium)

        let list = try await client.listRequests()
        XCTAssertEqual(list.count, 1)
        let fetched = try await client.getRequest(id: "req_42")
        XCTAssertEqual(fetched.id, "req_42")
        let history = try await client.requestHistory(id: "req_1")
        XCTAssertEqual(history.first?.toState, "approved")

        let approved = try await client.approveRequest(id: "req_1")
        XCTAssertEqual(approved.state, .approved)
        let denied = try await client.denyRequest(id: "req_1", reason: "no")
        XCTAssertEqual(denied.state, .denied)
        let cancelled = try await client.cancelRequest(id: "req_1")
        XCTAssertEqual(cancelled.state, .cancelled)

        let grant = try await client.provisionRequest(id: "req_1")
        XCTAssertEqual(grant.state, .active)
        XCTAssertTrue(grant.isActive(now: Date(timeIntervalSince1970: 0)))
        try await client.revokeGrant(id: grant.id)

        let detail = try await client.getRequestDetail(id: "req_1")
        XCTAssertEqual(detail.risk?.recommendation, .highRisk)
        XCTAssertEqual(detail.anomalies.count, 1)

        let leaver = try await client.emergencyOffboard(userExternalID: "user_1", reason: "left the company")
        XCTAssertEqual(leaver.userExternalID, "user_1")
        XCTAssertFalse(leaver.errored)
        XCTAssertEqual(leaver.layers.count, KillSwitchLayer.allCases.count)
    }

    func testEnumWireValues() {
        XCTAssertEqual(AccessRequestState.provisionFailed.rawValue, "provision_failed")
        XCTAssertEqual(AccessRequestState(rawValue: "active"), .active)
        // ai_reviewed is a real intermediate state (requested -> ai_reviewed ->
        // approved/denied) that getRequestDetail can surface; it must decode.
        XCTAssertEqual(AccessRequestState.aiReviewed.rawValue, "ai_reviewed")
        XCTAssertEqual(AccessRequestState(rawValue: "ai_reviewed"), .aiReviewed)
        XCTAssertEqual(WorkflowStep.securityReview.rawValue, "security_review")
        XCTAssertEqual(GrantState(rawValue: "revoked"), .revoked)
        XCTAssertNil(AccessRequestState(rawValue: "nope"))

        XCTAssertEqual(RiskRecommendation.highRisk.rawValue, "high_risk")
        XCTAssertEqual(RiskRecommendation(rawValue: "auto_approve_eligible"), .autoApproveEligible)
        XCTAssertEqual(KillSwitchLayer(rawValue: "scim_deprovision"), .scimDeprovision)
        XCTAssertEqual(KillSwitchLayerStatus(rawValue: "failed"), .failed)
        XCTAssertNil(RiskRecommendation(rawValue: "maybe"))
        XCTAssertNil(KillSwitchLayer(rawValue: "nuke"))
    }

    func testTypedErrorsAreEquatable() {
        XCTAssertEqual(AccessSDKError.unauthenticated, .unauthenticated)
        XCTAssertEqual(AccessSDKError.http(statusCode: 409, body: "x"), .http(statusCode: 409, body: "x"))
        XCTAssertNotEqual(AccessSDKError.stepUpRequired("a"), .stepUpRequired("b"))
    }

    func testLeaseCountdownClampedAndStateAware() {
        let base = Date(timeIntervalSince1970: 1_000_000)
        let active = AccessGrant(
            id: "g1", workspaceID: "ws", iamCoreUserID: "u", resourceRef: "r",
            state: .active, grantedAt: base, expiresAt: base.addingTimeInterval(600)
        )
        XCTAssertEqual(active.remaining(now: base), 600)
        XCTAssertEqual(active.remaining(now: base.addingTimeInterval(900)), 0)
        XCTAssertTrue(active.isActive(now: base))
        XCTAssertFalse(active.isActive(now: base.addingTimeInterval(900)))

        let nonExpiring = AccessGrant(id: "g2", workspaceID: "ws", iamCoreUserID: "u", resourceRef: "r", state: .active)
        XCTAssertNil(nonExpiring.remaining(now: base))
        XCTAssertTrue(nonExpiring.isActive(now: base))

        let revoked = AccessGrant(
            id: "g3", workspaceID: "ws", iamCoreUserID: "u", resourceRef: "r",
            state: .revoked, expiresAt: base.addingTimeInterval(600)
        )
        XCTAssertFalse(revoked.isActive(now: base)) // fail-closed despite future expiry
    }
}
