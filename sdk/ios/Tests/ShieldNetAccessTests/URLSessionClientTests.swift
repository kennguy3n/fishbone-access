//
// URLSessionClientTests.swift — real URLSession round-trip tests.
//
// We intercept network I/O with a `URLProtocol` subclass registered on a
// dedicated `URLSession`. This is NOT a mock of URLSession — the SDK drives a
// fully-real `URLSession` (request construction, headers, protocol lookup,
// `data(for:)` dispatch); the protocol subclass just returns canned responses
// so the tests are deterministic. A live server is impractical per test, so
// this stands in for `ztna-api` — the only mock in the suite, at the socket
// boundary.
//

import XCTest
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
@testable import ShieldNetAccess

/// `URLProtocol` subclass returning canned responses and recording requests.
final class URLProtocolStub: URLProtocol {
    nonisolated(unsafe) static var handler: ((URLRequest) -> (statusCode: Int, body: Data))?
    nonisolated(unsafe) static var captured: [URLRequest] = []

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        URLProtocolStub.captured.append(request)
        guard let handler = URLProtocolStub.handler else {
            client?.urlProtocol(self, didFailWithError: NSError(domain: "stub", code: -1))
            return
        }
        let (status, body) = handler(request)
        let response = HTTPURLResponse(
            url: request.url!,
            statusCode: status,
            httpVersion: "HTTP/1.1",
            headerFields: ["Content-Type": "application/json"]
        )!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: body)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

final class URLSessionClientTests: XCTestCase {
    private var client: URLSessionAccessClient!

    override func setUp() {
        super.setUp()
        URLProtocolStub.captured = []
        URLProtocolStub.handler = nil
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [URLProtocolStub.self]
        let session = URLSession(configuration: config)
        // baseURL WITHOUT /api/v1 — the client must append the prefix.
        client = URLSessionAccessClient(
            baseURL: URL(string: "https://access.test")!,
            session: session,
            authTokenProvider: { "tok_123" }
        )
    }

    override func tearDown() {
        URLProtocolStub.handler = nil
        URLProtocolStub.captured = []
        client = nil
        super.tearDown()
    }

    private func respond(_ status: Int, _ json: String) {
        URLProtocolStub.handler = { _ in (status, Data(json.utf8)) }
    }

    func testMeParsesIdentityAndSendsBearer() async throws {
        respond(200, #"{"user_id":"u1","tenant_id":"t1","roles":["approver"],"scopes":["access:write"],"mfa_satisfied":true}"#)
        let me = try await client.me()
        XCTAssertEqual(me.userID, "u1")
        XCTAssertEqual(me.tenantID, "t1")
        XCTAssertTrue(me.mfaSatisfied)

        let req = URLProtocolStub.captured.first
        XCTAssertEqual(req?.url?.path, "/api/v1/me")
        XCTAssertEqual(req?.value(forHTTPHeaderField: "Authorization"), "Bearer tok_123")
    }

    func testCreateRequestUnwrapsRequestAndWorkflow() async throws {
        respond(201, #"""
        {"request":{"id":"r1","workspace_id":"ws1","requester_id":"u1","target_user_id":"u2",
        "resource_ref":"projects/foo","role":"viewer","state":"requested","risk_level":"high",
        "risk_factors":["sensitive_resource"],"created_at":"2025-01-01T00:00:00Z"},
        "workflow":{"step_type":"security_review","reason":"risk=high","approved":false}}
        """#)
        let submission = try await client.createRequest(
            CreateAccessRequest(targetUserID: "u2", resourceRef: "projects/foo", role: "viewer", justification: "deploy", riskLevel: .high, riskFactors: ["sensitive_resource"])
        )
        XCTAssertEqual(submission.request.id, "r1")
        XCTAssertEqual(submission.request.state, .requested)
        XCTAssertEqual(submission.request.riskLevel, .high)
        XCTAssertEqual(submission.request.riskFactors, ["sensitive_resource"])
        XCTAssertEqual(submission.workflow?.stepType, .securityReview)

        let req = URLProtocolStub.captured.first
        XCTAssertEqual(req?.url?.path, "/api/v1/access-requests")
        XCTAssertEqual(req?.httpMethod, "POST")
    }

    func testListRequestsUnwrapsArray() async throws {
        respond(200, #"""
        {"requests":[
          {"id":"r1","workspace_id":"ws1","requester_id":"u1","resource_ref":"a","state":"active","created_at":"2025-01-01T00:00:00Z"},
          {"id":"r2","workspace_id":"ws1","requester_id":"u1","resource_ref":"b","state":"denied","created_at":"2025-01-02T00:00:00Z"}
        ]}
        """#)
        let rows = try await client.listRequests()
        XCTAssertEqual(rows.count, 2)
        XCTAssertEqual(rows[0].state, .active)
        XCTAssertEqual(rows[1].id, "r2")
    }

    func testGetRequestParsesExpiryForLeaseCountdown() async throws {
        respond(200, #"{"request":{"id":"r1","workspace_id":"ws1","requester_id":"u1","resource_ref":"a","state":"active","expires_at":"2025-01-01T01:00:00Z","created_at":"2025-01-01T00:00:00Z"}}"#)
        let req = try await client.getRequest(id: "r1")
        XCTAssertEqual(req.state, .active)
        XCTAssertNotNil(req.expiresAt)
        XCTAssertEqual(URLProtocolStub.captured.first?.url?.path, "/api/v1/access-requests/r1")
    }

    func testApproveSurfacesRiskVerdict() async throws {
        respond(200, #"{"request":{"id":"r1","workspace_id":"ws1","requester_id":"u1","resource_ref":"a","state":"approved","risk_level":"medium","created_at":"2025-01-01T00:00:00Z"}}"#)
        let approved = try await client.approveRequest(id: "r1", reason: "ok")
        XCTAssertEqual(approved.state, .approved)
        XCTAssertEqual(approved.riskLevel, .medium)
        XCTAssertEqual(URLProtocolStub.captured.first?.url?.path, "/api/v1/access-requests/r1/approve")
    }

    func testProvisionReturnsGrantAndComputesRemaining() async throws {
        respond(200, #"""
        {"grant":{"id":"g1","workspace_id":"ws1","request_id":"r1","connector_id":"c1","iam_core_user_id":"u1",
        "resource_ref":"projects/foo","role":"viewer","state":"active","granted_at":"2025-01-01T00:00:00Z",
        "expires_at":"2025-01-01T02:00:00Z"}}
        """#)
        let grant = try await client.provisionRequest(id: "r1")
        XCTAssertEqual(grant.state, .active)
        let now = ISO8601DateFormatter().date(from: "2025-01-01T00:30:00Z")!
        XCTAssertEqual(grant.remaining(now: now), 90 * 60)
        XCTAssertTrue(grant.isActive(now: now))
        XCTAssertEqual(URLProtocolStub.captured.first?.url?.path, "/api/v1/access-requests/r1/provision")
    }

    func testRevokeToleratesEmptyBody() async throws {
        URLProtocolStub.handler = { _ in (200, Data()) }
        try await client.revokeGrant(id: "g1", reason: "done")
        XCTAssertEqual(URLProtocolStub.captured.first?.url?.path, "/api/v1/grants/g1/revoke")
    }

    func testGetRequestDetailUnwrapsRiskAndAnomalies() async throws {
        respond(200, #"""
        {"request":{"id":"r1","workspace_id":"ws1","requester_id":"u1","resource_ref":"projects/foo",
        "state":"active","risk_level":"high","created_at":"2025-01-01T00:00:00Z"},
        "risk":{"id":"rv1","request_id":"r1","score":"high","recommendation":"high_risk",
        "factors":["sensitive_resource","off_hours"],"rationale":"sensitive prod access",
        "source":"ai_agent","degraded":false,"created_at":"2025-01-01T00:00:00Z"},
        "anomalies":[{"id":"af1","request_id":"r1","grant_id":"g1","kind":"impossible_travel",
        "severity":"high","reason":"two geos in 5m","confidence":0.92,"created_at":"2025-01-01T00:05:00Z"}]}
        """#)
        let detail = try await client.getRequestDetail(id: "r1")
        XCTAssertEqual(URLProtocolStub.captured.first?.url?.path, "/api/v1/access-requests/r1")
        XCTAssertEqual(detail.request.state, .active)
        XCTAssertEqual(detail.risk?.score, .high)
        XCTAssertEqual(detail.risk?.recommendation, .highRisk)
        XCTAssertEqual(detail.risk?.factors, ["sensitive_resource", "off_hours"])
        XCTAssertEqual(detail.anomalies.count, 1)
        XCTAssertEqual(detail.anomalies.first?.kind, "impossible_travel")
        XCTAssertEqual(detail.anomalies.first?.confidence, 0.92)
        XCTAssertTrue(detail.anomalies.first?.isElevated ?? false)

        // The classifier flags this as high-risk and gates the revoke.
        let plan = Revocation.plan(detail)
        XCTAssertTrue(plan.requiresStepUp)
    }

    func testGetRequestDetailToleratesNoRiskOrAnomalies() async throws {
        respond(200, #"{"request":{"id":"r1","workspace_id":"ws1","requester_id":"u1","resource_ref":"a","state":"requested","created_at":"2025-01-01T00:00:00Z"}}"#)
        let detail = try await client.getRequestDetail(id: "r1")
        XCTAssertEqual(detail.request.state, .requested)
        XCTAssertNil(detail.risk)
        XCTAssertTrue(detail.anomalies.isEmpty)
    }

    func testEmergencyOffboardPostsIdentityAndParsesBreakdown() async throws {
        respond(200, #"""
        {"leaver":{"user_external_id":"ext-1","errored":false,"layers":[
        {"layer":"grant_revoke","status":"done"},
        {"layer":"team_remove","status":"done"},
        {"layer":"iam_core_disable","status":"done"},
        {"layer":"session_revoke","status":"done"},
        {"layer":"scim_deprovision","status":"skipped","detail":"no scim connector"},
        {"layer":"identity_disable","status":"done"}]}}
        """#)
        let result = try await client.emergencyOffboard(userExternalID: "ext-1", reason: "left the company")
        let req = URLProtocolStub.captured.first
        XCTAssertEqual(req?.url?.path, "/api/v1/emergency-offboard")
        XCTAssertEqual(req?.httpMethod, "POST")
        XCTAssertEqual(result.userExternalID, "ext-1")
        XCTAssertFalse(result.errored)
        XCTAssertEqual(result.layers.count, 6)
        XCTAssertEqual(result.layers[4].status, .skipped)
        XCTAssertTrue(result.failedLayers.isEmpty)
    }

    func testEmergencyOffboardRecoversBreakdownFrom500() async throws {
        respond(500, #"""
        {"error":"one or more layers failed","leaver":{"user_external_id":"ext-1","errored":true,"layers":[
        {"layer":"grant_revoke","status":"done"},
        {"layer":"iam_core_disable","status":"failed","detail":"idp timeout"}]}}
        """#)
        let result = try await client.emergencyOffboard(userExternalID: "ext-1")
        XCTAssertTrue(result.errored)
        XCTAssertEqual(result.failedLayers.count, 1)
        XCTAssertEqual(result.failedLayers.first?.layer, .iamCoreDisable)
        XCTAssertEqual(result.failedLayers.first?.detail, "idp timeout")
    }

    func testEmergencyOffboardSurfacesStepUpGate() async {
        respond(403, #"{"error":"step-up MFA required"}"#)
        do {
            _ = try await client.emergencyOffboard(userExternalID: "ext-1")
            XCTFail("expected stepUpRequired")
        } catch let AccessSDKError.stepUpRequired(body) {
            XCTAssertTrue(body?.contains("step-up MFA required") ?? false)
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testEmergencyOffboardRejectsBlankIdentityWithoutNetwork() async {
        await assertThrows(.invalidInput("user_external_id is required")) {
            _ = try await self.client.emergencyOffboard(userExternalID: "  ")
        }
        XCTAssertTrue(URLProtocolStub.captured.isEmpty)
    }

    func testEmergencyOffboardWithoutBreakdownRethrowsHttp() async {
        respond(500, #"{"error":"upstream unavailable"}"#)
        do {
            _ = try await client.emergencyOffboard(userExternalID: "ext-1")
            XCTFail("expected http error")
        } catch let AccessSDKError.http(status, _) {
            XCTAssertEqual(status, 500)
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testUnauthorizedMapsToUnauthenticated() async {
        respond(401, #"{"error":"invalid token"}"#)
        await assertThrows(.unauthenticated) { _ = try await self.client.me() }
    }

    func testStepUpGateMapsToStepUpRequired() async {
        respond(403, #"{"error":"step-up MFA required"}"#)
        do {
            _ = try await client.provisionRequest(id: "r1")
            XCTFail("expected stepUpRequired")
        } catch let AccessSDKError.stepUpRequired(body) {
            XCTAssertTrue(body?.contains("step-up MFA required") ?? false)
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testOther403StaysGenericHttp() async {
        respond(403, #"{"error":"tenant mismatch"}"#)
        do {
            _ = try await client.listRequests()
            XCTFail("expected http error")
        } catch let AccessSDKError.http(status, _) {
            XCTAssertEqual(status, 403)
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testServerErrorMapsToHttp() async {
        respond(500, #"{"error":"boom"}"#)
        do {
            _ = try await client.me()
            XCTFail("expected http error")
        } catch let AccessSDKError.http(status, body) {
            XCTAssertEqual(status, 500)
            XCTAssertTrue(body?.contains("boom") ?? false)
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testMalformedJSONMapsToDecoding() async {
        respond(200, "not-json")
        do {
            _ = try await client.me()
            XCTFail("expected decoding error")
        } catch let AccessSDKError.decoding(msg) {
            XCTAssertFalse(msg.isEmpty)
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testClientSideValidationRejectsBadInput() async {
        await assertThrows(.invalidInput("target_user_id is required")) {
            _ = try await self.client.createRequest(CreateAccessRequest(targetUserID: "", resourceRef: "x"))
        }
        await assertThrows(.invalidInput("deny requires a reason")) {
            _ = try await self.client.denyRequest(id: "r1", reason: "  ")
        }
        await assertThrows(.invalidInput("id is required")) {
            _ = try await self.client.getRequest(id: "  ")
        }
        XCTAssertTrue(URLProtocolStub.captured.isEmpty)
    }

    func testBlankTokenMapsToUnauthenticatedWithoutNetwork() async {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [URLProtocolStub.self]
        let session = URLSession(configuration: config)
        let noToken = URLSessionAccessClient(
            baseURL: URL(string: "https://access.test/api/v1")!,
            session: session,
            authTokenProvider: { "" }
        )
        await assertThrows(.unauthenticated) { _ = try await noToken.me() }
        XCTAssertTrue(URLProtocolStub.captured.isEmpty)
    }

    func testWhitespaceOnlyTokenMapsToUnauthenticatedWithoutNetwork() async {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [URLProtocolStub.self]
        let session = URLSession(configuration: config)
        let wsToken = URLSessionAccessClient(
            baseURL: URL(string: "https://access.test/api/v1")!,
            session: session,
            authTokenProvider: { "   " }
        )
        await assertThrows(.unauthenticated) { _ = try await wsToken.me() }
        XCTAssertTrue(URLProtocolStub.captured.isEmpty)
    }

    func testListEnvelopesTolerateJSONNull() async throws {
        // A defensive parity check: a `null`/missing array decodes to empty
        // rather than throwing (mirrors Android's optJSONArray behaviour).
        respond(200, #"{"requests":null}"#)
        let rows = try await client.listRequests()
        XCTAssertTrue(rows.isEmpty)

        respond(200, #"{}"#)
        let history = try await client.requestHistory(id: "r1")
        XCTAssertTrue(history.isEmpty)
    }

    func testBaseURLWithMultipleTrailingSlashesIsNormalized() async throws {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [URLProtocolStub.self]
        let session = URLSession(configuration: config)
        let messy = URLSessionAccessClient(
            baseURL: URL(string: "https://access.test//")!,
            session: session,
            authTokenProvider: { "tok" }
        )
        URLProtocolStub.handler = { _ in (200, Data(#"{"user_id":"u1","tenant_id":"t1"}"#.utf8)) }
        _ = try await messy.me()
        XCTAssertEqual(URLProtocolStub.captured.first?.url?.path, "/api/v1/me")
    }

    // Asserts the block throws the expected `AccessSDKError`.
    private func assertThrows(
        _ expected: AccessSDKError,
        _ block: () async throws -> Void,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async {
        do {
            try await block()
            XCTFail("expected \(expected)", file: file, line: line)
        } catch let error as AccessSDKError {
            XCTAssertEqual(error, expected, file: file, line: line)
        } catch {
            XCTFail("unexpected error: \(error)", file: file, line: line)
        }
    }
}
