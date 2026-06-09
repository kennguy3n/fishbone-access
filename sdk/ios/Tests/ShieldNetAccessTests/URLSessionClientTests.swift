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
