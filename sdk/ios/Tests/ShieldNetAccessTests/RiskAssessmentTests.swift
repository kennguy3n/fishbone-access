//
// RiskAssessmentTests.swift — pure-function coverage for the WS5 risky-access
// classifier (`RiskAssessment`) and the step-up revocation planner
// (`Revocation`). No network: these assert the cross-platform severity logic
// that both the iOS and Android SDKs (and, by mirroring, the web console) use
// to decide which access to surface and which revokes to gate behind MFA.
//

import XCTest
@testable import ShieldNetAccess

final class RiskAssessmentTests: XCTestCase {
    private func request(_ level: RiskLevel?) -> AccessRequest {
        AccessRequest(
            id: "r1", workspaceID: "ws1", requesterID: "u1", resourceRef: "projects/foo",
            state: .active, riskLevel: level, createdAt: Date(timeIntervalSince1970: 0)
        )
    }

    private func verdict(_ score: RiskLevel, _ rec: RiskRecommendation, degraded: Bool = false) -> RiskVerdict {
        RiskVerdict(id: "rv1", requestID: "r1", score: score, recommendation: rec, degraded: degraded)
    }

    private func anomaly(_ severity: String?) -> AnomalyFlag {
        AnomalyFlag(id: "af1", requestID: "r1", kind: "impossible_travel", severity: severity)
    }

    func testHighBandAloneIsHighRiskAndRequiresStepUp() {
        let advisory = RiskAssessment.evaluate(request: request(.high), verdict: nil)
        XCTAssertTrue(advisory.isHighRisk)
        XCTAssertTrue(advisory.isElevated)
        XCTAssertTrue(advisory.reasons.contains { $0.lowercased().contains("high") })
        XCTAssertTrue(Revocation.plan(advisory).requiresStepUp)
    }

    func testHighRiskRecommendationDrivesHighRiskEvenWhenBandIsLow() {
        let advisory = RiskAssessment.evaluate(request: request(.low), verdict: verdict(.low, .highRisk))
        XCTAssertTrue(advisory.isHighRisk)
        XCTAssertTrue(advisory.reasons.contains { $0.lowercased().contains("high risk") })
    }

    func testElevatedAnomalyIsHighRiskRegardlessOfBand() {
        let advisory = RiskAssessment.evaluate(
            request: request(.low),
            verdict: verdict(.low, .autoApproveEligible),
            anomalies: [anomaly("critical")]
        )
        XCTAssertTrue(advisory.isHighRisk)
        XCTAssertEqual(advisory.anomalyCount, 1)
        XCTAssertTrue(advisory.reasons.contains { $0.contains("Anomalies (high)") })
    }

    func testMediumSignalsAreElevatedButNotHighRisk() {
        let advisory = RiskAssessment.evaluate(request: request(.medium), verdict: verdict(.medium, .needsReview))
        XCTAssertFalse(advisory.isHighRisk)
        XCTAssertTrue(advisory.isElevated)
        XCTAssertFalse(Revocation.plan(advisory).requiresStepUp)
    }

    func testLowSeverityAnomalyRaisesAwarenessButNotStepUp() {
        let advisory = RiskAssessment.evaluate(
            request: request(.low),
            verdict: verdict(.low, .autoApproveEligible),
            anomalies: [anomaly("low")]
        )
        XCTAssertFalse(advisory.isHighRisk)
        XCTAssertTrue(advisory.isElevated)
        XCTAssertTrue(advisory.reasons.contains { $0.hasPrefix("Anomalies:") })
    }

    func testLowAndUnscoredAccessIsNeitherElevatedNorHighRisk() {
        let none = RiskAssessment.evaluate(request: request(.low), verdict: nil)
        XCTAssertFalse(none.isElevated)
        XCTAssertFalse(none.isHighRisk)
        XCTAssertTrue(none.reasons.isEmpty)

        let unscored = RiskAssessment.evaluate(request: request(nil), verdict: nil)
        XCTAssertFalse(unscored.isElevated)
    }

    func testMediumVerdictBelowRequestBandIsElevatedWithReason() {
        // Request band low + medium verdict + auto-approve rec + no anomalies:
        // isElevated must still carry a justification (regression: it used to be
        // elevated with empty reasons -> "Risky active access — .").
        let advisory = RiskAssessment.evaluate(
            request: request(.low),
            verdict: verdict(.medium, .autoApproveEligible)
        )
        XCTAssertTrue(advisory.isElevated)
        XCTAssertFalse(advisory.isHighRisk)
        XCTAssertFalse(advisory.reasons.isEmpty)
        XCTAssertTrue(advisory.reasons.contains { $0.lowercased().contains("medium") })
    }

    func testDegradedVerdictIsCalledOut() {
        let advisory = RiskAssessment.evaluate(request: request(.medium), verdict: verdict(.medium, .needsReview, degraded: true))
        XCTAssertTrue(advisory.reasons.contains { $0.lowercased().contains("degraded") })
    }

    func testEvaluateViaDetailMatchesRawSignals() {
        let req = request(.high)
        let v = verdict(.high, .highRisk)
        let flags = [anomaly("high")]
        let detail = AccessRequestDetail(request: req, risk: v, anomalies: flags)
        XCTAssertEqual(RiskAssessment.evaluate(detail), RiskAssessment.evaluate(request: req, verdict: v, anomalies: flags))
        XCTAssertTrue(Revocation.plan(detail).requiresStepUp)
    }
}
