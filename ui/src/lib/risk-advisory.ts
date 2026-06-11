// risk-advisory.ts — risky-access classification for the web console (WS5).
//
// The control plane computes the AI risk verdict and advisory anomaly flags
// server-side; `GET /api/v1/access-requests/:id` returns `{ request, risk,
// anomalies }`. This module turns those raw signals into a single, renderable
// `RiskAdvisory` so the console can surface anomalous / high-risk *active*
// access and offer a one-tap revoke — without re-deriving the severity logic at
// every call site.
//
// The classification is a pure function (no I/O, no React) and is the byte-for-
// byte mirror of the mobile SDKs' `RiskAssessment.evaluate`
// (`sdk/android/.../Risk.kt`, `sdk/ios/.../Risk.swift`) so the three platforms
// agree on which access is risky and which revokes warrant step-up MFA.

import type { AccessRequest, RiskVerdict, AnomalyFlag } from "@/api/access";

// A host-renderable risk summary derived purely from the server's signals.
//
// - `isHighRisk` — the access warrants an urgent, step-up-gated revoke (HIGH AI
//   band, a `high_risk` recommendation, or a high/critical anomaly).
// - `isElevated` — worth surfacing for awareness (medium-or-above, a
//   `needs_review` recommendation, or any anomaly) even if not yet high-risk.
// - `reasons` — short, human-readable justifications for a banner / toast.
// - `anomalyCount` — number of advisory anomaly flags backing this summary.
export interface RiskAdvisory {
  isHighRisk: boolean;
  isElevated: boolean;
  reasons: string[];
  anomalyCount: number;
}

// True when an anomaly flag is `high`/`critical` severity (case-insensitive) —
// a forward-compatible check rather than matching literals at the call site.
export function anomalyIsElevated(flag: AnomalyFlag): boolean {
  const s = flag.severity?.toLowerCase();
  return s === "high" || s === "critical";
}

function bandIs(value: string | undefined, band: string): boolean {
  return (value ?? "").toLowerCase() === band;
}

// evaluateRisk is the pure classification of the server's risk signals into a
// `RiskAdvisory`. Severity is the fail-safe union of three independent signals
// (the request risk band, the latest AI verdict, and any advisory anomalies):
// ANY one high signal makes the access high-risk.
export function evaluateRisk(
  request: AccessRequest,
  risk?: RiskVerdict,
  anomalies: AnomalyFlag[] = [],
): RiskAdvisory {
  const reasons: string[] = [];

  // 1. Coarse request band.
  if (bandIs(request.risk_level, "high")) reasons.push("AI risk band: high");
  else if (bandIs(request.risk_level, "medium"))
    reasons.push("AI risk band: medium");

  // 2. Latest AI verdict (band + routing recommendation).
  if (risk) {
    if (bandIs(risk.score, "high") && !bandIs(request.risk_level, "high")) {
      reasons.push("AI verdict score: high");
    } else if (bandIs(risk.score, "medium") && !bandIs(request.risk_level, "medium")) {
      // A medium verdict score is an `isElevated` trigger, so it must
      // contribute a reason — otherwise an elevated advisory could render with
      // an empty justification ("Risky active access — .").
      reasons.push("AI verdict score: medium");
    }
    if (risk.recommendation === "high_risk")
      reasons.push("Recommendation: high risk");
    else if (risk.recommendation === "needs_review")
      reasons.push("Recommendation: needs review");
    if (risk.degraded) reasons.push("AI scoring degraded (fail-open)");
  }

  // 3. Advisory anomaly flags.
  const elevatedAnomalies = anomalies.filter(anomalyIsElevated).length;
  if (elevatedAnomalies > 0) {
    reasons.push(`Anomalies (high): ${elevatedAnomalies}`);
  } else if (anomalies.length > 0) {
    reasons.push(`Anomalies: ${anomalies.length}`);
  }

  const isHighRisk =
    bandIs(request.risk_level, "high") ||
    bandIs(risk?.score, "high") ||
    risk?.recommendation === "high_risk" ||
    elevatedAnomalies > 0;

  const isElevated =
    isHighRisk ||
    bandIs(request.risk_level, "medium") ||
    bandIs(risk?.score, "medium") ||
    risk?.recommendation === "needs_review" ||
    anomalies.length > 0;

  return { isHighRisk, isElevated, reasons, anomalyCount: anomalies.length };
}

// revocationRequiresStepUp mirrors the SDKs' `Revocation.plan`: a high-risk
// revoke should be gated behind step-up MFA so the requirement is consistent
// across web, Android and iOS. The kill-switch (emergency offboard) path is
// additionally enforced server-side by the RequireMFA claim gate.
export function revocationRequiresStepUp(advisory: RiskAdvisory): boolean {
  return advisory.isHighRisk;
}
