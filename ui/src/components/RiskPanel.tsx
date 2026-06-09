import { useIntl } from "react-intl";
import { Badge } from "@/components/ui";
import type { Tone } from "@/lib/format";
import { riskScoreTone } from "@/lib/format";
import type {
  RiskVerdict,
  RiskRecommendation,
  AnomalyFlag,
} from "@/api/access";

// recommendationTone maps the routing recommendation to a badge tone:
// high_risk → danger, needs_review → warn, auto_approve_eligible → ok.
function recommendationTone(rec?: RiskRecommendation): Tone {
  switch (rec) {
    case "high_risk":
      return "danger";
    case "needs_review":
      return "warn";
    case "auto_approve_eligible":
      return "ok";
    default:
      return "neutral";
  }
}

const RECOMMENDATION_KEY: Record<RiskRecommendation, string> = {
  auto_approve_eligible: "requests.rec.autoApprove",
  needs_review: "requests.rec.needsReview",
  high_risk: "requests.rec.highRisk",
};

// RecommendationBadge renders the localized routing recommendation with the
// right tone. Falls back to the raw value for any unknown recommendation so a
// future backend value never renders blank.
export function RecommendationBadge({ rec }: { rec?: RiskRecommendation }) {
  const intl = useIntl();
  if (!rec) return <span className="muted">—</span>;
  const id = RECOMMENDATION_KEY[rec];
  return (
    <Badge tone={recommendationTone(rec)}>
      {id ? intl.formatMessage({ id, defaultMessage: rec }) : rec}
    </Badge>
  );
}

// ScoreBadge renders the risk band (the band name itself is not translated —
// low/medium/high are stable enum values — but the tone conveys severity for
// colour-blind-safe scanning alongside the text).
export function ScoreBadge({ score }: { score?: string }) {
  if (!score) return <span className="muted">—</span>;
  return <Badge tone={riskScoreTone(score)}>{score}</Badge>;
}

const ANOMALY_SEVERITY_TONE: Record<string, Tone> = {
  high: "danger",
  critical: "danger",
  medium: "warn",
  low: "info",
};

// RiskPanel renders a verdict's score, recommendation, factors and the model's
// rationale. It is the inline AI risk panel shown in the create flow and the
// approver view. A degraded verdict (AI agent unreachable) is called out
// explicitly so the operator knows the score came from the fail-open fallback
// rather than the model.
export function RiskPanel({ verdict }: { verdict?: RiskVerdict }) {
  const intl = useIntl();
  if (!verdict) {
    return (
      <p className="muted">
        {intl.formatMessage({
          id: "requests.risk.none",
          defaultMessage: "No AI verdict for this request.",
        })}
      </p>
    );
  }
  const factors = verdict.factors ?? [];
  return (
    <div className="risk-panel">
      {verdict.degraded && (
        <div className="risk-panel__degraded" role="status">
          {intl.formatMessage({
            id: "requests.risk.degraded",
            defaultMessage:
              "AI scoring unavailable — defaulted to human review.",
          })}
        </div>
      )}
      <dl className="kv">
        <div>
          <dt>
            {intl.formatMessage({
              id: "requests.risk.score",
              defaultMessage: "Risk score",
            })}
          </dt>
          <dd>
            <ScoreBadge score={verdict.score} />
          </dd>
        </div>
        <div>
          <dt>
            {intl.formatMessage({
              id: "requests.risk.recommendation",
              defaultMessage: "Recommendation",
            })}
          </dt>
          <dd>
            <RecommendationBadge rec={verdict.recommendation} />
          </dd>
        </div>
        {factors.length > 0 && (
          <div>
            <dt>
              {intl.formatMessage({
                id: "requests.risk.factors",
                defaultMessage: "Risk factors",
              })}
            </dt>
            <dd>
              <div className="chip-row">
                {factors.map((f) => (
                  <span key={f} className="chip">
                    {f}
                  </span>
                ))}
              </div>
            </dd>
          </div>
        )}
        {verdict.rationale && (
          <div>
            <dt>
              {intl.formatMessage({
                id: "requests.risk.rationale",
                defaultMessage: "AI rationale",
              })}
            </dt>
            <dd>{verdict.rationale}</dd>
          </div>
        )}
      </dl>
    </div>
  );
}

// AnomalyList renders the advisory anomaly flags surfaced against an approved
// elevation. Advisory only — these never change the request state.
export function AnomalyList({ flags }: { flags?: AnomalyFlag[] }) {
  const intl = useIntl();
  if (!flags || flags.length === 0) {
    return (
      <p className="muted">
        {intl.formatMessage({
          id: "requests.anomalies.none",
          defaultMessage: "No anomaly flags.",
        })}
      </p>
    );
  }
  return (
    <ul className="anomaly-list">
      {flags.map((flag) => (
        <li key={flag.id} className="anomaly-list__item">
          <Badge tone={ANOMALY_SEVERITY_TONE[flag.severity ?? ""] ?? "neutral"}>
            {flag.severity || "info"}
          </Badge>
          <div>
            <b>{flag.kind}</b>
            {flag.reason && (
              <p className="muted" style={{ margin: "2px 0 0", fontSize: 12 }}>
                {flag.reason}
              </p>
            )}
          </div>
        </li>
      ))}
    </ul>
  );
}
