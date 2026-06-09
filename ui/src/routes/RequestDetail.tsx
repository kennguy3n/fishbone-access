import { useState } from "react";
import { useIntl } from "react-intl";
import { useNavigate, useParams } from "@tanstack/react-router";
import {
  PageHeader,
  Card,
  Badge,
  StatusBadge,
  Spinner,
  AsyncBoundary,
} from "@/components/ui";
import { Modal } from "@/components/Modal";
import { useToast } from "@/components/Toast";
import { RiskPanel, AnomalyList } from "@/components/RiskPanel";
import {
  useAccessRequest,
  useRequestHistory,
  useRequestAction,
  useMe,
  type AccessRequest,
  type RiskVerdict,
  type AccessRequestHistoryEntry,
  ApiError,
} from "@/api/access";
import { formatDateTime, titleCase, riskScoreTone } from "@/lib/format";

type RequestAction = "approve" | "deny" | "cancel" | "provision";

// Which actions an operator can take from a given request state. Mirrors the
// backend state machine: requested/ai_reviewed → approve/deny/cancel, approved
// → provision/cancel; terminal states expose nothing.
function actionsFor(state: string): RequestAction[] {
  switch (state) {
    case "requested":
    case "ai_reviewed":
      return ["approve", "deny", "cancel"];
    case "approved":
      return ["provision", "cancel"];
    case "provision_failed":
      return ["provision", "cancel"];
    default:
      return [];
  }
}

// A high-risk verdict gates approval behind step-up MFA, mirroring the backend
// fail-CLOSED gate (lifecycle.RequiresStepUp). The control plane is always the
// source of truth — it rejects an un-stepped-up approve with 403 — but the UI
// pre-empts that so the operator understands why approve is blocked.
function requiresStepUp(verdict?: RiskVerdict): boolean {
  return verdict?.recommendation === "high_risk";
}

export function RequestDetail() {
  const intl = useIntl();
  const { requestId } = useParams({ strict: false }) as { requestId?: string };
  const navigate = useNavigate();
  const toast = useToast();

  const reqQuery = useAccessRequest(requestId);
  const historyQuery = useRequestHistory(requestId);
  const actionMut = useRequestAction(requestId ?? "");
  const me = useMe();

  // Deny/cancel collect an optional reason via a small modal.
  const [reasonFor, setReasonFor] = useState<RequestAction | null>(null);
  const [reason, setReason] = useState("");

  const actionLabel = (a: RequestAction): string => {
    switch (a) {
      case "approve":
        return intl.formatMessage({ id: "requests.action.approve", defaultMessage: "Approve" });
      case "deny":
        return intl.formatMessage({ id: "requests.action.deny", defaultMessage: "Deny" });
      case "cancel":
        return intl.formatMessage({ id: "requests.action.cancel", defaultMessage: "Cancel" });
      case "provision":
        return intl.formatMessage({ id: "requests.action.provision", defaultMessage: "Provision now" });
    }
  };

  const run = async (action: RequestAction, withReason?: string) => {
    try {
      const result = await actionMut.mutateAsync({
        action,
        reason: withReason,
      });
      toast.success(
        intl.formatMessage(
          { id: "requests.actionDone", defaultMessage: "Request {action}d" },
          { action },
        ),
      );
      setReasonFor(null);
      setReason("");
      if (action === "provision" && result.grant) {
        toast.info(
          intl.formatMessage({ id: "requests.grantProvisioned", defaultMessage: "Grant provisioned" }),
          `Grant ${result.grant.id.slice(0, 8)}… is now ${result.grant.state}.`,
        );
      }
    } catch (err) {
      toast.error(
        intl.formatMessage(
          { id: "requests.actionFailed", defaultMessage: "Could not {action} request" },
          { action },
        ),
        err instanceof ApiError ? err.message : undefined,
      );
    }
  };

  const onAction = (action: RequestAction) => {
    if (action === "deny" || action === "cancel") {
      setReasonFor(action);
    } else {
      run(action);
    }
  };

  return (
    <>
      <PageHeader
        title={intl.formatMessage({ id: "requests.detail.title", defaultMessage: "Access request" })}
        subtitle={requestId}
        actions={
          <button className="btn" onClick={() => navigate({ to: "/requests" })}>
            {intl.formatMessage({ id: "common.back", defaultMessage: "Back" })}
          </button>
        }
      />
      <AsyncBoundary
        isLoading={reqQuery.isLoading}
        error={reqQuery.error}
        data={reqQuery.data}
        onRetry={reqQuery.refetch}
      >
        {(detail) => {
          const req = detail.request;
          const verdict = detail.risk;
          const actions = actionsFor(req.state);
          // Block approve behind step-up MFA for a high-risk verdict when the
          // session's token does not carry a satisfied MFA claim. The backend
          // enforces this fail-CLOSED regardless; this only improves the UX.
          const stepUpNeeded =
            requiresStepUp(verdict) && !(me.data?.mfa_satisfied ?? false);
          return (
            <div className="grid grid--2">
              <Card
                title={intl.formatMessage({ id: "requests.detail.details", defaultMessage: "Details" })}
                actions={<StatusBadge status={req.state} />}
              >
                <RequestFields req={req} />

                {actions.length > 0 ? (
                  <>
                    {stepUpNeeded && (
                      <div className="risk-panel__degraded" role="status" style={{ marginTop: 14 }}>
                        {intl.formatMessage({
                          id: "requests.stepup.required",
                          defaultMessage: "High-risk — step-up MFA required to approve.",
                        })}
                      </div>
                    )}
                    <div className="field-row" style={{ marginTop: 14 }}>
                      {actions.map((a) => {
                        const blocked = a === "approve" && stepUpNeeded;
                        return (
                          <button
                            key={a}
                            className={`btn btn--sm ${
                              a === "deny"
                                ? "btn--danger"
                                : a === "cancel"
                                  ? "btn--ghost"
                                  : "btn--primary"
                            }`}
                            disabled={actionMut.isPending || blocked}
                            title={
                              blocked
                                ? intl.formatMessage({
                                    id: "requests.stepup.required",
                                    defaultMessage: "High-risk — step-up MFA required to approve.",
                                  })
                                : undefined
                            }
                            onClick={() => onAction(a)}
                          >
                            {actionMut.isPending ? <Spinner /> : actionLabel(a)}
                          </button>
                        );
                      })}
                    </div>
                  </>
                ) : (
                  <p className="muted" style={{ marginTop: 14, fontSize: 12 }}>
                    {intl.formatMessage(
                      {
                        id: "requests.detail.terminal",
                        defaultMessage:
                          "This request is in a terminal state ({state}) — no further actions.",
                      },
                      { state: titleCase(req.state) },
                    )}
                  </p>
                )}
              </Card>

              <Card
                title={intl.formatMessage({ id: "requests.risk.title", defaultMessage: "AI risk review" })}
                subtitle={intl.formatMessage({
                  id: "requests.risk.subtitle",
                  defaultMessage:
                    "Scored server-side by the access AI agent. Advisory — a high-risk request is never auto-approved.",
                })}
                actions={
                  verdict ? <Badge tone={riskScoreTone(verdict.score)}>{verdict.score}</Badge> : undefined
                }
              >
                <RiskPanel verdict={verdict} />
              </Card>

              <Card
                title={intl.formatMessage({ id: "requests.anomalies.title", defaultMessage: "Anomaly flags" })}
                subtitle={intl.formatMessage({
                  id: "requests.anomalies.subtitle",
                  defaultMessage:
                    "Advisory signals from the anomaly-detection skill on the approved elevation.",
                })}
              >
                <AnomalyList flags={detail.anomalies} />
              </Card>

              <Card
                title={intl.formatMessage({ id: "requests.history.title", defaultMessage: "History" })}
                subtitle={intl.formatMessage({
                  id: "requests.history.subtitle",
                  defaultMessage: "Every state transition is recorded with the actor and reason.",
                })}
              >
                <AsyncBoundary
                  isLoading={historyQuery.isLoading}
                  error={historyQuery.error}
                  data={historyQuery.data}
                  onRetry={historyQuery.refetch}
                  isEmpty={(h) => h.length === 0}
                  empty={
                    <p className="muted">
                      {intl.formatMessage({ id: "requests.history.empty", defaultMessage: "No history yet." })}
                    </p>
                  }
                >
                  {(history) => <Timeline entries={history} />}
                </AsyncBoundary>
              </Card>
            </div>
          );
        }}
      </AsyncBoundary>

      {reasonFor && (
        <Modal
          title={intl.formatMessage(
            { id: "requests.decision.title", defaultMessage: "{action} request" },
            { action: actionLabel(reasonFor) },
          )}
          onClose={() => setReasonFor(null)}
          footer={
            <>
              <button
                className="btn btn--ghost"
                onClick={() => setReasonFor(null)}
              >
                {intl.formatMessage({ id: "common.cancel", defaultMessage: "Cancel" })}
              </button>
              <button
                className={`btn ${reasonFor === "deny" ? "btn--danger" : "btn--primary"}`}
                disabled={actionMut.isPending}
                onClick={() => run(reasonFor, reason.trim() || undefined)}
              >
                {actionMut.isPending ? <Spinner /> : actionLabel(reasonFor)}
              </button>
            </>
          }
        >
          <label className="field">
            <span>
              {intl.formatMessage({
                id: "requests.decision.reason",
                defaultMessage: "Reason (optional, recorded in history)",
              })}
            </span>
            <textarea
              rows={3}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder={intl.formatMessage({
                id: "requests.decision.reasonPlaceholder",
                defaultMessage: "Add context for this decision…",
              })}
            />
          </label>
        </Modal>
      )}
    </>
  );
}

function RequestFields({ req }: { req: AccessRequest }) {
  const intl = useIntl();
  return (
    <dl className="kv">
      <div>
        <dt>{intl.formatMessage({ id: "requests.col.resource", defaultMessage: "Resource" })}</dt>
        <dd>
          <code>{req.resource_ref}</code>
        </dd>
      </div>
      <div>
        <dt>{intl.formatMessage({ id: "requests.create.role", defaultMessage: "Role" })}</dt>
        <dd>{req.role || <span className="muted">—</span>}</dd>
      </div>
      <div>
        <dt>{intl.formatMessage({ id: "requests.field.requester", defaultMessage: "Requester" })}</dt>
        <dd>
          <code>{req.requester_id}</code>
        </dd>
      </div>
      <div>
        <dt>{intl.formatMessage({ id: "requests.field.target", defaultMessage: "Target user" })}</dt>
        <dd>
          {req.target_user_id ? (
            <code>{req.target_user_id}</code>
          ) : (
            <span className="muted">
              {intl.formatMessage({ id: "requests.field.self", defaultMessage: "self" })}
            </span>
          )}
        </dd>
      </div>
      <div>
        <dt>{intl.formatMessage({ id: "requests.risk.score", defaultMessage: "Risk score" })}</dt>
        <dd>
          {req.risk_level ? (
            <Badge tone={riskScoreTone(req.risk_level)}>{req.risk_level}</Badge>
          ) : (
            <span className="muted">—</span>
          )}
        </dd>
      </div>
      <div>
        <dt>{intl.formatMessage({ id: "requests.create.justification", defaultMessage: "Justification" })}</dt>
        <dd>{req.justification || <span className="muted">—</span>}</dd>
      </div>
      <div>
        <dt>{intl.formatMessage({ id: "requests.field.created", defaultMessage: "Created" })}</dt>
        <dd>{formatDateTime(req.created_at)}</dd>
      </div>
    </dl>
  );
}

function Timeline({ entries }: { entries: AccessRequestHistoryEntry[] }) {
  // Newest first.
  const sorted = [...entries].sort((a, b) =>
    b.created_at.localeCompare(a.created_at),
  );
  return (
    <ol className="timeline">
      {sorted.map((e) => (
        <li key={e.id} className="timeline__item">
          <span className="timeline__dot" aria-hidden />
          <div>
            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <b>
                {e.from_state ? `${titleCase(e.from_state)} → ` : ""}
                {titleCase(e.to_state)}
              </b>
              <span className="muted" style={{ fontSize: 12 }}>
                {formatDateTime(e.created_at)}
              </span>
            </div>
            <p className="muted" style={{ margin: "2px 0 0", fontSize: 12 }}>
              {e.actor ? `by ${e.actor}` : "system"}
              {e.reason ? ` · ${e.reason}` : ""}
            </p>
          </div>
        </li>
      ))}
    </ol>
  );
}
