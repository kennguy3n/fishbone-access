import { useState } from "react";
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
import {
  useAccessRequest,
  useRequestHistory,
  useRequestAction,
  type AccessRequestHistoryEntry,
  ApiError,
} from "@/api/access";
import { formatDateTime, titleCase } from "@/lib/format";

type RequestAction = "approve" | "deny" | "cancel" | "provision";

// Which actions an operator can take from a given request state. Mirrors the
// backend state machine: requested → approve/deny/cancel, approved →
// provision/cancel; terminal states expose nothing.
function actionsFor(state: string): RequestAction[] {
  switch (state) {
    case "requested":
      return ["approve", "deny", "cancel"];
    case "approved":
      return ["provision", "cancel"];
    case "provision_failed":
      return ["provision", "cancel"];
    default:
      return [];
  }
}

const ACTION_LABEL: Record<RequestAction, string> = {
  approve: "Approve",
  deny: "Deny",
  cancel: "Cancel",
  provision: "Provision now",
};

export function RequestDetail() {
  const { requestId } = useParams({ strict: false }) as { requestId?: string };
  const navigate = useNavigate();
  const toast = useToast();

  const reqQuery = useAccessRequest(requestId);
  const historyQuery = useRequestHistory(requestId);
  const actionMut = useRequestAction(requestId ?? "");

  // Deny/cancel collect an optional reason via a small modal.
  const [reasonFor, setReasonFor] = useState<RequestAction | null>(null);
  const [reason, setReason] = useState("");

  const run = async (action: RequestAction, withReason?: string) => {
    try {
      const result = await actionMut.mutateAsync({
        action,
        reason: withReason,
      });
      toast.success(`Request ${action}d`);
      setReasonFor(null);
      setReason("");
      if (action === "provision" && result.grant) {
        toast.info(
          "Grant provisioned",
          `Grant ${result.grant.id.slice(0, 8)}… is now ${result.grant.state}.`,
        );
      }
    } catch (err) {
      toast.error(
        `Could not ${action} request`,
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
        title="Access request"
        subtitle={requestId}
        actions={
          <button className="btn" onClick={() => navigate({ to: "/requests" })}>
            Back
          </button>
        }
      />
      <AsyncBoundary
        isLoading={reqQuery.isLoading}
        error={reqQuery.error}
        data={reqQuery.data}
        onRetry={reqQuery.refetch}
      >
        {(req) => {
          const actions = actionsFor(req.state);
          return (
            <div className="grid grid--2">
              <Card
                title="Details"
                actions={<StatusBadge status={req.state} />}
              >
                <dl className="kv">
                  <div>
                    <dt>Resource</dt>
                    <dd>
                      <code>{req.resource_ref}</code>
                    </dd>
                  </div>
                  <div>
                    <dt>Role</dt>
                    <dd>{req.role || <span className="muted">—</span>}</dd>
                  </div>
                  <div>
                    <dt>Requester</dt>
                    <dd>
                      <code>{req.requester_id}</code>
                    </dd>
                  </div>
                  <div>
                    <dt>Target user</dt>
                    <dd>
                      {req.target_user_id ? (
                        <code>{req.target_user_id}</code>
                      ) : (
                        <span className="muted">self</span>
                      )}
                    </dd>
                  </div>
                  <div>
                    <dt>Risk</dt>
                    <dd>
                      {req.risk_level ? (
                        <Badge
                          tone={
                            req.risk_level === "high" ||
                            req.risk_level === "critical"
                              ? "danger"
                              : req.risk_level === "medium"
                                ? "warn"
                                : "ok"
                          }
                        >
                          {req.risk_level}
                        </Badge>
                      ) : (
                        <span className="muted">—</span>
                      )}
                    </dd>
                  </div>
                  <div>
                    <dt>Justification</dt>
                    <dd>{req.justification || <span className="muted">—</span>}</dd>
                  </div>
                  <div>
                    <dt>Created</dt>
                    <dd>{formatDateTime(req.created_at)}</dd>
                  </div>
                </dl>

                {actions.length > 0 ? (
                  <div className="field-row" style={{ marginTop: 14 }}>
                    {actions.map((a) => (
                      <button
                        key={a}
                        className={`btn btn--sm ${
                          a === "deny"
                            ? "btn--danger"
                            : a === "cancel"
                              ? "btn--ghost"
                              : "btn--primary"
                        }`}
                        disabled={actionMut.isPending}
                        onClick={() => onAction(a)}
                      >
                        {actionMut.isPending ? <Spinner /> : ACTION_LABEL[a]}
                      </button>
                    ))}
                  </div>
                ) : (
                  <p className="muted" style={{ marginTop: 14, fontSize: 12 }}>
                    This request is in a terminal state ({titleCase(req.state)})
                    — no further actions.
                  </p>
                )}
              </Card>

              <Card
                title="History"
                subtitle="Every state transition is recorded with the actor and reason."
              >
                <AsyncBoundary
                  isLoading={historyQuery.isLoading}
                  error={historyQuery.error}
                  data={historyQuery.data}
                  onRetry={historyQuery.refetch}
                  isEmpty={(h) => h.length === 0}
                  empty={<p className="muted">No history yet.</p>}
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
          title={`${ACTION_LABEL[reasonFor]} request`}
          onClose={() => setReasonFor(null)}
          footer={
            <>
              <button
                className="btn btn--ghost"
                onClick={() => setReasonFor(null)}
              >
                Cancel
              </button>
              <button
                className={`btn ${reasonFor === "deny" ? "btn--danger" : "btn--primary"}`}
                disabled={actionMut.isPending}
                onClick={() => run(reasonFor, reason.trim() || undefined)}
              >
                {actionMut.isPending ? <Spinner /> : ACTION_LABEL[reasonFor]}
              </button>
            </>
          }
        >
          <label className="field">
            <span>Reason (optional, recorded in history)</span>
            <textarea
              rows={3}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Add context for this decision…"
            />
          </label>
        </Modal>
      )}
    </>
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
