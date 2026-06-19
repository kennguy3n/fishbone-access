import { useState } from "react";
import { useIntl, FormattedMessage, type IntlShape } from "react-intl";
import {
  PageHeader,
  Card,
  Badge,
  StatusBadge,
  AsyncBoundary,
} from "@/components/ui";
import { DataTable, type Column } from "@/components/DataTable";
import { EmptyState } from "@/components/EmptyState";
import { Modal } from "@/components/Modal";
import { useToast } from "@/components/Toast";
import {
  useRuns,
  useEmergencyOffboard,
  failedOffboardFromError,
  type WorkflowRun,
  type LeaverResult,
} from "@/api/workflows";
import { ApiError, useMe } from "@/api/access";
import { formatRelative, titleCase } from "@/lib/format";
import { RowActivate } from "@/routes/lane/RowActivate";

function errMessage(err: unknown, fallback: string): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof Error) return err.message;
  return fallback;
}

// Short, reusable label for a run's execution mode. Live runs touch real
// systems; dry-runs are side-effect-free rehearsals.
function modeLabel(intl: IntlShape, mode: string): string {
  return mode === "live"
    ? intl.formatMessage({ id: "jml.mode.live", defaultMessage: "Live" })
    : intl.formatMessage({ id: "jml.mode.dryRun", defaultMessage: "Dry-run" });
}

// emergency-offboard is gated ONLY by middleware.RequireMFA, which 403s with
// "step-up MFA required" when the session JWT lacks the MFA claim. Unlike
// PolicyEditor's promote path (RequireMFA AND RequireStepUpMFA, whose three
// sibling "step-up mfa ..." messages must be told apart with anchored regexes),
// this endpoint has no sibling step-up message to disambiguate — so we key off
// the same "step-up mfa" marker the Android/iOS SDKs use (STEP_UP_MARKER /
// isStepUp), keeping web/Android/iOS byte-for-byte identical and robust if the
// server ever appends context (e.g. "...required for emergency offboard").
// Other 403s (missing workspace permission, tenant mismatch) don't carry the
// marker, so they correctly fall through to the real server message.
const isSessionMfaRequired = (err: ApiError) =>
  err.status === 403 && /step-up mfa/i.test(err.message);

// Per-run step audit, shown in a modal from the dashboard.
function RunDetail({ run }: { run: WorkflowRun }) {
  const intl = useIntl();
  const steps = run.steps ?? [];
  return (
    <div>
      <div className="kv" style={{ marginBottom: 12 }}>
        <div>
          <dt>{intl.formatMessage({ id: "jml.run.subject", defaultMessage: "Subject" })}</dt>
          <dd>
            <code>{run.subject_external_id || "—"}</code>
          </dd>
        </div>
        <div>
          <dt>{intl.formatMessage({ id: "jml.run.mode", defaultMessage: "Mode" })}</dt>
          <dd>{modeLabel(intl, run.mode)}</dd>
        </div>
        <div>
          <dt>{intl.formatMessage({ id: "jml.col.state", defaultMessage: "Status" })}</dt>
          <dd>
            <StatusBadge status={run.status} />
          </dd>
        </div>
        <div>
          <dt>{intl.formatMessage({ id: "jml.run.started", defaultMessage: "Started" })}</dt>
          <dd>{formatRelative(run.started_at)}</dd>
        </div>
      </div>
      {steps.length === 0 ? (
        <p className="muted">
          {intl.formatMessage({
            id: "jml.run.noSteps",
            defaultMessage: "No per-step detail was recorded for this run.",
          })}
        </p>
      ) : (
        <div className="table-wrap">
          <table className="data">
            <thead>
              <tr>
                <th style={{ width: 40 }}>#</th>
                <th>{intl.formatMessage({ id: "jml.step.col.step", defaultMessage: "Step" })}</th>
                <th style={{ width: 120 }}>{intl.formatMessage({ id: "jml.step.col.outcome", defaultMessage: "Outcome" })}</th>
                <th>{intl.formatMessage({ id: "jml.step.col.detail", defaultMessage: "Detail" })}</th>
              </tr>
            </thead>
            <tbody>
              {steps.map((s) => (
                <tr key={s.index}>
                  <td>{s.index + 1}</td>
                  <td>
                    <b>{s.name || titleCase(s.type)}</b>
                    {s.layers && s.layers.length > 0 && (
                      <div style={{ marginTop: 6, display: "grid", gap: 4 }}>
                        {s.layers.map((l) => (
                          <span
                            key={l.layer}
                            style={{
                              display: "inline-flex",
                              gap: 6,
                              fontSize: 12,
                            }}
                          >
                            <Badge
                              tone={l.status === "failed" ? "danger" : "neutral"}
                            >
                              {titleCase(l.layer)}
                            </Badge>
                            {l.detail && (
                              <span className="muted">{l.detail}</span>
                            )}
                          </span>
                        ))}
                      </div>
                    )}
                  </td>
                  <td>
                    <StatusBadge status={s.status} />
                  </td>
                  <td className="muted">{s.detail || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// The six kill-switch layers, in execution order, so the result breakdown lists
// every layer even when the server omits a no-op layer from a partial failure.
const KILL_SWITCH_LAYERS = [
  "grant_revoke",
  "team_remove",
  "iam_core_disable",
  "session_revoke",
  "scim_deprovision",
  "identity_disable",
] as const;

// LeaverBreakdown renders the per-layer outcome of an emergency offboard so the
// operator can see exactly which of the six layers succeeded, and retry/escalate
// the ones that failed on a partial failure (errored=true).
function LeaverBreakdown({ result }: { result: LeaverResult }) {
  const intl = useIntl();
  const byLayer = new Map(result.layers.map((l) => [l.layer, l]));
  return (
    <div className="table-wrap">
      <table className="data">
        <thead>
          <tr>
            <th>{intl.formatMessage({ id: "jml.layer.col.layer", defaultMessage: "Layer" })}</th>
            <th style={{ width: 120 }}>{intl.formatMessage({ id: "jml.step.col.outcome", defaultMessage: "Outcome" })}</th>
            <th>{intl.formatMessage({ id: "jml.step.col.detail", defaultMessage: "Detail" })}</th>
          </tr>
        </thead>
        <tbody>
          {KILL_SWITCH_LAYERS.map((layer) => {
            const outcome = byLayer.get(layer);
            return (
              <tr key={layer}>
                <td>
                  <b>{titleCase(layer)}</b>
                </td>
                <td>
                  {outcome ? (
                    <StatusBadge status={outcome.status} />
                  ) : (
                    <Badge tone="neutral">
                      {intl.formatMessage({
                        id: "jml.layer.skipped",
                        defaultMessage: "Skipped",
                      })}
                    </Badge>
                  )}
                </td>
                <td className="muted">{outcome?.detail || "—"}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// Standalone six-layer leaver kill switch — the "break glass" path, gated by
// step-up MFA server-side (the RequireMFA claim) and confirmed here before
// firing. On completion the per-layer breakdown stays on screen so the operator
// can verify every layer (and retry any failed one on a partial failure).
function EmergencyOffboard({ onClose }: { onClose: () => void }) {
  const intl = useIntl();
  const toast = useToast();
  // staleTime: 0 so the MFA advisory below reflects the *current* session each
  // time the dialog opens (the global default is a 5-min cache with no
  // refetch-on-focus, which would otherwise show a stale claim after the
  // operator completes step-up MFA out-of-band).
  const me = useMe({ staleTime: 0 });
  const [externalId, setExternalId] = useState("");
  const [reason, setReason] = useState("");
  const [confirm, setConfirm] = useState("");
  const [result, setResult] = useState<LeaverResult | null>(null);
  const offboard = useEmergencyOffboard();

  // middleware.RequireMFA is the authoritative gate: the server rejects a
  // session whose token lacks the step-up MFA claim with 403 "step-up MFA
  // required", which `run` catches via isSessionMfaRequired and surfaces as a
  // toast. We therefore do NOT disable the button on the (cacheable) client
  // mfa_satisfied claim — doing so could strand the operator with a disabled
  // button after they satisfy MFA out-of-band. The claim drives an advisory
  // banner only; the server stays the source of truth.
  const mfaSatisfied = me.data?.mfa_satisfied ?? false;
  // The confirmation keyword is a fixed safety token, not prose: it stays
  // "OFFBOARD" in every locale so a translated UI can't accidentally make the
  // break-glass action easier to trigger.
  const CONFIRM_TOKEN = "OFFBOARD";
  const armed =
    externalId.trim().length > 0 && confirm.trim() === CONFIRM_TOKEN;

  const failuresTitle = intl.formatMessage({
    id: "jml.offboard.failuresTitle",
    defaultMessage: "Offboard completed with failures",
  });
  const failuresDetail = intl.formatMessage({
    id: "jml.offboard.failuresDetail",
    defaultMessage:
      "One or more layers failed — review the per-layer breakdown below.",
  });

  const run = async () => {
    try {
      const res = await offboard.mutateAsync({
        userExternalID: externalId.trim(),
        reason: reason.trim() || undefined,
      });
      setResult(res);
      if (res.errored) {
        toast.error(failuresTitle, failuresDetail);
      } else {
        toast.success(
          intl.formatMessage({
            id: "jml.offboard.completeTitle",
            defaultMessage: "Emergency offboard complete",
          }),
          intl.formatMessage({
            id: "jml.offboard.completeDetail",
            defaultMessage: "All six layers ran for this identity.",
          }),
        );
      }
    } catch (err) {
      if (err instanceof ApiError && isSessionMfaRequired(err)) {
        toast.error(
          intl.formatMessage({
            id: "jml.offboard.stepupTitle",
            defaultMessage: "Step-up MFA required",
          }),
          intl.formatMessage({
            id: "jml.offboard.stepupDetail",
            defaultMessage:
              "Re-authenticate with MFA to run an emergency offboard.",
          }),
        );
        return;
      }
      // A partial failure comes back as HTTP 500 carrying the same per-layer
      // breakdown under `leaver`; recover and render it (as both SDKs do) so
      // the operator sees which layers failed and can retry, rather than an
      // opaque error toast.
      const partial = failedOffboardFromError(err);
      if (partial) {
        setResult(partial);
        toast.error(failuresTitle, failuresDetail);
        return;
      }
      toast.error(
        intl.formatMessage({
          id: "jml.offboard.couldNot",
          defaultMessage: "Could not run the emergency offboard",
        }),
        errMessage(
          err,
          intl.formatMessage({
            id: "common.genericError",
            defaultMessage: "Something went wrong. Please try again.",
          }),
        ),
      );
    }
  };

  return (
    <Modal
      title={intl.formatMessage({
        id: "jml.offboard.title",
        defaultMessage: "Emergency offboard",
      })}
      onClose={onClose}
      footer={
        result ? (
          <button className="btn btn--primary" onClick={onClose}>
            {intl.formatMessage({ id: "common.done", defaultMessage: "Done" })}
          </button>
        ) : (
          <>
            <button className="btn btn--ghost" onClick={onClose}>
              {intl.formatMessage({ id: "common.cancel", defaultMessage: "Cancel" })}
            </button>
            <button
              className="btn btn--danger"
              onClick={run}
              disabled={!armed || offboard.isPending}
            >
              {offboard.isPending
                ? intl.formatMessage({ id: "jml.offboard.running", defaultMessage: "Running…" })
                : intl.formatMessage({ id: "jml.offboard.run", defaultMessage: "Run kill switch" })}
            </button>
          </>
        )
      }
    >
      {result ? (
        <>
          <div
            className={`notice ${result.errored ? "notice--danger" : "notice--info"}`}
            style={{ marginBottom: 12 }}
          >
            {result.errored
              ? intl.formatMessage(
                  {
                    id: "jml.offboard.resultFailed",
                    defaultMessage:
                      "Offboard of {user} completed with failures — retry the failed layers below.",
                  },
                  { user: result.user_external_id },
                )
              : intl.formatMessage(
                  {
                    id: "jml.offboard.resultOk",
                    defaultMessage: "All six layers ran for {user}.",
                  },
                  { user: result.user_external_id },
                )}
          </div>
          <LeaverBreakdown result={result} />
        </>
      ) : (
        <>
          <div className="notice notice--danger" style={{ marginBottom: 12 }}>
            {intl.formatMessage({
              id: "jml.offboard.warning",
              defaultMessage:
                "This runs all six offboarding layers (grant revoke → team remove → iam-core disable → session revoke → SCIM deprovision → identity disable) for the identity. It is irreversible and requires step-up MFA.",
            })}
          </div>
          {!mfaSatisfied && (
            <div className="notice notice--warn" style={{ marginBottom: 12 }}>
              {intl.formatMessage({
                id: "jml.offboard.mfaAdvisory",
                defaultMessage:
                  "Your session has not completed step-up MFA, so the server will reject this offboard. Re-authenticate with MFA, then run the kill switch.",
              })}
            </div>
          )}
          <label className="field">
            <span>
              {intl.formatMessage({
                id: "jml.offboard.externalId",
                defaultMessage: "User external ID",
              })}
            </span>
            <input
              value={externalId}
              placeholder={intl.formatMessage({
                id: "jml.offboard.externalIdPlaceholder",
                defaultMessage: "e.g. ada@corp.example",
              })}
              onChange={(e) => setExternalId(e.target.value)}
            />
          </label>
          <label className="field">
            <span>
              {intl.formatMessage({
                id: "jml.offboard.reason",
                defaultMessage: "Reason",
              })}{" "}
              <span className="muted">
                {intl.formatMessage({
                  id: "jml.offboard.reasonAudited",
                  defaultMessage: "(audited)",
                })}
              </span>
            </span>
            <input
              value={reason}
              placeholder={intl.formatMessage({
                id: "jml.offboard.reasonPlaceholder",
                defaultMessage: "Why this offboard is happening",
              })}
              onChange={(e) => setReason(e.target.value)}
            />
          </label>
          <label className="field">
            <span>
              <FormattedMessage
                id="jml.offboard.confirmLabel"
                defaultMessage="Type {token} to confirm"
                values={{ token: <code>{CONFIRM_TOKEN}</code> }}
              />
            </span>
            <input
              value={confirm}
              placeholder={CONFIRM_TOKEN}
              onChange={(e) => setConfirm(e.target.value)}
            />
          </label>
        </>
      )}
    </Modal>
  );
}

// JML dashboard: recent workflow runs with status, plus the per-run step audit
// and the standalone emergency-offboard action.
export function JmlRuns() {
  const intl = useIntl();
  const { data, isLoading, error, refetch } = useRuns(100);
  const [selected, setSelected] = useState<WorkflowRun | null>(null);
  const [offboardOpen, setOffboardOpen] = useState(false);

  const columns: Column<WorkflowRun>[] = [
    {
      header: intl.formatMessage({
        id: "jml.run.subject",
        defaultMessage: "Subject",
      }),
      cell: (r) => (
        <RowActivate
          label={intl.formatMessage(
            { id: "jml.run.open", defaultMessage: "Open run for {subject}" },
            { subject: r.subject_external_id || "—" },
          )}
          onActivate={() => setSelected(r)}
        >
          <b>
            <code>{r.subject_external_id || "—"}</code>
          </b>
          <span className="muted" style={{ fontSize: 12 }}>
            {intl.formatMessage(
              {
                id: "jml.run.stepCount",
                defaultMessage:
                  "{count, plural, one {# step} other {# steps}}",
              },
              { count: (r.steps ?? []).length },
            )}
            {r.trigger ? ` · ${titleCase(r.trigger)}` : ""}
          </span>
        </RowActivate>
      ),
    },
    {
      header: intl.formatMessage({
        id: "jml.run.mode",
        defaultMessage: "Mode",
      }),
      width: 110,
      cell: (r) => (
        <Badge tone={r.mode === "live" ? "info" : "neutral"}>
          {modeLabel(intl, r.mode)}
        </Badge>
      ),
    },
    {
      header: intl.formatMessage({
        id: "jml.col.state",
        defaultMessage: "State",
      }),
      width: 130,
      cell: (r) => <StatusBadge status={r.status} />,
    },
    {
      header: intl.formatMessage({
        id: "jml.run.started",
        defaultMessage: "Started",
      }),
      width: 130,
      cell: (r) => <span className="muted">{formatRelative(r.started_at)}</span>,
    },
  ];

  return (
    <>
      <PageHeader
        title={intl.formatMessage({
          id: "nav.jmlRuns",
          defaultMessage: "JML runs",
        })}
        subtitle={intl.formatMessage({
          id: "jml.runs.subtitle",
          defaultMessage:
            "Recent live workflow executions with per-step audit, plus the standalone emergency offboard.",
        })}
        actions={
          <button
            className="btn btn--danger"
            onClick={() => setOffboardOpen(true)}
          >
            {intl.formatMessage({
              id: "jml.offboard.title",
              defaultMessage: "Emergency offboard",
            })}
          </button>
        }
      />

      <Card>
        <AsyncBoundary
          isLoading={isLoading}
          error={error}
          data={data}
          onRetry={refetch}
          isEmpty={(rows) => rows.length === 0}
          empty={
            <EmptyState
              title={intl.formatMessage({
                id: "jml.runs.empty.title",
                defaultMessage: "No runs yet",
              })}
              description={intl.formatMessage({
                id: "jml.runs.empty.desc",
                defaultMessage:
                  "Published workflows that run for an identity appear here with their per-step audit.",
              })}
            />
          }
        >
          {(rows) => (
            <DataTable
              columns={columns}
              rows={rows}
              rowKey={(r) => r.id}
              onRowClick={(r) => setSelected(r)}
            />
          )}
        </AsyncBoundary>
      </Card>

      {selected && (
        <Modal
          title={intl.formatMessage({
            id: "jml.run.detail",
            defaultMessage: "Run detail",
          })}
          onClose={() => setSelected(null)}
          footer={
            <button className="btn" onClick={() => setSelected(null)}>
              {intl.formatMessage({ id: "common.close", defaultMessage: "Close" })}
            </button>
          }
        >
          <RunDetail run={selected} />
        </Modal>
      )}

      {offboardOpen && (
        <EmergencyOffboard onClose={() => setOffboardOpen(false)} />
      )}
    </>
  );
}
