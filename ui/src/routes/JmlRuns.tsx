import { useState } from "react";
import { useIntl } from "react-intl";
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
  type WorkflowRun,
} from "@/api/workflows";
import { ApiError } from "@/api/access";
import { formatRelative, titleCase } from "@/lib/format";

function errMessage(err: unknown): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof Error) return err.message;
  return "Something went wrong.";
}

// Per-run step audit, shown in a modal from the dashboard.
function RunDetail({ run }: { run: WorkflowRun }) {
  const steps = run.steps ?? [];
  return (
    <div>
      <div className="kv" style={{ marginBottom: 12 }}>
        <div>
          <dt>Subject</dt>
          <dd>
            <code>{run.subject_external_id || "—"}</code>
          </dd>
        </div>
        <div>
          <dt>Mode</dt>
          <dd>{run.mode === "dry_run" ? "Dry-run" : "Live"}</dd>
        </div>
        <div>
          <dt>Status</dt>
          <dd>
            <StatusBadge status={run.status} />
          </dd>
        </div>
        <div>
          <dt>Started</dt>
          <dd>{formatRelative(run.started_at)}</dd>
        </div>
      </div>
      {steps.length === 0 ? (
        <p className="muted">No per-step detail recorded for this run.</p>
      ) : (
        <div className="table-wrap">
          <table className="data">
            <thead>
              <tr>
                <th style={{ width: 40 }}>#</th>
                <th>Step</th>
                <th style={{ width: 120 }}>Outcome</th>
                <th>Detail</th>
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

// Standalone six-layer leaver kill switch — the "break glass" path, gated by
// step-up MFA server-side and confirmed here before firing.
function EmergencyOffboard({ onClose }: { onClose: () => void }) {
  const intl = useIntl();
  const toast = useToast();
  const [externalId, setExternalId] = useState("");
  const [reason, setReason] = useState("");
  const [confirm, setConfirm] = useState("");
  const offboard = useEmergencyOffboard();

  const armed = externalId.trim().length > 0 && confirm.trim() === "OFFBOARD";

  const run = async () => {
    try {
      const res = await offboard.mutateAsync({
        userExternalID: externalId.trim(),
        reason: reason.trim() || undefined,
      });
      if (res.errored) {
        toast.error(
          "Offboard completed with failures",
          "One or more layers failed — review the run audit.",
        );
      } else {
        toast.success(
          "Emergency offboard complete",
          "All six layers ran for this identity.",
        );
      }
      onClose();
    } catch (err) {
      if (err instanceof ApiError && err.status === 403) {
        toast.error(
          "Step-up MFA required",
          "Re-authenticate with MFA to run an emergency offboard.",
        );
        return;
      }
      toast.error("Could not offboard", errMessage(err));
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
        <>
          <button className="btn btn--ghost" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn btn--danger"
            onClick={run}
            disabled={!armed || offboard.isPending}
          >
            {offboard.isPending ? "Running…" : "Run kill switch"}
          </button>
        </>
      }
    >
      <div className="notice notice--danger" style={{ marginBottom: 12 }}>
        This runs all six offboarding layers (grant revoke → team remove →
        iam-core disable → session revoke → SCIM deprovision → identity disable)
        for the identity. It is irreversible and requires step-up MFA.
      </div>
      <label className="field">
        <span>User external ID</span>
        <input
          value={externalId}
          placeholder="e.g. ada@corp.example"
          onChange={(e) => setExternalId(e.target.value)}
        />
      </label>
      <label className="field">
        <span>
          Reason <span className="muted">(audited)</span>
        </span>
        <input
          value={reason}
          placeholder="Why this offboard is happening"
          onChange={(e) => setReason(e.target.value)}
        />
      </label>
      <label className="field">
        <span>
          Type <code>OFFBOARD</code> to confirm
        </span>
        <input
          value={confirm}
          placeholder="OFFBOARD"
          onChange={(e) => setConfirm(e.target.value)}
        />
      </label>
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
        <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
          <b>
            <code>{r.subject_external_id || "—"}</code>
          </b>
          <span className="muted" style={{ fontSize: 12 }}>
            {(r.steps ?? []).length} step(s)
            {r.trigger ? ` · ${titleCase(r.trigger)}` : ""}
          </span>
        </div>
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
          {r.mode === "live" ? "Live" : "Dry-run"}
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
              Close
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
