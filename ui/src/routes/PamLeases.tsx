import { useEffect, useState } from "react";
import { PageHeader, Badge, StatusBadge, AsyncBoundary, Card } from "@/components/ui";
import { DataTable, type Column } from "@/components/DataTable";
import { EmptyState } from "@/components/EmptyState";
import { Modal } from "@/components/Modal";
import { useToast } from "@/components/Toast";
import {
  usePamLeases,
  usePamTargets,
  useRequestPamLease,
  useApprovePamLease,
  useRevokePamLease,
  useMe,
  type PamLease,
  type PamLeaseState,
  type RequestPamLeaseInput,
  ApiError,
} from "@/api/access";
import { formatDateTime } from "@/lib/format";

// The lease state machine, in order. Expired and Revoked are both terminal and
// share the final slot; which one is reached depends on whether the TTL lapsed
// or an admin killed the lease early.
const FLOW: { state: PamLeaseState; label: string }[] = [
  { state: "requested", label: "Requested" },
  { state: "approved", label: "Approved" },
  { state: "active", label: "Active" },
  { state: "expired", label: "Expired" },
];

const TERMINAL: PamLeaseState[] = ["expired", "revoked"];

// stageIndex maps a lease state to its position in FLOW so the stepper can mark
// stages reached vs pending. Revoked maps to the terminal slot like expired.
function stageIndex(state: PamLeaseState): number {
  if (state === "revoked") return FLOW.length - 1;
  return FLOW.findIndex((s) => s.state === state);
}

// LeaseStateMachine renders the Requested → Approved → Active → Expired/Revoked
// progression as a horizontal stepper, highlighting the current stage. The
// terminal label switches to "Revoked" (danger) when the lease was killed early.
function LeaseStateMachine({ state }: { state: PamLeaseState }) {
  const current = stageIndex(state);
  const revoked = state === "revoked";
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 8,
        flexWrap: "wrap",
      }}
    >
      {FLOW.map((stage, i) => {
        const isTerminalSlot = i === FLOW.length - 1;
        const label = isTerminalSlot && revoked ? "Revoked" : stage.label;
        const reached = i <= current;
        let tone: "ok" | "warn" | "danger" | "neutral" | "info" = "neutral";
        if (reached) {
          if (isTerminalSlot)
            tone = revoked || state === "expired" ? "danger" : "neutral";
          else if (i === current) tone = state === "active" ? "ok" : "info";
          else tone = "ok";
        }
        return (
          <div
            key={stage.state}
            style={{ display: "flex", alignItems: "center", gap: 8 }}
          >
            <Badge tone={tone} dot={i === current}>
              {label}
            </Badge>
            {!isTerminalSlot && <span className="muted">→</span>}
          </div>
        );
      })}
    </div>
  );
}

// Countdown renders the remaining time until expires_at, ticking once a second.
// It is the visible TTL enforcement: when it hits zero the lease is expired by
// the server sweep and the row re-renders into its terminal state on refetch.
function Countdown({ expiresAt }: { expiresAt?: string | null }) {
  const [, setTick] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setTick((n) => n + 1), 1000);
    return () => clearInterval(t);
  }, []);
  if (!expiresAt) return <span className="muted">—</span>;
  const ms = new Date(expiresAt).getTime() - Date.now();
  if (Number.isNaN(ms)) return <span className="muted">—</span>;
  if (ms <= 0) return <Badge tone="danger">Expired</Badge>;
  const total = Math.floor(ms / 1000);
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  const text =
    h > 0 ? `${h}h ${m}m ${s}s` : m > 0 ? `${m}m ${s}s` : `${s}s`;
  return <Badge tone={total < 60 ? "warn" : "ok"}>{text}</Badge>;
}

const emptyDraft: RequestPamLeaseInput = {
  target_id: "",
  ttl_seconds: 3600,
  reason: "",
};

export function PamLeases() {
  const toast = useToast();
  // Leases driving an active countdown need to refresh as the server sweep
  // expires them; poll on a modest interval.
  const { data, isLoading, error, refetch } = usePamLeases();
  const targets = usePamTargets();
  const requestMut = useRequestPamLease();
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState<RequestPamLeaseInput>(emptyDraft);
  const [detail, setDetail] = useState<PamLease | null>(null);

  const targetName = (id: string) =>
    targets.data?.find((t) => t.id === id)?.name ?? id.slice(0, 8);

  const valid = draft.target_id && (draft.ttl_seconds ?? 0) > 0;

  const submit = async () => {
    if (!valid) return;
    try {
      await requestMut.mutateAsync({
        ...draft,
        reason: draft.reason?.trim() || undefined,
      });
      toast.success("Lease requested", "Awaiting approval");
      setOpen(false);
      setDraft(emptyDraft);
      refetch();
    } catch (err) {
      toast.error(
        "Could not request lease",
        err instanceof ApiError ? err.message : undefined,
      );
    }
  };

  const columns: Column<PamLease>[] = [
    {
      header: "Lease",
      cell: (l) => (
        <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
          <b>{targetName(l.target_id)}</b>
          <span className="muted" style={{ fontSize: 12 }}>
            {l.subject}
            {l.reason ? ` · ${l.reason}` : ""}
          </span>
        </div>
      ),
    },
    { header: "State", cell: (l) => <StatusBadge status={l.state} /> },
    {
      header: "Risk",
      cell: (l) =>
        l.risk_level ? (
          <Badge
            tone={
              l.risk_level === "high" || l.risk_level === "critical"
                ? "danger"
                : l.risk_level === "medium"
                  ? "warn"
                  : "ok"
            }
          >
            {l.risk_level}
            {l.risk_degraded ? " (degraded)" : ""}
          </Badge>
        ) : (
          <span className="muted">—</span>
        ),
    },
    {
      header: "Expires in",
      cell: (l) =>
        l.state === "approved" || l.state === "active" ? (
          <Countdown expiresAt={l.expires_at} />
        ) : (
          <span className="muted">—</span>
        ),
    },
  ];

  return (
    <>
      <PageHeader
        title="JIT leases"
        subtitle="Just-in-time privileged access. A lease flows Requested → Approved → Active → Expired/Revoked; the credential is brokered only while the lease is live."
        actions={
          <button className="btn btn--primary" onClick={() => setOpen(true)}>
            Request lease
          </button>
        }
      />
      <AsyncBoundary
        isLoading={isLoading}
        error={error}
        data={data}
        onRetry={refetch}
        isEmpty={(rows) => rows.length === 0}
        empty={
          <EmptyState
            title="No leases yet"
            description="Request a just-in-time lease against a target to broker time-boxed privileged access through the gateway."
            action={
              <button
                className="btn btn--primary btn--sm"
                onClick={() => setOpen(true)}
              >
                Request lease
              </button>
            }
          />
        }
      >
        {(rows) => (
          <DataTable
            columns={columns}
            rows={rows}
            rowKey={(l) => l.id}
            onRowClick={(l) => setDetail(l)}
          />
        )}
      </AsyncBoundary>

      {open && (
        <Modal
          title="Request JIT lease"
          onClose={() => setOpen(false)}
          footer={
            <>
              <button className="btn btn--ghost" onClick={() => setOpen(false)}>
                Cancel
              </button>
              <button
                className="btn btn--primary"
                disabled={!valid || requestMut.isPending}
                onClick={submit}
              >
                Request lease
              </button>
            </>
          }
        >
          <label className="field">
            <span>Target (required)</span>
            <select
              value={draft.target_id}
              onChange={(e) =>
                setDraft({ ...draft, target_id: e.target.value })
              }
            >
              <option value="">Select a target…</option>
              {(targets.data ?? []).map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name} ({t.protocol})
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            <span>Requested TTL (seconds)</span>
            <input
              type="number"
              min={1}
              value={draft.ttl_seconds}
              onChange={(e) =>
                setDraft({
                  ...draft,
                  ttl_seconds: Number(e.target.value) || 0,
                })
              }
            />
          </label>
          <label className="field">
            <span>Reason (audited)</span>
            <textarea
              rows={2}
              value={draft.reason}
              placeholder="Incident #4821 — restart stuck worker"
              onChange={(e) => setDraft({ ...draft, reason: e.target.value })}
            />
          </label>
        </Modal>
      )}

      {detail && (
        <LeaseDetailModal
          lease={detail}
          targetName={targetName(detail.target_id)}
          onClose={() => setDetail(null)}
          onChanged={() => {
            refetch();
            setDetail(null);
          }}
        />
      )}
    </>
  );
}

// LeaseDetailModal shows the state machine, the risk rationale, and the
// approve/revoke controls. Approve grants the TTL window; revoke kills the lease
// early (terminal). Both are server-audited transitions.
function LeaseDetailModal({
  lease,
  targetName,
  onClose,
  onChanged,
}: {
  lease: PamLease;
  targetName: string;
  onClose: () => void;
  onChanged: () => void;
}) {
  const toast = useToast();
  const me = useMe();
  const approveMut = useApprovePamLease(lease.id);
  const revokeMut = useRevokePamLease(lease.id);
  const [reason, setReason] = useState("");

  const terminal = TERMINAL.includes(lease.state);
  const canApprove = lease.state === "requested";
  const canRevoke = !terminal;
  // Approve/revoke open and close a privileged window, so the server step-up-MFA
  // gates them. Mirror that here so an operator without satisfied MFA sees a
  // disabled control with a reason rather than a 403 toast.
  const mfaSatisfied = !!me.data?.mfa_satisfied;
  const mfaReason = !me.data
    ? "Checking authorization…"
    : "Requires step-up MFA.";

  const approve = async () => {
    try {
      await approveMut.mutateAsync(undefined);
      toast.success("Lease approved");
      onChanged();
    } catch (err) {
      toast.error(
        "Could not approve",
        err instanceof ApiError ? err.message : undefined,
      );
    }
  };

  const revoke = async () => {
    try {
      await revokeMut.mutateAsync(reason.trim() || undefined);
      toast.success("Lease revoked");
      onChanged();
    } catch (err) {
      toast.error(
        "Could not revoke",
        err instanceof ApiError ? err.message : undefined,
      );
    }
  };

  return (
    <Modal
      title={`Lease · ${targetName}`}
      onClose={onClose}
      footer={
        <>
          <button className="btn btn--ghost" onClick={onClose}>
            Close
          </button>
          {canApprove && (
            <button
              className="btn btn--primary"
              disabled={approveMut.isPending || !mfaSatisfied}
              title={mfaSatisfied ? undefined : mfaReason}
              onClick={approve}
            >
              Approve
            </button>
          )}
          {canRevoke && (
            <button
              className="btn btn--danger"
              disabled={revokeMut.isPending || !mfaSatisfied}
              title={mfaSatisfied ? undefined : mfaReason}
              onClick={revoke}
            >
              Revoke
            </button>
          )}
        </>
      }
    >
      <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
        <LeaseStateMachine state={lease.state} />
        <Card title="Details">
          <dl className="kv">
            <dt>Subject</dt>
            <dd>{lease.subject}</dd>
            <dt>Requested by</dt>
            <dd>{lease.requested_by}</dd>
            {lease.approved_by && (
              <>
                <dt>Approved by</dt>
                <dd>{lease.approved_by}</dd>
              </>
            )}
            <dt>Granted at</dt>
            <dd>{formatDateTime(lease.granted_at)}</dd>
            <dt>Expires at</dt>
            <dd>{formatDateTime(lease.expires_at)}</dd>
            {lease.reason && (
              <>
                <dt>Reason</dt>
                <dd>{lease.reason}</dd>
              </>
            )}
            {lease.revoke_reason && (
              <>
                <dt>Revoke reason</dt>
                <dd>{lease.revoke_reason}</dd>
              </>
            )}
          </dl>
        </Card>
        {lease.risk_level && (
          <Card
            title="Risk assessment"
            subtitle={lease.risk_degraded ? "Degraded (model unavailable — fail-open)" : "AI risk scored at request time"}
          >
            <p>
              <Badge
                tone={
                  lease.risk_level === "high" ||
                  lease.risk_level === "critical"
                    ? "danger"
                    : lease.risk_level === "medium"
                      ? "warn"
                      : "ok"
                }
              >
                {lease.risk_level}
              </Badge>
            </p>
            {lease.risk_reason && <p className="muted">{lease.risk_reason}</p>}
          </Card>
        )}
        {canRevoke && (
          <label className="field">
            <span>Revoke reason (optional, audited)</span>
            <input
              value={reason}
              placeholder="Task complete / access no longer needed"
              onChange={(e) => setReason(e.target.value)}
            />
          </label>
        )}
      </div>
    </Modal>
  );
}
