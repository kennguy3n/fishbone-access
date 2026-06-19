import { useEffect, useId, useState } from "react";
import { FormattedMessage, useIntl, type IntlShape } from "react-intl";
import {
  PageHeader,
  Badge,
  StatusBadge,
  AsyncBoundary,
  Card,
} from "@/components/ui";
import { DataTable, type Column } from "@/components/DataTable";
import { EmptyState, EmptyIllustration } from "@/components/EmptyState";
import { Modal } from "@/components/Modal";
import { HelpTooltip } from "@/components/HelpTooltip";
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
import { takeRequestTarget } from "./pamHandoff";

// The lease state machine, in order. Expired and Revoked are both terminal and
// share the final slot; which one is reached depends on whether the TTL lapsed
// or an admin killed the lease early.
const FLOW: { state: PamLeaseState; id: string; def: string }[] = [
  { state: "requested", id: "pam.leases.stRequested", def: "Requested" },
  { state: "approved", id: "pam.leases.stApproved", def: "Approved" },
  { state: "active", id: "pam.leases.stActive", def: "Active" },
  { state: "expired", id: "pam.leases.stExpired", def: "Expired" },
];

const TERMINAL: PamLeaseState[] = ["expired", "revoked"];

// stageIndex maps a lease state to its position in FLOW so the stepper can mark
// stages reached vs pending. Revoked maps to the terminal slot like expired.
function stageIndex(state: PamLeaseState): number {
  if (state === "revoked") return FLOW.length - 1;
  return FLOW.findIndex((s) => s.state === state);
}

function riskTone(level?: string): "ok" | "warn" | "danger" {
  if (level === "high" || level === "critical") return "danger";
  if (level === "medium") return "warn";
  return "ok";
}

// Plain-language label for a risk level, so a non-expert reads "High" rather
// than a raw enum; unknown values fall back to the server string.
function riskLabel(intl: IntlShape, level: string): string {
  switch (level) {
    case "low":
      return intl.formatMessage({ id: "pam.leases.riskLow", defaultMessage: "Low" });
    case "medium":
      return intl.formatMessage({ id: "pam.leases.riskMedium", defaultMessage: "Medium" });
    case "high":
      return intl.formatMessage({ id: "pam.leases.riskHigh", defaultMessage: "High" });
    case "critical":
      return intl.formatMessage({ id: "pam.leases.riskCritical", defaultMessage: "Critical" });
    default:
      return level;
  }
}

// LeaseStateMachine renders the Requested → Approved → Active → Expired/Revoked
// progression as a horizontal stepper, highlighting the current stage. The
// terminal label switches to "Revoked" (danger) when the lease was killed early.
function LeaseStateMachine({ state }: { state: PamLeaseState }) {
  const intl = useIntl();
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
        const label =
          isTerminalSlot && revoked
            ? intl.formatMessage({ id: "pam.leases.stRevoked", defaultMessage: "Revoked" })
            : intl.formatMessage({ id: stage.id, defaultMessage: stage.def });
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
            {!isTerminalSlot && (
              <span className="muted" aria-hidden="true">
                →
              </span>
            )}
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
  const intl = useIntl();
  const [, setTick] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setTick((n) => n + 1), 1000);
    return () => clearInterval(t);
  }, []);
  if (!expiresAt) return <span className="muted">—</span>;
  const ms = new Date(expiresAt).getTime() - Date.now();
  if (Number.isNaN(ms)) return <span className="muted">—</span>;
  if (ms <= 0)
    return (
      <Badge tone="danger">
        <FormattedMessage id="pam.leases.expired" defaultMessage="Expired" />
      </Badge>
    );
  const total = Math.floor(ms / 1000);
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  const text = h > 0 ? `${h}h ${m}m ${s}s` : m > 0 ? `${m}m ${s}s` : `${s}s`;
  return (
    <Badge tone={total < 60 ? "warn" : "ok"}>
      <span
        aria-label={intl.formatMessage(
          { id: "pam.leases.expiresInLabel", defaultMessage: "Expires in {time}" },
          { time: text },
        )}
      >
        {text}
      </span>
    </Badge>
  );
}

const emptyDraft: RequestPamLeaseInput = {
  target_id: "",
  ttl_seconds: 3600,
  reason: "",
};

export function PamLeases() {
  const intl = useIntl();
  const toast = useToast();
  // Leases driving an active countdown need to refresh as the server sweep
  // expires them; poll on a modest interval.
  const { data, isLoading, error, refetch } = usePamLeases();
  const targets = usePamTargets();
  const requestMut = useRequestPamLease();
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState<RequestPamLeaseInput>(emptyDraft);
  const [attempted, setAttempted] = useState(false);
  const [detail, setDetail] = useState<PamLease | null>(null);
  const targetErrId = useId();
  const reasonHintId = useId();

  const targetName = (id: string) =>
    targets.data?.find((t) => t.id === id)?.name ?? id.slice(0, 8);

  // Default a request's TTL to the target's configured cap when it sets one, so
  // the operator starts inside policy rather than guessing a number. An uncapped
  // target falls back to the standard default so the field never carries a
  // previously-selected target's cap.
  const selectTarget = (id: string) => {
    const cap = targets.data?.find((t) => t.id === id)?.lease_ttl_seconds ?? 0;
    setDraft((d) => ({
      ...d,
      target_id: id,
      ttl_seconds: cap > 0 ? cap : emptyDraft.ttl_seconds,
    }));
  };

  const openRequest = (targetId?: string) => {
    setAttempted(false);
    setDraft(emptyDraft);
    if (targetId) selectTarget(targetId);
    setOpen(true);
  };

  // Honour a "Request access" handoff from the targets screen: open the form
  // pre-selected. Runs once targets are available so the cap can prefill.
  const targetsLoaded = !targets.isLoading;
  useEffect(() => {
    if (!targetsLoaded) return;
    const handoff = takeRequestTarget();
    if (handoff) openRequest(handoff);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [targetsLoaded]);

  const valid = !!draft.target_id && (draft.ttl_seconds ?? 0) > 0;

  const submit = async () => {
    setAttempted(true);
    if (!valid) return;
    try {
      await requestMut.mutateAsync({
        ...draft,
        reason: draft.reason?.trim() || undefined,
      });
      toast.success(
        intl.formatMessage({ id: "pam.leases.toastRequested", defaultMessage: "Lease requested" }),
        intl.formatMessage({ id: "pam.leases.toastRequestedBody", defaultMessage: "It's now awaiting approval." }),
      );
      setOpen(false);
      setDraft(emptyDraft);
      setAttempted(false);
      refetch();
    } catch (err) {
      toast.error(
        intl.formatMessage({ id: "pam.leases.toastRequestErr", defaultMessage: "Could not request lease" }),
        err instanceof ApiError ? err.message : undefined,
      );
    }
  };

  const columns: Column<PamLease>[] = [
    {
      header: intl.formatMessage({ id: "pam.leases.colLease", defaultMessage: "Lease" }),
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
    {
      header: intl.formatMessage({ id: "pam.leases.colState", defaultMessage: "State" }),
      cell: (l) => <StatusBadge status={l.state} />,
    },
    {
      header: intl.formatMessage({ id: "pam.leases.colRisk", defaultMessage: "Risk" }),
      cell: (l) =>
        l.risk_level ? (
          <Badge tone={riskTone(l.risk_level)}>
            {riskLabel(intl, l.risk_level)}
            {l.risk_degraded
              ? ` ${intl.formatMessage({ id: "pam.leases.riskDegradedSuffix", defaultMessage: "(estimated)" })}`
              : ""}
          </Badge>
        ) : (
          <span className="muted">—</span>
        ),
    },
    {
      header: intl.formatMessage({ id: "pam.leases.colExpires", defaultMessage: "Expires in" }),
      cell: (l) =>
        l.state === "approved" || l.state === "active" ? (
          <Countdown expiresAt={l.expires_at} />
        ) : (
          <span className="muted">—</span>
        ),
    },
  ];

  return (
    <div>
      <PageHeader
        title={intl.formatMessage({ id: "pam.leases.title", defaultMessage: "Just-in-time leases" })}
        subtitle={intl.formatMessage({
          id: "pam.leases.subtitle",
          defaultMessage:
            "Time-boxed privileged access. A lease moves Requested → Approved → Active → Expired, and the credential is brokered only while it's live — so access is never standing.",
        })}
        actions={
          <button className="btn btn--primary" onClick={() => openRequest()}>
            <FormattedMessage id="pam.leases.request" defaultMessage="Request lease" />
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
            illustration={<EmptyIllustration kind="policy" />}
            title={intl.formatMessage({ id: "pam.leases.emptyTitle", defaultMessage: "No leases yet" })}
            description={intl.formatMessage({
              id: "pam.leases.emptyBody",
              defaultMessage:
                "Request a just-in-time lease against a target to get time-boxed, fully audited access brokered through the gateway. Nothing is granted until it's approved.",
            })}
            action={
              <button className="btn btn--primary btn--sm" onClick={() => openRequest()}>
                <FormattedMessage id="pam.leases.request" defaultMessage="Request lease" />
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
          title={intl.formatMessage({ id: "pam.leases.modalTitle", defaultMessage: "Request a just-in-time lease" })}
          onClose={() => setOpen(false)}
          busy={requestMut.isPending}
          footer={
            <>
              <button
                className="btn btn--ghost"
                onClick={() => setOpen(false)}
                disabled={requestMut.isPending}
              >
                <FormattedMessage id="pam.leases.cancel" defaultMessage="Cancel" />
              </button>
              <button
                className="btn btn--primary"
                disabled={requestMut.isPending}
                onClick={submit}
              >
                <FormattedMessage id="pam.leases.request" defaultMessage="Request lease" />
              </button>
            </>
          }
        >
          <label className="field">
            <span>
              <FormattedMessage id="pam.leases.fieldTarget" defaultMessage="Target" />{" "}
              <span className="field__required" aria-hidden="true">
                *
              </span>
            </span>
            <select
              value={draft.target_id}
              aria-required="true"
              aria-invalid={attempted && !draft.target_id ? true : undefined}
              aria-describedby={attempted && !draft.target_id ? targetErrId : undefined}
              onChange={(e) => selectTarget(e.target.value)}
            >
              <option value="">
                {intl.formatMessage({ id: "pam.leases.targetPlaceholder", defaultMessage: "Select a target…" })}
              </option>
              {(targets.data ?? []).map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name} ({t.protocol})
                </option>
              ))}
            </select>
            {attempted && !draft.target_id && (
              <span className="field__error" id={targetErrId} role="alert">
                <FormattedMessage
                  id="pam.leases.errTarget"
                  defaultMessage="Choose the system you need access to."
                />
              </span>
            )}
          </label>
          <label className="field">
            <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
              <FormattedMessage id="pam.leases.fieldTtl" defaultMessage="How long do you need it? (seconds)" />
              <HelpTooltip>
                <FormattedMessage
                  id="pam.leases.ttlHelp"
                  defaultMessage="The lease expires automatically after this long, ending the session and revoking the credential. Ask for the shortest window that gets the job done."
                />
              </HelpTooltip>
            </span>
            <input
              type="number"
              min={1}
              value={draft.ttl_seconds}
              onChange={(e) =>
                setDraft({ ...draft, ttl_seconds: Number(e.target.value) || 0 })
              }
            />
          </label>
          <label className="field">
            <span>
              <FormattedMessage id="pam.leases.fieldReason" defaultMessage="Reason (recorded for audit)" />
            </span>
            <textarea
              rows={2}
              value={draft.reason}
              aria-describedby={reasonHintId}
              placeholder={intl.formatMessage({
                id: "pam.leases.reasonPlaceholder",
                defaultMessage: "Incident #4821 — restart stuck worker",
              })}
              onChange={(e) => setDraft({ ...draft, reason: e.target.value })}
            />
            <span className="field__hint muted" id={reasonHintId}>
              <FormattedMessage
                id="pam.leases.reasonHint"
                defaultMessage="A clear reason speeds up approval and is kept in the audit trail."
              />
            </span>
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
    </div>
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
  const intl = useIntl();
  const toast = useToast();
  const me = useMe();
  const approveMut = useApprovePamLease(lease.id);
  const revokeMut = useRevokePamLease(lease.id);
  const actionPending = approveMut.isPending || revokeMut.isPending;
  const [reason, setReason] = useState("");
  const mfaNoteId = useId();

  const terminal = TERMINAL.includes(lease.state);
  const canApprove = lease.state === "requested";
  const canRevoke = !terminal;
  // Approve/revoke open and close a privileged window, so the server step-up-MFA
  // gates them. Mirror that here so an operator without satisfied MFA sees a
  // disabled control with a plain-language reason rather than a 403 toast.
  const mfaSatisfied = !!me.data?.mfa_satisfied;
  const mfaReason = !me.data
    ? intl.formatMessage({ id: "pam.leases.mfaChecking", defaultMessage: "Checking your authorization…" })
    : intl.formatMessage({
        id: "pam.leases.mfaRequired",
        defaultMessage:
          "Approving or revoking needs step-up MFA. Re-verify with your authenticator, then return here.",
      });
  const showMfaNote = (canApprove || canRevoke) && !mfaSatisfied;

  const approve = async () => {
    try {
      await approveMut.mutateAsync(undefined);
      toast.success(intl.formatMessage({ id: "pam.leases.toastApproved", defaultMessage: "Lease approved" }));
      onChanged();
    } catch (err) {
      toast.error(
        intl.formatMessage({ id: "pam.leases.toastApproveErr", defaultMessage: "Could not approve the lease" }),
        err instanceof ApiError ? err.message : undefined,
      );
    }
  };

  const revoke = async () => {
    try {
      await revokeMut.mutateAsync(reason.trim() || undefined);
      toast.success(intl.formatMessage({ id: "pam.leases.toastRevoked", defaultMessage: "Lease revoked" }));
      onChanged();
    } catch (err) {
      toast.error(
        intl.formatMessage({ id: "pam.leases.toastRevokeErr", defaultMessage: "Could not revoke the lease" }),
        err instanceof ApiError ? err.message : undefined,
      );
    }
  };

  return (
    <Modal
      title={intl.formatMessage(
        { id: "pam.leases.detailTitle", defaultMessage: "Lease · {target}" },
        { target: targetName },
      )}
      onClose={onClose}
      busy={actionPending}
      footer={
        <>
          <button
            className="btn btn--ghost"
            onClick={onClose}
            disabled={actionPending}
          >
            <FormattedMessage id="pam.leases.close" defaultMessage="Close" />
          </button>
          {canApprove && (
            <button
              className="btn btn--primary"
              disabled={actionPending || !mfaSatisfied}
              aria-describedby={showMfaNote ? mfaNoteId : undefined}
              onClick={approve}
            >
              <FormattedMessage id="pam.leases.approve" defaultMessage="Approve" />
            </button>
          )}
          {canRevoke && (
            <button
              className="btn btn--danger"
              disabled={actionPending || !mfaSatisfied}
              aria-describedby={showMfaNote ? mfaNoteId : undefined}
              onClick={revoke}
            >
              <FormattedMessage id="pam.leases.revoke" defaultMessage="Revoke access" />
            </button>
          )}
        </>
      }
    >
      <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
        <LeaseStateMachine state={lease.state} />

        {showMfaNote && (
          <p className="callout callout--info" id={mfaNoteId}>
            {mfaReason}
          </p>
        )}

        <Card title={intl.formatMessage({ id: "pam.leases.detailsCard", defaultMessage: "Details" })}>
          <dl className="kv">
            <dt>
              <FormattedMessage id="pam.leases.subject" defaultMessage="Subject" />
            </dt>
            <dd>{lease.subject}</dd>
            <dt>
              <FormattedMessage id="pam.leases.requestedBy" defaultMessage="Requested by" />
            </dt>
            <dd>{lease.requested_by}</dd>
            {lease.approved_by && (
              <>
                <dt>
                  <FormattedMessage id="pam.leases.approvedBy" defaultMessage="Approved by" />
                </dt>
                <dd>{lease.approved_by}</dd>
              </>
            )}
            <dt>
              <FormattedMessage id="pam.leases.grantedAt" defaultMessage="Granted at" />
            </dt>
            <dd>{formatDateTime(lease.granted_at)}</dd>
            <dt>
              <FormattedMessage id="pam.leases.expiresAt" defaultMessage="Expires at" />
            </dt>
            <dd>{formatDateTime(lease.expires_at)}</dd>
            {lease.reason && (
              <>
                <dt>
                  <FormattedMessage id="pam.leases.reason" defaultMessage="Reason" />
                </dt>
                <dd>{lease.reason}</dd>
              </>
            )}
            {lease.revoke_reason && (
              <>
                <dt>
                  <FormattedMessage id="pam.leases.revokeReason" defaultMessage="Revoke reason" />
                </dt>
                <dd>{lease.revoke_reason}</dd>
              </>
            )}
          </dl>
        </Card>

        {lease.risk_level && (
          <Card
            title={intl.formatMessage({ id: "pam.leases.riskCard", defaultMessage: "Risk assessment" })}
            subtitle={
              lease.risk_degraded
                ? intl.formatMessage({
                    id: "pam.leases.riskDegraded",
                    defaultMessage: "Estimated — the scoring model was unavailable, so access was allowed by default.",
                  })
                : intl.formatMessage({
                    id: "pam.leases.riskScored",
                    defaultMessage: "Scored automatically when the lease was requested.",
                  })
            }
          >
            <p>
              <Badge tone={riskTone(lease.risk_level)}>
                {riskLabel(intl, lease.risk_level)}
              </Badge>
            </p>
            {lease.risk_reason && <p className="muted">{lease.risk_reason}</p>}
          </Card>
        )}

        {canRevoke && (
          <label className="field">
            <span>
              <FormattedMessage
                id="pam.leases.revokeReasonField"
                defaultMessage="Revoke reason (optional, recorded for audit)"
              />
            </span>
            <input
              value={reason}
              placeholder={intl.formatMessage({
                id: "pam.leases.revokeReasonPlaceholder",
                defaultMessage: "Task complete / access no longer needed",
              })}
              onChange={(e) => setReason(e.target.value)}
            />
          </label>
        )}
      </div>
    </Modal>
  );
}
