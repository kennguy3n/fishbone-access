import { useMemo, useState } from "react";
import { PageHeader, Badge, StatusBadge, AsyncBoundary, Card } from "@/components/ui";
import { DataTable, type Column } from "@/components/DataTable";
import { EmptyState } from "@/components/EmptyState";
import { Modal } from "@/components/Modal";
import { useToast } from "@/components/Toast";
import {
  usePamSessions,
  useSessionReplay,
  usePausePamSession,
  useResumePamSession,
  useTerminatePamSession,
  useMe,
  type PamSession,
  ApiError,
} from "@/api/access";
import { formatDateTime, formatRelative } from "@/lib/format";

// TAKEOVER_SCOPE gates the high-risk live-control actions. The server enforces
// RequirePermission("pam.takeover") + step-up MFA regardless (fail-closed); the
// UI mirrors the gate so an unauthorized operator sees disabled controls with a
// reason instead of a 403 surprise.
const TAKEOVER_SCOPE = "pam.takeover";

function isActive(s: PamSession): boolean {
  return s.state === "active";
}

export function PamSessions() {
  const toast = useToast();
  const me = useMe();
  const [activeOnly, setActiveOnly] = useState(true);
  // Live console: poll so pause/terminate from another operator and new
  // sessions surface without a manual refresh.
  const { data, isLoading, error, refetch } = usePamSessions(
    { active_only: activeOnly },
    { refetchInterval: 5000 },
  );
  const [detail, setDetail] = useState<PamSession | null>(null);

  const canTakeover = useMemo(() => {
    const scopes = me.data?.scopes ?? [];
    return scopes.includes(TAKEOVER_SCOPE) && !!me.data?.mfa_satisfied;
  }, [me.data]);

  const takeoverReason = useMemo(() => {
    if (!me.data) return "Checking authorization…";
    if (!(me.data.scopes ?? []).includes(TAKEOVER_SCOPE))
      return "Requires the pam.takeover permission.";
    if (!me.data.mfa_satisfied) return "Requires step-up MFA.";
    return "";
  }, [me.data]);

  const columns: Column<PamSession>[] = [
    {
      header: "Session",
      cell: (s) => (
        <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
          <b>{s.subject}</b>
          <span className="muted" style={{ fontSize: 12 }}>
            <Badge tone="info">{s.protocol}</Badge>
            {s.client_addr ? ` · ${s.client_addr}` : ""}
          </span>
        </div>
      ),
    },
    {
      header: "State",
      cell: (s) => (
        <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
          <StatusBadge status={s.state} />
          {s.paused && <Badge tone="warn">Paused</Badge>}
        </div>
      ),
    },
    {
      header: "Started",
      cell: (s) => <span className="muted">{formatRelative(s.started_at)}</span>,
    },
    {
      header: "Ended",
      cell: (s) =>
        s.ended_at ? (
          <span className="muted">{formatRelative(s.ended_at)}</span>
        ) : (
          <Badge tone="ok" dot>
            Live
          </Badge>
        ),
    },
  ];

  return (
    <>
      <PageHeader
        title="Live sessions"
        subtitle="Active and recorded privileged sessions. Authorized operators can pause, resume, or terminate a live session; every recording is replayable."
        actions={
          <label
            className="field"
            style={{ flexDirection: "row", alignItems: "center", gap: 8 }}
          >
            <input
              type="checkbox"
              checked={activeOnly}
              style={{ width: "auto" }}
              onChange={(e) => setActiveOnly(e.target.checked)}
            />
            <span>Active only</span>
          </label>
        }
      />
      {!canTakeover && takeoverReason && (
        <Card>
          <p className="muted">
            Live session control (pause / terminate) is disabled: {takeoverReason}
          </p>
        </Card>
      )}
      <AsyncBoundary
        isLoading={isLoading}
        error={error}
        data={data}
        onRetry={refetch}
        isEmpty={(rows) => rows.length === 0}
        empty={
          <EmptyState
            title="No sessions"
            description="Privileged sessions opened through the gateway appear here, live and after they end, with full replay."
          />
        }
      >
        {(rows) => (
          <DataTable
            columns={columns}
            rows={rows}
            rowKey={(s) => s.id}
            onRowClick={(s) => setDetail(s)}
          />
        )}
      </AsyncBoundary>

      {detail && (
        <SessionDetailModal
          session={detail}
          canTakeover={canTakeover}
          takeoverReason={takeoverReason}
          onClose={() => setDetail(null)}
          onChanged={() => refetch()}
          notifyError={(title, err) =>
            toast.error(title, err instanceof ApiError ? err.message : undefined)
          }
          notifySuccess={(t) => toast.success(t)}
        />
      )}
    </>
  );
}

function SessionDetailModal({
  session,
  canTakeover,
  takeoverReason,
  onClose,
  onChanged,
  notifyError,
  notifySuccess,
}: {
  session: PamSession;
  canTakeover: boolean;
  takeoverReason: string;
  onClose: () => void;
  onChanged: () => void;
  notifyError: (title: string, err: unknown) => void;
  notifySuccess: (title: string) => void;
}) {
  const pauseMut = usePausePamSession(session.id);
  const resumeMut = useResumePamSession(session.id);
  const terminateMut = useTerminatePamSession(session.id);
  const [showReplay, setShowReplay] = useState(false);

  const live = isActive(session);

  const run = async (
    fn: () => Promise<unknown>,
    okMsg: string,
    errMsg: string,
  ) => {
    try {
      await fn();
      notifySuccess(okMsg);
      onChanged();
    } catch (err) {
      notifyError(errMsg, err);
    }
  };

  return (
    <Modal
      title={`Session · ${session.subject}`}
      onClose={onClose}
      footer={
        <>
          <button className="btn btn--ghost" onClick={onClose}>
            Close
          </button>
          <button
            className="btn btn--ghost"
            onClick={() => setShowReplay((v) => !v)}
          >
            {showReplay ? "Hide replay" : "View replay"}
          </button>
          {live && (
            <>
              {session.paused ? (
                <button
                  className="btn btn--primary"
                  disabled={!canTakeover || resumeMut.isPending}
                  title={canTakeover ? undefined : takeoverReason}
                  onClick={() =>
                    run(
                      () => resumeMut.mutateAsync(),
                      "Session resumed",
                      "Could not resume",
                    )
                  }
                >
                  Resume
                </button>
              ) : (
                <button
                  className="btn btn--primary"
                  disabled={!canTakeover || pauseMut.isPending}
                  title={canTakeover ? undefined : takeoverReason}
                  onClick={() =>
                    run(
                      () => pauseMut.mutateAsync(),
                      "Session paused",
                      "Could not pause",
                    )
                  }
                >
                  Pause
                </button>
              )}
              <button
                className="btn btn--danger"
                disabled={!canTakeover || terminateMut.isPending}
                title={canTakeover ? undefined : takeoverReason}
                onClick={() =>
                  run(
                    () => terminateMut.mutateAsync(),
                    "Session terminated",
                    "Could not terminate",
                  )
                }
              >
                Terminate
              </button>
            </>
          )}
        </>
      }
    >
      <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
        <Card title="Details">
          <dl className="kv">
            <dt>State</dt>
            <dd>
              <StatusBadge status={session.state} />
              {session.paused && (
                <Badge tone="warn" dot>
                  Paused{session.paused_by ? ` by ${session.paused_by}` : ""}
                </Badge>
              )}
            </dd>
            <dt>Protocol</dt>
            <dd>{session.protocol}</dd>
            <dt>Client</dt>
            <dd>{session.client_addr || "—"}</dd>
            <dt>Started</dt>
            <dd>{formatDateTime(session.started_at)}</dd>
            {session.ended_at && (
              <>
                <dt>Ended</dt>
                <dd>{formatDateTime(session.ended_at)}</dd>
              </>
            )}
            {session.terminated_by && (
              <>
                <dt>Terminated by</dt>
                <dd>{session.terminated_by}</dd>
              </>
            )}
          </dl>
        </Card>
        {showReplay && <ReplayPanel sessionId={session.id} />}
      </div>
    </Modal>
  );
}

// ReplayPanel fetches the recorded session frames and renders them as a
// direction-coloured transcript. Input (operator→target) and output
// (target→operator) are decoded from base64 for display.
function ReplayPanel({ sessionId }: { sessionId: string }) {
  const { data, isLoading, error, refetch } = useSessionReplay(sessionId);
  return (
    <Card
      title="Session replay"
      subtitle={data?.truncated ? "Recording truncated (size cap reached)" : undefined}
    >
      <AsyncBoundary
        isLoading={isLoading}
        error={error}
        data={data}
        onRetry={refetch}
        isEmpty={(r) => r.frames.length === 0}
        empty={<EmptyState title="No recording" description="This session has no replay yet." />}
      >
        {(r) => (
          <pre
            style={{
              maxHeight: 320,
              overflow: "auto",
              fontSize: 12,
              lineHeight: 1.5,
              margin: 0,
              whiteSpace: "pre-wrap",
              wordBreak: "break-all",
            }}
          >
            {r.frames.map((f, i) => (
              <span
                key={i}
                style={{
                  color:
                    f.direction === "input"
                      ? "var(--color-accent, #2563eb)"
                      : f.direction === "control"
                        ? "var(--color-warn, #b45309)"
                        : "inherit",
                }}
              >
                {decodeFrame(f.payload)}
              </span>
            ))}
          </pre>
        )}
      </AsyncBoundary>
    </Card>
  );
}

// decodeFrame turns a base64 payload into displayable text. A decode failure
// (binary protocol bytes) degrades to a placeholder rather than throwing.
function decodeFrame(b64: string): string {
  try {
    return atob(b64);
  } catch {
    return "·";
  }
}
