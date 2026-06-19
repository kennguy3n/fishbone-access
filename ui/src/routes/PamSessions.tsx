import { useId, useMemo, useState } from "react";
import { FormattedMessage, useIntl } from "react-intl";
import { PageHeader, Badge, StatusBadge, AsyncBoundary, Card } from "@/components/ui";
import { DataTable, type Column } from "@/components/DataTable";
import { EmptyState, EmptyIllustration } from "@/components/EmptyState";
import { Modal } from "@/components/Modal";
import { useToast } from "@/components/Toast";
import { ReplayLaunch } from "@/components/ReplayLaunch";
import {
  usePamSessions,
  useSessionReplay,
  usePausePamSession,
  useResumePamSession,
  useTerminatePamSession,
  useMe,
  useMyPermissions,
  type PamSession,
  ApiError,
} from "@/api/access";
import { formatDateTime, formatRelative } from "@/lib/format";

// TAKEOVER_PERMISSION gates the high-risk live-control actions. The server
// enforces RequirePermission("pam.takeover") + step-up MFA regardless
// (fail-closed); the UI mirrors the gate so an unauthorized operator sees
// disabled controls with a reason instead of a 403 surprise.
const TAKEOVER_PERMISSION = "pam.takeover";

function isActive(s: PamSession): boolean {
  return s.state === "active";
}

export function PamSessions() {
  const intl = useIntl();
  const toast = useToast();
  const me = useMe();
  const { data: myPerms } = useMyPermissions();
  const [activeOnly, setActiveOnly] = useState(true);
  // Live console: poll so pause/terminate from another operator and new
  // sessions surface without a manual refresh.
  const { data, isLoading, error, refetch } = usePamSessions(
    { active_only: activeOnly },
    { refetchInterval: 5000 },
  );
  const [detail, setDetail] = useState<PamSession | null>(null);
  const denyNoteId = useId();

  // Gate against the server's RBAC-resolved permission set (the exact set
  // RequirePermission enforces), not the JWT scopes/roles which no longer drive
  // RBAC. undefined = still loading or the RBAC tier isn't mounted (server gate
  // then no-ops) → treat as allowed so an authorized operator never sees a
  // false-negative disabled control; the server stays the authority either way.
  const hasTakeoverPerm =
    myPerms === undefined
      ? true
      : myPerms.permissions.includes(TAKEOVER_PERMISSION);

  const canTakeover = hasTakeoverPerm && !!me.data?.mfa_satisfied;

  // Plain-language explanation of why live-control is unavailable, with the
  // remedy — never a raw permission token or status code.
  const takeoverReason = useMemo(() => {
    if (!hasTakeoverPerm)
      return intl.formatMessage({
        id: "pam.sessions.denyPerm",
        defaultMessage:
          "You don't have permission to control live sessions. Ask a workspace owner to grant you privileged-session control.",
      });
    if (!me.data?.mfa_satisfied)
      return intl.formatMessage({
        id: "pam.sessions.denyMfa",
        defaultMessage:
          "Re-verify with step-up MFA to pause, resume, or terminate live sessions.",
      });
    return "";
  }, [me.data, hasTakeoverPerm, intl]);

  const columns: Column<PamSession>[] = [
    {
      header: intl.formatMessage({ id: "pam.sessions.colSession", defaultMessage: "Session" }),
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
      header: intl.formatMessage({ id: "pam.sessions.colState", defaultMessage: "State" }),
      cell: (s) => (
        <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
          <StatusBadge status={s.state} />
          {s.paused && (
            <Badge tone="warn">
              <FormattedMessage id="pam.sessions.paused" defaultMessage="Paused" />
            </Badge>
          )}
        </div>
      ),
    },
    {
      header: intl.formatMessage({ id: "pam.sessions.colStarted", defaultMessage: "Started" }),
      cell: (s) => <span className="muted">{formatRelative(s.started_at)}</span>,
    },
    {
      header: intl.formatMessage({ id: "pam.sessions.colEnded", defaultMessage: "Ended" }),
      cell: (s) =>
        s.ended_at ? (
          <span className="muted">{formatRelative(s.ended_at)}</span>
        ) : (
          <Badge tone="ok" dot>
            <FormattedMessage id="pam.sessions.live" defaultMessage="Live" />
          </Badge>
        ),
    },
  ];

  return (
    <>
      <PageHeader
        title={intl.formatMessage({ id: "pam.sessions.title", defaultMessage: "Live sessions" })}
        subtitle={intl.formatMessage({
          id: "pam.sessions.subtitle",
          defaultMessage:
            "Privileged sessions brokered through the gateway, live and after they end. Authorized operators can pause, resume, or terminate a live session, and every session is recorded for tamper-evident replay.",
        })}
        actions={
          <label className="checkbox-inline">
            <input
              type="checkbox"
              checked={activeOnly}
              style={{ width: "auto" }}
              onChange={(e) => setActiveOnly(e.target.checked)}
            />
            <span>
              <FormattedMessage id="pam.sessions.activeOnly" defaultMessage="Show live only" />
            </span>
          </label>
        }
      />
      {!canTakeover && takeoverReason && (
        <p className="callout callout--info" id={denyNoteId} style={{ marginBottom: 16 }}>
          <FormattedMessage
            id="pam.sessions.denyIntro"
            defaultMessage="Live-session control is read-only for you right now."
          />{" "}
          {takeoverReason}
        </p>
      )}
      <AsyncBoundary
        isLoading={isLoading}
        error={error}
        data={data}
        onRetry={refetch}
        isEmpty={(rows) => rows.length === 0}
        empty={
          <EmptyState
            illustration={<EmptyIllustration kind="search" />}
            title={
              activeOnly
                ? intl.formatMessage({
                    id: "pam.sessions.emptyTitleLive",
                    defaultMessage: "No live sessions right now",
                  })
                : intl.formatMessage({
                    id: "pam.sessions.emptyTitleAll",
                    defaultMessage: "No sessions yet",
                  })
            }
            description={intl.formatMessage({
              id: "pam.sessions.emptyBody",
              defaultMessage:
                "Privileged sessions opened against a target through an approved lease appear here in real time, and stay available for full replay after they end.",
            })}
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
  const intl = useIntl();
  const pauseMut = usePausePamSession(session.id);
  const resumeMut = useResumePamSession(session.id);
  const terminateMut = useTerminatePamSession(session.id);
  const [showReplay, setShowReplay] = useState(false);
  const denyNoteId = useId();

  const live = isActive(session);
  const showDenyNote = live && !canTakeover && !!takeoverReason;

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
      title={intl.formatMessage(
        { id: "pam.sessions.detailTitle", defaultMessage: "Session · {subject}" },
        { subject: session.subject },
      )}
      onClose={onClose}
      footer={
        <>
          <button className="btn btn--ghost" onClick={onClose}>
            <FormattedMessage id="pam.sessions.close" defaultMessage="Close" />
          </button>
          <button
            className="btn btn--ghost"
            onClick={() => setShowReplay((v) => !v)}
          >
            {showReplay ? (
              <FormattedMessage id="pam.sessions.hideReplay" defaultMessage="Hide replay" />
            ) : (
              <FormattedMessage id="pam.sessions.viewReplay" defaultMessage="View replay" />
            )}
          </button>
          <ReplayLaunch sessionId={session.id} />
          {live && (
            <>
              {session.paused ? (
                <button
                  className="btn btn--primary"
                  disabled={!canTakeover || resumeMut.isPending}
                  title={canTakeover ? undefined : takeoverReason}
                  aria-describedby={showDenyNote ? denyNoteId : undefined}
                  onClick={() =>
                    run(
                      () => resumeMut.mutateAsync(),
                      intl.formatMessage({ id: "pam.sessions.toastResumed", defaultMessage: "Session resumed" }),
                      intl.formatMessage({ id: "pam.sessions.toastResumeErr", defaultMessage: "Could not resume the session" }),
                    )
                  }
                >
                  <FormattedMessage id="pam.sessions.resume" defaultMessage="Resume" />
                </button>
              ) : (
                <button
                  className="btn btn--primary"
                  disabled={!canTakeover || pauseMut.isPending}
                  title={canTakeover ? undefined : takeoverReason}
                  aria-describedby={showDenyNote ? denyNoteId : undefined}
                  onClick={() =>
                    run(
                      () => pauseMut.mutateAsync(),
                      intl.formatMessage({ id: "pam.sessions.toastPaused", defaultMessage: "Session paused" }),
                      intl.formatMessage({ id: "pam.sessions.toastPauseErr", defaultMessage: "Could not pause the session" }),
                    )
                  }
                >
                  <FormattedMessage id="pam.sessions.pause" defaultMessage="Pause" />
                </button>
              )}
              <button
                className="btn btn--danger"
                disabled={!canTakeover || terminateMut.isPending}
                title={canTakeover ? undefined : takeoverReason}
                aria-describedby={showDenyNote ? denyNoteId : undefined}
                onClick={() =>
                  run(
                    () => terminateMut.mutateAsync(),
                    intl.formatMessage({ id: "pam.sessions.toastTerminated", defaultMessage: "Session terminated" }),
                    intl.formatMessage({ id: "pam.sessions.toastTerminateErr", defaultMessage: "Could not terminate the session" }),
                  )
                }
              >
                <FormattedMessage id="pam.sessions.terminate" defaultMessage="Terminate" />
              </button>
            </>
          )}
        </>
      }
    >
      <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
        {showDenyNote && (
          <p className="callout callout--info" id={denyNoteId}>
            {takeoverReason}
          </p>
        )}
        <Card title={intl.formatMessage({ id: "pam.sessions.detailsCard", defaultMessage: "Details" })}>
          <dl className="kv">
            <dt>
              <FormattedMessage id="pam.sessions.state" defaultMessage="State" />
            </dt>
            <dd>
              <StatusBadge status={session.state} />
              {session.paused && (
                <Badge tone="warn" dot>
                  <FormattedMessage id="pam.sessions.paused" defaultMessage="Paused" />
                  {session.paused_by
                    ? ` ${intl.formatMessage({ id: "pam.sessions.pausedBy", defaultMessage: "by {who}" }, { who: session.paused_by })}`
                    : ""}
                </Badge>
              )}
            </dd>
            <dt>
              <FormattedMessage id="pam.sessions.protocol" defaultMessage="Protocol" />
            </dt>
            <dd>{session.protocol}</dd>
            <dt>
              <FormattedMessage id="pam.sessions.client" defaultMessage="Client address" />
            </dt>
            <dd>{session.client_addr || "—"}</dd>
            <dt>
              <FormattedMessage id="pam.sessions.started" defaultMessage="Started" />
            </dt>
            <dd>{formatDateTime(session.started_at)}</dd>
            {session.ended_at && (
              <>
                <dt>
                  <FormattedMessage id="pam.sessions.ended" defaultMessage="Ended" />
                </dt>
                <dd>{formatDateTime(session.ended_at)}</dd>
              </>
            )}
            {session.terminated_by && (
              <>
                <dt>
                  <FormattedMessage id="pam.sessions.terminatedBy" defaultMessage="Terminated by" />
                </dt>
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
// terminal-styled, direction-coloured transcript. Input (operator→target),
// control (proxy) and output (target→operator) are decoded from base64; a
// legend reinforces the colour cue with a label (WCAG 1.4.1).
function ReplayPanel({ sessionId }: { sessionId: string }) {
  const intl = useIntl();
  const { data, isLoading, error, refetch } = useSessionReplay(sessionId);
  const legend = [
    { color: "var(--accent)", label: intl.formatMessage({ id: "pam.sessions.legendInput", defaultMessage: "Operator input" }) },
    { color: "var(--warn-alt)", label: intl.formatMessage({ id: "pam.sessions.legendControl", defaultMessage: "Proxy control" }) },
    { color: "var(--terminal-fg)", label: intl.formatMessage({ id: "pam.sessions.legendOutput", defaultMessage: "Target output" }) },
  ];
  return (
    <Card
      title={intl.formatMessage({ id: "pam.sessions.replayCard", defaultMessage: "Session replay" })}
      subtitle={
        data?.truncated
          ? intl.formatMessage({
              id: "pam.sessions.replayTruncated",
              defaultMessage: "Recording truncated — it reached the size cap, so later activity isn't shown.",
            })
          : undefined
      }
    >
      <AsyncBoundary
        isLoading={isLoading}
        error={error}
        data={data}
        onRetry={refetch}
        isEmpty={(r) => r.frames.length === 0}
        empty={
          <EmptyState
            title={intl.formatMessage({ id: "pam.sessions.replayEmptyTitle", defaultMessage: "No recording yet" })}
            description={intl.formatMessage({
              id: "pam.sessions.replayEmptyBody",
              defaultMessage: "This session hasn't produced any recorded activity to replay.",
            })}
          />
        }
      >
        {(r) => (
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            <pre
              aria-label={intl.formatMessage({ id: "pam.sessions.replayAria", defaultMessage: "Session transcript" })}
              style={{
                maxHeight: 320,
                overflow: "auto",
                fontSize: 12,
                lineHeight: 1.5,
                margin: 0,
                padding: 12,
                whiteSpace: "pre-wrap",
                wordBreak: "break-all",
                background: "var(--terminal-bg)",
                color: "var(--terminal-fg)",
                fontFamily: "var(--mono)",
                borderRadius: "var(--radius)",
                border: "1px solid var(--border-soft)",
              }}
            >
              {r.frames.map((f, i) => (
                <span
                  key={i}
                  style={{
                    color:
                      f.direction === "input"
                        ? "var(--accent)"
                        : f.direction === "control"
                          ? "var(--warn-alt)"
                          : "var(--terminal-fg)",
                  }}
                >
                  {decodeFrame(f.payload)}
                </span>
              ))}
            </pre>
            <div
              className="muted"
              style={{ display: "flex", gap: 16, flexWrap: "wrap", fontSize: 12, alignItems: "center" }}
            >
              {legend.map((item) => (
                <span key={item.label} style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
                  <span
                    aria-hidden="true"
                    style={{
                      width: 10,
                      height: 10,
                      borderRadius: "var(--radius-xs)",
                      background: item.color,
                      flex: "none",
                    }}
                  />
                  {item.label}
                </span>
              ))}
            </div>
          </div>
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
