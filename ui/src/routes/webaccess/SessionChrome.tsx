// SessionChrome is the governance-forward frame around a live web-access
// session: it makes the "this session is recorded and policy-governed" promise
// explicit and always visible, shows the live link state (connecting / ready /
// ended) with a latency reading, counts down the lease window, and exposes the
// operator's own disconnect control. It is intentionally loud about governance
// — an SME admin should never wonder whether a privileged session is audited.

import { useEffect, useState } from "react";
import { FormattedMessage } from "react-intl";
import { Badge } from "@/components/ui";
import { Icon } from "@/components/Icon";
import type {
  ReadyInfo,
  StatusFrame,
  WebSessionPhase,
} from "./useWebSession";

interface SessionChromeProps {
  phase: WebSessionPhase;
  ready?: ReadyInfo;
  latencyMs?: number;
  status?: StatusFrame;
  closeReason?: string;
  onDisconnect: () => void;
  children: React.ReactNode;
}

/** Human label + tone for the live connection phase. */
function phaseTone(phase: WebSessionPhase): { tone: string; key: string } {
  switch (phase) {
    case "connecting":
    case "authenticating":
      return { tone: "warn", key: phase };
    case "ready":
      return { tone: "ok", key: "ready" };
    case "error":
      return { tone: "danger", key: "error" };
    default:
      return { tone: "neutral", key: "closed" };
  }
}

function PhaseLabel({ phase }: { phase: WebSessionPhase }) {
  switch (phase) {
    case "connecting":
      return (
        <FormattedMessage
          id="webaccess.phase.connecting"
          defaultMessage="Connecting"
        />
      );
    case "authenticating":
      return (
        <FormattedMessage
          id="webaccess.phase.authorizing"
          defaultMessage="Authorizing"
        />
      );
    case "ready":
      return (
        <FormattedMessage
          id="webaccess.phase.connected"
          defaultMessage="Connected"
        />
      );
    case "error":
      return (
        <FormattedMessage
          id="webaccess.phase.connectionError"
          defaultMessage="Connection error"
        />
      );
    default:
      return (
        <FormattedMessage
          id="webaccess.phase.disconnected"
          defaultMessage="Disconnected"
        />
      );
  }
}

/** Live mm:ss countdown to the lease expiry, or null when there is no window. */
function useCountdown(expiresAt?: string): string | null {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!expiresAt) return;
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, [expiresAt]);
  if (!expiresAt) return null;
  const ms = new Date(expiresAt).getTime() - now;
  if (Number.isNaN(ms)) return null;
  if (ms <= 0) return "00:00";
  const total = Math.floor(ms / 1000);
  const m = Math.floor(total / 60);
  const s = total % 60;
  return `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
}

export function SessionChrome({
  phase,
  ready,
  latencyMs,
  status,
  closeReason,
  onDisconnect,
  children,
}: SessionChromeProps) {
  const { tone } = phaseTone(phase);
  const countdown = useCountdown(ready?.leaseExpiresAt);
  const paused = status?.state === "paused";
  const terminated = status?.state === "terminated";

  return (
    <div className="webaccess-session">
      <div className="webaccess-session__bar">
        <div className="webaccess-session__identity">
          <span className={`webaccess-session__dot webaccess-session__dot--${tone}`} aria-hidden />
          <div className="webaccess-session__title">
            <strong>{ready?.targetName ?? "—"}</strong>
            <span className="muted">{ready?.targetAddress}</span>
          </div>
          {ready?.protocol && <Badge tone="info">{ready.protocol}</Badge>}
        </div>

        <div className="webaccess-session__meta">
          <span className="webaccess-session__phase">
            <PhaseLabel phase={phase} />
          </span>
          {phase === "ready" && latencyMs !== undefined && (
            <span className="webaccess-session__latency muted" title="Round-trip latency of the governed link">
              <Icon name="network" size={14} /> {latencyMs} ms
            </span>
          )}
          {countdown && (
            <span className="webaccess-session__lease muted" title="Time remaining on your lease">
              <Icon name="key" size={14} /> {countdown}
            </span>
          )}
          <button className="btn btn--sm btn--danger" onClick={onDisconnect}>
            <FormattedMessage
              id="webaccess.session.end"
              defaultMessage="End session"
            />
          </button>
        </div>
      </div>

      <div className="webaccess-session__governance" role="note">
        <Icon name="audit" size={14} />
        {ready?.recording ? (
          <FormattedMessage
            id="webaccess.session.recorded"
            defaultMessage="This session is being recorded."
          />
        ) : (
          <FormattedMessage
            id="webaccess.session.audited"
            defaultMessage="This session is audited."
          />
        )}
        {ready?.policyGoverned && (
          <FormattedMessage
            id="webaccess.session.policyGoverned"
            defaultMessage="Every command is checked against your command policy."
          />
        )}
        {ready?.subject && (
          <span className="muted">
            <FormattedMessage
              id="webaccess.session.actingAs"
              defaultMessage="Acting as {subject}"
              values={{ subject: ready.subject }}
            />
          </span>
        )}
      </div>

      {paused && (
        <div className="webaccess-session__notice webaccess-session__notice--warn" role="status">
          <FormattedMessage
            id="webaccess.session.paused"
            defaultMessage="An administrator has paused this session. Your input is held until it resumes; output stays live."
          />
        </div>
      )}
      {terminated && (
        <div className="webaccess-session__notice webaccess-session__notice--danger" role="alert">
          <FormattedMessage
            id="webaccess.session.terminated"
            defaultMessage="Session terminated: {reason}"
            values={{ reason: status?.reason || closeReason || "ended by policy" }}
          />
        </div>
      )}
      {phase === "error" && !terminated && (
        <div className="webaccess-session__notice webaccess-session__notice--danger" role="alert">
          {closeReason || (
            <FormattedMessage
              id="webaccess.session.connectFailed"
              defaultMessage="The connection could not be established."
            />
          )}
        </div>
      )}

      <div className="webaccess-session__body">{children}</div>
    </div>
  );
}
