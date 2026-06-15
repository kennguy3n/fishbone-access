// DbSession binds the web-database bridge to the query console: statements are
// sent to the bridge, and result / error frames are correlated back to the
// statement that produced them (the bridge answers serially, so a FIFO match is
// exact) and rendered in the transcript. The governed-session chrome wraps it
// with the recording / policy banner, live latency, and lease countdown.

import { useCallback, useRef, useState } from "react";
import { FormattedMessage } from "react-intl";
import { SessionChrome } from "./SessionChrome";
import { DbConsole, type ConsoleEntry } from "./DbConsole";
import { useWebSession, type StatusFrame } from "./useWebSession";

interface DbSessionProps {
  rawToken: string;
  onExit: () => void;
}

export function DbSession({ rawToken, onExit }: DbSessionProps) {
  const [entries, setEntries] = useState<ConsoleEntry[]>([]);
  const [status, setStatus] = useState<StatusFrame | undefined>();
  const nextId = useRef(1);

  // Resolve the oldest still-running statement with the given mutation, since
  // the bridge replies to statements strictly in order.
  const resolveOldest = useCallback(
    (mut: (e: ConsoleEntry) => ConsoleEntry) => {
      setEntries((prev) => {
        const idx = prev.findIndex((e) => e.status === "running");
        if (idx === -1) return prev;
        const copy = prev.slice();
        copy[idx] = mut(copy[idx]);
        return copy;
      });
    },
    [],
  );

  const session = useWebSession({
    kind: "db",
    rawToken,
    onResult: (result) =>
      resolveOldest((e) => ({ ...e, status: "ok", result })),
    onError: (error) =>
      resolveOldest((e) => ({
        ...e,
        status: error.denied ? "denied" : "error",
        error,
      })),
    onStatus: setStatus,
  });

  const onRun = useCallback(
    (sql: string) => {
      const id = nextId.current++;
      setEntries((prev) => [...prev, { id, sql, status: "running" }]);
      session.sendQuery(sql);
    },
    [session],
  );

  const ended = session.phase === "closed" || session.phase === "error";

  return (
    <SessionChrome
      phase={session.phase}
      ready={session.ready}
      latencyMs={session.latencyMs}
      status={status}
      closeReason={session.closeReason}
      onDisconnect={session.disconnect}
    >
      <DbConsole entries={entries} onRun={onRun} disabled={session.phase !== "ready"} />
      {ended && (
        <div className="webaccess-session__ended">
          <button className="btn btn--primary btn--sm" onClick={onExit}>
            <FormattedMessage
              id="webaccess.backToTargets"
              defaultMessage="Back to targets"
            />
          </button>
        </div>
      )}
    </SessionChrome>
  );
}
