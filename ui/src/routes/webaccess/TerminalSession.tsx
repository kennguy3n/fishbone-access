// TerminalSession binds the web-SSH bridge to the xterm surface: upstream bytes
// are written into the emulator, keystrokes and resizes are sent back to the
// upstream PTY, and the governed-session chrome wraps it with the recording /
// policy banner, live latency, and lease countdown. When the session ends it
// prints a local closing line and offers a way back to the target list.

import { useCallback, useRef, useState } from "react";
import { FormattedMessage } from "react-intl";
import { SessionChrome } from "./SessionChrome";
import { Terminal, type TerminalHandle } from "./Terminal";
import { useWebSession, type StatusFrame } from "./useWebSession";

interface TerminalSessionProps {
  rawToken: string;
  onExit: () => void;
}

export function TerminalSession({ rawToken, onExit }: TerminalSessionProps) {
  const termRef = useRef<TerminalHandle>(null);
  const [status, setStatus] = useState<StatusFrame | undefined>();

  const session = useWebSession({
    kind: "ssh",
    rawToken,
    onBinary: (data) => termRef.current?.write(data),
    onReady: () => termRef.current?.focus(),
    onStatus: (s) => {
      setStatus(s);
      if (s.state === "terminated") {
        termRef.current?.writeln(
          `\r\n\u001b[31m■ Session terminated: ${s.reason ?? "ended by policy"}\u001b[0m`,
        );
      }
    },
    onError: (e) => {
      termRef.current?.writeln(`\r\n\u001b[33m! ${e.message}\u001b[0m`);
    },
  });

  const onData = useCallback(
    (d: string) => session.sendInput(d),
    [session],
  );
  const onResize = useCallback(
    (cols: number, rows: number) => session.sendResize(cols, rows),
    [session],
  );

  const ended =
    session.phase === "closed" || session.phase === "error";

  return (
    <SessionChrome
      phase={session.phase}
      ready={session.ready}
      latencyMs={session.latencyMs}
      status={status}
      closeReason={session.closeReason}
      onDisconnect={session.disconnect}
    >
      <Terminal
        ref={termRef}
        onData={onData}
        onResize={onResize}
        disabled={session.phase !== "ready"}
      />
      {ended && (
        <div className="webaccess-session__ended">
          <button className="btn btn--primary btn--sm" onClick={onExit}>
            <FormattedMessage defaultMessage="Back to targets" />
          </button>
        </div>
      )}
    </SessionChrome>
  );
}
