// DbConsole is the interactive web-database query surface: an operator types a
// statement, presses Run (or Ctrl/Cmd+Enter), and each statement is appended to
// a transcript with a clean result grid, a write summary, or a policy-deny /
// error banner. Every statement is gated and audited server-side; this surface
// only renders what the bridge streams back.

import { useEffect, useRef, useState } from "react";
import { FormattedMessage, useIntl } from "react-intl";
import { Badge } from "@/components/ui";
import type { ResultFrame, ErrorFrame } from "./useWebSession";

/** One statement in the console transcript and its server outcome. */
export interface ConsoleEntry {
  id: number;
  sql: string;
  status: "running" | "ok" | "error" | "denied";
  result?: ResultFrame;
  error?: ErrorFrame;
}

interface DbConsoleProps {
  entries: ConsoleEntry[];
  onRun: (sql: string) => void;
  /** True while the link is not ready or has ended (input disabled). */
  disabled?: boolean;
}

export function DbConsole({ entries, onRun, disabled }: DbConsoleProps) {
  const intl = useIntl();
  const [sql, setSql] = useState("");
  const transcriptRef = useRef<HTMLDivElement | null>(null);

  // Keep the newest statement in view as the transcript grows.
  useEffect(() => {
    const el = transcriptRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [entries]);

  const run = () => {
    const trimmed = sql.trim();
    if (!trimmed || disabled) return;
    onRun(trimmed);
    setSql("");
  };

  const onKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
      e.preventDefault();
      run();
    }
  };

  return (
    <div className="webaccess-db">
      <div className="webaccess-db__transcript" ref={transcriptRef}>
        {entries.length === 0 ? (
          <div className="webaccess-db__hint">
            <FormattedMessage defaultMessage="Type a SQL statement below and press Run. Each statement is checked against your command policy and recorded before it executes." />
          </div>
        ) : (
          entries.map((entry) => <TranscriptItem key={entry.id} entry={entry} />)
        )}
      </div>

      <div className="webaccess-db__composer">
        <textarea
          className="webaccess-db__input"
          value={sql}
          spellCheck={false}
          disabled={disabled}
          placeholder={intl.formatMessage({
            defaultMessage: "SELECT * FROM …",
          })}
          aria-label={intl.formatMessage({ defaultMessage: "SQL statement" })}
          onChange={(e) => setSql(e.target.value)}
          onKeyDown={onKeyDown}
          rows={3}
        />
        <div className="webaccess-db__composer-actions">
          <span className="muted webaccess-db__kbd-hint">
            <FormattedMessage defaultMessage="Ctrl / ⌘ + Enter to run" />
          </span>
          <button
            className="btn btn--primary btn--sm"
            onClick={run}
            disabled={disabled || sql.trim() === ""}
          >
            <FormattedMessage defaultMessage="Run" />
          </button>
        </div>
      </div>
    </div>
  );
}

function TranscriptItem({ entry }: { entry: ConsoleEntry }) {
  return (
    <div className="webaccess-db__entry">
      <div className="webaccess-db__sql">
        <span className="webaccess-db__prompt" aria-hidden>
          ›
        </span>
        <code>{entry.sql}</code>
      </div>
      {entry.status === "running" && (
        <div className="muted webaccess-db__running">
          <FormattedMessage defaultMessage="Running…" />
        </div>
      )}
      {entry.status === "denied" && entry.error && (
        <div className="webaccess-db__deny">
          <Badge tone="danger">
            <FormattedMessage defaultMessage="Policy denied" />
          </Badge>
          <span>{entry.error.message}</span>
        </div>
      )}
      {entry.status === "error" && entry.error && (
        <div className="webaccess-db__error">
          <Badge tone="warn">
            <FormattedMessage defaultMessage="Error" />
          </Badge>
          <span>{entry.error.message}</span>
        </div>
      )}
      {entry.status === "ok" && entry.result && (
        <ResultView result={entry.result} />
      )}
    </div>
  );
}

function ResultView({ result }: { result: ResultFrame }) {
  const hasRows = result.columns.length > 0;

  if (!hasRows) {
    // A write / DDL statement: show the command tag and affected-row count.
    return (
      <div className="webaccess-db__summary">
        <Badge tone="ok">{result.command || "OK"}</Badge>
        <span className="muted">
          <FormattedMessage
            defaultMessage="{n, plural, one {# row} other {# rows}} affected · {ms} ms"
            values={{ n: result.rowsAffected, ms: result.elapsedMs }}
          />
        </span>
      </div>
    );
  }

  return (
    <div className="webaccess-db__result">
      <div className="webaccess-db__grid-wrap">
        <table className="webaccess-db__grid">
          <thead>
            <tr>
              <th className="webaccess-db__rownum" aria-hidden />
              {result.columns.map((c, i) => (
                <th key={i} scope="col">
                  <span className="webaccess-db__col-name">{c.name}</span>
                  {c.type && (
                    <span className="webaccess-db__col-type">{c.type}</span>
                  )}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {result.rows.map((row, ri) => (
              <tr key={ri}>
                <td className="webaccess-db__rownum">{ri + 1}</td>
                {row.map((cell, ci) => (
                  <td key={ci}>
                    {cell === null ? (
                      <span className="webaccess-db__null">NULL</span>
                    ) : (
                      cell
                    )}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="webaccess-db__result-meta muted">
        <FormattedMessage
          defaultMessage="{n, plural, one {# row} other {# rows}} · {ms} ms"
          values={{ n: result.rows.length, ms: result.elapsedMs }}
        />
        {result.truncated && (
          <Badge tone="warn">
            <FormattedMessage defaultMessage="Truncated to row cap" />
          </Badge>
        )}
      </div>
    </div>
  );
}
