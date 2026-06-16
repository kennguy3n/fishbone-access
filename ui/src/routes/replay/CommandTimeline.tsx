import { useMemo } from "react";
import { FormattedMessage, useIntl } from "react-intl";
import { Badge } from "@/components/ui";
import { EmptyState } from "@/components/EmptyState";
import type { CommandTimelineEntry } from "./api";
import { mmss } from "./util";

// CommandTimeline renders the session's executed statements as a clickable,
// playback-synchronized rail beside the transcript. Each row jumps the player
// to the instant the command was typed (when locatable in the keystrokes);
// policy-denied commands are highlighted so an auditor can scan straight to
// them. The row at the current playhead is marked active.
export function CommandTimeline({
  timeline,
  offsetsMs,
  posMs,
  onJump,
}: {
  timeline: CommandTimelineEntry[];
  /** Per-command ms offset (aligned to `timeline`), or null when not locatable. */
  offsetsMs: (number | null)[];
  posMs: number;
  onJump: (entry: CommandTimelineEntry, index: number) => void;
}) {
  const intl = useIntl();

  // The active command is the last one whose located offset is <= the playhead.
  const activeIndex = useMemo(() => {
    let ans = -1;
    offsetsMs.forEach((o, i) => {
      if (o != null && o <= posMs) ans = i;
    });
    return ans;
  }, [offsetsMs, posMs]);

  if (timeline.length === 0) {
    return (
      <EmptyState
        title={intl.formatMessage({ id: "replay.timeline.1", defaultMessage: "No commands" })}
        description={intl.formatMessage({ id: "replay.timeline.2",
          defaultMessage:
            "This session has no reconstructed commands. Output-only sessions still replay in the transcript.",
        })}
      />
    );
  }

  return (
    <ul
      className="replay-timeline"
      style={{ listStyle: "none", margin: 0, padding: 0 }}
      aria-label={intl.formatMessage({ id: "replay.timeline.3", defaultMessage: "Command timeline" })}
    >
      {timeline.map((entry, i) => {
        const offset = offsetsMs[i];
        const locatable = offset != null;
        const active = i === activeIndex;
        return (
          <li key={entry.seq}>
            <button
              type="button"
              className="replay-timeline__row"
              disabled={!locatable}
              aria-current={active ? "true" : undefined}
              title={
                locatable
                  ? intl.formatMessage({ id: "replay.timeline.4",
                      defaultMessage: "Jump to this command in the replay",
                    })
                  : intl.formatMessage({ id: "replay.timeline.5",
                      defaultMessage:
                        "This command could not be located in the recorded keystrokes",
                    })
              }
              onClick={() => locatable && onJump(entry, i)}
              style={{
                display: "flex",
                gap: 10,
                alignItems: "baseline",
                width: "100%",
                textAlign: "left",
                border: "none",
                borderLeft: `3px solid ${
                  entry.denied
                    ? "var(--color-danger, #dc2626)"
                    : active
                      ? "var(--color-accent, #2563eb)"
                      : "transparent"
                }`,
                background: active
                  ? "var(--surface-hover, rgba(37,99,235,0.08))"
                  : "transparent",
                padding: "8px 12px",
                cursor: locatable ? "pointer" : "default",
                opacity: locatable ? 1 : 0.55,
                font: "inherit",
              }}
            >
              <span
                className="muted"
                style={{
                  fontVariantNumeric: "tabular-nums",
                  fontSize: 12,
                  minWidth: 44,
                }}
              >
                {offset != null ? mmss(offset) : "—"}
              </span>
              <code
                style={{
                  flex: 1,
                  fontSize: 12.5,
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-word",
                }}
              >
                {entry.command || "—"}
              </code>
              {entry.denied ? (
                <Badge tone="danger">
                  <FormattedMessage id="replay.timeline.6" defaultMessage="Denied" />
                </Badge>
              ) : (
                entry.decision &&
                entry.decision !== "allow" && (
                  <Badge tone="warn">{entry.decision}</Badge>
                )
              )}
            </button>
          </li>
        );
      })}
    </ul>
  );
}
