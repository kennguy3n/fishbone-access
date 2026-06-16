import { useEffect, useMemo, useRef } from "react";
import { FormattedMessage, useIntl } from "react-intl";
import type { ReplayFrame } from "./api";
import type { Playback } from "./usePlayback";
import { decodeBase64, mmss, stripAnsi } from "./util";

const SPEEDS = [0.5, 1, 2, 4] as const;

// ReplayPlayer renders the time-ordered transcript as a terminal-styled pane
// driven by the shared Playback clock, with transport controls (play/pause,
// restart, speed) and a seek scrubber. Operator keystrokes (input) are tinted
// with the accent colour and proxy-injected annotations (control) with the warn
// colour, so an auditor can distinguish who produced each byte. ANSI control
// sequences are stripped for legible display; the raw bytes remain what the
// SHA-256 integrity check runs over.
export function ReplayPlayer({
  frames,
  playback,
}: {
  frames: ReplayFrame[];
  playback: Playback;
}) {
  const intl = useIntl();
  const { posMs, totalMs, currentIndex, playing, speed } = playback;
  const paneRef = useRef<HTMLPreElement>(null);

  // Decode + sanitise every frame once; playback only changes how many are
  // shown, not their content.
  const decoded = useMemo(
    () =>
      frames.map((f) => ({
        direction: f.direction,
        text: stripAnsi(decodeBase64(f.payload)),
      })),
    [frames],
  );

  const visible = currentIndex < 0 ? [] : decoded.slice(0, currentIndex + 1);

  // Keep the newest output in view as playback advances.
  useEffect(() => {
    const el = paneRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [currentIndex]);

  const color = (direction: string) =>
    direction === "input"
      ? "var(--color-accent, #60a5fa)"
      : direction === "control"
        ? "var(--color-warn, #fbbf24)"
        : "inherit";

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      <pre
        ref={paneRef}
        className="replay-terminal"
        tabIndex={0}
        role="log"
        aria-label={intl.formatMessage({ id: "replay.player.1",
          defaultMessage: "Session transcript",
        })}
        style={{
          margin: 0,
          height: 420,
          overflow: "auto",
          padding: 16,
          borderRadius: 10,
          background: "#0b1020",
          color: "#e5e7eb",
          fontFamily:
            "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
          fontSize: 13,
          lineHeight: 1.55,
          whiteSpace: "pre-wrap",
          wordBreak: "break-word",
          border: "1px solid var(--border-soft, #1f2937)",
        }}
      >
        {visible.length === 0 ? (
          <span style={{ opacity: 0.6 }}>
            {intl.formatMessage({ id: "replay.player.2",
              defaultMessage: "Press play to start the replay.",
            })}
          </span>
        ) : (
          visible.map((f, i) => (
            <span key={i} style={{ color: color(f.direction) }}>
              {f.text}
            </span>
          ))
        )}
      </pre>

      {/* Transport controls */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 12,
          flexWrap: "wrap",
        }}
      >
        <button
          type="button"
          className="btn btn--primary btn--sm"
          onClick={playback.toggle}
          aria-label={
            playing
              ? intl.formatMessage({ id: "replay.player.3", defaultMessage: "Pause" })
              : intl.formatMessage({ id: "replay.player.4", defaultMessage: "Play" })
          }
        >
          {playing ? (
            <FormattedMessage id="replay.player.7" defaultMessage="Pause" />
          ) : (
            <FormattedMessage id="replay.player.8" defaultMessage="Play" />
          )}
        </button>
        <button
          type="button"
          className="btn btn--ghost btn--sm"
          onClick={playback.restart}
        >
          <FormattedMessage id="replay.player.9" defaultMessage="Restart" />
        </button>

        <input
          type="range"
          min={0}
          max={Math.max(1, Math.round(totalMs))}
          value={Math.round(posMs)}
          step={1}
          onChange={(e) => playback.seekMs(Number(e.target.value))}
          aria-label={intl.formatMessage({ id: "replay.player.5",
            defaultMessage: "Seek through the recording",
          })}
          style={{ flex: 1, minWidth: 160, cursor: "pointer" }}
        />
        <span
          className="muted"
          style={{
            fontVariantNumeric: "tabular-nums",
            fontSize: 12,
            minWidth: 92,
            textAlign: "right",
          }}
        >
          {mmss(posMs)} / {mmss(totalMs)}
        </span>

        <label
          className="field"
          style={{ flexDirection: "row", alignItems: "center", gap: 6 }}
        >
          <span className="muted" style={{ fontSize: 12 }}>
            <FormattedMessage id="replay.player.10" defaultMessage="Speed" />
          </span>
          <select
            value={speed}
            onChange={(e) => playback.setSpeed(Number(e.target.value))}
            style={{ width: "auto" }}
            aria-label={intl.formatMessage({ id: "replay.player.6",
              defaultMessage: "Playback speed",
            })}
          >
            {SPEEDS.map((s) => (
              <option key={s} value={s}>
                {s}×
              </option>
            ))}
          </select>
        </label>
      </div>
    </div>
  );
}
