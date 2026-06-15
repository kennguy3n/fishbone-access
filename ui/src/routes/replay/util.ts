// Shared decoding/formatting helpers for the replay player. Kept separate so
// the player component stays focused on playback state and the helpers can be
// unit-reasoned about in isolation.

import type { ReplayFrame } from "./api";

// decodeBase64 turns a base64 frame payload into a UTF-8 string. atob yields a
// binary (latin1) string; we widen it back to bytes and decode as UTF-8 so
// multibyte output (accents, box-drawing, CJK) renders correctly. A malformed
// payload degrades to an empty string rather than throwing mid-playback.
export function decodeBase64(b64: string): string {
  try {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i += 1) bytes[i] = bin.charCodeAt(i);
    return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  } catch {
    return "";
  }
}

// ANSI/control-sequence stripper. Terminal recordings are littered with CSI
// escape codes (colour, cursor moves, clears); rendering them verbatim in a
// styled transcript would show garbage. We strip the common families and keep
// printable text + newlines/tabs so the transcript reads cleanly. This is a
// pragmatic display transform — the raw bytes remain available via the API and
// are what the SHA-256 integrity check runs over.
// eslint-disable-next-line no-control-regex
const ANSI_CSI = /\u001b\[[0-9;?]*[ -/]*[@-~]/g;
// eslint-disable-next-line no-control-regex
const ANSI_OSC = /\u001b\][^\u0007\u001b]*(?:\u0007|\u001b\\)/g;
// eslint-disable-next-line no-control-regex
const ANSI_SINGLE = /\u001b[@-Z\\-_]/g;
// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g;

export function stripAnsi(s: string): string {
  return s
    .replace(ANSI_OSC, "")
    .replace(ANSI_CSI, "")
    .replace(ANSI_SINGLE, "")
    .replace(/\r\n/g, "\n")
    .replace(/\r/g, "\n")
    .replace(CONTROL_CHARS, "");
}

// frameOffsetsMs computes each frame's millisecond offset from the first frame,
// so playback can schedule frames on a normalised timeline regardless of the
// absolute capture wall-clock. Returns offsets aligned 1:1 with frames.
export function frameOffsetsMs(frames: ReplayFrame[]): number[] {
  if (frames.length === 0) return [];
  const t0 = new Date(frames[0].at).getTime();
  return frames.map((f) => {
    const t = new Date(f.at).getTime();
    const d = Number.isNaN(t) ? 0 : t - t0;
    return d < 0 ? 0 : d;
  });
}

// formatDurationMs renders a millisecond span as a compact h/m/s clock
// (e.g. 1h 02m, 3m 05s, 12.4s, 420ms) for the player scrubber + metadata.
export function formatDurationMs(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return "—";
  if (ms < 1000) return `${Math.round(ms)}ms`;
  const totalSec = ms / 1000;
  if (totalSec < 60) return `${totalSec.toFixed(1)}s`;
  const sec = Math.floor(totalSec % 60);
  const totalMin = Math.floor(totalSec / 60);
  if (totalMin < 60) return `${totalMin}m ${String(sec).padStart(2, "0")}s`;
  const min = totalMin % 60;
  const hr = Math.floor(totalMin / 60);
  return `${hr}h ${String(min).padStart(2, "0")}m`;
}

// formatBytes renders a byte count as B/KB/MB for the metadata panel.
export function formatBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

// computeCommandOffsets maps each command string to the ms offset at which it
// first appears in the recorded INPUT keystrokes (or null when it can't be
// located — e.g. a DB statement that wasn't reconstructable from raw frames).
// The command timeline uses this to jump the transcript to a statement and to
// highlight which command is "active" at the current playhead. Offsets are
// returned aligned 1:1 with the input `commands`.
export function computeCommandOffsets(
  frames: ReplayFrame[],
  offsets: number[],
  commands: string[],
): (number | null)[] {
  // Running concatenation of decoded input text, with the frame index each
  // character boundary belongs to — so we can resolve a match to a frame time.
  const segments: { idx: number; text: string }[] = [];
  let running = "";
  frames.forEach((f, idx) => {
    if (f.direction === "input") {
      running += decodeBase64(f.payload);
      segments.push({ idx, text: running });
    }
  });
  let searchFrom = 0;
  return commands.map((cmd) => {
    const needle = cmd.trim();
    if (!needle) return null;
    // Search forward from the previous match so repeated commands resolve to
    // successive occurrences rather than all collapsing onto the first.
    const seg = segments.find(
      (s, i) => i >= searchFrom && s.text.includes(needle),
    );
    if (!seg) return null;
    searchFrom = segments.indexOf(seg) + 1;
    return offsets[seg.idx] ?? null;
  });
}

// mmss renders an elapsed-ms value as m:ss for the scrubber time labels.
export function mmss(ms: number): string {
  const totalSec = Math.max(0, Math.floor(ms / 1000));
  const sec = totalSec % 60;
  const min = Math.floor(totalSec / 60);
  return `${min}:${String(sec).padStart(2, "0")}`;
}
