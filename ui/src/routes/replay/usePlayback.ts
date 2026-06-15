// usePlayback drives the replay timeline: a normalised millisecond clock over
// the recording's frame offsets with play/pause/seek/speed. It is the single
// source of playback truth shared by the transcript pane and the command
// timeline, so clicking a command and scrubbing the bar stay in sync.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ReplayFrame } from "./api";
import { decodeBase64, frameOffsetsMs } from "./util";

export interface Playback {
  /** Current playhead position in ms from the first frame. */
  posMs: number;
  /** Whole recording span in ms. */
  totalMs: number;
  /** Index of the last frame at or before posMs (-1 before the first frame). */
  currentIndex: number;
  playing: boolean;
  /** Playback rate multiplier (1 = real time). */
  speed: number;
  offsets: number[];
  play: () => void;
  pause: () => void;
  toggle: () => void;
  /** Seek to an absolute ms position (clamped to [0, totalMs]). */
  seekMs: (ms: number) => void;
  setSpeed: (s: number) => void;
  /** Restart from the beginning, paused. */
  restart: () => void;
  /**
   * Seek to the first moment the given operator command appears in the recorded
   * INPUT keystrokes, returning true when found. This is how the command
   * timeline jumps the transcript to the instant a statement was typed.
   */
  seekToCommand: (command: string) => boolean;
}

// Real-time playback caps frame scheduling to wall-clock; long idle gaps
// between frames (operator thinking) are compressed so a 20-minute session with
// sparse activity does not force a 20-minute watch. Gaps longer than this many
// ms are clamped to it during playback advancement.
const MAX_IDLE_GAP_MS = 2500;

export function usePlayback(frames: ReplayFrame[]): Playback {
  const offsets = useMemo(() => frameOffsetsMs(frames), [frames]);
  const totalMs = offsets.length ? offsets[offsets.length - 1] : 0;

  const [posMs, setPosMs] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);

  // Cumulative input text per frame boundary, built lazily for command seek.
  const inputCumRef = useRef<{ idx: number; text: string }[] | null>(null);

  const clampMs = useCallback(
    (ms: number) => Math.min(Math.max(0, ms), totalMs),
    [totalMs],
  );

  const seekMs = useCallback((ms: number) => setPosMs(clampMs(ms)), [clampMs]);

  const play = useCallback(() => {
    setPosMs((p) => (p >= totalMs ? 0 : p));
    setPlaying(true);
  }, [totalMs]);
  const pause = useCallback(() => setPlaying(false), []);
  const toggle = useCallback(() => {
    setPlaying((v) => {
      if (!v) setPosMs((p) => (p >= totalMs ? 0 : p));
      return !v;
    });
  }, [totalMs]);
  const restart = useCallback(() => {
    setPlaying(false);
    setPosMs(0);
  }, []);

  // Advance the clock with rAF while playing. We compress long idle gaps so
  // scheduling tracks the next frame rather than real wall-clock dead time.
  const rafRef = useRef<number | null>(null);
  const lastTsRef = useRef<number | null>(null);
  useEffect(() => {
    if (!playing) {
      lastTsRef.current = null;
      if (rafRef.current != null) cancelAnimationFrame(rafRef.current);
      return;
    }
    const step = (ts: number) => {
      const last = lastTsRef.current;
      lastTsRef.current = ts;
      if (last != null) {
        const dreal = ts - last;
        setPosMs((prev) => {
          let next = prev + dreal * speed;
          // Compress the dead gap to the next frame if we're sitting in a long
          // idle stretch (no frame between prev and the clamped real advance).
          const nextOffsetIdx = offsets.findIndex((o) => o > prev);
          if (nextOffsetIdx > 0) {
            const gapStart = offsets[nextOffsetIdx - 1];
            const gapEnd = offsets[nextOffsetIdx];
            if (
              prev >= gapStart &&
              next < gapEnd &&
              gapEnd - prev > MAX_IDLE_GAP_MS
            ) {
              next = Math.min(gapEnd, prev + MAX_IDLE_GAP_MS * speed);
            }
          }
          if (next >= totalMs) {
            setPlaying(false);
            return totalMs;
          }
          return next;
        });
      }
      rafRef.current = requestAnimationFrame(step);
    };
    rafRef.current = requestAnimationFrame(step);
    return () => {
      if (rafRef.current != null) cancelAnimationFrame(rafRef.current);
    };
  }, [playing, speed, offsets, totalMs]);

  const currentIndex = useMemo(() => {
    // Last frame whose offset <= posMs.
    let lo = 0;
    let hi = offsets.length - 1;
    let ans = -1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (offsets[mid] <= posMs) {
        ans = mid;
        lo = mid + 1;
      } else {
        hi = mid - 1;
      }
    }
    return ans;
  }, [offsets, posMs]);

  const seekToCommand = useCallback(
    (command: string) => {
      const needle = command.trim();
      if (!needle) return false;
      if (!inputCumRef.current) {
        // Build cumulative input text once: for each input frame, the running
        // concatenation of decoded input up to and including it.
        const cum: { idx: number; text: string }[] = [];
        let running = "";
        frames.forEach((f, idx) => {
          if (f.direction === "input") {
            running += decodeBase64(f.payload);
            cum.push({ idx, text: running });
          }
        });
        inputCumRef.current = cum;
      }
      const hit = inputCumRef.current.find((c) => c.text.includes(needle));
      if (!hit) return false;
      seekMs(offsets[hit.idx] ?? 0);
      return true;
    },
    [frames, offsets, seekMs],
  );

  return {
    posMs,
    totalMs,
    currentIndex,
    playing,
    speed,
    offsets,
    play,
    pause,
    toggle,
    seekMs,
    setSpeed,
    restart,
    seekToCommand,
  };
}
