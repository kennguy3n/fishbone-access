// Terminal renders the in-browser web-SSH PTY using xterm.js, styled to the
// Access console design tokens so it reads as part of the product rather than a
// bolted-on emulator. It is a controlled surface: incoming upstream bytes are
// written via the imperative handle, operator keystrokes are reported through
// `onData`, and viewport changes are reported through `onResize` so the parent
// can drive the upstream PTY window.

import {
  forwardRef,
  useEffect,
  useImperativeHandle,
  useRef,
} from "react";
import { Terminal as XTerm } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";

export interface TerminalHandle {
  /** Write upstream bytes to the emulator. */
  write: (data: Uint8Array) => void;
  /** Move keyboard focus into the terminal. */
  focus: () => void;
  /** Print a local status line (not sent upstream), e.g. on disconnect. */
  writeln: (line: string) => void;
}

interface TerminalProps {
  onData: (data: string) => void;
  onResize: (cols: number, rows: number) => void;
  /** Disables input echo handling once the session has ended. */
  disabled?: boolean;
}

/** Reads a CSS custom property off the document root for theme parity. */
function cssVar(name: string, fallback: string): string {
  if (typeof window === "undefined") return fallback;
  const v = getComputedStyle(document.documentElement).getPropertyValue(name);
  return v.trim() || fallback;
}

export const Terminal = forwardRef<TerminalHandle, TerminalProps>(
  function Terminal({ onData, onResize, disabled }, ref) {
    const containerRef = useRef<HTMLDivElement | null>(null);
    const termRef = useRef<XTerm | null>(null);
    const fitRef = useRef<FitAddon | null>(null);
    // Keep callbacks fresh without re-initialising the emulator.
    const onDataRef = useRef(onData);
    const onResizeRef = useRef(onResize);
    onDataRef.current = onData;
    onResizeRef.current = onResize;

    useImperativeHandle(ref, () => ({
      write: (data) => termRef.current?.write(data),
      focus: () => termRef.current?.focus(),
      writeln: (line) => termRef.current?.writeln(line),
    }));

    useEffect(() => {
      const container = containerRef.current;
      if (!container) return;

      const term = new XTerm({
        cursorBlink: true,
        convertEol: false,
        scrollback: 5000,
        fontSize: 13,
        fontFamily:
          cssVar("--mono", "'JetBrains Mono', ui-monospace, monospace"),
        theme: {
          background: cssVar("--terminal-bg", "#0a0d12"),
          foreground: cssVar("--terminal-fg", "#eef2f8"),
          cursor: cssVar("--brand", "#4d83f0"),
          cursorAccent: cssVar("--terminal-bg", "#0a0d12"),
          selectionBackground: "rgba(77, 131, 240, 0.35)",
        },
      });
      const fit = new FitAddon();
      term.loadAddon(fit);
      term.open(container);
      // The container is laid out by flexbox; fit after the first paint so the
      // addon measures the settled size.
      requestAnimationFrame(() => {
        try {
          fit.fit();
          onResizeRef.current(term.cols, term.rows);
        } catch {
          /* container not measurable yet; the ResizeObserver re-fits */
        }
      });
      term.focus();

      const dataSub = term.onData((d) => onDataRef.current(d));

      const ro = new ResizeObserver(() => {
        try {
          fit.fit();
          onResizeRef.current(term.cols, term.rows);
        } catch {
          /* ignore transient zero-size during layout */
        }
      });
      ro.observe(container);

      termRef.current = term;
      fitRef.current = fit;

      return () => {
        dataSub.dispose();
        ro.disconnect();
        term.dispose();
        termRef.current = null;
        fitRef.current = null;
      };
    }, []);

    return (
      <div
        ref={containerRef}
        className="webaccess-terminal"
        role="application"
        aria-label="Interactive SSH terminal"
        aria-disabled={disabled}
        tabIndex={-1}
      />
    );
  },
);
