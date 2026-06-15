// useWebSession drives one clientless web-access WebSocket from the browser.
//
// It owns the bridge handshake and the live connection state machine for both
// the web-SSH terminal and the web-database console: it opens the socket with
// the iam-core bearer carried as a subprotocol, sends the one-shot connect
// token in the first frame, and surfaces the governed-session description the
// bridge returns. Control frames (ready / result / error / status / pong) are
// dispatched to typed callbacks; raw terminal bytes (SSH) are delivered to
// `onBinary`. A periodic heartbeat measures the live round-trip latency of the
// governed link. See internal/webaccess for the server side of this protocol.

import { useCallback, useEffect, useRef, useState } from "react";
import {
  webAccessSocketURL,
  webAccessSubprotocols,
  type WebAccessKind,
} from "@/api/access";

/** Lifecycle of the governed link, as the UI renders it. */
export type WebSessionPhase =
  | "connecting"
  | "authenticating"
  | "ready"
  | "closed"
  | "error";

/** The governed-session description the bridge sends once the link is live. */
export interface ReadyInfo {
  sessionId: string;
  protocol: string;
  targetName: string;
  targetAddress: string;
  subject: string;
  recording: boolean;
  policyGoverned: boolean;
  leaseExpiresAt?: string;
}

/** A database result frame (SELECT rows or a write summary). */
export interface ResultFrame {
  columns: { name: string; type?: string }[];
  rows: (string | null)[][];
  command?: string;
  rowsAffected: number;
  elapsedMs: number;
  truncated: boolean;
}

/** A non-fatal operator-facing error (policy deny or upstream/query error). */
export interface ErrorFrame {
  message: string;
  denied: boolean;
}

/** A session lifecycle transition (paused / resumed / closed / terminated). */
export interface StatusFrame {
  state: string;
  reason?: string;
}

export interface WebSessionCallbacks {
  /** Raw terminal output bytes (web-SSH only). */
  onBinary?: (data: Uint8Array) => void;
  onReady?: (info: ReadyInfo) => void;
  onResult?: (result: ResultFrame) => void;
  onError?: (err: ErrorFrame) => void;
  onStatus?: (status: StatusFrame) => void;
}

export interface WebSessionOptions extends WebSessionCallbacks {
  kind: WebAccessKind;
  /** The one-shot raw PAM connect token presented in the first frame. */
  rawToken: string;
  /** Initial terminal dimensions for SSH (ignored for DB). */
  cols?: number;
  rows?: number;
}

const HEARTBEAT_MS = 4000;

/** Heartbeat-derived RTT of the governed link, plus the live phase. */
export interface WebSessionState {
  phase: WebSessionPhase;
  ready?: ReadyInfo;
  /** Last fatal/disconnect message, when phase is "error" or "closed". */
  closeReason?: string;
  /** Live round-trip latency in milliseconds, once a heartbeat round-trips. */
  latencyMs?: number;
}

export interface WebSession extends WebSessionState {
  /** Send raw keystroke bytes to the upstream shell (web-SSH). */
  sendInput: (data: Uint8Array | string) => void;
  /** Push a terminal resize to the upstream PTY (web-SSH). */
  sendResize: (cols: number, rows: number) => void;
  /** Submit a statement to the database console (web-DB). */
  sendQuery: (sql: string) => void;
  /** Close the link from the operator side. */
  disconnect: () => void;
}

/**
 * useWebSession connects exactly once for the life of the component (the page
 * mounts a fresh session component per launch, so identity is positional). It
 * tears the socket down on unmount, so navigating away or closing the session
 * panel ends the governed session cleanly.
 */
export function useWebSession(options: WebSessionOptions): WebSession {
  const { kind, rawToken, cols, rows } = options;

  // Keep the latest callbacks in a ref so the connect effect can stay
  // dependency-stable (it must run once) without going stale.
  const cbRef = useRef<WebSessionCallbacks>(options);
  cbRef.current = options;

  const wsRef = useRef<WebSocket | null>(null);
  const [state, setState] = useState<WebSessionState>({ phase: "connecting" });

  const send = useCallback((value: unknown) => {
    const ws = wsRef.current;
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(value));
    }
  }, []);

  const sendInput = useCallback((data: Uint8Array | string) => {
    const ws = wsRef.current;
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    ws.send(typeof data === "string" ? new TextEncoder().encode(data) : data);
  }, []);

  const sendResize = useCallback(
    (c: number, r: number) => send({ type: "resize", cols: c, rows: r }),
    [send],
  );

  const sendQuery = useCallback(
    (sql: string) => send({ type: "query", sql }),
    [send],
  );

  const disconnect = useCallback(() => {
    wsRef.current?.close();
  }, []);

  useEffect(() => {
    let closed = false;
    let heartbeat: ReturnType<typeof setInterval> | undefined;
    const ws = new WebSocket(webAccessSocketURL(kind), webAccessSubprotocols());
    ws.binaryType = "arraybuffer";
    wsRef.current = ws;
    setState({ phase: "connecting" });

    ws.onopen = () => {
      setState((s) => ({ ...s, phase: "authenticating" }));
      ws.send(
        JSON.stringify({
          type: "hello",
          token: rawToken,
          ...(kind === "ssh" ? { cols: cols ?? 80, rows: rows ?? 24 } : {}),
        }),
      );
      heartbeat = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: "ping", ts: Math.round(performance.now()) }));
        }
      }, HEARTBEAT_MS);
    };

    ws.onmessage = (ev: MessageEvent) => {
      if (typeof ev.data !== "string") {
        cbRef.current.onBinary?.(new Uint8Array(ev.data as ArrayBuffer));
        return;
      }
      let msg: Record<string, unknown>;
      try {
        msg = JSON.parse(ev.data);
      } catch {
        return;
      }
      switch (msg.type) {
        case "ready": {
          const info: ReadyInfo = {
            sessionId: String(msg.session_id ?? ""),
            protocol: String(msg.protocol ?? ""),
            targetName: String(msg.target_name ?? ""),
            targetAddress: String(msg.target_address ?? ""),
            subject: String(msg.subject ?? ""),
            recording: Boolean(msg.recording),
            policyGoverned: Boolean(msg.policy_governed),
            leaseExpiresAt: msg.lease_expires_at
              ? String(msg.lease_expires_at)
              : undefined,
          };
          setState((s) => ({ ...s, phase: "ready", ready: info }));
          cbRef.current.onReady?.(info);
          break;
        }
        case "result": {
          const result: ResultFrame = {
            columns: Array.isArray(msg.columns)
              ? (msg.columns as { name: string; type?: string }[])
              : [],
            rows: Array.isArray(msg.rows) ? (msg.rows as (string | null)[][]) : [],
            command: msg.command ? String(msg.command) : undefined,
            rowsAffected: Number(msg.rows_affected ?? 0),
            elapsedMs: Number(msg.elapsed_ms ?? 0),
            truncated: Boolean(msg.truncated),
          };
          cbRef.current.onResult?.(result);
          break;
        }
        case "error":
          cbRef.current.onError?.({
            message: String(msg.message ?? "Error"),
            denied: Boolean(msg.denied),
          });
          break;
        case "status": {
          const status: StatusFrame = {
            state: String(msg.state ?? ""),
            reason: msg.reason ? String(msg.reason) : undefined,
          };
          cbRef.current.onStatus?.(status);
          if (status.state === "terminated" || status.state === "closed") {
            setState((s) => ({ ...s, closeReason: status.reason }));
          }
          break;
        }
        case "pong": {
          const ts = Number(msg.ts ?? 0);
          const rtt = Math.max(0, Math.round(performance.now() - ts));
          setState((s) => ({ ...s, latencyMs: rtt }));
          break;
        }
      }
    };

    ws.onerror = () => {
      if (closed) return;
      setState((s) =>
        s.phase === "ready"
          ? s
          : { ...s, phase: "error", closeReason: "Connection failed" },
      );
    };

    ws.onclose = (ev: CloseEvent) => {
      closed = true;
      if (heartbeat) clearInterval(heartbeat);
      setState((s) => ({
        ...s,
        phase: s.phase === "error" ? "error" : "closed",
        closeReason:
          s.closeReason ??
          (ev.reason || (s.phase === "ready" ? undefined : "Connection closed")),
      }));
    };

    return () => {
      closed = true;
      if (heartbeat) clearInterval(heartbeat);
      ws.onopen = ws.onmessage = ws.onerror = ws.onclose = null;
      if (
        ws.readyState === WebSocket.OPEN ||
        ws.readyState === WebSocket.CONNECTING
      ) {
        ws.close();
      }
      wsRef.current = null;
    };
    // Connect once per mount; rawToken/kind identify a single launch and never
    // change for a mounted session component.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return { ...state, sendInput, sendResize, sendQuery, disconnect };
}
