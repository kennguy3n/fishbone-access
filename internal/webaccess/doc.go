// Package webaccess is the clientless browser-access bridge: it terminates an
// in-browser web-SSH terminal or web database console on a WebSocket served by
// ztna-api and splices it onto a governed privileged session, so an operator
// opens a real interactive shell or SQL session to a target with nothing
// installed but a browser.
//
// The bridge is deliberately a thin new FRONT-END onto the existing PAM
// machinery, not a parallel access path. It reuses the same services the native
// pam-gateway proxies use, so a browser session can never be less governed than
// a native one:
//
//   - Authorisation is a one-shot PAM connect token. The browser mints the
//     token through the authenticated REST surface (iam-core bearer + step-up
//     MFA where the target requires it, validated by the broker at mint time),
//     then presents it as the first WebSocket frame. The bridge redeems it via
//     pam.Broker.RedeemConnectToken, which re-validates the JIT lease is live,
//     opens the session row, appends the pam.session.opened audit event, and
//     yields the upstream credential in-memory — exactly as the SSH/Postgres/
//     MySQL listeners do. The bridge additionally pins the redeemed session to
//     the workspace the WebSocket caller authenticated for, so a token can only
//     ever be driven inside its own tenant.
//   - Every command (SSH) and statement (SQL) is gated live by
//     pam.SessionManager.LogCommand against the workspace's active command
//     policies and appended to the per-workspace audit hash chain before it
//     reaches the target. A deny on an interactive shell tears the session
//     down (fail-closed, matching the SSH proxy); a deny in the database
//     console refuses that one statement and keeps the console open (matching
//     the Postgres/MySQL proxies).
//   - Both directions of the session are captured by a gateway.IORecorder and
//     flushed to the same ReplayStore the gateway writes to, with the SHA-256
//     integrity descriptor anchored in the audit chain
//     (pam.SessionManager.RecordRecording) — so a browser session is replayable
//     and tamper-evident like any other.
//   - The session is registered in a gateway.SessionHub so an administrator can
//     monitor, soft-pause, or terminate it through the existing live
//     session-control surface; a SessionReconciler bridges control decisions
//     issued through the API (a different code path) onto the in-process
//     browser session.
//
// Graphical protocols (RDP/VNC canvas streaming) are intentionally out of
// scope: this package handles only the text/interactive protocols (SSH, and the
// PostgreSQL/MySQL query consoles) so everything it ships is real and complete.
package webaccess
