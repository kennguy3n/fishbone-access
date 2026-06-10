package gateway

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
	"github.com/kennguy3n/fishbone-access/internal/services/pam"
)

// connectTokenHeader is the request header an operator's HTTP client sets to
// present its one-shot connect token. A dedicated header (rather than reusing
// Authorization) keeps the operator's session credential separate from the
// upstream credential the gateway injects, so the proxy can strip the token
// before forwarding without disturbing any Authorization the operator sent.
const connectTokenHeader = "X-Pam-Connect-Token" //nolint:gosec // header name, not a credential.

// maxWebRequestsPerConn bounds how many requests the proxy services on one
// keep-alive operator connection before forcing a close. A single redeemed
// connect token authorizes one session, which may carry many requests (a web
// console loads many assets); the bound stops a connection from being held open
// indefinitely.
const maxWebRequestsPerConn = 10000

// WebProxy is the gateway.ConnHandler for the HTTP/HTTPS listener (:8080). It is
// a reverse proxy for privileged web consoles (router admin pages, NAS UIs,
// printer management): the operator points a browser or HTTP client at the
// gateway and presents the one-shot connect token in the X-Pam-Connect-Token
// header. The proxy redeems it, opens a session, then for every request on the
// (keep-alive) connection it gates the method+path against the 1C policy
// engine, injects the upstream credential the operator never sees (HTTP Basic,
// Bearer token, or a form-login cookie), forwards to the upstream, and relays
// the response. Each request/response is recorded as a metadata log line (not
// the body) for replay, and the session open/close lands in the workspace audit
// hash chain via the session manager.
type WebProxy struct {
	broker      *pam.Broker
	sessions    *pam.SessionManager
	hub         *SessionHub
	store       ReplayStore
	dialTimeout time.Duration
	recMaxBytes int
}

// WebProxyConfig configures a WebProxy.
type WebProxyConfig struct {
	Broker      *pam.Broker
	Sessions    *pam.SessionManager
	Hub         *SessionHub
	Store       ReplayStore
	DialTimeout time.Duration
	RecMaxBytes int
}

// NewWebProxy builds a WebProxy. broker and sessions are required.
func NewWebProxy(cfg WebProxyConfig) (*WebProxy, error) {
	if cfg.Broker == nil || cfg.Sessions == nil {
		return nil, errors.New("gateway: WebProxy requires broker and session manager")
	}
	dt := cfg.DialTimeout
	if dt <= 0 {
		dt = 15 * time.Second
	}
	return &WebProxy{
		broker:      cfg.Broker,
		sessions:    cfg.Sessions,
		hub:         cfg.Hub,
		store:       cfg.Store,
		dialTimeout: dt,
		recMaxBytes: cfg.RecMaxBytes,
	}, nil
}

// Handle implements gateway.ConnHandler.
func (p *WebProxy) Handle(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()
	clientAddr := conn.RemoteAddr().String()

	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		logger.Warnf(ctx, "web-proxy: read request from %s: %v", clientAddr, err)
		return
	}

	token := webConnectToken(req)
	if token == "" {
		writeHTTPError(conn, http.StatusUnauthorized, "missing connect token")
		return
	}
	leased, err := p.broker.RedeemConnectToken(ctx, token, clientAddr)
	if err != nil {
		writeHTTPError(conn, http.StatusUnauthorized, "connect token rejected")
		logger.Warnf(ctx, "web-proxy: redeem from %s failed: %v", clientAddr, err)
		return
	}
	if leased.Target.Protocol != models.PAMProtocolHTTP {
		writeHTTPError(conn, http.StatusBadRequest, "token is not for an http target")
		reconcileOrphanSession(ctx, p.sessions, leased.Session, "web-proxy")
		return
	}
	session := leased.Session
	logger.Infof(ctx, "web-proxy: session %s opened for %s → %s", session.ID, session.Subject, leased.Target.Address)

	sessCtx, cancel := context.WithCancel(ctx)
	rec := NewIORecorder(sessCtx, session.ID.String(), p.recMaxBytes)
	defer cancel()
	if p.hub != nil {
		defer p.hub.Register(session.ID, session.WorkspaceID, session.Subject, rec, cancel)()
	}
	defer func() {
		flushCtx, fcancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer fcancel()
		if err := rec.Flush(flushCtx, p.store); err != nil {
			logger.Warnf(ctx, "web-proxy: flush replay %s: %v", session.ID, err)
		}
		if recording := rec.Recording(); recording.Stored {
			if err := p.sessions.RecordRecording(flushCtx, session, pam.RecordingRef{
				Key: recording.Key, SHA256: recording.SHA256, Bytes: recording.Bytes, Truncated: recording.Truncated,
			}); err != nil {
				logger.Warnf(ctx, "web-proxy: record recording evidence %s: %v", session.ID, err)
			}
		}
		if err := p.sessions.CloseSession(flushCtx, session.WorkspaceID, session.ID); err != nil {
			logger.Warnf(ctx, "web-proxy: close session %s: %v", session.ID, err)
		}
	}()

	client, base, err := p.upstreamClient(leased)
	if err != nil {
		writeHTTPError(conn, http.StatusBadGateway, "upstream client init failed")
		rec.Annotate(fmt.Sprintf("[upstream client init failed: %v]", err))
		return
	}
	// Close idle keep-alive connections to the upstream when the session ends so
	// a long-lived gateway does not leak pooled sockets per closed session.
	defer client.CloseIdleConnections()

	// Form-login targets authenticate once per session by POSTing credentials to
	// the configured login path; the resulting session cookie rides the client's
	// jar onto every forwarded request.
	if err := p.maybeFormLogin(sessCtx, client, base, leased, rec); err != nil {
		writeHTTPError(conn, http.StatusBadGateway, "upstream form login failed")
		rec.Annotate(fmt.Sprintf("[form login failed: %v]", err))
		logger.Warnf(ctx, "web-proxy: form login to %s: %v", leased.Target.Address, err)
		return
	}

	// Service the first request, then continue reading keep-alive requests off
	// the same connection until the operator or upstream closes it.
	for i := 0; i < maxWebRequestsPerConn; i++ {
		if sessCtx.Err() != nil {
			return
		}
		// Honour the live soft-pause gate before servicing the next operator
		// request: while an admin has frozen the session no further HTTP
		// request is forwarded to the upstream until resume or teardown.
		rec.WaitWhilePaused()
		keepAlive := p.serveRequest(sessCtx, conn, req, client, base, leased, session, rec)
		if !keepAlive {
			return
		}
		req, err = http.ReadRequest(br)
		if err != nil {
			return
		}
	}
}

// serveRequest gates, forwards, and relays one operator request. It returns
// true if the connection may carry another request (keep-alive), false if the
// proxy should close it.
func (p *WebProxy) serveRequest(ctx context.Context, operator net.Conn, req *http.Request, client *http.Client, base string, leased *pam.LeasedSession, session *models.PAMSession, rec *IORecorder) (keepAlive bool) {
	// Read and buffer the request body so it can be forwarded; an operator may
	// pipeline another request after it, so we must consume exactly this body.
	defer func() { _ = req.Body.Close() }()

	reqLine := req.Method + " " + req.URL.RequestURI()
	rec.Record(DirInput, []byte(reqLine+"\n"))

	decision, derr := p.sessions.LogCommand(ctx, session, reqLine)
	if derr != nil || !decision.Allowed() {
		reason := decision.Reason
		if reason == "" {
			reason = "denied by command policy"
		}
		rec.Annotate(fmt.Sprintf("[request denied: %s]", reason))
		// A denied request keeps the session usable for subsequent allowed
		// paths, so the 403 is written keep-alive (Content-Length delimited, no
		// Connection: close) and the connection survives unless the operator
		// itself asked to close. The unread request body must be consumed before
		// the next http.ReadRequest or the body bytes would be misparsed as the
		// following request and desync the keep-alive stream. Drain it
		// explicitly rather than relying on http.body.Close's internal draining
		// (an undocumented net/http implementation detail): a bounded copy to
		// io.Discard is the documented, version-stable way to consume it.
		_, _ = io.Copy(io.Discard, req.Body)
		writeHTTPDeny(operator, "pam-gateway: "+reason)
		return !shouldClose(req)
	}

	out, err := p.buildUpstreamRequest(ctx, req, base, leased)
	if err != nil {
		writeHTTPError(operator, http.StatusBadGateway, "upstream request build failed")
		rec.Annotate(fmt.Sprintf("[upstream request build failed: %v]", err))
		return false
	}

	resp, err := client.Do(out)
	if err != nil {
		writeHTTPError(operator, http.StatusBadGateway, "upstream request failed")
		rec.Annotate(fmt.Sprintf("[upstream request failed: %v]", err))
		return false
	}
	defer func() { _ = resp.Body.Close() }()

	rec.Record(DirOutput, []byte(fmt.Sprintf("%s %d (%s)\n", resp.Proto, resp.StatusCode, contentLengthLabel(resp))))

	// Relay the response verbatim (status, headers, body) to the operator.
	if err := resp.Write(operator); err != nil {
		return false
	}
	// Honour close semantics from either side.
	if shouldClose(req) || resp.Close {
		return false
	}
	return true
}

// buildUpstreamRequest clones the operator request onto the upstream base URL,
// strips hop-by-hop and gateway-only headers, and injects the upstream
// credential (Bearer or Basic). Form-login targets carry their credential as a
// cookie on the client jar instead, so no Authorization header is added for
// them.
func (p *WebProxy) buildUpstreamRequest(ctx context.Context, req *http.Request, base string, leased *pam.LeasedSession) (*http.Request, error) {
	target := base + req.URL.RequestURI()
	out, err := http.NewRequestWithContext(ctx, req.Method, target, req.Body)
	if err != nil {
		return nil, err
	}
	// Copy operator headers, minus the connect token and any operator-supplied
	// Authorization (the gateway is the sole authority on upstream credentials).
	for k, vs := range req.Header {
		if strings.EqualFold(k, connectTokenHeader) || strings.EqualFold(k, "Authorization") {
			continue
		}
		for _, v := range vs {
			out.Header.Add(k, v)
		}
	}
	out.ContentLength = req.ContentLength

	cfg := decodeTargetConfig(leased.Target.Config)
	switch authMode(cfg, leased.Secret) {
	case webAuthBearer:
		out.Header.Set("Authorization", "Bearer "+leased.Secret.Token)
	case webAuthBasic:
		out.Header.Set("Authorization", "Basic "+basicAuth(credUser(leased), leased.Secret.Password))
	case webAuthForm:
		// Credential rides the cookie jar; nothing to inject per request.
	case webAuthNone:
		// No credential configured; the request is proxied as-is.
	}
	return out, nil
}

// upstreamClient builds the per-session HTTP client whose transport always
// dials the leased target's address (so the operator cannot pivot to an
// arbitrary host by changing the request Host) and whose cookie jar carries a
// form-login session. TLS to the upstream is enabled by a "tls":"true" config
// key; a "ca_cert" PEM pins the upstream identity, otherwise the gateway (the
// audited trust boundary) skips verification.
func (p *WebProxy) upstreamClient(leased *pam.LeasedSession) (*http.Client, string, error) {
	cfg := decodeTargetConfig(leased.Target.Config)
	scheme := "http"
	var tlsCfg *tls.Config
	if cfg["tls"] == "true" {
		scheme = "https"
		host := leased.Target.Address
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		tlsCfg = &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
		if ca := cfg["ca_cert"]; ca != "" {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM([]byte(ca)) {
				tlsCfg.RootCAs = pool
			}
		} else {
			tlsCfg.InsecureSkipVerify = true //nolint:gosec // no CA pinned: the gateway is the audited trust boundary to the upstream console.
		}
	}
	addr := leased.Target.Address
	dialer := &net.Dialer{Timeout: p.dialTimeout}
	tr := &http.Transport{
		Proxy: nil,
		// Pin every dial to the leased target regardless of the request URL host.
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig:     tlsCfg,
		MaxIdleConns:        4,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: p.dialTimeout,
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, "", err
	}
	client := &http.Client{Transport: tr, Jar: jar}
	return client, scheme + "://" + leased.Target.Address, nil
}

// maybeFormLogin performs a one-time form-based authentication when the target
// is configured for it (auth=form). It POSTs the vault credential to the
// configured login path; the upstream's Set-Cookie response seeds the client
// jar so every subsequent forwarded request is authenticated.
func (p *WebProxy) maybeFormLogin(ctx context.Context, client *http.Client, base string, leased *pam.LeasedSession, rec *IORecorder) error {
	cfg := decodeTargetConfig(leased.Target.Config)
	if authMode(cfg, leased.Secret) != webAuthForm {
		return nil
	}
	loginPath := cfg["login_path"]
	if loginPath == "" {
		return errors.New("form auth configured but login_path is empty")
	}
	userField := cfg["user_field"]
	if userField == "" {
		userField = "username"
	}
	passField := cfg["pass_field"]
	if passField == "" {
		passField = "password"
	}
	form := url.Values{
		userField: {credUser(leased)},
		passField: {leased.Secret.Password},
	}
	loginURL := base + loginPath
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, loginURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(httpReq)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	// Drain the body so the connection can be reused from the pool.
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("login returned status %d", resp.StatusCode)
	}
	rec.Annotate(fmt.Sprintf("[form login ok: POST %s → %d]", loginPath, resp.StatusCode))
	return nil
}

// --- helpers ---

// webAuthMode enumerates how the gateway injects the upstream credential.
type webAuthMode int

const (
	webAuthNone webAuthMode = iota
	webAuthBearer
	webAuthBasic
	webAuthForm
)

// authMode picks the credential-injection mode from the target config and the
// populated secret fields. An explicit config "auth" wins; otherwise the
// presence of a Token implies Bearer and a Username/Password implies Basic.
func authMode(cfg map[string]string, secret pam.Secret) webAuthMode {
	switch strings.ToLower(cfg["auth"]) {
	case "form":
		return webAuthForm
	case "bearer":
		return webAuthBearer
	case "basic":
		return webAuthBasic
	}
	switch {
	case secret.Token != "":
		return webAuthBearer
	case secret.Username != "" || secret.Password != "":
		return webAuthBasic
	default:
		return webAuthNone
	}
}

// webConnectToken extracts the one-shot token from the dedicated header or, as a
// fallback, an Authorization: Bearer header.
func webConnectToken(req *http.Request) string {
	if t := strings.TrimSpace(req.Header.Get(connectTokenHeader)); t != "" {
		return t
	}
	return bearerToken(req.Header.Get("Authorization"))
}

// shouldClose reports whether the operator requested connection close (HTTP/1.0
// without keep-alive, or an explicit Connection: close).
func shouldClose(req *http.Request) bool {
	return req.Close
}

// writeHTTPDeny writes a keep-alive 403 to the operator. Unlike writeHTTPError
// it does not send Connection: close, so a single denied path does not tear
// down a session that may still issue allowed requests.
func writeHTTPDeny(w io.Writer, msg string) {
	body := msg + "\n"
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s",
		http.StatusForbidden, http.StatusText(http.StatusForbidden), len(body), body)
}

// contentLengthLabel renders a response's body size for the recorded log line
// without reading the body.
func contentLengthLabel(resp *http.Response) string {
	if resp.ContentLength >= 0 {
		return fmt.Sprintf("%d bytes", resp.ContentLength)
	}
	return "unknown length"
}
