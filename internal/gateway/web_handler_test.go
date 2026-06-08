package gateway

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/services/pam"
)

// --- unit tests -----------------------------------------------------------

func TestWebAuthMode(t *testing.T) {
	cases := []struct {
		cfg    map[string]string
		secret pam.Secret
		want   webAuthMode
	}{
		{map[string]string{"auth": "form"}, pam.Secret{Password: "p"}, webAuthForm},
		{map[string]string{"auth": "bearer"}, pam.Secret{}, webAuthBearer},
		{map[string]string{"auth": "basic"}, pam.Secret{}, webAuthBasic},
		{nil, pam.Secret{Token: "t"}, webAuthBearer},
		{nil, pam.Secret{Username: "u", Password: "p"}, webAuthBasic},
		{nil, pam.Secret{}, webAuthNone},
	}
	for i, c := range cases {
		if got := authMode(c.cfg, c.secret); got != c.want {
			t.Errorf("case %d: authMode = %d, want %d", i, got, c.want)
		}
	}
}

func TestWebConnectToken(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(connectTokenHeader, "header-tok")
	if got := webConnectToken(req); got != "header-tok" {
		t.Fatalf("dedicated header token = %q", got)
	}

	req2, _ := http.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("Authorization", "Bearer fallback-tok")
	if got := webConnectToken(req2); got != "fallback-tok" {
		t.Fatalf("authorization fallback token = %q", got)
	}
}

// --- integration test against a mock HTTP upstream ------------------------

func TestWebProxyEndToEndBasicAuth(t *testing.T) {
	env := newProxyTestEnv(t)
	env.seedDeny(t, "no-secret-path", []string{"*"}, []string{"cmd:get /secret*"})

	var mu sync.Mutex
	var sawAuth []string
	var sawTokenHeader bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		sawAuth = append(sawAuth, r.Header.Get("Authorization"))
		if r.Header.Get(connectTokenHeader) != "" {
			sawTokenHeader = true
		}
		mu.Unlock()
		fmt.Fprintf(w, "hello from %s", r.URL.Path)
	}))
	defer upstream.Close()

	addr := strings.TrimPrefix(upstream.URL, "http://")
	target := env.createTarget(t, models.PAMProtocolHTTP, addr, pam.Secret{Username: "admin", Password: "s3cret"})
	token := env.mintToken(t, target.ID, "alice")

	proxy, err := NewWebProxy(WebProxyConfig{Broker: env.broker, Sessions: env.sessions, Hub: env.hub, Store: env.store, DialTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewWebProxy: %v", err)
	}

	client, server := pipeConn(t)
	defer client.Close()
	done := make(chan struct{})
	go func() {
		proxy.Handle(context.Background(), server)
		close(done)
	}()

	cr := bufio.NewReader(client)

	// First request: allowed path. Token presented in the dedicated header.
	writeRawRequest(t, client, "GET", "/admin", token, true)
	resp := readRawResponse(t, cr, "GET")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("allowed request status = %d", resp.StatusCode)
	}
	body := readBody(t, resp)
	if body != "hello from /admin" {
		t.Fatalf("upstream body = %q", body)
	}

	// Second request: denied path → 403 from the gateway, never hits upstream.
	writeRawRequest(t, client, "GET", "/secret/keys", token, true)
	resp2 := readRawResponse(t, cr, "GET")
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("denied request status = %d, want 403", resp2.StatusCode)
	}
	_ = readBody(t, resp2)

	_ = client.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("proxy did not return")
	}

	mu.Lock()
	defer mu.Unlock()
	// Upstream saw exactly one request (the allowed one) with injected Basic auth
	// and never the operator's connect-token header.
	if len(sawAuth) != 1 {
		t.Fatalf("upstream saw %d requests, want 1 (denied path must not reach it)", len(sawAuth))
	}
	wantAuth := "Basic " + basicAuth("admin", "s3cret")
	if sawAuth[0] != wantAuth {
		t.Fatalf("upstream Authorization = %q, want %q", sawAuth[0], wantAuth)
	}
	if sawTokenHeader {
		t.Fatal("connect-token header leaked to upstream")
	}

	// Session recorded both directions + the deny annotation, and is closed.
	rows := env.sessionRows(t)
	if len(rows) != 1 || rows[0].State != models.PAMSessionClosed {
		t.Fatalf("session not closed cleanly: %+v", rows)
	}
	frames := parseFrames(t, env.store.put[rows[0].ID.String()])
	var sawReq, sawResp, sawDeny bool
	for _, f := range frames {
		s := string(f.payload)
		switch {
		case f.dir == DirInput && strings.Contains(s, "GET /admin"):
			sawReq = true
		case f.dir == DirOutput && strings.Contains(s, "200"):
			sawResp = true
		case f.dir == DirControl && strings.Contains(s, "request denied"):
			sawDeny = true
		}
	}
	if !sawReq || !sawResp || !sawDeny {
		t.Fatalf("recording incomplete: req=%v resp=%v deny=%v", sawReq, sawResp, sawDeny)
	}

	cmds := env.commandRows(t, rows[0].ID)
	if len(cmds) != 2 || cmds[0].Decision != models.PAMDecisionAllow || cmds[1].Decision != models.PAMDecisionDeny {
		t.Fatalf("command rows unexpected: %+v", cmds)
	}
}

// TestWebProxyFormLogin proves the proxy performs a one-time form login,
// captures the upstream session cookie, and rides it onto forwarded requests.
func TestWebProxyFormLogin(t *testing.T) {
	env := newProxyTestEnv(t)

	const sessionCookie = "SID=form-session-xyz"
	var mu sync.Mutex
	var loginForm url.Values
	var protectedCookie string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			_ = r.ParseForm()
			mu.Lock()
			loginForm = r.PostForm
			mu.Unlock()
			http.SetCookie(w, &http.Cookie{Name: "SID", Value: "form-session-xyz", Path: "/"})
			w.WriteHeader(http.StatusOK)
		default:
			mu.Lock()
			if c, err := r.Cookie("SID"); err == nil {
				protectedCookie = c.Name + "=" + c.Value
			}
			mu.Unlock()
			fmt.Fprint(w, "protected-ok")
		}
	}))
	defer upstream.Close()

	addr := strings.TrimPrefix(upstream.URL, "http://")
	target, err := env.vault.CreateTarget(context.Background(), pam.CreateTargetInput{
		WorkspaceID: env.workspaceID, Name: "web-form", Protocol: models.PAMProtocolHTTP, Address: addr,
		Secret: pam.Secret{Username: "operator", Password: "formpass"},
		Config: jsonConfig(t, map[string]string{"auth": "form", "login_path": "/login", "user_field": "user", "pass_field": "pass"}),
		Actor:  "admin",
	})
	if err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}
	token := env.mintToken(t, target.ID, "alice")

	proxy, err := NewWebProxy(WebProxyConfig{Broker: env.broker, Sessions: env.sessions, Hub: env.hub, Store: env.store, DialTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewWebProxy: %v", err)
	}
	client, server := pipeConn(t)
	defer client.Close()
	done := make(chan struct{})
	go func() {
		proxy.Handle(context.Background(), server)
		close(done)
	}()

	cr := bufio.NewReader(client)
	writeRawRequest(t, client, "GET", "/dashboard", token, false)
	resp := readRawResponse(t, cr, "GET")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("form-auth request status = %d", resp.StatusCode)
	}
	if b := readBody(t, resp); b != "protected-ok" {
		t.Fatalf("body = %q", b)
	}
	<-done

	mu.Lock()
	defer mu.Unlock()
	if loginForm.Get("user") != "operator" || loginForm.Get("pass") != "formpass" {
		t.Fatalf("login form did not carry injected credentials: %v", loginForm)
	}
	if protectedCookie != sessionCookie {
		t.Fatalf("protected request cookie = %q, want %q", protectedCookie, sessionCookie)
	}
}

// --- raw HTTP test helpers ------------------------------------------------

func writeRawRequest(t *testing.T, w net.Conn, method, path, token string, keepAlive bool) {
	t.Helper()
	conn := "close"
	if keepAlive {
		conn = "keep-alive"
	}
	req := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: console.internal\r\n%s: %s\r\nConnection: %s\r\n\r\n",
		method, path, connectTokenHeader, token, conn)
	if _, err := w.Write([]byte(req)); err != nil {
		t.Fatalf("write request: %v", err)
	}
}

func readRawResponse(t *testing.T, r *bufio.Reader, method string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(method, "/", nil)
	resp, err := http.ReadResponse(r, req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}
