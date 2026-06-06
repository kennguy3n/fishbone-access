package cloudflare

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

type cfRevokeRoundtrip struct {
	Method string
	Path   string
	Auth   string
	Body   map[string]string
}

func newCFRevokeTestServer(t *testing.T, status int, capture *[]cfRevokeRoundtrip) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var parsed map[string]string
		_ = json.Unmarshal(body, &parsed)
		mu.Lock()
		*capture = append(*capture, cfRevokeRoundtrip{
			Method: r.Method, Path: r.URL.Path, Auth: r.Header.Get("Authorization"), Body: parsed,
		})
		mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"result": true, "success": true}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func cfRevokeConfig() map[string]interface{}  { return map[string]interface{}{"account_id": "acct-1"} }
func cfRevokeSecrets() map[string]interface{} { return map[string]interface{}{"api_token": "t-1"} }

func TestCloudflare_RevokeUserSessions_HappyPath(t *testing.T) {
	var captured []cfRevokeRoundtrip
	srv := newCFRevokeTestServer(t, http.StatusOK, &captured)
	conn := New()
	conn.urlOverride = srv.URL
	if err := conn.RevokeUserSessions(context.Background(), cfRevokeConfig(), cfRevokeSecrets(), "alice@example.com"); err != nil {
		t.Fatalf("RevokeUserSessions: %v", err)
	}
	if !strings.HasSuffix(captured[0].Path, "/accounts/acct-1/access/organizations/revoke_user") {
		t.Errorf("path=%q; want suffix /accounts/acct-1/access/organizations/revoke_user", captured[0].Path)
	}
	if captured[0].Method != http.MethodPost {
		t.Errorf("method=%q; want POST", captured[0].Method)
	}
	if captured[0].Auth != "Bearer t-1" {
		t.Errorf("auth=%q; want Bearer t-1", captured[0].Auth)
	}
	if captured[0].Body["email"] != "alice@example.com" {
		t.Errorf("body.email=%q; want alice@example.com", captured[0].Body["email"])
	}
}

func TestCloudflare_RevokeUserSessions_NotFoundIsIdempotent(t *testing.T) {
	var captured []cfRevokeRoundtrip
	srv := newCFRevokeTestServer(t, http.StatusNotFound, &captured)
	conn := New()
	conn.urlOverride = srv.URL
	if err := conn.RevokeUserSessions(context.Background(), cfRevokeConfig(), cfRevokeSecrets(), "ghost@example.com"); err != nil {
		t.Errorf("Revoke on 404 returned %v; want nil", err)
	}
}

func TestCloudflare_RevokeUserSessions_ServerErrorPropagates(t *testing.T) {
	var captured []cfRevokeRoundtrip
	srv := newCFRevokeTestServer(t, http.StatusInternalServerError, &captured)
	conn := New()
	conn.urlOverride = srv.URL
	err := conn.RevokeUserSessions(context.Background(), cfRevokeConfig(), cfRevokeSecrets(), "alice@example.com")
	if err == nil {
		t.Error("err = nil; want non-nil for 500")
	}
}

func TestCloudflare_RevokeUserSessions_MissingEmailIsValidationError(t *testing.T) {
	conn := New()
	err := conn.RevokeUserSessions(context.Background(), cfRevokeConfig(), cfRevokeSecrets(), "")
	if err == nil || !strings.Contains(err.Error(), "email") {
		t.Errorf("err=%v; want email-required validation error", err)
	}
}

func TestCloudflare_RevokeUserSessions_LegacyAPIKeyAuth(t *testing.T) {
	var captured []cfRevokeRoundtrip
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var parsed map[string]string
		_ = json.Unmarshal(body, &parsed)
		mu.Lock()
		captured = append(captured, cfRevokeRoundtrip{
			Method: r.Method, Path: r.URL.Path,
			Auth: "X-Auth-Email=" + r.Header.Get("X-Auth-Email") + ";X-Auth-Key=" + r.Header.Get("X-Auth-Key"),
			Body: parsed,
		})
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success": true}`))
	}))
	defer srv.Close()
	conn := New()
	conn.urlOverride = srv.URL
	cfg := map[string]interface{}{"account_id": "acct-1", "email": "admin@example.com"}
	secrets := map[string]interface{}{"api_key": "legacy-key"}
	if err := conn.RevokeUserSessions(context.Background(), cfg, secrets, "alice@example.com"); err != nil {
		t.Fatalf("RevokeUserSessions: %v", err)
	}
	if captured[0].Auth != "X-Auth-Email=admin@example.com;X-Auth-Key=legacy-key" {
		t.Errorf("legacy auth headers=%q; want X-Auth-Email + X-Auth-Key", captured[0].Auth)
	}
}

func TestCloudflare_SatisfiesSessionRevokerInterface(_ *testing.T) {
	var _ access.SessionRevoker = (*CloudflareAccessConnector)(nil)
}
