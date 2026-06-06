package tailscale

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

type tsRevokeRoundtrip struct {
	Method string
	Path   string
	Auth   string
}

func newTSRevokeTestServer(t *testing.T, status int, respBody string, capture *[]tsRevokeRoundtrip) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		*capture = append(*capture, tsRevokeRoundtrip{
			Method: r.Method, Path: r.URL.Path, Auth: r.Header.Get("Authorization"),
		})
		mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(respBody))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func tsRevokeConfig() map[string]interface{}  { return map[string]interface{}{"tailnet": "example.com"} }
func tsRevokeSecrets() map[string]interface{} { return map[string]interface{}{"api_key": "v1"} }

func TestTailscale_RevokeUserSessions_HappyPath(t *testing.T) {
	var captured []tsRevokeRoundtrip
	srv := newTSRevokeTestServer(t, http.StatusOK, ``, &captured)
	conn := New()
	conn.urlOverride = srv.URL
	if err := conn.RevokeUserSessions(context.Background(), tsRevokeConfig(), tsRevokeSecrets(), "u-123"); err != nil {
		t.Fatalf("RevokeUserSessions: %v", err)
	}
	if !strings.HasSuffix(captured[0].Path, "/api/v2/user/u-123/suspend") {
		t.Errorf("path=%q; want suffix /api/v2/user/u-123/suspend", captured[0].Path)
	}
	if captured[0].Method != http.MethodPost {
		t.Errorf("method=%q; want POST", captured[0].Method)
	}
	if !strings.HasPrefix(captured[0].Auth, "Basic ") {
		t.Errorf("auth=%q; want Basic auth (api_key as username)", captured[0].Auth)
	}
}

func TestTailscale_RevokeUserSessions_NotFoundIsIdempotent(t *testing.T) {
	var captured []tsRevokeRoundtrip
	srv := newTSRevokeTestServer(t, http.StatusNotFound, ``, &captured)
	conn := New()
	conn.urlOverride = srv.URL
	if err := conn.RevokeUserSessions(context.Background(), tsRevokeConfig(), tsRevokeSecrets(), "ghost"); err != nil {
		t.Errorf("Revoke on 404 returned %v; want nil", err)
	}
}

func TestTailscale_RevokeUserSessions_AlreadySuspendedIsIdempotent(t *testing.T) {
	var captured []tsRevokeRoundtrip
	srv := newTSRevokeTestServer(t, http.StatusBadRequest, `{"message":"user is already suspended"}`, &captured)
	conn := New()
	conn.urlOverride = srv.URL
	if err := conn.RevokeUserSessions(context.Background(), tsRevokeConfig(), tsRevokeSecrets(), "u-123"); err != nil {
		t.Errorf("Revoke on already-suspended returned %v; want nil", err)
	}
}

func TestTailscale_RevokeUserSessions_ServerErrorPropagates(t *testing.T) {
	var captured []tsRevokeRoundtrip
	srv := newTSRevokeTestServer(t, http.StatusInternalServerError, ``, &captured)
	conn := New()
	conn.urlOverride = srv.URL
	err := conn.RevokeUserSessions(context.Background(), tsRevokeConfig(), tsRevokeSecrets(), "u-123")
	if err == nil {
		t.Error("err = nil; want non-nil for 500")
	}
}

func TestTailscale_RevokeUserSessions_MissingExternalIDIsValidationError(t *testing.T) {
	conn := New()
	err := conn.RevokeUserSessions(context.Background(), tsRevokeConfig(), tsRevokeSecrets(), "")
	if err == nil || !strings.Contains(err.Error(), "external id is required") {
		t.Errorf("err=%v; want external-id-required validation error", err)
	}
}

func TestTailscale_SatisfiesSessionRevokerInterface(_ *testing.T) {
	var _ access.SessionRevoker = (*TailscaleAccessConnector)(nil)
}
