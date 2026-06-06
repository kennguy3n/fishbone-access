package tailscale

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

type tsSCIMRoundtrip struct {
	Method string
	Path   string
	Auth   string
	Body   string
}

func newTSSCIMTestServer(t *testing.T, status int, capture *[]tsSCIMRoundtrip) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		*capture = append(*capture, tsSCIMRoundtrip{
			Method: r.Method, Path: r.URL.Path, Auth: r.Header.Get("Authorization"), Body: string(body),
		})
		mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func tsSCIMConfig() map[string]interface{}  { return map[string]interface{}{"tailnet": "example.com"} }
func tsSCIMSecrets() map[string]interface{} { return map[string]interface{}{"api_key": "v1", "scim_token": "scim-1"} }

func withTSSCIMTestServer(t *testing.T, srv *httptest.Server) *TailscaleAccessConnector {
	t.Helper()
	conn := New()
	conn.urlOverride = srv.URL
	prev := SetSCIMClientForTest(access.NewSCIMClient().WithHTTPClient(srv.Client()))
	t.Cleanup(func() { SetSCIMClientForTest(prev) })
	return conn
}

func TestTailscale_PushSCIMUser_HappyPath(t *testing.T) {
	var captured []tsSCIMRoundtrip
	srv := newTSSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withTSSCIMTestServer(t, srv)
	if err := conn.PushSCIMUser(context.Background(), tsSCIMConfig(), tsSCIMSecrets(), access.SCIMUser{
		ExternalID: "u1", UserName: "alice@example.com", Email: "alice@example.com", Active: true,
	}); err != nil {
		t.Fatalf("PushSCIMUser: %v", err)
	}
	if !strings.HasSuffix(captured[0].Path, "/api/v2/tailnet/example.com/scim/v2/Users") {
		t.Errorf("path=%q; want suffix /api/v2/tailnet/example.com/scim/v2/Users", captured[0].Path)
	}
	if captured[0].Auth != "Bearer scim-1" {
		t.Errorf("auth=%q; want Bearer scim-1", captured[0].Auth)
	}
}

func TestTailscale_DeleteSCIMResource_404IsIdempotent(t *testing.T) {
	var captured []tsSCIMRoundtrip
	srv := newTSSCIMTestServer(t, http.StatusNotFound, &captured)
	conn := withTSSCIMTestServer(t, srv)
	if err := conn.DeleteSCIMResource(context.Background(), tsSCIMConfig(), tsSCIMSecrets(), "Users", "missing"); err != nil {
		t.Errorf("Delete on 404 returned %v; want nil", err)
	}
}

func TestTailscale_PushSCIMUser_ServerErrorSurfaces(t *testing.T) {
	var captured []tsSCIMRoundtrip
	srv := newTSSCIMTestServer(t, http.StatusInternalServerError, &captured)
	conn := withTSSCIMTestServer(t, srv)
	err := conn.PushSCIMUser(context.Background(), tsSCIMConfig(), tsSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteServer) {
		t.Errorf("err=%v; want wrap of access.ErrSCIMRemoteServer", err)
	}
}

func TestTailscale_PushSCIMUser_UnauthorizedSurfaces(t *testing.T) {
	var captured []tsSCIMRoundtrip
	srv := newTSSCIMTestServer(t, http.StatusUnauthorized, &captured)
	conn := withTSSCIMTestServer(t, srv)
	err := conn.PushSCIMUser(context.Background(), tsSCIMConfig(), tsSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteUnauthorized) {
		t.Errorf("err=%v; want wrap of access.ErrSCIMRemoteUnauthorized", err)
	}
}

func TestTailscale_PushSCIMUser_MissingSCIMTokenIsValidationError(t *testing.T) {
	conn := New()
	err := conn.PushSCIMUser(context.Background(), tsSCIMConfig(), map[string]interface{}{"api_key": "v1"}, access.SCIMUser{ExternalID: "u", UserName: "u"})
	if err == nil || !strings.Contains(err.Error(), "scim_token is required") {
		t.Errorf("err=%v; want scim_token-required validation error", err)
	}
}

func TestTailscale_SatisfiesSCIMProvisionerInterface(_ *testing.T) {
	var _ access.SCIMProvisioner = (*TailscaleAccessConnector)(nil)
}
