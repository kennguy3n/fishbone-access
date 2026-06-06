package cloudflare

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

type cfSCIMRoundtrip struct {
	Method string
	Path   string
	Auth   string
	Body   string
}

func newCFSCIMTestServer(t *testing.T, status int, capture *[]cfSCIMRoundtrip) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		*capture = append(*capture, cfSCIMRoundtrip{
			Method: r.Method, Path: r.URL.Path, Auth: r.Header.Get("Authorization"), Body: string(body),
		})
		mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func cfSCIMConfig() map[string]interface{}  { return map[string]interface{}{"account_id": "acct-1"} }
func cfSCIMSecrets() map[string]interface{} { return map[string]interface{}{"api_token": "t", "scim_token": "scim-1"} }

func withCFSCIMTestServer(t *testing.T, srv *httptest.Server) *CloudflareAccessConnector {
	t.Helper()
	conn := New()
	conn.urlOverride = srv.URL
	prev := SetSCIMClientForTest(access.NewSCIMClient().WithHTTPClient(srv.Client()))
	t.Cleanup(func() { SetSCIMClientForTest(prev) })
	return conn
}

func TestCloudflare_PushSCIMUser_HappyPath(t *testing.T) {
	var captured []cfSCIMRoundtrip
	srv := newCFSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withCFSCIMTestServer(t, srv)
	if err := conn.PushSCIMUser(context.Background(), cfSCIMConfig(), cfSCIMSecrets(), access.SCIMUser{
		ExternalID: "u1", UserName: "alice@example.com", Email: "alice@example.com", Active: true,
	}); err != nil {
		t.Fatalf("PushSCIMUser: %v", err)
	}
	if !strings.HasSuffix(captured[0].Path, "/Users") {
		t.Errorf("path=%q; want suffix /Users", captured[0].Path)
	}
	if captured[0].Auth != "Bearer scim-1" {
		t.Errorf("auth=%q; want Bearer scim-1", captured[0].Auth)
	}
}

func TestCloudflare_DeleteSCIMResource_404IsIdempotent(t *testing.T) {
	var captured []cfSCIMRoundtrip
	srv := newCFSCIMTestServer(t, http.StatusNotFound, &captured)
	conn := withCFSCIMTestServer(t, srv)
	if err := conn.DeleteSCIMResource(context.Background(), cfSCIMConfig(), cfSCIMSecrets(), "Users", "missing"); err != nil {
		t.Errorf("Delete on 404 returned %v; want nil", err)
	}
}

func TestCloudflare_PushSCIMUser_ServerErrorSurfaces(t *testing.T) {
	var captured []cfSCIMRoundtrip
	srv := newCFSCIMTestServer(t, http.StatusInternalServerError, &captured)
	conn := withCFSCIMTestServer(t, srv)
	err := conn.PushSCIMUser(context.Background(), cfSCIMConfig(), cfSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteServer) {
		t.Errorf("err=%v; want wrap of access.ErrSCIMRemoteServer", err)
	}
}

func TestCloudflare_PushSCIMUser_UnauthorizedSurfaces(t *testing.T) {
	var captured []cfSCIMRoundtrip
	srv := newCFSCIMTestServer(t, http.StatusUnauthorized, &captured)
	conn := withCFSCIMTestServer(t, srv)
	err := conn.PushSCIMUser(context.Background(), cfSCIMConfig(), cfSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteUnauthorized) {
		t.Errorf("err=%v; want wrap of access.ErrSCIMRemoteUnauthorized", err)
	}
}

func TestCloudflare_PushSCIMUser_MissingSCIMTokenIsValidationError(t *testing.T) {
	conn := New()
	err := conn.PushSCIMUser(context.Background(), cfSCIMConfig(), map[string]interface{}{"api_token": "t"}, access.SCIMUser{ExternalID: "u", UserName: "u"})
	if err == nil || !strings.Contains(err.Error(), "scim_token is required") {
		t.Errorf("err=%v; want scim_token-required validation error", err)
	}
}

func TestCloudflare_SatisfiesSCIMProvisionerInterface(_ *testing.T) {
	var _ access.SCIMProvisioner = (*CloudflareAccessConnector)(nil)
}
