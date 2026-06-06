package rippling

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

type ripplingSCIMRoundtrip struct {
	Method string
	Path   string
	Auth   string
	Body   string
}

func newRipplingSCIMTestServer(t *testing.T, status int, capture *[]ripplingSCIMRoundtrip) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		*capture = append(*capture, ripplingSCIMRoundtrip{
			Method: r.Method, Path: r.URL.Path, Auth: r.Header.Get("Authorization"), Body: string(body),
		})
		mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func ripplingSCIMConfig() map[string]interface{} { return map[string]interface{}{} }
func ripplingSCIMSecrets() map[string]interface{} {
	return map[string]interface{}{"api_key": "v1", "scim_token": "scim-1"}
}

func withRipplingSCIMTestServer(t *testing.T, srv *httptest.Server) *RipplingAccessConnector {
	t.Helper()
	conn := New()
	conn.urlOverride = srv.URL
	prev := SetSCIMClientForTest(access.NewSCIMClient().WithHTTPClient(srv.Client()))
	t.Cleanup(func() { SetSCIMClientForTest(prev) })
	return conn
}

func TestRippling_PushSCIMUser_HappyPath(t *testing.T) {
	var captured []ripplingSCIMRoundtrip
	srv := newRipplingSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withRipplingSCIMTestServer(t, srv)
	if err := conn.PushSCIMUser(context.Background(), ripplingSCIMConfig(), ripplingSCIMSecrets(), access.SCIMUser{
		ExternalID: "u1", UserName: "alice@example.com", Email: "alice@example.com", Active: true,
	}); err != nil {
		t.Fatalf("PushSCIMUser: %v", err)
	}
	if !strings.HasSuffix(captured[0].Path, "/platform/api/scim/v2/Users") {
		t.Errorf("path=%q; want suffix /platform/api/scim/v2/Users", captured[0].Path)
	}
	if captured[0].Auth != "Bearer scim-1" {
		t.Errorf("auth=%q; want Bearer scim-1", captured[0].Auth)
	}
}

func TestRippling_DeleteSCIMResource_404IsIdempotent(t *testing.T) {
	var captured []ripplingSCIMRoundtrip
	srv := newRipplingSCIMTestServer(t, http.StatusNotFound, &captured)
	conn := withRipplingSCIMTestServer(t, srv)
	if err := conn.DeleteSCIMResource(context.Background(), ripplingSCIMConfig(), ripplingSCIMSecrets(), "Users", "missing"); err != nil {
		t.Errorf("Delete on 404 returned %v; want nil", err)
	}
}

func TestRippling_PushSCIMUser_ServerErrorSurfaces(t *testing.T) {
	var captured []ripplingSCIMRoundtrip
	srv := newRipplingSCIMTestServer(t, http.StatusInternalServerError, &captured)
	conn := withRipplingSCIMTestServer(t, srv)
	err := conn.PushSCIMUser(context.Background(), ripplingSCIMConfig(), ripplingSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteServer) {
		t.Errorf("err=%v; want wrap of access.ErrSCIMRemoteServer", err)
	}
}

func TestRippling_PushSCIMUser_UnauthorizedSurfaces(t *testing.T) {
	var captured []ripplingSCIMRoundtrip
	srv := newRipplingSCIMTestServer(t, http.StatusUnauthorized, &captured)
	conn := withRipplingSCIMTestServer(t, srv)
	err := conn.PushSCIMUser(context.Background(), ripplingSCIMConfig(), ripplingSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteUnauthorized) {
		t.Errorf("err=%v; want wrap of access.ErrSCIMRemoteUnauthorized", err)
	}
}

func TestRippling_PushSCIMUser_MissingSCIMTokenIsValidationError(t *testing.T) {
	conn := New()
	err := conn.PushSCIMUser(context.Background(), ripplingSCIMConfig(), map[string]interface{}{"api_key": "v1"}, access.SCIMUser{ExternalID: "u", UserName: "u"})
	if err == nil || !strings.Contains(err.Error(), "scim_token is required") {
		t.Errorf("err=%v; want scim_token-required validation error", err)
	}
}

func TestRippling_SatisfiesSCIMProvisionerInterface(_ *testing.T) {
	var _ access.SCIMProvisioner = (*RipplingAccessConnector)(nil)
}
