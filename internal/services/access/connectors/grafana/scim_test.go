package grafana

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

type grafanaSCIMRoundtrip struct {
	Method string
	Path   string
	Auth   string
	Body   string
}

func newGrafanaSCIMTestServer(t *testing.T, status int, capture *[]grafanaSCIMRoundtrip) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		*capture = append(*capture, grafanaSCIMRoundtrip{
			Method: r.Method, Path: r.URL.Path, Auth: r.Header.Get("Authorization"), Body: string(body),
		})
		mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func grafanaSCIMConfig() map[string]interface{} {
	return map[string]interface{}{"base_url": "https://stack.grafana.net"}
}
func grafanaSCIMSecrets() map[string]interface{} {
	return map[string]interface{}{"token": "v1", "scim_token": "scim-1"}
}

func withGrafanaSCIMTestServer(t *testing.T, srv *httptest.Server) *GrafanaAccessConnector {
	t.Helper()
	conn := New()
	conn.urlOverride = srv.URL
	prev := SetSCIMClientForTest(access.NewSCIMClient().WithHTTPClient(srv.Client()))
	t.Cleanup(func() { SetSCIMClientForTest(prev) })
	return conn
}

func TestGrafana_PushSCIMUser_HappyPath(t *testing.T) {
	var captured []grafanaSCIMRoundtrip
	srv := newGrafanaSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withGrafanaSCIMTestServer(t, srv)
	if err := conn.PushSCIMUser(context.Background(), grafanaSCIMConfig(), grafanaSCIMSecrets(), access.SCIMUser{
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

func TestGrafana_DeleteSCIMResource_404IsIdempotent(t *testing.T) {
	var captured []grafanaSCIMRoundtrip
	srv := newGrafanaSCIMTestServer(t, http.StatusNotFound, &captured)
	conn := withGrafanaSCIMTestServer(t, srv)
	if err := conn.DeleteSCIMResource(context.Background(), grafanaSCIMConfig(), grafanaSCIMSecrets(), "Users", "missing"); err != nil {
		t.Errorf("Delete on 404 returned %v; want nil", err)
	}
}

func TestGrafana_PushSCIMUser_ServerErrorSurfaces(t *testing.T) {
	var captured []grafanaSCIMRoundtrip
	srv := newGrafanaSCIMTestServer(t, http.StatusInternalServerError, &captured)
	conn := withGrafanaSCIMTestServer(t, srv)
	err := conn.PushSCIMUser(context.Background(), grafanaSCIMConfig(), grafanaSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteServer) {
		t.Errorf("err=%v; want wrap of access.ErrSCIMRemoteServer", err)
	}
}

func TestGrafana_PushSCIMUser_UnauthorizedSurfaces(t *testing.T) {
	var captured []grafanaSCIMRoundtrip
	srv := newGrafanaSCIMTestServer(t, http.StatusUnauthorized, &captured)
	conn := withGrafanaSCIMTestServer(t, srv)
	err := conn.PushSCIMUser(context.Background(), grafanaSCIMConfig(), grafanaSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteUnauthorized) {
		t.Errorf("err=%v; want wrap of access.ErrSCIMRemoteUnauthorized", err)
	}
}

func TestGrafana_PushSCIMUser_MissingSCIMTokenIsValidationError(t *testing.T) {
	conn := New()
	err := conn.PushSCIMUser(context.Background(), grafanaSCIMConfig(), map[string]interface{}{"token": "v1"}, access.SCIMUser{ExternalID: "u", UserName: "u"})
	if err == nil || !strings.Contains(err.Error(), "scim_token is required") {
		t.Errorf("err=%v; want scim_token-required validation error", err)
	}
}

func TestGrafana_PushSCIMUser_MissingBaseURLIsValidationError(t *testing.T) {
	// No urlOverride, no scim_base_url override, no scim_path → expect base-url error.
	conn := New()
	err := conn.PushSCIMUser(context.Background(),
		map[string]interface{}{"base_url": "https://stack.grafana.net"},
		map[string]interface{}{"token": "v1", "scim_token": "scim-1"},
		access.SCIMUser{ExternalID: "u", UserName: "u"})
	if err == nil || !strings.Contains(err.Error(), "scim_base_url") {
		t.Errorf("err=%v; want scim_base_url validation error", err)
	}
}

func TestGrafana_SatisfiesSCIMProvisionerInterface(_ *testing.T) {
	var _ access.SCIMProvisioner = (*GrafanaAccessConnector)(nil)
}
