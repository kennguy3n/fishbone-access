package launchdarkly

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

type ldSCIMRoundtrip struct {
	Method string
	Path   string
	Auth   string
	Body   string
}

func newLDSCIMTestServer(t *testing.T, status int, capture *[]ldSCIMRoundtrip) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		*capture = append(*capture, ldSCIMRoundtrip{
			Method: r.Method,
			Path:   r.URL.Path,
			Auth:   r.Header.Get("Authorization"),
			Body:   string(body),
		})
		mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func ldSCIMConfig() map[string]interface{} { return map[string]interface{}{} }
func ldSCIMSecrets() map[string]interface{} {
	return map[string]interface{}{"api_key": "api-1", "scim_token": "scim-1"}
}

func withLDSCIMTestServer(t *testing.T, srv *httptest.Server) *LaunchDarklyAccessConnector {
	t.Helper()
	conn := New()
	conn.urlOverride = srv.URL
	prev := SetSCIMClientForTest(access.NewSCIMClient().WithHTTPClient(srv.Client()))
	t.Cleanup(func() { SetSCIMClientForTest(prev) })
	return conn
}

func TestLaunchDarkly_PushSCIMUser_HappyPath(t *testing.T) {
	var captured []ldSCIMRoundtrip
	srv := newLDSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withLDSCIMTestServer(t, srv)
	if err := conn.PushSCIMUser(context.Background(), ldSCIMConfig(), ldSCIMSecrets(), access.SCIMUser{
		ExternalID: "u1", UserName: "alice@example.com", Email: "alice@example.com", Active: true,
	}); err != nil {
		t.Fatalf("PushSCIMUser: %v", err)
	}
	if !strings.HasSuffix(captured[0].Path, "/trust/scim/v2/Users") {
		t.Errorf("path=%q; want suffix /trust/scim/v2/Users", captured[0].Path)
	}
	if captured[0].Auth != "Bearer scim-1" {
		t.Errorf("auth=%q; want Bearer scim-1", captured[0].Auth)
	}
}

func TestLaunchDarkly_PushSCIMGroup_HappyPath(t *testing.T) {
	var captured []ldSCIMRoundtrip
	srv := newLDSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withLDSCIMTestServer(t, srv)
	if err := conn.PushSCIMGroup(context.Background(), ldSCIMConfig(), ldSCIMSecrets(), access.SCIMGroup{
		ExternalID: "g1", DisplayName: "Engineering",
	}); err != nil {
		t.Fatalf("PushSCIMGroup: %v", err)
	}
	if !strings.HasSuffix(captured[0].Path, "/Groups") {
		t.Errorf("path=%q; want suffix /Groups", captured[0].Path)
	}
}

func TestLaunchDarkly_DeleteSCIMResource_HappyPath(t *testing.T) {
	var captured []ldSCIMRoundtrip
	srv := newLDSCIMTestServer(t, http.StatusNoContent, &captured)
	conn := withLDSCIMTestServer(t, srv)
	if err := conn.DeleteSCIMResource(context.Background(), ldSCIMConfig(), ldSCIMSecrets(), "Users", "u9"); err != nil {
		t.Fatalf("DeleteSCIMResource: %v", err)
	}
	if captured[0].Method != http.MethodDelete {
		t.Errorf("method=%q; want DELETE", captured[0].Method)
	}
}

func TestLaunchDarkly_DeleteSCIMResource_404IsIdempotent(t *testing.T) {
	var captured []ldSCIMRoundtrip
	srv := newLDSCIMTestServer(t, http.StatusNotFound, &captured)
	conn := withLDSCIMTestServer(t, srv)
	if err := conn.DeleteSCIMResource(context.Background(), ldSCIMConfig(), ldSCIMSecrets(), "Users", "missing"); err != nil {
		t.Errorf("Delete on 404 returned %v; want nil", err)
	}
}

func TestLaunchDarkly_PushSCIMUser_ServerErrorSurfaces(t *testing.T) {
	var captured []ldSCIMRoundtrip
	srv := newLDSCIMTestServer(t, http.StatusInternalServerError, &captured)
	conn := withLDSCIMTestServer(t, srv)
	err := conn.PushSCIMUser(context.Background(), ldSCIMConfig(), ldSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteServer) {
		t.Errorf("err=%v; want wrap of access.ErrSCIMRemoteServer", err)
	}
}

func TestLaunchDarkly_PushSCIMUser_UnauthorizedSurfaces(t *testing.T) {
	var captured []ldSCIMRoundtrip
	srv := newLDSCIMTestServer(t, http.StatusUnauthorized, &captured)
	conn := withLDSCIMTestServer(t, srv)
	err := conn.PushSCIMUser(context.Background(), ldSCIMConfig(), ldSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteUnauthorized) {
		t.Errorf("err=%v; want wrap of access.ErrSCIMRemoteUnauthorized", err)
	}
}

func TestLaunchDarkly_PushSCIMUser_MissingSCIMTokenIsValidationError(t *testing.T) {
	conn := New()
	err := conn.PushSCIMUser(context.Background(), ldSCIMConfig(), map[string]interface{}{"api_key": "api-1"}, access.SCIMUser{ExternalID: "u", UserName: "u"})
	if err == nil || !strings.Contains(err.Error(), "scim_token is required") {
		t.Errorf("err=%v; want scim_token-required validation error", err)
	}
}

func TestLaunchDarkly_SatisfiesSCIMProvisionerInterface(_ *testing.T) {
	var _ access.SCIMProvisioner = (*LaunchDarklyAccessConnector)(nil)
}
