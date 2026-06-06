package sumo_logic

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

type sumoSCIMRoundtrip struct {
	Method string
	Path   string
	Auth   string
	Body   string
}

func newSumoSCIMTestServer(t *testing.T, status int, capture *[]sumoSCIMRoundtrip) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		*capture = append(*capture, sumoSCIMRoundtrip{
			Method: r.Method, Path: r.URL.Path, Auth: r.Header.Get("Authorization"), Body: string(body),
		})
		mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func sumoSCIMConfig() map[string]interface{} { return map[string]interface{}{"deployment": "us2"} }
func sumoSCIMSecrets() map[string]interface{} {
	return map[string]interface{}{"access_id": "a", "access_key": "b", "scim_token": "scim-1"}
}

func withSumoSCIMTestServer(t *testing.T, srv *httptest.Server) *SumoLogicAccessConnector {
	t.Helper()
	conn := New()
	conn.urlOverride = srv.URL
	prev := SetSCIMClientForTest(access.NewSCIMClient().WithHTTPClient(srv.Client()))
	t.Cleanup(func() { SetSCIMClientForTest(prev) })
	return conn
}

func TestSumoLogic_PushSCIMUser_HappyPath(t *testing.T) {
	var captured []sumoSCIMRoundtrip
	srv := newSumoSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withSumoSCIMTestServer(t, srv)
	if err := conn.PushSCIMUser(context.Background(), sumoSCIMConfig(), sumoSCIMSecrets(), access.SCIMUser{
		ExternalID: "u1", UserName: "alice@example.com", Email: "alice@example.com", Active: true,
	}); err != nil {
		t.Fatalf("PushSCIMUser: %v", err)
	}
	if !strings.HasSuffix(captured[0].Path, "/api/v1/scim/v2/Users") {
		t.Errorf("path=%q; want suffix /api/v1/scim/v2/Users", captured[0].Path)
	}
	if captured[0].Auth != "Bearer scim-1" {
		t.Errorf("auth=%q; want Bearer scim-1", captured[0].Auth)
	}
}

func TestSumoLogic_PushSCIMGroup_HappyPath(t *testing.T) {
	var captured []sumoSCIMRoundtrip
	srv := newSumoSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withSumoSCIMTestServer(t, srv)
	if err := conn.PushSCIMGroup(context.Background(), sumoSCIMConfig(), sumoSCIMSecrets(), access.SCIMGroup{
		ExternalID: "g1", DisplayName: "SOC",
	}); err != nil {
		t.Fatalf("PushSCIMGroup: %v", err)
	}
	if !strings.HasSuffix(captured[0].Path, "/Groups") {
		t.Errorf("path=%q; want suffix /Groups", captured[0].Path)
	}
}

func TestSumoLogic_DeleteSCIMResource_404IsIdempotent(t *testing.T) {
	var captured []sumoSCIMRoundtrip
	srv := newSumoSCIMTestServer(t, http.StatusNotFound, &captured)
	conn := withSumoSCIMTestServer(t, srv)
	if err := conn.DeleteSCIMResource(context.Background(), sumoSCIMConfig(), sumoSCIMSecrets(), "Users", "missing"); err != nil {
		t.Errorf("Delete on 404 returned %v; want nil", err)
	}
}

func TestSumoLogic_PushSCIMUser_ServerErrorSurfaces(t *testing.T) {
	var captured []sumoSCIMRoundtrip
	srv := newSumoSCIMTestServer(t, http.StatusInternalServerError, &captured)
	conn := withSumoSCIMTestServer(t, srv)
	err := conn.PushSCIMUser(context.Background(), sumoSCIMConfig(), sumoSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteServer) {
		t.Errorf("err=%v; want wrap of access.ErrSCIMRemoteServer", err)
	}
}

func TestSumoLogic_PushSCIMUser_UnauthorizedSurfaces(t *testing.T) {
	var captured []sumoSCIMRoundtrip
	srv := newSumoSCIMTestServer(t, http.StatusUnauthorized, &captured)
	conn := withSumoSCIMTestServer(t, srv)
	err := conn.PushSCIMUser(context.Background(), sumoSCIMConfig(), sumoSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteUnauthorized) {
		t.Errorf("err=%v; want wrap of access.ErrSCIMRemoteUnauthorized", err)
	}
}

func TestSumoLogic_PushSCIMUser_MissingSCIMTokenIsValidationError(t *testing.T) {
	conn := New()
	err := conn.PushSCIMUser(context.Background(), sumoSCIMConfig(), map[string]interface{}{"access_id": "a", "access_key": "b"}, access.SCIMUser{ExternalID: "u", UserName: "u"})
	if err == nil || !strings.Contains(err.Error(), "scim_token is required") {
		t.Errorf("err=%v; want scim_token-required validation error", err)
	}
}

func TestSumoLogic_SatisfiesSCIMProvisionerInterface(_ *testing.T) {
	var _ access.SCIMProvisioner = (*SumoLogicAccessConnector)(nil)
}
