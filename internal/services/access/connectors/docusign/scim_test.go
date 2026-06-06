package docusign

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

type docusignSCIMRoundtrip struct {
	Method string
	Path   string
	Auth   string
	Body   string
}

func newDocuSignSCIMTestServer(t *testing.T, status int, capture *[]docusignSCIMRoundtrip) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		*capture = append(*capture, docusignSCIMRoundtrip{
			Method: r.Method, Path: r.URL.Path, Auth: r.Header.Get("Authorization"), Body: string(body),
		})
		mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func docusignSCIMConfig() map[string]interface{} {
	return map[string]interface{}{"account_environment": "demo"}
}
func docusignSCIMSecrets() map[string]interface{} {
	return map[string]interface{}{"token": "v1", "scim_token": "scim-1"}
}

func withDocuSignSCIMTestServer(t *testing.T, srv *httptest.Server) *DocuSignAccessConnector {
	t.Helper()
	conn := New()
	conn.urlOverride = srv.URL
	prev := SetSCIMClientForTest(access.NewSCIMClient().WithHTTPClient(srv.Client()))
	t.Cleanup(func() { SetSCIMClientForTest(prev) })
	return conn
}

func TestDocuSign_PushSCIMUser_HappyPath(t *testing.T) {
	var captured []docusignSCIMRoundtrip
	srv := newDocuSignSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withDocuSignSCIMTestServer(t, srv)
	if err := conn.PushSCIMUser(context.Background(), docusignSCIMConfig(), docusignSCIMSecrets(), access.SCIMUser{
		ExternalID: "u1", UserName: "alice@example.com", Email: "alice@example.com", Active: true,
	}); err != nil {
		t.Fatalf("PushSCIMUser: %v", err)
	}
	if !strings.HasSuffix(captured[0].Path, "/scim/v2/Users") {
		t.Errorf("path=%q; want suffix /scim/v2/Users", captured[0].Path)
	}
	if captured[0].Auth != "Bearer scim-1" {
		t.Errorf("auth=%q; want Bearer scim-1", captured[0].Auth)
	}
}

func TestDocuSign_DeleteSCIMResource_404IsIdempotent(t *testing.T) {
	var captured []docusignSCIMRoundtrip
	srv := newDocuSignSCIMTestServer(t, http.StatusNotFound, &captured)
	conn := withDocuSignSCIMTestServer(t, srv)
	if err := conn.DeleteSCIMResource(context.Background(), docusignSCIMConfig(), docusignSCIMSecrets(), "Users", "missing"); err != nil {
		t.Errorf("Delete on 404 returned %v; want nil", err)
	}
}

func TestDocuSign_PushSCIMUser_ServerErrorSurfaces(t *testing.T) {
	var captured []docusignSCIMRoundtrip
	srv := newDocuSignSCIMTestServer(t, http.StatusInternalServerError, &captured)
	conn := withDocuSignSCIMTestServer(t, srv)
	err := conn.PushSCIMUser(context.Background(), docusignSCIMConfig(), docusignSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteServer) {
		t.Errorf("err=%v; want wrap of access.ErrSCIMRemoteServer", err)
	}
}

func TestDocuSign_PushSCIMUser_UnauthorizedSurfaces(t *testing.T) {
	var captured []docusignSCIMRoundtrip
	srv := newDocuSignSCIMTestServer(t, http.StatusUnauthorized, &captured)
	conn := withDocuSignSCIMTestServer(t, srv)
	err := conn.PushSCIMUser(context.Background(), docusignSCIMConfig(), docusignSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteUnauthorized) {
		t.Errorf("err=%v; want wrap of access.ErrSCIMRemoteUnauthorized", err)
	}
}

func TestDocuSign_PushSCIMUser_MissingSCIMTokenIsValidationError(t *testing.T) {
	conn := New()
	err := conn.PushSCIMUser(context.Background(), docusignSCIMConfig(), map[string]interface{}{"token": "v1"}, access.SCIMUser{ExternalID: "u", UserName: "u"})
	if err == nil || !strings.Contains(err.Error(), "scim_token is required") {
		t.Errorf("err=%v; want scim_token-required validation error", err)
	}
}

func TestDocuSign_SatisfiesSCIMProvisionerInterface(_ *testing.T) {
	var _ access.SCIMProvisioner = (*DocuSignAccessConnector)(nil)
}
