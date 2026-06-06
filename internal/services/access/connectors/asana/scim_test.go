package asana

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

type scimRoundtrip struct {
	Method string
	Path   string
	Auth   string
	Body   string
}

func newAsanaSCIMTestServer(t *testing.T, status int, capture *[]scimRoundtrip) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		*capture = append(*capture, scimRoundtrip{
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

func asanaSCIMConfig() map[string]interface{} { return map[string]interface{}{"workspace_gid": "W1"} }
func asanaSCIMSecrets() map[string]interface{} {
	return map[string]interface{}{"access_token": "asana-token"}
}

func withAsanaSCIMTestServer(t *testing.T, srv *httptest.Server) *AsanaAccessConnector {
	t.Helper()
	conn := New()
	conn.urlOverride = srv.URL
	prev := SetSCIMClientForTest(access.NewSCIMClient().WithHTTPClient(srv.Client()))
	t.Cleanup(func() { SetSCIMClientForTest(prev) })
	return conn
}

func TestAsanaConnector_PushSCIMUser_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newAsanaSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withAsanaSCIMTestServer(t, srv)

	if err := conn.PushSCIMUser(context.Background(), asanaSCIMConfig(), asanaSCIMSecrets(), access.SCIMUser{
		ExternalID: "u1", UserName: "alice@example.com", DisplayName: "Alice", Email: "alice@example.com", Active: true,
	}); err != nil {
		t.Fatalf("PushSCIMUser: %v", err)
	}
	if !strings.HasSuffix(captured[0].Path, "/scim/Users") {
		t.Errorf("path = %q; want suffix /scim/Users", captured[0].Path)
	}
	if captured[0].Auth != "Bearer asana-token" {
		t.Errorf("auth = %q; want Bearer asana-token", captured[0].Auth)
	}
}

func TestAsanaConnector_PushSCIMGroup_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newAsanaSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withAsanaSCIMTestServer(t, srv)

	if err := conn.PushSCIMGroup(context.Background(), asanaSCIMConfig(), asanaSCIMSecrets(), access.SCIMGroup{
		ExternalID: "g1", DisplayName: "Engineering",
	}); err != nil {
		t.Fatalf("PushSCIMGroup: %v", err)
	}
	if !strings.HasSuffix(captured[0].Path, "/scim/Groups") {
		t.Errorf("path = %q; want suffix /scim/Groups", captured[0].Path)
	}
}

func TestAsanaConnector_DeleteSCIMResource_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newAsanaSCIMTestServer(t, http.StatusNoContent, &captured)
	conn := withAsanaSCIMTestServer(t, srv)

	if err := conn.DeleteSCIMResource(context.Background(), asanaSCIMConfig(), asanaSCIMSecrets(), "Users", "u9"); err != nil {
		t.Fatalf("DeleteSCIMResource: %v", err)
	}
	if captured[0].Method != http.MethodDelete {
		t.Errorf("method = %q; want DELETE", captured[0].Method)
	}
}

func TestAsanaConnector_DeleteSCIMResource_404IsIdempotent(t *testing.T) {
	var captured []scimRoundtrip
	srv := newAsanaSCIMTestServer(t, http.StatusNotFound, &captured)
	conn := withAsanaSCIMTestServer(t, srv)

	if err := conn.DeleteSCIMResource(context.Background(), asanaSCIMConfig(), asanaSCIMSecrets(), "Users", "u-gone"); err != nil {
		t.Errorf("DeleteSCIMResource returned %v; want nil", err)
	}
}

func TestAsanaConnector_PushSCIMUser_ServerErrorSurfaces(t *testing.T) {
	var captured []scimRoundtrip
	srv := newAsanaSCIMTestServer(t, http.StatusInternalServerError, &captured)
	conn := withAsanaSCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), asanaSCIMConfig(), asanaSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteServer) {
		t.Errorf("err = %v; want wrap of access.ErrSCIMRemoteServer", err)
	}
}

func TestAsanaConnector_PushSCIMUser_UnauthorizedSurfaces(t *testing.T) {
	var captured []scimRoundtrip
	srv := newAsanaSCIMTestServer(t, http.StatusUnauthorized, &captured)
	conn := withAsanaSCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), asanaSCIMConfig(), asanaSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteUnauthorized) {
		t.Errorf("err = %v; want wrap of access.ErrSCIMRemoteUnauthorized", err)
	}
}

func TestAsanaConnector_PushSCIMUser_MissingTokenSurfaces(t *testing.T) {
	conn := New()
	err := conn.PushSCIMUser(context.Background(), asanaSCIMConfig(), map[string]interface{}{}, access.SCIMUser{ExternalID: "u", UserName: "u"})
	if err == nil {
		t.Error("PushSCIMUser returned nil; want missing-token error")
	}
}

func TestAsanaConnector_SatisfiesSCIMProvisionerInterface(t *testing.T) {
	var _ access.SCIMProvisioner = New()
}
