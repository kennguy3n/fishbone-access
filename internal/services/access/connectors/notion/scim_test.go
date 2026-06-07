package notion

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

func newNotionSCIMTestServer(t *testing.T, status int, capture *[]scimRoundtrip) *httptest.Server {
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

func notionSCIMConfig() map[string]interface{} { return map[string]interface{}{} }
func notionSCIMSecrets() map[string]interface{} {
	return map[string]interface{}{"api_token": "notion-token"}
}

func withNotionSCIMTestServer(t *testing.T, srv *httptest.Server) *NotionAccessConnector {
	t.Helper()
	conn := New()
	conn.urlOverride = srv.URL
	prev := SetSCIMClientForTest(access.NewSCIMClient().WithHTTPClient(srv.Client()))
	t.Cleanup(func() { SetSCIMClientForTest(prev) })
	return conn
}

func TestNotionConnector_PushSCIMUser_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newNotionSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withNotionSCIMTestServer(t, srv)

	if err := conn.PushSCIMUser(context.Background(), notionSCIMConfig(), notionSCIMSecrets(), access.SCIMUser{
		ExternalID: "u1", UserName: "alice@example.com", DisplayName: "Alice", Email: "alice@example.com", Active: true,
	}); err != nil {
		t.Fatalf("PushSCIMUser: %v", err)
	}
	if !strings.HasSuffix(captured[0].Path, "/scim/v2/Users") {
		t.Errorf("path = %q; want suffix /scim/v2/Users", captured[0].Path)
	}
	if captured[0].Auth != "Bearer notion-token" {
		t.Errorf("auth = %q; want Bearer notion-token", captured[0].Auth)
	}
}

func TestNotionConnector_PushSCIMGroup_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newNotionSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withNotionSCIMTestServer(t, srv)

	if err := conn.PushSCIMGroup(context.Background(), notionSCIMConfig(), notionSCIMSecrets(), access.SCIMGroup{
		ExternalID: "g1", DisplayName: "Engineering",
	}); err != nil {
		t.Fatalf("PushSCIMGroup: %v", err)
	}
	if !strings.HasSuffix(captured[0].Path, "/scim/v2/Groups") {
		t.Errorf("path = %q; want suffix /scim/v2/Groups", captured[0].Path)
	}
}

func TestNotionConnector_DeleteSCIMResource_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newNotionSCIMTestServer(t, http.StatusNoContent, &captured)
	conn := withNotionSCIMTestServer(t, srv)

	if err := conn.DeleteSCIMResource(context.Background(), notionSCIMConfig(), notionSCIMSecrets(), "Users", "u9"); err != nil {
		t.Fatalf("DeleteSCIMResource: %v", err)
	}
	if captured[0].Method != http.MethodDelete {
		t.Errorf("method = %q; want DELETE", captured[0].Method)
	}
}

func TestNotionConnector_DeleteSCIMResource_404IsIdempotent(t *testing.T) {
	var captured []scimRoundtrip
	srv := newNotionSCIMTestServer(t, http.StatusNotFound, &captured)
	conn := withNotionSCIMTestServer(t, srv)

	if err := conn.DeleteSCIMResource(context.Background(), notionSCIMConfig(), notionSCIMSecrets(), "Users", "u-gone"); err != nil {
		t.Errorf("DeleteSCIMResource returned %v; want nil", err)
	}
}

func TestNotionConnector_PushSCIMUser_ServerErrorSurfaces(t *testing.T) {
	var captured []scimRoundtrip
	srv := newNotionSCIMTestServer(t, http.StatusInternalServerError, &captured)
	conn := withNotionSCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), notionSCIMConfig(), notionSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteServer) {
		t.Errorf("err = %v; want wrap of access.ErrSCIMRemoteServer", err)
	}
}

func TestNotionConnector_PushSCIMUser_UnauthorizedSurfaces(t *testing.T) {
	var captured []scimRoundtrip
	srv := newNotionSCIMTestServer(t, http.StatusUnauthorized, &captured)
	conn := withNotionSCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), notionSCIMConfig(), notionSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteUnauthorized) {
		t.Errorf("err = %v; want wrap of access.ErrSCIMRemoteUnauthorized", err)
	}
}

func TestNotionConnector_PushSCIMUser_MissingTokenSurfaces(t *testing.T) {
	conn := New()
	err := conn.PushSCIMUser(context.Background(), notionSCIMConfig(), map[string]interface{}{}, access.SCIMUser{ExternalID: "u", UserName: "u"})
	if err == nil {
		t.Error("PushSCIMUser returned nil; want missing-token error")
	}
}

func TestNotionConnector_SatisfiesSCIMProvisionerInterface(t *testing.T) {
	var _ access.SCIMProvisioner = New()
}
