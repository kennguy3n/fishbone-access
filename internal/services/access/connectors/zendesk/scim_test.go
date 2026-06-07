package zendesk

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

func newZendeskSCIMTestServer(t *testing.T, status int, capture *[]scimRoundtrip) *httptest.Server {
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

func zendeskSCIMConfig() map[string]interface{} {
	return map[string]interface{}{"subdomain": "acme"}
}
func zendeskSCIMSecrets() map[string]interface{} {
	return map[string]interface{}{"api_token": "z-token", "email": "ops@example.com"}
}

func withZendeskSCIMTestServer(t *testing.T, srv *httptest.Server) *ZendeskAccessConnector {
	t.Helper()
	conn := New()
	conn.urlOverride = srv.URL
	prev := SetSCIMClientForTest(access.NewSCIMClient().WithHTTPClient(srv.Client()))
	t.Cleanup(func() { SetSCIMClientForTest(prev) })
	return conn
}

func TestZendeskConnector_PushSCIMUser_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newZendeskSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withZendeskSCIMTestServer(t, srv)

	if err := conn.PushSCIMUser(context.Background(), zendeskSCIMConfig(), zendeskSCIMSecrets(), access.SCIMUser{
		ExternalID: "u1", UserName: "alice@example.com", DisplayName: "Alice", Email: "alice@example.com", Active: true,
	}); err != nil {
		t.Fatalf("PushSCIMUser: %v", err)
	}
	if captured[0].Path != "/api/v2/scim/v2/Users" {
		t.Errorf("path = %q; want /api/v2/scim/v2/Users", captured[0].Path)
	}
	if !strings.HasPrefix(captured[0].Auth, "Basic ") {
		t.Errorf("auth = %q; want Basic prefix", captured[0].Auth)
	}
}

func TestZendeskConnector_PushSCIMGroup_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newZendeskSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withZendeskSCIMTestServer(t, srv)

	if err := conn.PushSCIMGroup(context.Background(), zendeskSCIMConfig(), zendeskSCIMSecrets(), access.SCIMGroup{
		ExternalID: "g1", DisplayName: "Engineering",
	}); err != nil {
		t.Fatalf("PushSCIMGroup: %v", err)
	}
	if !strings.HasSuffix(captured[0].Path, "/scim/v2/Groups") {
		t.Errorf("path = %q; want suffix /scim/v2/Groups", captured[0].Path)
	}
}

func TestZendeskConnector_DeleteSCIMResource_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newZendeskSCIMTestServer(t, http.StatusNoContent, &captured)
	conn := withZendeskSCIMTestServer(t, srv)

	if err := conn.DeleteSCIMResource(context.Background(), zendeskSCIMConfig(), zendeskSCIMSecrets(), "Users", "u9"); err != nil {
		t.Fatalf("DeleteSCIMResource: %v", err)
	}
	if captured[0].Method != http.MethodDelete {
		t.Errorf("method = %q; want DELETE", captured[0].Method)
	}
}

func TestZendeskConnector_DeleteSCIMResource_404IsIdempotent(t *testing.T) {
	var captured []scimRoundtrip
	srv := newZendeskSCIMTestServer(t, http.StatusNotFound, &captured)
	conn := withZendeskSCIMTestServer(t, srv)

	if err := conn.DeleteSCIMResource(context.Background(), zendeskSCIMConfig(), zendeskSCIMSecrets(), "Users", "u-gone"); err != nil {
		t.Errorf("DeleteSCIMResource returned %v; want nil", err)
	}
}

func TestZendeskConnector_PushSCIMUser_ServerErrorSurfaces(t *testing.T) {
	var captured []scimRoundtrip
	srv := newZendeskSCIMTestServer(t, http.StatusInternalServerError, &captured)
	conn := withZendeskSCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), zendeskSCIMConfig(), zendeskSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteServer) {
		t.Errorf("err = %v; want wrap of access.ErrSCIMRemoteServer", err)
	}
}

func TestZendeskConnector_PushSCIMUser_UnauthorizedSurfaces(t *testing.T) {
	var captured []scimRoundtrip
	srv := newZendeskSCIMTestServer(t, http.StatusUnauthorized, &captured)
	conn := withZendeskSCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), zendeskSCIMConfig(), zendeskSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteUnauthorized) {
		t.Errorf("err = %v; want wrap of access.ErrSCIMRemoteUnauthorized", err)
	}
}

func TestZendeskConnector_PushSCIMUser_MissingTokenSurfaces(t *testing.T) {
	conn := New()
	err := conn.PushSCIMUser(context.Background(), zendeskSCIMConfig(), map[string]interface{}{}, access.SCIMUser{ExternalID: "u", UserName: "u"})
	if err == nil {
		t.Error("PushSCIMUser returned nil; want missing-token error")
	}
}

func TestZendeskConnector_SatisfiesSCIMProvisionerInterface(t *testing.T) {
	var _ access.SCIMProvisioner = New()
}
