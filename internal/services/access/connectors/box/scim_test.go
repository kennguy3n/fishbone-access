package box

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

func newBoxSCIMTestServer(t *testing.T, status int, capture *[]scimRoundtrip) *httptest.Server {
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

func boxSCIMConfig() map[string]interface{} { return map[string]interface{}{} }
func boxSCIMSecrets() map[string]interface{} {
	return map[string]interface{}{"access_token": "box-token"}
}

func withBoxSCIMTestServer(t *testing.T, srv *httptest.Server) *BoxAccessConnector {
	t.Helper()
	conn := New()
	conn.urlOverride = srv.URL
	prev := SetSCIMClientForTest(access.NewSCIMClient().WithHTTPClient(srv.Client()))
	t.Cleanup(func() { SetSCIMClientForTest(prev) })
	return conn
}

func TestBoxConnector_PushSCIMUser_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newBoxSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withBoxSCIMTestServer(t, srv)

	if err := conn.PushSCIMUser(context.Background(), boxSCIMConfig(), boxSCIMSecrets(), access.SCIMUser{
		ExternalID: "u1", UserName: "alice@example.com", DisplayName: "Alice", Email: "alice@example.com", Active: true,
	}); err != nil {
		t.Fatalf("PushSCIMUser: %v", err)
	}
	if !strings.HasSuffix(captured[0].Path, "/2.0/scim/Users") {
		t.Errorf("path = %q; want suffix /2.0/scim/Users", captured[0].Path)
	}
	if captured[0].Auth != "Bearer box-token" {
		t.Errorf("auth = %q; want Bearer box-token", captured[0].Auth)
	}
}

func TestBoxConnector_PushSCIMGroup_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newBoxSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withBoxSCIMTestServer(t, srv)

	if err := conn.PushSCIMGroup(context.Background(), boxSCIMConfig(), boxSCIMSecrets(), access.SCIMGroup{
		ExternalID: "g1", DisplayName: "Engineering",
	}); err != nil {
		t.Fatalf("PushSCIMGroup: %v", err)
	}
	if !strings.HasSuffix(captured[0].Path, "/2.0/scim/Groups") {
		t.Errorf("path = %q; want suffix /2.0/scim/Groups", captured[0].Path)
	}
}

func TestBoxConnector_DeleteSCIMResource_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newBoxSCIMTestServer(t, http.StatusNoContent, &captured)
	conn := withBoxSCIMTestServer(t, srv)

	if err := conn.DeleteSCIMResource(context.Background(), boxSCIMConfig(), boxSCIMSecrets(), "Users", "u9"); err != nil {
		t.Fatalf("DeleteSCIMResource: %v", err)
	}
	if captured[0].Method != http.MethodDelete {
		t.Errorf("method = %q; want DELETE", captured[0].Method)
	}
}

func TestBoxConnector_DeleteSCIMResource_404IsIdempotent(t *testing.T) {
	var captured []scimRoundtrip
	srv := newBoxSCIMTestServer(t, http.StatusNotFound, &captured)
	conn := withBoxSCIMTestServer(t, srv)

	if err := conn.DeleteSCIMResource(context.Background(), boxSCIMConfig(), boxSCIMSecrets(), "Users", "u-gone"); err != nil {
		t.Errorf("DeleteSCIMResource returned %v; want nil", err)
	}
}

func TestBoxConnector_PushSCIMUser_ServerErrorSurfaces(t *testing.T) {
	var captured []scimRoundtrip
	srv := newBoxSCIMTestServer(t, http.StatusInternalServerError, &captured)
	conn := withBoxSCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), boxSCIMConfig(), boxSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteServer) {
		t.Errorf("err = %v; want wrap of access.ErrSCIMRemoteServer", err)
	}
}

func TestBoxConnector_PushSCIMUser_UnauthorizedSurfaces(t *testing.T) {
	var captured []scimRoundtrip
	srv := newBoxSCIMTestServer(t, http.StatusUnauthorized, &captured)
	conn := withBoxSCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), boxSCIMConfig(), boxSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteUnauthorized) {
		t.Errorf("err = %v; want wrap of access.ErrSCIMRemoteUnauthorized", err)
	}
}

func TestBoxConnector_PushSCIMUser_MissingTokenSurfaces(t *testing.T) {
	conn := New()
	err := conn.PushSCIMUser(context.Background(), boxSCIMConfig(), map[string]interface{}{}, access.SCIMUser{ExternalID: "u", UserName: "u"})
	if err == nil {
		t.Error("PushSCIMUser returned nil; want missing-token error")
	}
}

func TestBoxConnector_SatisfiesSCIMProvisionerInterface(t *testing.T) {
	var _ access.SCIMProvisioner = New()
}
