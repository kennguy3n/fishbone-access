package datadog

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

func newDatadogSCIMTestServer(t *testing.T, status int, capture *[]scimRoundtrip) *httptest.Server {
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

func datadogSCIMConfig() map[string]interface{} { return map[string]interface{}{} }
func datadogSCIMSecrets() map[string]interface{} {
	return map[string]interface{}{
		"api_key":         "k",
		"application_key": "ak",
	}
}

func withDatadogSCIMTestServer(t *testing.T, srv *httptest.Server) *DatadogAccessConnector {
	t.Helper()
	conn := New()
	conn.urlOverride = srv.URL
	prev := SetSCIMClientForTest(access.NewSCIMClient().WithHTTPClient(srv.Client()))
	t.Cleanup(func() { SetSCIMClientForTest(prev) })
	return conn
}

func TestDatadogConnector_PushSCIMUser_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newDatadogSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withDatadogSCIMTestServer(t, srv)

	if err := conn.PushSCIMUser(context.Background(), datadogSCIMConfig(), datadogSCIMSecrets(), access.SCIMUser{
		ExternalID: "u1", UserName: "alice@example.com", DisplayName: "Alice", Email: "alice@example.com", Active: true,
	}); err != nil {
		t.Fatalf("PushSCIMUser: %v", err)
	}
	if captured[0].Path != "/api/v2/scim/Users" {
		t.Errorf("path = %q; want /api/v2/scim/Users", captured[0].Path)
	}
	if captured[0].Auth != "Bearer ak" {
		t.Errorf("auth = %q; want Bearer ak", captured[0].Auth)
	}
}

func TestDatadogConnector_PushSCIMGroup_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newDatadogSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withDatadogSCIMTestServer(t, srv)

	if err := conn.PushSCIMGroup(context.Background(), datadogSCIMConfig(), datadogSCIMSecrets(), access.SCIMGroup{
		ExternalID: "g1", DisplayName: "Engineering",
	}); err != nil {
		t.Fatalf("PushSCIMGroup: %v", err)
	}
	if !strings.HasSuffix(captured[0].Path, "/api/v2/scim/Groups") {
		t.Errorf("path = %q; want suffix /api/v2/scim/Groups", captured[0].Path)
	}
}

func TestDatadogConnector_DeleteSCIMResource_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newDatadogSCIMTestServer(t, http.StatusNoContent, &captured)
	conn := withDatadogSCIMTestServer(t, srv)

	if err := conn.DeleteSCIMResource(context.Background(), datadogSCIMConfig(), datadogSCIMSecrets(), "Users", "u9"); err != nil {
		t.Fatalf("DeleteSCIMResource: %v", err)
	}
	if captured[0].Method != http.MethodDelete {
		t.Errorf("method = %q; want DELETE", captured[0].Method)
	}
}

func TestDatadogConnector_DeleteSCIMResource_404IsIdempotent(t *testing.T) {
	var captured []scimRoundtrip
	srv := newDatadogSCIMTestServer(t, http.StatusNotFound, &captured)
	conn := withDatadogSCIMTestServer(t, srv)

	if err := conn.DeleteSCIMResource(context.Background(), datadogSCIMConfig(), datadogSCIMSecrets(), "Users", "u-gone"); err != nil {
		t.Errorf("DeleteSCIMResource returned %v; want nil", err)
	}
}

func TestDatadogConnector_PushSCIMUser_ServerErrorSurfaces(t *testing.T) {
	var captured []scimRoundtrip
	srv := newDatadogSCIMTestServer(t, http.StatusInternalServerError, &captured)
	conn := withDatadogSCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), datadogSCIMConfig(), datadogSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteServer) {
		t.Errorf("err = %v; want wrap of access.ErrSCIMRemoteServer", err)
	}
}

func TestDatadogConnector_PushSCIMUser_UnauthorizedSurfaces(t *testing.T) {
	var captured []scimRoundtrip
	srv := newDatadogSCIMTestServer(t, http.StatusUnauthorized, &captured)
	conn := withDatadogSCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), datadogSCIMConfig(), datadogSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteUnauthorized) {
		t.Errorf("err = %v; want wrap of access.ErrSCIMRemoteUnauthorized", err)
	}
}

func TestDatadogConnector_PushSCIMUser_MissingTokenRejected(t *testing.T) {
	conn := New()
	err := conn.PushSCIMUser(context.Background(), datadogSCIMConfig(), map[string]interface{}{
		"api_key": "k",
	}, access.SCIMUser{ExternalID: "u", UserName: "u"})
	if err == nil {
		t.Fatal("PushSCIMUser missing application_key returned nil; want error")
	}
}
