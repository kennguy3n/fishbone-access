package jira

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

func newJiraSCIMTestServer(t *testing.T, status int, capture *[]scimRoundtrip) *httptest.Server {
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

func jiraSCIMConfig() map[string]interface{} {
	return map[string]interface{}{
		"cloud_id":          "cloud-1",
		"site_url":          "https://example.atlassian.net",
		"scim_directory_id": "dir-9",
	}
}

func jiraSCIMSecrets() map[string]interface{} {
	return map[string]interface{}{
		"email":      "ops@example.com",
		"api_token":  "rest-token",
		"scim_token": "scim-bearer",
	}
}

func withJiraSCIMTestServer(t *testing.T, srv *httptest.Server) *JiraAccessConnector {
	t.Helper()
	conn := New()
	conn.urlOverride = srv.URL
	prev := SetSCIMClientForTest(access.NewSCIMClient().WithHTTPClient(srv.Client()))
	t.Cleanup(func() { SetSCIMClientForTest(prev) })
	return conn
}

func TestJiraConnector_PushSCIMUser_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newJiraSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withJiraSCIMTestServer(t, srv)

	if err := conn.PushSCIMUser(context.Background(), jiraSCIMConfig(), jiraSCIMSecrets(), access.SCIMUser{
		ExternalID:  "u1",
		UserName:    "alice@example.com",
		DisplayName: "Alice",
		Email:       "alice@example.com",
		Active:      true,
	}); err != nil {
		t.Fatalf("PushSCIMUser: %v", err)
	}
	if len(captured) != 1 {
		t.Fatalf("captured = %d; want 1", len(captured))
	}
	if !strings.HasSuffix(captured[0].Path, "/scim/directory/dir-9/Users") {
		t.Errorf("path = %q; want suffix /scim/directory/dir-9/Users", captured[0].Path)
	}
	if captured[0].Auth != "Bearer scim-bearer" {
		t.Errorf("auth = %q; want Bearer scim-bearer", captured[0].Auth)
	}
}

func TestJiraConnector_PushSCIMGroup_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newJiraSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withJiraSCIMTestServer(t, srv)

	if err := conn.PushSCIMGroup(context.Background(), jiraSCIMConfig(), jiraSCIMSecrets(), access.SCIMGroup{
		ExternalID:  "g1",
		DisplayName: "Engineering",
	}); err != nil {
		t.Fatalf("PushSCIMGroup: %v", err)
	}
	if !strings.HasSuffix(captured[0].Path, "/scim/directory/dir-9/Groups") {
		t.Errorf("path = %q; want suffix /scim/directory/dir-9/Groups", captured[0].Path)
	}
}

func TestJiraConnector_DeleteSCIMResource_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newJiraSCIMTestServer(t, http.StatusNoContent, &captured)
	conn := withJiraSCIMTestServer(t, srv)

	if err := conn.DeleteSCIMResource(context.Background(), jiraSCIMConfig(), jiraSCIMSecrets(), "Users", "u9"); err != nil {
		t.Fatalf("DeleteSCIMResource: %v", err)
	}
	if captured[0].Method != http.MethodDelete {
		t.Errorf("method = %q; want DELETE", captured[0].Method)
	}
}

func TestJiraConnector_DeleteSCIMResource_404IsIdempotent(t *testing.T) {
	var captured []scimRoundtrip
	srv := newJiraSCIMTestServer(t, http.StatusNotFound, &captured)
	conn := withJiraSCIMTestServer(t, srv)

	if err := conn.DeleteSCIMResource(context.Background(), jiraSCIMConfig(), jiraSCIMSecrets(), "Users", "u-gone"); err != nil {
		t.Errorf("DeleteSCIMResource returned %v; want nil", err)
	}
}

func TestJiraConnector_PushSCIMUser_ServerErrorSurfaces(t *testing.T) {
	var captured []scimRoundtrip
	srv := newJiraSCIMTestServer(t, http.StatusServiceUnavailable, &captured)
	conn := withJiraSCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), jiraSCIMConfig(), jiraSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteServer) {
		t.Errorf("err = %v; want wrap of access.ErrSCIMRemoteServer", err)
	}
}

func TestJiraConnector_PushSCIMUser_UnauthorizedSurfaces(t *testing.T) {
	var captured []scimRoundtrip
	srv := newJiraSCIMTestServer(t, http.StatusForbidden, &captured)
	conn := withJiraSCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), jiraSCIMConfig(), jiraSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteUnauthorized) {
		t.Errorf("err = %v; want wrap of access.ErrSCIMRemoteUnauthorized", err)
	}
}

func TestJiraConnector_PushSCIMUser_MissingDirectoryIDSurfaces(t *testing.T) {
	conn := New()
	err := conn.PushSCIMUser(context.Background(), map[string]interface{}{}, jiraSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if err == nil {
		t.Error("PushSCIMUser returned nil; want missing scim_directory_id error")
	}
}

func TestJiraConnector_PushSCIMUser_MissingSCIMTokenSurfaces(t *testing.T) {
	conn := New()
	err := conn.PushSCIMUser(context.Background(),
		map[string]interface{}{"scim_directory_id": "dir-1"},
		map[string]interface{}{},
		access.SCIMUser{ExternalID: "u", UserName: "u"},
	)
	if err == nil {
		t.Error("PushSCIMUser returned nil; want missing scim_token error")
	}
}

func TestJiraConnector_SatisfiesSCIMProvisionerInterface(t *testing.T) {
	var _ access.SCIMProvisioner = New()
}
