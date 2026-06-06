package github

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

func newGitHubSCIMTestServer(t *testing.T, status int, capture *[]scimRoundtrip) *httptest.Server {
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

func githubSCIMConfig() map[string]interface{} {
	return map[string]interface{}{"organization": "acme"}
}

func githubSCIMSecrets() map[string]interface{} {
	return map[string]interface{}{"access_token": "ghp-token"}
}

func withGitHubSCIMTestServer(t *testing.T, srv *httptest.Server) *GitHubAccessConnector {
	t.Helper()
	conn := New()
	conn.urlOverride = srv.URL
	prev := SetSCIMClientForTest(access.NewSCIMClient().WithHTTPClient(srv.Client()))
	t.Cleanup(func() { SetSCIMClientForTest(prev) })
	return conn
}

func TestGitHubConnector_PushSCIMUser_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newGitHubSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withGitHubSCIMTestServer(t, srv)

	if err := conn.PushSCIMUser(context.Background(), githubSCIMConfig(), githubSCIMSecrets(), access.SCIMUser{
		ExternalID:  "u1",
		UserName:    "alice",
		DisplayName: "Alice",
		Email:       "alice@example.com",
		Active:      true,
	}); err != nil {
		t.Fatalf("PushSCIMUser: %v", err)
	}
	if len(captured) != 1 {
		t.Fatalf("captured = %d; want 1", len(captured))
	}
	if !strings.HasSuffix(captured[0].Path, "/scim/v2/organizations/acme/Users") {
		t.Errorf("path = %q; want suffix /scim/v2/organizations/acme/Users", captured[0].Path)
	}
	if captured[0].Auth != "Bearer ghp-token" {
		t.Errorf("auth = %q; want Bearer ghp-token", captured[0].Auth)
	}
}

func TestGitHubConnector_PushSCIMGroup_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newGitHubSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withGitHubSCIMTestServer(t, srv)

	if err := conn.PushSCIMGroup(context.Background(), githubSCIMConfig(), githubSCIMSecrets(), access.SCIMGroup{
		ExternalID:  "g1",
		DisplayName: "Engineering",
	}); err != nil {
		t.Fatalf("PushSCIMGroup: %v", err)
	}
	if !strings.HasSuffix(captured[0].Path, "/scim/v2/organizations/acme/Groups") {
		t.Errorf("path = %q; want suffix /scim/v2/organizations/acme/Groups", captured[0].Path)
	}
}

func TestGitHubConnector_DeleteSCIMResource_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newGitHubSCIMTestServer(t, http.StatusNoContent, &captured)
	conn := withGitHubSCIMTestServer(t, srv)

	if err := conn.DeleteSCIMResource(context.Background(), githubSCIMConfig(), githubSCIMSecrets(), "Users", "u9"); err != nil {
		t.Fatalf("DeleteSCIMResource: %v", err)
	}
	if captured[0].Method != http.MethodDelete {
		t.Errorf("method = %q; want DELETE", captured[0].Method)
	}
}

func TestGitHubConnector_DeleteSCIMResource_404IsIdempotent(t *testing.T) {
	var captured []scimRoundtrip
	srv := newGitHubSCIMTestServer(t, http.StatusNotFound, &captured)
	conn := withGitHubSCIMTestServer(t, srv)

	if err := conn.DeleteSCIMResource(context.Background(), githubSCIMConfig(), githubSCIMSecrets(), "Users", "u-gone"); err != nil {
		t.Errorf("DeleteSCIMResource returned %v; want nil", err)
	}
}

func TestGitHubConnector_PushSCIMUser_ServerErrorSurfaces(t *testing.T) {
	var captured []scimRoundtrip
	srv := newGitHubSCIMTestServer(t, http.StatusInternalServerError, &captured)
	conn := withGitHubSCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), githubSCIMConfig(), githubSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteServer) {
		t.Errorf("err = %v; want wrap of access.ErrSCIMRemoteServer", err)
	}
}

func TestGitHubConnector_PushSCIMUser_UnauthorizedSurfaces(t *testing.T) {
	var captured []scimRoundtrip
	srv := newGitHubSCIMTestServer(t, http.StatusUnauthorized, &captured)
	conn := withGitHubSCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), githubSCIMConfig(), githubSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteUnauthorized) {
		t.Errorf("err = %v; want wrap of access.ErrSCIMRemoteUnauthorized", err)
	}
}

func TestGitHubConnector_PushSCIMUser_MissingOrgSurfaces(t *testing.T) {
	conn := New()
	err := conn.PushSCIMUser(context.Background(), map[string]interface{}{}, githubSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if err == nil {
		t.Error("PushSCIMUser returned nil; want missing-organization error")
	}
}

func TestGitHubConnector_SatisfiesSCIMProvisionerInterface(t *testing.T) {
	var _ access.SCIMProvisioner = New()
}
