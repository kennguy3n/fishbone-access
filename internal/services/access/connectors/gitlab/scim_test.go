package gitlab

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

type gitlabSCIMRoundtrip struct {
	Method string
	Path   string
	Auth   string
	Body   string
}

func newGitLabSCIMTestServer(t *testing.T, status int, capture *[]gitlabSCIMRoundtrip) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		*capture = append(*capture, gitlabSCIMRoundtrip{
			Method: r.Method,
			Path:   r.URL.EscapedPath(),
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

func gitlabSCIMConfig() map[string]interface{} {
	return map[string]interface{}{"group_id": "acme-corp"}
}

func gitlabSCIMSecrets() map[string]interface{} {
	return map[string]interface{}{
		"access_token": "glpat-broad",
		"scim_token":   "glpat-scim",
	}
}

func withGitLabSCIMTestServer(t *testing.T, srv *httptest.Server) *GitLabAccessConnector {
	t.Helper()
	conn := New()
	conn.urlOverride = srv.URL
	prev := SetSCIMClientForTest(access.NewSCIMClient().WithHTTPClient(srv.Client()))
	t.Cleanup(func() { SetSCIMClientForTest(prev) })
	return conn
}

func TestGitLabConnector_PushSCIMUser_HappyPath(t *testing.T) {
	var captured []gitlabSCIMRoundtrip
	srv := newGitLabSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withGitLabSCIMTestServer(t, srv)

	if err := conn.PushSCIMUser(context.Background(), gitlabSCIMConfig(), gitlabSCIMSecrets(), access.SCIMUser{
		ExternalID:  "U1",
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
	if !strings.HasSuffix(captured[0].Path, "/api/scim/v2/groups/acme-corp/Users") {
		t.Errorf("path = %q; want suffix /api/scim/v2/groups/acme-corp/Users", captured[0].Path)
	}
	if captured[0].Auth != "Bearer glpat-scim" {
		t.Errorf("auth = %q; want Bearer glpat-scim (dedicated scim_token preferred)", captured[0].Auth)
	}
}

func TestGitLabConnector_PushSCIMUser_FallsBackToAccessTokenWhenScimTokenUnset(t *testing.T) {
	var captured []gitlabSCIMRoundtrip
	srv := newGitLabSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withGitLabSCIMTestServer(t, srv)

	secrets := map[string]interface{}{"access_token": "glpat-broad"}
	if err := conn.PushSCIMUser(context.Background(), gitlabSCIMConfig(), secrets, access.SCIMUser{
		ExternalID: "U1",
		UserName:   "alice@example.com",
	}); err != nil {
		t.Fatalf("PushSCIMUser: %v", err)
	}
	if captured[0].Auth != "Bearer glpat-broad" {
		t.Errorf("auth = %q; want Bearer glpat-broad (fallback to access_token)", captured[0].Auth)
	}
}

func TestGitLabConnector_PushSCIMUser_GroupPathOverride(t *testing.T) {
	var captured []gitlabSCIMRoundtrip
	srv := newGitLabSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withGitLabSCIMTestServer(t, srv)

	cfg := map[string]interface{}{"group_id": "12345", "group_path": "my-org/my-subgroup"}
	if err := conn.PushSCIMUser(context.Background(), cfg, gitlabSCIMSecrets(), access.SCIMUser{ExternalID: "U", UserName: "u"}); err != nil {
		t.Fatalf("PushSCIMUser: %v", err)
	}
	if !strings.Contains(captured[0].Path, "/api/scim/v2/groups/my-org%2Fmy-subgroup/Users") {
		t.Errorf("path = %q; want nested group_path URL-encoded as single segment (my-org%%2Fmy-subgroup) overriding numeric group_id", captured[0].Path)
	}
}

func TestGitLabConnector_PushSCIMGroup_HappyPath(t *testing.T) {
	var captured []gitlabSCIMRoundtrip
	srv := newGitLabSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withGitLabSCIMTestServer(t, srv)

	if err := conn.PushSCIMGroup(context.Background(), gitlabSCIMConfig(), gitlabSCIMSecrets(), access.SCIMGroup{
		ExternalID:  "G1",
		DisplayName: "Engineering",
		MemberIDs:   []string{"U1"},
	}); err != nil {
		t.Fatalf("PushSCIMGroup: %v", err)
	}
	if !strings.HasSuffix(captured[0].Path, "/Groups") {
		t.Errorf("path = %q; want suffix /Groups", captured[0].Path)
	}
}

func TestGitLabConnector_DeleteSCIMResource_404IsIdempotent(t *testing.T) {
	var captured []gitlabSCIMRoundtrip
	srv := newGitLabSCIMTestServer(t, http.StatusNotFound, &captured)
	conn := withGitLabSCIMTestServer(t, srv)

	if err := conn.DeleteSCIMResource(context.Background(), gitlabSCIMConfig(), gitlabSCIMSecrets(), "Users", "U-gone"); err != nil {
		t.Errorf("DeleteSCIMResource returned %v; want nil for 404 (idempotent)", err)
	}
}

func TestGitLabConnector_PushSCIMUser_ServerErrorSurfaces(t *testing.T) {
	var captured []gitlabSCIMRoundtrip
	srv := newGitLabSCIMTestServer(t, http.StatusBadGateway, &captured)
	conn := withGitLabSCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), gitlabSCIMConfig(), gitlabSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteServer) {
		t.Errorf("err = %v; want wrap of access.ErrSCIMRemoteServer", err)
	}
}

func TestGitLabConnector_PushSCIMUser_UnauthorizedSurfaces(t *testing.T) {
	var captured []gitlabSCIMRoundtrip
	srv := newGitLabSCIMTestServer(t, http.StatusUnauthorized, &captured)
	conn := withGitLabSCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), gitlabSCIMConfig(), gitlabSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteUnauthorized) {
		t.Errorf("err = %v; want wrap of access.ErrSCIMRemoteUnauthorized", err)
	}
}

func TestGitLabConnector_PushSCIMUser_MissingTokenSurfaces(t *testing.T) {
	conn := New()
	secrets := map[string]interface{}{}
	err := conn.PushSCIMUser(context.Background(), gitlabSCIMConfig(), secrets, access.SCIMUser{ExternalID: "u", UserName: "u"})
	if err == nil {
		t.Error("PushSCIMUser returned nil; want missing-token error")
	}
}

func TestGitLabConnector_SatisfiesSCIMProvisionerInterface(t *testing.T) {
	var _ access.SCIMProvisioner = New()
}

// TestGitLabConnector_PushSCIMUser_NumericGroupIDRequiresGroupPath
// pins the behaviour that GitLab's /api/scim/v2/groups endpoint
// requires the URL-encoded group path, not the numeric group_id. If
// the operator supplied only a numeric group_id we refuse with a
// clear error rather than silently 404ing against GitLab.
func TestGitLabConnector_PushSCIMUser_NumericGroupIDRequiresGroupPath(t *testing.T) {
	conn := New()
	cfg := map[string]interface{}{"group_id": "12345"}
	err := conn.PushSCIMUser(context.Background(), cfg, gitlabSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if err == nil {
		t.Fatal("PushSCIMUser returned nil; want numeric-group_id rejection")
	}
	msg := err.Error()
	if !strings.Contains(msg, "group_path is required") || !strings.Contains(msg, "12345") {
		t.Errorf("error = %q; want mention of group_path and the numeric id", msg)
	}
}

// TestGitLabConnector_PushSCIMUser_NumericGroupIDAcceptedWhenGroupPathSet
// pins that supplying group_path alongside a numeric group_id is
// the documented escape hatch — the SCIM call should proceed against
// the path-keyed URL.
func TestGitLabConnector_PushSCIMUser_NumericGroupIDAcceptedWhenGroupPathSet(t *testing.T) {
	captured := []string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = append(captured, r.URL.EscapedPath())
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"u"}`))
	}))
	defer srv.Close()
	conn := withGitLabSCIMTestServer(t, srv)
	cfg := map[string]interface{}{"group_id": "12345", "group_path": "acme-corp"}
	if err := conn.PushSCIMUser(context.Background(), cfg, gitlabSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"}); err != nil {
		t.Fatalf("PushSCIMUser: %v", err)
	}
	if len(captured) != 1 || !strings.Contains(captured[0], "/api/scim/v2/groups/acme-corp/Users") {
		t.Errorf("captured path = %v; want /api/scim/v2/groups/acme-corp/Users", captured)
	}
}


// TestGitLabConnector_PushSCIMUser_NestedGroupPathURLEncoded pins
// that nested group paths (with forward slashes) are URL-encoded as
// a single path segment when building the SCIM endpoint. Without
// the encoding the internal / would split into spurious path
// segments and the SCIM request would 404 on GitLab.
func TestGitLabConnector_PushSCIMUser_NestedGroupPathURLEncoded(t *testing.T) {
	captured := []string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = append(captured, r.URL.EscapedPath())
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"u"}`))
	}))
	defer srv.Close()
	conn := withGitLabSCIMTestServer(t, srv)
	cfg := map[string]interface{}{"group_id": "acme-corp", "group_path": "acme/devops"}
	if err := conn.PushSCIMUser(context.Background(), cfg, gitlabSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"}); err != nil {
		t.Fatalf("PushSCIMUser: %v", err)
	}
	if len(captured) != 1 || !strings.Contains(captured[0], "/api/scim/v2/groups/acme%2Fdevops/Users") {
		t.Errorf("captured path = %v; want /api/scim/v2/groups/acme%%2Fdevops/Users (nested group path URL-encoded as single segment)", captured)
	}
}
