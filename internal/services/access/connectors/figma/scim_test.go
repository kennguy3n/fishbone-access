package figma

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

func newFigmaSCIMTestServer(t *testing.T, status int, capture *[]scimRoundtrip) *httptest.Server {
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

func figmaSCIMConfig() map[string]interface{} { return map[string]interface{}{"team_id": "T1"} }
func figmaSCIMSecrets() map[string]interface{} {
	return map[string]interface{}{"access_token": "figma-token"}
}

func withFigmaSCIMTestServer(t *testing.T, srv *httptest.Server) *FigmaAccessConnector {
	t.Helper()
	conn := New()
	conn.urlOverride = srv.URL
	prev := SetSCIMClientForTest(access.NewSCIMClient().WithHTTPClient(srv.Client()))
	t.Cleanup(func() { SetSCIMClientForTest(prev) })
	return conn
}

func TestFigmaConnector_PushSCIMUser_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newFigmaSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withFigmaSCIMTestServer(t, srv)

	if err := conn.PushSCIMUser(context.Background(), figmaSCIMConfig(), figmaSCIMSecrets(), access.SCIMUser{
		ExternalID: "u1", UserName: "alice@example.com", DisplayName: "Alice", Email: "alice@example.com", Active: true,
	}); err != nil {
		t.Fatalf("PushSCIMUser: %v", err)
	}
	if captured[0].Path != "/scim/v2/Users" {
		t.Errorf("path = %q; want exactly /scim/v2/Users", captured[0].Path)
	}
	if captured[0].Auth != "Bearer figma-token" {
		t.Errorf("auth = %q; want Bearer figma-token", captured[0].Auth)
	}
}

// TestFigmaConnector_scimBaseURL_StripsRESTPrefix locks in that the
// SCIM base URL is the host root (`/scim/v2`) and not the REST API's
// `/v1` version prefix — a regression caught during review.
func TestFigmaConnector_scimBaseURL_StripsRESTPrefix(t *testing.T) {
	conn := New()
	conn.urlOverride = "https://api.figma.com/v1"
	cfg, _, err := conn.scimConfig(figmaSCIMConfig(), figmaSCIMSecrets())
	if err != nil {
		t.Fatalf("scimConfig: %v", err)
	}
	if got, _ := cfg["scim_base_url"].(string); got != "https://api.figma.com/scim/v2" {
		t.Errorf("scim_base_url = %q; want https://api.figma.com/scim/v2", got)
	}
}

func TestFigmaConnector_PushSCIMGroup_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newFigmaSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withFigmaSCIMTestServer(t, srv)

	if err := conn.PushSCIMGroup(context.Background(), figmaSCIMConfig(), figmaSCIMSecrets(), access.SCIMGroup{
		ExternalID: "g1", DisplayName: "Engineering",
	}); err != nil {
		t.Fatalf("PushSCIMGroup: %v", err)
	}
	if !strings.HasSuffix(captured[0].Path, "/scim/v2/Groups") {
		t.Errorf("path = %q; want suffix /scim/v2/Groups", captured[0].Path)
	}
}

func TestFigmaConnector_DeleteSCIMResource_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newFigmaSCIMTestServer(t, http.StatusNoContent, &captured)
	conn := withFigmaSCIMTestServer(t, srv)

	if err := conn.DeleteSCIMResource(context.Background(), figmaSCIMConfig(), figmaSCIMSecrets(), "Users", "u9"); err != nil {
		t.Fatalf("DeleteSCIMResource: %v", err)
	}
	if captured[0].Method != http.MethodDelete {
		t.Errorf("method = %q; want DELETE", captured[0].Method)
	}
}

func TestFigmaConnector_DeleteSCIMResource_404IsIdempotent(t *testing.T) {
	var captured []scimRoundtrip
	srv := newFigmaSCIMTestServer(t, http.StatusNotFound, &captured)
	conn := withFigmaSCIMTestServer(t, srv)

	if err := conn.DeleteSCIMResource(context.Background(), figmaSCIMConfig(), figmaSCIMSecrets(), "Users", "u-gone"); err != nil {
		t.Errorf("DeleteSCIMResource returned %v; want nil", err)
	}
}

func TestFigmaConnector_PushSCIMUser_ServerErrorSurfaces(t *testing.T) {
	var captured []scimRoundtrip
	srv := newFigmaSCIMTestServer(t, http.StatusInternalServerError, &captured)
	conn := withFigmaSCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), figmaSCIMConfig(), figmaSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteServer) {
		t.Errorf("err = %v; want wrap of access.ErrSCIMRemoteServer", err)
	}
}

func TestFigmaConnector_PushSCIMUser_UnauthorizedSurfaces(t *testing.T) {
	var captured []scimRoundtrip
	srv := newFigmaSCIMTestServer(t, http.StatusUnauthorized, &captured)
	conn := withFigmaSCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), figmaSCIMConfig(), figmaSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteUnauthorized) {
		t.Errorf("err = %v; want wrap of access.ErrSCIMRemoteUnauthorized", err)
	}
}

func TestFigmaConnector_PushSCIMUser_MissingTokenSurfaces(t *testing.T) {
	conn := New()
	err := conn.PushSCIMUser(context.Background(), figmaSCIMConfig(), map[string]interface{}{}, access.SCIMUser{ExternalID: "u", UserName: "u"})
	if err == nil {
		t.Error("PushSCIMUser returned nil; want missing-token error")
	}
}

func TestFigmaConnector_SatisfiesSCIMProvisionerInterface(t *testing.T) {
	var _ access.SCIMProvisioner = New()
}
