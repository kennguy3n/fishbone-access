package auth0

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

func newSCIMTestServer(t *testing.T, status int, capture *[]scimRoundtrip) *httptest.Server {
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

func auth0SCIMConfig() map[string]interface{} {
	return map[string]interface{}{"domain": "uney.us.auth0.com"}
}

func auth0SCIMSecrets() map[string]interface{} {
	return map[string]interface{}{
		"client_id":            "cid",
		"client_secret":        "csecret",
		"management_api_token": "mgmt-token",
	}
}

func withAuth0SCIMTestServer(t *testing.T, srv *httptest.Server) *Auth0AccessConnector {
	t.Helper()
	conn := New()
	conn.urlOverride = srv.URL
	prev := SetSCIMClientForTest(access.NewSCIMClient().WithHTTPClient(srv.Client()))
	t.Cleanup(func() { SetSCIMClientForTest(prev) })
	return conn
}

func TestAuth0Connector_PushSCIMUser_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withAuth0SCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), auth0SCIMConfig(), auth0SCIMSecrets(), access.SCIMUser{
		ExternalID:  "user-1",
		UserName:    "alice@example.com",
		DisplayName: "Alice",
		Email:       "alice@example.com",
		Active:      true,
	})
	if err != nil {
		t.Fatalf("PushSCIMUser: %v", err)
	}
	if len(captured) != 1 {
		t.Fatalf("captured len = %d; want 1", len(captured))
	}
	c := captured[0]
	if c.Method != http.MethodPost {
		t.Errorf("method = %q; want POST", c.Method)
	}
	if !strings.HasSuffix(c.Path, "/api/v2/Users") {
		t.Errorf("path = %q; want suffix /api/v2/Users", c.Path)
	}
	if c.Auth != "Bearer mgmt-token" {
		t.Errorf("auth = %q; want %q", c.Auth, "Bearer mgmt-token")
	}
	if !strings.Contains(c.Body, `"externalId":"user-1"`) {
		t.Errorf("body missing externalId; body = %s", c.Body)
	}
}

func TestAuth0Connector_PushSCIMUser_NormalisesAuthHeader(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withAuth0SCIMTestServer(t, srv)

	secrets := map[string]interface{}{"management_api_token": "Bearer mgmt-token"}
	if err := conn.PushSCIMUser(context.Background(), auth0SCIMConfig(), secrets, access.SCIMUser{ExternalID: "u", UserName: "u"}); err != nil {
		t.Fatalf("PushSCIMUser: %v", err)
	}
	if got := captured[0].Auth; got != "Bearer mgmt-token" {
		t.Errorf("auth = %q; want %q (must not double-prefix)", got, "Bearer mgmt-token")
	}
}

func TestAuth0Connector_PushSCIMGroup_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withAuth0SCIMTestServer(t, srv)

	if err := conn.PushSCIMGroup(context.Background(), auth0SCIMConfig(), auth0SCIMSecrets(), access.SCIMGroup{
		ExternalID:  "g-1",
		DisplayName: "Engineering",
		MemberIDs:   []string{"u-1"},
	}); err != nil {
		t.Fatalf("PushSCIMGroup: %v", err)
	}
	if !strings.HasSuffix(captured[0].Path, "/api/v2/Groups") {
		t.Errorf("path = %q; want suffix /api/v2/Groups", captured[0].Path)
	}
}

func TestAuth0Connector_DeleteSCIMResource_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSCIMTestServer(t, http.StatusNoContent, &captured)
	conn := withAuth0SCIMTestServer(t, srv)

	if err := conn.DeleteSCIMResource(context.Background(), auth0SCIMConfig(), auth0SCIMSecrets(), "Users", "user-9"); err != nil {
		t.Fatalf("DeleteSCIMResource: %v", err)
	}
	if captured[0].Method != http.MethodDelete {
		t.Errorf("method = %q; want DELETE", captured[0].Method)
	}
	if !strings.HasSuffix(captured[0].Path, "/api/v2/Users/user-9") {
		t.Errorf("path = %q; want suffix /api/v2/Users/user-9", captured[0].Path)
	}
}

func TestAuth0Connector_DeleteSCIMResource_404IsIdempotent(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSCIMTestServer(t, http.StatusNotFound, &captured)
	conn := withAuth0SCIMTestServer(t, srv)

	if err := conn.DeleteSCIMResource(context.Background(), auth0SCIMConfig(), auth0SCIMSecrets(), "Users", "user-gone"); err != nil {
		t.Errorf("DeleteSCIMResource returned %v; want nil", err)
	}
}

func TestAuth0Connector_PushSCIMUser_ServerErrorSurfaces(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSCIMTestServer(t, http.StatusBadGateway, &captured)
	conn := withAuth0SCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), auth0SCIMConfig(), auth0SCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteServer) {
		t.Errorf("err = %v; want it to wrap access.ErrSCIMRemoteServer", err)
	}
}

func TestAuth0Connector_PushSCIMUser_UnauthorizedSurfaces(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSCIMTestServer(t, http.StatusUnauthorized, &captured)
	conn := withAuth0SCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), auth0SCIMConfig(), auth0SCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteUnauthorized) {
		t.Errorf("err = %v; want it to wrap access.ErrSCIMRemoteUnauthorized", err)
	}
}

func TestAuth0Connector_PushSCIMUser_InvalidConfigSurfaces(t *testing.T) {
	conn := New()
	err := conn.PushSCIMUser(context.Background(),
		map[string]interface{}{}, // missing domain
		auth0SCIMSecrets(),
		access.SCIMUser{ExternalID: "u", UserName: "u"},
	)
	if err == nil {
		t.Error("PushSCIMUser returned nil; want config-invalid error")
	}
}

func TestAuth0Connector_PushSCIMUser_MissingTokenSurfaces(t *testing.T) {
	conn := New()
	err := conn.PushSCIMUser(context.Background(), auth0SCIMConfig(), map[string]interface{}{
		"client_id":     "cid",
		"client_secret": "csecret",
	}, access.SCIMUser{ExternalID: "u", UserName: "u"})
	if err == nil || !strings.Contains(err.Error(), "management_api_token") {
		t.Errorf("err = %v; want missing management_api_token", err)
	}
}

func TestAuth0Connector_SatisfiesSCIMProvisionerInterface(t *testing.T) {
	var _ access.SCIMProvisioner = New()
}
