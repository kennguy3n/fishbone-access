package onepassword

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

// scimRoundtrip captures one SCIM HTTP exchange the test server
// observed: method + path + Authorization header + raw body.
type scimRoundtrip struct {
	Method string
	Path   string
	Auth   string
	Body   string
}

// newSCIMTestServer returns an httptest.Server whose handler records
// every inbound request into the supplied capture slice. status
// drives the HTTP response code.
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

// withOnePasswordSCIMTestServer points the 1Password connector +
// the package-level SCIMClient at the supplied test server. Returns
// the connector ready for SCIM dispatch. The previous SCIMClient is
// restored on test cleanup.
func withOnePasswordSCIMTestServer(t *testing.T, srv *httptest.Server) *OnePasswordAccessConnector {
	t.Helper()
	conn := New()
	conn.urlOverride = srv.URL
	prev := SetSCIMClientForTest(access.NewSCIMClient().WithHTTPClient(srv.Client()))
	t.Cleanup(func() { SetSCIMClientForTest(prev) })
	return conn
}

func opConfig() map[string]interface{} {
	return map[string]interface{}{"account_url": "https://uney.1password.com"}
}

func opSecrets() map[string]interface{} {
	return map[string]interface{}{"scim_bridge_token": "tok-abc"}
}

// TestOnePasswordConnector_PushSCIMUser_HappyPath asserts the
// connector composes the SCIM bridge base URL, forwards the bearer
// token as the Authorization header, and POSTs a SCIM user payload
// to /scim/v2/Users.
func TestOnePasswordConnector_PushSCIMUser_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withOnePasswordSCIMTestServer(t, srv)

	if err := conn.PushSCIMUser(context.Background(), opConfig(), opSecrets(), access.SCIMUser{
		ExternalID:  "user-1",
		UserName:    "alice@example.com",
		DisplayName: "Alice",
		Email:       "alice@example.com",
		Active:      true,
	}); err != nil {
		t.Fatalf("PushSCIMUser: %v", err)
	}
	if len(captured) != 1 {
		t.Fatalf("captured len = %d; want 1", len(captured))
	}
	c := captured[0]
	if c.Method != http.MethodPost {
		t.Errorf("method = %q; want POST", c.Method)
	}
	if !strings.HasSuffix(c.Path, "/scim/v2/Users") {
		t.Errorf("path = %q; want suffix /scim/v2/Users", c.Path)
	}
	if c.Auth != "Bearer tok-abc" {
		t.Errorf("auth = %q; want %q", c.Auth, "Bearer tok-abc")
	}
	if !strings.Contains(c.Body, `"externalId":"user-1"`) {
		t.Errorf("body missing externalId; body = %s", c.Body)
	}
}

// TestOnePasswordConnector_PushSCIMUser_FallsBackToServiceAccountToken
// asserts the bearer-token fallback: if scim_bridge_token is empty
// but service_account_token is set, the connector uses the service
// account token instead.
func TestOnePasswordConnector_PushSCIMUser_FallsBackToServiceAccountToken(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withOnePasswordSCIMTestServer(t, srv)

	secrets := map[string]interface{}{"service_account_token": "svc-xyz"}
	if err := conn.PushSCIMUser(context.Background(), opConfig(), secrets, access.SCIMUser{ExternalID: "u", UserName: "u"}); err != nil {
		t.Fatalf("PushSCIMUser: %v", err)
	}
	if got := captured[0].Auth; got != "Bearer svc-xyz" {
		t.Errorf("auth = %q; want %q", got, "Bearer svc-xyz")
	}
}

// TestOnePasswordConnector_PushSCIMGroup_HappyPath asserts a group
// push lands at /scim/v2/Groups with the encoded member IDs.
func TestOnePasswordConnector_PushSCIMGroup_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withOnePasswordSCIMTestServer(t, srv)

	if err := conn.PushSCIMGroup(context.Background(), opConfig(), opSecrets(), access.SCIMGroup{
		ExternalID:  "g-1",
		DisplayName: "Engineering",
		MemberIDs:   []string{"u-1", "u-2"},
	}); err != nil {
		t.Fatalf("PushSCIMGroup: %v", err)
	}
	if !strings.HasSuffix(captured[0].Path, "/scim/v2/Groups") {
		t.Errorf("path = %q; want suffix /scim/v2/Groups", captured[0].Path)
	}
	if !strings.Contains(captured[0].Body, `"value":"u-1"`) {
		t.Errorf("body missing member u-1; body = %s", captured[0].Body)
	}
}

// TestOnePasswordConnector_DeleteSCIMResource_HappyPath asserts a
// delete fires DELETE /scim/v2/Users/{externalID}.
func TestOnePasswordConnector_DeleteSCIMResource_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSCIMTestServer(t, http.StatusNoContent, &captured)
	conn := withOnePasswordSCIMTestServer(t, srv)

	if err := conn.DeleteSCIMResource(context.Background(), opConfig(), opSecrets(), "Users", "user-9"); err != nil {
		t.Fatalf("DeleteSCIMResource: %v", err)
	}
	if captured[0].Method != http.MethodDelete {
		t.Errorf("method = %q; want DELETE", captured[0].Method)
	}
	if !strings.HasSuffix(captured[0].Path, "/scim/v2/Users/user-9") {
		t.Errorf("path = %q; want suffix /scim/v2/Users/user-9", captured[0].Path)
	}
}

// TestOnePasswordConnector_DeleteSCIMResource_404IsIdempotent asserts
// a 404 from the SCIM endpoint surfaces as a successful delete.
func TestOnePasswordConnector_DeleteSCIMResource_404IsIdempotent(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSCIMTestServer(t, http.StatusNotFound, &captured)
	conn := withOnePasswordSCIMTestServer(t, srv)

	if err := conn.DeleteSCIMResource(context.Background(), opConfig(), opSecrets(), "Users", "user-gone"); err != nil {
		t.Errorf("DeleteSCIMResource returned %v; want nil (404 must be a no-op success)", err)
	}
}

// TestOnePasswordConnector_PushSCIMUser_UnauthorizedSurfaces asserts a
// 401 from the SCIM bridge surfaces as access.ErrSCIMRemoteUnauthorized.
func TestOnePasswordConnector_PushSCIMUser_UnauthorizedSurfaces(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSCIMTestServer(t, http.StatusUnauthorized, &captured)
	conn := withOnePasswordSCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), opConfig(), opSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if err == nil {
		t.Fatal("PushSCIMUser returned nil; want unauthorized sentinel")
	}
	if !errors.Is(err, access.ErrSCIMRemoteUnauthorized) {
		t.Errorf("err = %v; want it to wrap access.ErrSCIMRemoteUnauthorized", err)
	}
}

// TestOnePasswordConnector_PushSCIMUser_InvalidConfigSurfaces asserts
// that a missing account_url surfaces as a config error before any
// HTTP I/O.
func TestOnePasswordConnector_PushSCIMUser_InvalidConfigSurfaces(t *testing.T) {
	conn := New()
	err := conn.PushSCIMUser(context.Background(),
		map[string]interface{}{}, // missing account_url
		opSecrets(),
		access.SCIMUser{ExternalID: "u", UserName: "u"},
	)
	if err == nil {
		t.Error("PushSCIMUser returned nil; want config-invalid error")
	}
}

// TestOnePasswordConnector_SatisfiesSCIMProvisionerInterface asserts
// the connector satisfies the access.SCIMProvisioner optional
// interface at compile-time.
func TestOnePasswordConnector_SatisfiesSCIMProvisionerInterface(t *testing.T) {
	var _ access.SCIMProvisioner = New()
}
