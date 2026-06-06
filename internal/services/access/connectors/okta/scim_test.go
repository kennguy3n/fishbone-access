package okta

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

// withOktaSCIMTestServer points the okta connector + the
// package-level SCIMClient at the supplied test server. Returns the
// connector ready for SCIM dispatch. The previous SCIMClient is
// restored on test cleanup.
func withOktaSCIMTestServer(t *testing.T, srv *httptest.Server) *OktaAccessConnector {
	t.Helper()
	conn := New()
	conn.urlOverride = srv.URL
	prev := SetSCIMClientForTest(access.NewSCIMClient().WithHTTPClient(srv.Client()))
	t.Cleanup(func() { SetSCIMClientForTest(prev) })
	return conn
}

func oktaConfig() map[string]interface{} {
	return map[string]interface{}{"okta_domain": "uney.okta.com"}
}

func oktaSecrets() map[string]interface{} {
	return map[string]interface{}{"api_token": "deadbeef"}
}

// TestOktaConnector_PushSCIMUser_HappyPath asserts the connector
// composes the SCIM v2.0 base URL from okta_domain, forwards the
// SSWS-prefixed API token verbatim as the Authorization header,
// and POSTs a SCIM user payload to /api/scim/v2/Users.
func TestOktaConnector_PushSCIMUser_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withOktaSCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), oktaConfig(), oktaSecrets(), access.SCIMUser{
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
	if !strings.HasSuffix(c.Path, "/api/scim/v2/Users") {
		t.Errorf("path = %q; want suffix /api/scim/v2/Users", c.Path)
	}
	if c.Auth != "SSWS deadbeef" {
		t.Errorf("auth = %q; want %q", c.Auth, "SSWS deadbeef")
	}
	if !strings.Contains(c.Body, `"externalId":"user-1"`) {
		t.Errorf("body missing externalId; body = %s", c.Body)
	}
}

// TestOktaConnector_PushSCIMUser_NormalisesAuthHeader asserts the
// connector tolerates an api_token already prefixed with "SSWS "
// (operators sometimes paste it that way) without producing a
// double-prefix Authorization header.
func TestOktaConnector_PushSCIMUser_NormalisesAuthHeader(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withOktaSCIMTestServer(t, srv)

	secrets := map[string]interface{}{"api_token": "SSWS deadbeef"}
	if err := conn.PushSCIMUser(context.Background(), oktaConfig(), secrets, access.SCIMUser{ExternalID: "u", UserName: "u"}); err != nil {
		t.Fatalf("PushSCIMUser: %v", err)
	}
	if got := captured[0].Auth; got != "SSWS deadbeef" {
		t.Errorf("auth = %q; want %q (must not double-prefix)", got, "SSWS deadbeef")
	}
}

// TestOktaConnector_PushSCIMGroup_HappyPath asserts a group push
// lands at /api/scim/v2/Groups with the encoded member IDs.
func TestOktaConnector_PushSCIMGroup_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withOktaSCIMTestServer(t, srv)

	if err := conn.PushSCIMGroup(context.Background(), oktaConfig(), oktaSecrets(), access.SCIMGroup{
		ExternalID:  "g-1",
		DisplayName: "Engineering",
		MemberIDs:   []string{"u-1", "u-2"},
	}); err != nil {
		t.Fatalf("PushSCIMGroup: %v", err)
	}
	if !strings.HasSuffix(captured[0].Path, "/api/scim/v2/Groups") {
		t.Errorf("path = %q; want suffix /api/scim/v2/Groups", captured[0].Path)
	}
	if !strings.Contains(captured[0].Body, `"value":"u-1"`) || !strings.Contains(captured[0].Body, `"value":"u-2"`) {
		t.Errorf("body missing member IDs; body = %s", captured[0].Body)
	}
}

// TestOktaConnector_DeleteSCIMResource_HappyPath asserts a delete
// fires DELETE /api/scim/v2/Users/{externalID}.
func TestOktaConnector_DeleteSCIMResource_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSCIMTestServer(t, http.StatusNoContent, &captured)
	conn := withOktaSCIMTestServer(t, srv)

	if err := conn.DeleteSCIMResource(context.Background(), oktaConfig(), oktaSecrets(), "Users", "user-9"); err != nil {
		t.Fatalf("DeleteSCIMResource: %v", err)
	}
	if captured[0].Method != http.MethodDelete {
		t.Errorf("method = %q; want DELETE", captured[0].Method)
	}
	if !strings.HasSuffix(captured[0].Path, "/api/scim/v2/Users/user-9") {
		t.Errorf("path = %q; want suffix /api/scim/v2/Users/user-9", captured[0].Path)
	}
}

// TestOktaConnector_DeleteSCIMResource_404IsIdempotent asserts a
// 404 from the SCIM endpoint surfaces as a successful delete (the
// SCIM contract requires idempotency; the resource is already
// gone).
func TestOktaConnector_DeleteSCIMResource_404IsIdempotent(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSCIMTestServer(t, http.StatusNotFound, &captured)
	conn := withOktaSCIMTestServer(t, srv)

	if err := conn.DeleteSCIMResource(context.Background(), oktaConfig(), oktaSecrets(), "Users", "user-gone"); err != nil {
		t.Errorf("DeleteSCIMResource returned %v; want nil (404 must be a no-op success)", err)
	}
}

// TestOktaConnector_PushSCIMUser_ServerErrorSurfaces asserts a 5xx
// from the SCIM endpoint surfaces as access.ErrSCIMRemoteServer so
// the JML retry loop can react.
func TestOktaConnector_PushSCIMUser_ServerErrorSurfaces(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSCIMTestServer(t, http.StatusInternalServerError, &captured)
	conn := withOktaSCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), oktaConfig(), oktaSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if err == nil {
		t.Fatal("PushSCIMUser returned nil; want server-error sentinel")
	}
	if !errors.Is(err, access.ErrSCIMRemoteServer) {
		t.Errorf("err = %v; want it to wrap access.ErrSCIMRemoteServer", err)
	}
}

// TestOktaConnector_PushSCIMUser_InvalidConfigSurfaces asserts that
// a malformed connector config (missing okta_domain) surfaces as an
// error before any HTTP I/O.
func TestOktaConnector_PushSCIMUser_InvalidConfigSurfaces(t *testing.T) {
	conn := New()
	err := conn.PushSCIMUser(context.Background(),
		map[string]interface{}{}, // missing okta_domain
		oktaSecrets(),
		access.SCIMUser{ExternalID: "u", UserName: "u"},
	)
	if err == nil {
		t.Error("PushSCIMUser returned nil; want config-invalid error")
	}
}

// TestOktaConnector_SatisfiesSCIMProvisionerInterface asserts the
// connector satisfies the access.SCIMProvisioner optional interface
// at compile-time. This guards against accidental signature drift
// when the interface evolves.
func TestOktaConnector_SatisfiesSCIMProvisionerInterface(t *testing.T) {
	var _ access.SCIMProvisioner = New()
}
