package monday

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

type mondaySCIMRoundtrip struct {
	Method string
	Path   string
	Auth   string
	Body   string
}

func newMondaySCIMTestServer(t *testing.T, status int, capture *[]mondaySCIMRoundtrip) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		*capture = append(*capture, mondaySCIMRoundtrip{
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

func mondaySCIMConfig() map[string]interface{} { return map[string]interface{}{} }
func mondaySCIMSecrets() map[string]interface{} {
	return map[string]interface{}{"api_token": "tok-1", "scim_token": "scim-1"}
}

func withMondaySCIMTestServer(t *testing.T, srv *httptest.Server) *MondayAccessConnector {
	t.Helper()
	conn := New()
	conn.urlOverride = srv.URL
	prev := SetSCIMClientForTest(access.NewSCIMClient().WithHTTPClient(srv.Client()))
	t.Cleanup(func() { SetSCIMClientForTest(prev) })
	return conn
}

func TestMonday_PushSCIMUser_HappyPath(t *testing.T) {
	var captured []mondaySCIMRoundtrip
	srv := newMondaySCIMTestServer(t, http.StatusCreated, &captured)
	conn := withMondaySCIMTestServer(t, srv)
	if err := conn.PushSCIMUser(context.Background(), mondaySCIMConfig(), mondaySCIMSecrets(), access.SCIMUser{
		ExternalID: "u1", UserName: "alice@example.com", Email: "alice@example.com", Active: true,
	}); err != nil {
		t.Fatalf("PushSCIMUser: %v", err)
	}
	if !strings.HasSuffix(captured[0].Path, "/scim/v2/Users") {
		t.Errorf("path=%q; want suffix /scim/v2/Users", captured[0].Path)
	}
	if captured[0].Auth != "Bearer scim-1" {
		t.Errorf("auth=%q; want Bearer scim-1", captured[0].Auth)
	}
}

func TestMonday_PushSCIMGroup_HappyPath(t *testing.T) {
	var captured []mondaySCIMRoundtrip
	srv := newMondaySCIMTestServer(t, http.StatusCreated, &captured)
	conn := withMondaySCIMTestServer(t, srv)
	if err := conn.PushSCIMGroup(context.Background(), mondaySCIMConfig(), mondaySCIMSecrets(), access.SCIMGroup{
		ExternalID: "g1", DisplayName: "Engineering",
	}); err != nil {
		t.Fatalf("PushSCIMGroup: %v", err)
	}
	if !strings.HasSuffix(captured[0].Path, "/Groups") {
		t.Errorf("path=%q; want suffix /Groups", captured[0].Path)
	}
}

func TestMonday_DeleteSCIMResource_HappyPath(t *testing.T) {
	var captured []mondaySCIMRoundtrip
	srv := newMondaySCIMTestServer(t, http.StatusNoContent, &captured)
	conn := withMondaySCIMTestServer(t, srv)
	if err := conn.DeleteSCIMResource(context.Background(), mondaySCIMConfig(), mondaySCIMSecrets(), "Users", "u9"); err != nil {
		t.Fatalf("DeleteSCIMResource: %v", err)
	}
	if captured[0].Method != http.MethodDelete {
		t.Errorf("method=%q; want DELETE", captured[0].Method)
	}
}

func TestMonday_DeleteSCIMResource_404IsIdempotent(t *testing.T) {
	var captured []mondaySCIMRoundtrip
	srv := newMondaySCIMTestServer(t, http.StatusNotFound, &captured)
	conn := withMondaySCIMTestServer(t, srv)
	if err := conn.DeleteSCIMResource(context.Background(), mondaySCIMConfig(), mondaySCIMSecrets(), "Users", "missing"); err != nil {
		t.Errorf("Delete on 404 returned %v; want nil", err)
	}
}

func TestMonday_PushSCIMUser_ServerErrorSurfaces(t *testing.T) {
	var captured []mondaySCIMRoundtrip
	srv := newMondaySCIMTestServer(t, http.StatusInternalServerError, &captured)
	conn := withMondaySCIMTestServer(t, srv)
	err := conn.PushSCIMUser(context.Background(), mondaySCIMConfig(), mondaySCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteServer) {
		t.Errorf("err=%v; want wrap of access.ErrSCIMRemoteServer", err)
	}
}

func TestMonday_PushSCIMUser_UnauthorizedSurfaces(t *testing.T) {
	var captured []mondaySCIMRoundtrip
	srv := newMondaySCIMTestServer(t, http.StatusUnauthorized, &captured)
	conn := withMondaySCIMTestServer(t, srv)
	err := conn.PushSCIMUser(context.Background(), mondaySCIMConfig(), mondaySCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteUnauthorized) {
		t.Errorf("err=%v; want wrap of access.ErrSCIMRemoteUnauthorized", err)
	}
}

func TestMonday_PushSCIMUser_MissingSCIMTokenIsValidationError(t *testing.T) {
	conn := New()
	err := conn.PushSCIMUser(context.Background(), mondaySCIMConfig(), map[string]interface{}{"api_token": "tok-1"}, access.SCIMUser{ExternalID: "u", UserName: "u"})
	if err == nil || !strings.Contains(err.Error(), "scim_token is required") {
		t.Errorf("err=%v; want scim_token-required validation error", err)
	}
}

func TestMonday_SatisfiesSCIMProvisionerInterface(_ *testing.T) {
	var _ access.SCIMProvisioner = (*MondayAccessConnector)(nil)
}

// TestMonday_PushSCIMUser_BaseURLOverrideReadFromConfigRaw pins
// that the `scim_base_url` override is read from configRaw — NOT
// secretsRaw. Endpoint URLs are non-sensitive routing data and
// belong with the rest of the connector configuration, matching
// the convention shared by every other SCIM-enabled connector.
// A previous version silently ignored the documented config key.
func TestMonday_PushSCIMUser_BaseURLOverrideReadFromConfigRaw(t *testing.T) {
	var captured []mondaySCIMRoundtrip
	srv := newMondaySCIMTestServer(t, http.StatusCreated, &captured)
	prev := SetSCIMClientForTest(access.NewSCIMClient().WithHTTPClient(srv.Client()))
	t.Cleanup(func() { SetSCIMClientForTest(prev) })

	conn := New() // no urlOverride: the SCIM base URL must come from configRaw
	cfg := map[string]interface{}{"scim_base_url": srv.URL}
	if err := conn.PushSCIMUser(context.Background(), cfg, mondaySCIMSecrets(), access.SCIMUser{
		ExternalID: "U1",
		UserName:   "alice@example.com",
	}); err != nil {
		t.Fatalf("PushSCIMUser: %v", err)
	}
	if len(captured) != 1 {
		t.Fatalf("captured = %d; want 1 request hitting the configRaw-provided base URL", len(captured))
	}
}

// TestMonday_PushSCIMUser_BaseURLOverrideInSecretsRawIsIgnored
// pins that putting `scim_base_url` in secretsRaw is a no-op —
// secrets are encrypted-at-rest and URLs are not secrets. If the
// operator misconfigures the key into secretsRaw the connector
// falls back to the public default endpoint, not the proxy URL.
func TestMonday_PushSCIMUser_BaseURLOverrideInSecretsRawIsIgnored(t *testing.T) {
	conn := New()
	secrets := map[string]interface{}{
		"scim_token":    "tok",
		"scim_base_url": "https://proxy.example.invalid:9999/scim/v2",
	}
	// The connector should NOT route to the invalid host even though
	// secretsRaw contains scim_base_url, because the override is
	// only read from configRaw. We assert by capturing the resolved
	// base URL through scimConfig directly.
	scimCfg, _, err := conn.scimConfig(map[string]interface{}{}, secrets)
	if err != nil {
		t.Fatalf("scimConfig: %v", err)
	}
	if got := scimCfg["scim_base_url"]; got != mondaySCIMDefaultBaseURL {
		t.Errorf("scim_base_url = %q; want default %q (secretsRaw key must be ignored)", got, mondaySCIMDefaultBaseURL)
	}
}
