package lastpass

import (
	"context"
	"encoding/base64"
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

func lpSCIMConfig() map[string]interface{} {
	return map[string]interface{}{"account_number": "12345"}
}

func lpSCIMSecrets() map[string]interface{} {
	return map[string]interface{}{
		"provisioning_hash": "ph",
		"api_key":           "apikey",
	}
}

func withLastPassSCIMTestServer(t *testing.T, srv *httptest.Server) *LastPassAccessConnector {
	t.Helper()
	conn := New()
	conn.urlOverride = srv.URL
	prev := SetSCIMClientForTest(access.NewSCIMClient().WithHTTPClient(srv.Client()))
	t.Cleanup(func() { SetSCIMClientForTest(prev) })
	return conn
}

func expectedLPAuth() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte("12345:apikey"))
}

// TestLastPassSCIMBaseURL verifies the SCIM base URL defaults to the
// SCIM 2.0 root (so the client builds .../scim/v2/Users), never the
// proprietary enterpriseapi.php endpoint, and that an operator can
// override it via configRaw["scim_base_url"].
func TestLastPassSCIMBaseURL(t *testing.T) {
	conn := New() // no urlOverride: exercise the production default
	scimCfg, _, err := conn.scimConfig(lpSCIMConfig(), lpSCIMSecrets())
	if err != nil {
		t.Fatalf("scimConfig: %v", err)
	}
	got, _ := scimCfg["scim_base_url"].(string)
	if got != lastpassSCIMDefaultBaseURL {
		t.Fatalf("default scim_base_url = %q; want %q", got, lastpassSCIMDefaultBaseURL)
	}
	if strings.Contains(got, "enterpriseapi.php") {
		t.Fatalf("SCIM base URL must not reuse the enterpriseapi.php endpoint: %q", got)
	}

	cfg := lpSCIMConfig()
	cfg["scim_base_url"] = "https://scim.proxy.example.com/v2/"
	scimCfg, _, err = conn.scimConfig(cfg, lpSCIMSecrets())
	if err != nil {
		t.Fatalf("scimConfig override: %v", err)
	}
	if got, _ := scimCfg["scim_base_url"].(string); got != "https://scim.proxy.example.com/v2" {
		t.Fatalf("override scim_base_url = %q; want trailing slash trimmed", got)
	}
}

func TestLastPassConnector_PushSCIMUser_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withLastPassSCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), lpSCIMConfig(), lpSCIMSecrets(), access.SCIMUser{
		ExternalID: "u-1",
		UserName:   "alice@example.com",
		Email:      "alice@example.com",
		Active:     true,
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
	if !strings.HasSuffix(c.Path, "/Users") {
		t.Errorf("path = %q; want suffix /Users", c.Path)
	}
	if c.Auth != expectedLPAuth() {
		t.Errorf("auth = %q; want %q", c.Auth, expectedLPAuth())
	}
}

func TestLastPassConnector_PushSCIMGroup_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withLastPassSCIMTestServer(t, srv)

	if err := conn.PushSCIMGroup(context.Background(), lpSCIMConfig(), lpSCIMSecrets(), access.SCIMGroup{
		ExternalID:  "g",
		DisplayName: "Eng",
		MemberIDs:   []string{"u-1"},
	}); err != nil {
		t.Fatalf("PushSCIMGroup: %v", err)
	}
	if !strings.HasSuffix(captured[0].Path, "/Groups") {
		t.Errorf("path = %q; want /Groups suffix", captured[0].Path)
	}
}

func TestLastPassConnector_DeleteSCIMResource_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSCIMTestServer(t, http.StatusNoContent, &captured)
	conn := withLastPassSCIMTestServer(t, srv)

	if err := conn.DeleteSCIMResource(context.Background(), lpSCIMConfig(), lpSCIMSecrets(), "Users", "u-9"); err != nil {
		t.Fatalf("DeleteSCIMResource: %v", err)
	}
	if captured[0].Method != http.MethodDelete {
		t.Errorf("method = %q; want DELETE", captured[0].Method)
	}
	if !strings.HasSuffix(captured[0].Path, "/Users/u-9") {
		t.Errorf("path = %q; want /Users/u-9 suffix", captured[0].Path)
	}
}

func TestLastPassConnector_DeleteSCIMResource_404IsIdempotent(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSCIMTestServer(t, http.StatusNotFound, &captured)
	conn := withLastPassSCIMTestServer(t, srv)

	if err := conn.DeleteSCIMResource(context.Background(), lpSCIMConfig(), lpSCIMSecrets(), "Users", "u-gone"); err != nil {
		t.Errorf("DeleteSCIMResource returned %v; want nil", err)
	}
}

func TestLastPassConnector_PushSCIMUser_ServerErrorSurfaces(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSCIMTestServer(t, http.StatusInternalServerError, &captured)
	conn := withLastPassSCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), lpSCIMConfig(), lpSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteServer) {
		t.Errorf("err = %v; want it to wrap ErrSCIMRemoteServer", err)
	}
}

func TestLastPassConnector_PushSCIMUser_UnauthorizedSurfaces(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSCIMTestServer(t, http.StatusUnauthorized, &captured)
	conn := withLastPassSCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), lpSCIMConfig(), lpSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteUnauthorized) {
		t.Errorf("err = %v; want ErrSCIMRemoteUnauthorized", err)
	}
}

func TestLastPassConnector_PushSCIMUser_InvalidConfigSurfaces(t *testing.T) {
	conn := New()
	err := conn.PushSCIMUser(context.Background(),
		map[string]interface{}{}, // missing account_number
		lpSCIMSecrets(),
		access.SCIMUser{ExternalID: "u", UserName: "u"},
	)
	if err == nil {
		t.Error("PushSCIMUser returned nil; want config-invalid error")
	}
}

func TestLastPassConnector_PushSCIMUser_MissingAPIKeySurfaces(t *testing.T) {
	conn := New()
	err := conn.PushSCIMUser(context.Background(), lpSCIMConfig(), map[string]interface{}{
		"provisioning_hash": "ph",
	}, access.SCIMUser{ExternalID: "u", UserName: "u"})
	if err == nil || !strings.Contains(err.Error(), "api_key") {
		t.Errorf("err = %v; want missing api_key", err)
	}
}

func TestLastPassConnector_SatisfiesSCIMProvisionerInterface(t *testing.T) {
	var _ access.SCIMProvisioner = New()
}
