package ping_identity

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

func pingSCIMConfig() map[string]interface{} {
	return map[string]interface{}{
		"environment_id": "env-123",
		"region":         "NA",
	}
}

func pingSCIMSecrets() map[string]interface{} {
	return map[string]interface{}{
		"client_id":     "cid",
		"client_secret": "csecret",
		"api_key":       "ping-token",
	}
}

func withPingSCIMTestServer(t *testing.T, srv *httptest.Server) *PingIdentityAccessConnector {
	t.Helper()
	conn := New()
	conn.urlOverride = srv.URL
	prev := SetSCIMClientForTest(access.NewSCIMClient().WithHTTPClient(srv.Client()))
	t.Cleanup(func() { SetSCIMClientForTest(prev) })
	return conn
}

func TestPingConnector_PushSCIMUser_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withPingSCIMTestServer(t, srv)

	if err := conn.PushSCIMUser(context.Background(), pingSCIMConfig(), pingSCIMSecrets(), access.SCIMUser{
		ExternalID: "u-1",
		UserName:   "alice@example.com",
		Email:      "alice@example.com",
		Active:     true,
	}); err != nil {
		t.Fatalf("PushSCIMUser: %v", err)
	}
	c := captured[0]
	if c.Method != http.MethodPost {
		t.Errorf("method = %q; want POST", c.Method)
	}
	if !strings.HasSuffix(c.Path, "/v1/environments/env-123/Users") {
		t.Errorf("path = %q; want suffix /v1/environments/env-123/Users", c.Path)
	}
	if c.Auth != "Bearer ping-token" {
		t.Errorf("auth = %q; want %q", c.Auth, "Bearer ping-token")
	}
}

func TestPingConnector_PushSCIMUser_NormalisesAuthHeader(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withPingSCIMTestServer(t, srv)

	secrets := map[string]interface{}{
		"client_id":     "cid",
		"client_secret": "csecret",
		"api_key":       "Bearer ping-token",
	}
	if err := conn.PushSCIMUser(context.Background(), pingSCIMConfig(), secrets, access.SCIMUser{ExternalID: "u", UserName: "u"}); err != nil {
		t.Fatalf("PushSCIMUser: %v", err)
	}
	if got := captured[0].Auth; got != "Bearer ping-token" {
		t.Errorf("auth = %q; want %q (must not double-prefix)", got, "Bearer ping-token")
	}
}

func TestPingConnector_PushSCIMGroup_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withPingSCIMTestServer(t, srv)

	if err := conn.PushSCIMGroup(context.Background(), pingSCIMConfig(), pingSCIMSecrets(), access.SCIMGroup{
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

func TestPingConnector_DeleteSCIMResource_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSCIMTestServer(t, http.StatusNoContent, &captured)
	conn := withPingSCIMTestServer(t, srv)

	if err := conn.DeleteSCIMResource(context.Background(), pingSCIMConfig(), pingSCIMSecrets(), "Users", "u-9"); err != nil {
		t.Fatalf("DeleteSCIMResource: %v", err)
	}
	if !strings.HasSuffix(captured[0].Path, "/Users/u-9") {
		t.Errorf("path = %q; want /Users/u-9 suffix", captured[0].Path)
	}
}

func TestPingConnector_DeleteSCIMResource_404IsIdempotent(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSCIMTestServer(t, http.StatusNotFound, &captured)
	conn := withPingSCIMTestServer(t, srv)

	if err := conn.DeleteSCIMResource(context.Background(), pingSCIMConfig(), pingSCIMSecrets(), "Users", "u-gone"); err != nil {
		t.Errorf("DeleteSCIMResource returned %v; want nil", err)
	}
}

func TestPingConnector_PushSCIMUser_ServerErrorSurfaces(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSCIMTestServer(t, http.StatusInternalServerError, &captured)
	conn := withPingSCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), pingSCIMConfig(), pingSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteServer) {
		t.Errorf("err = %v; want ErrSCIMRemoteServer", err)
	}
}

func TestPingConnector_PushSCIMUser_UnauthorizedSurfaces(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSCIMTestServer(t, http.StatusUnauthorized, &captured)
	conn := withPingSCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), pingSCIMConfig(), pingSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteUnauthorized) {
		t.Errorf("err = %v; want ErrSCIMRemoteUnauthorized", err)
	}
}

func TestPingConnector_PushSCIMUser_InvalidConfigSurfaces(t *testing.T) {
	conn := New()
	err := conn.PushSCIMUser(context.Background(),
		map[string]interface{}{}, // missing env / region
		pingSCIMSecrets(),
		access.SCIMUser{ExternalID: "u", UserName: "u"},
	)
	if err == nil {
		t.Error("PushSCIMUser returned nil; want config-invalid error")
	}
}

func TestPingConnector_PushSCIMUser_MissingAPIKeySurfaces(t *testing.T) {
	conn := New()
	err := conn.PushSCIMUser(context.Background(), pingSCIMConfig(), map[string]interface{}{
		"client_id":     "cid",
		"client_secret": "csecret",
	}, access.SCIMUser{ExternalID: "u", UserName: "u"})
	if err == nil || !strings.Contains(err.Error(), "api_key") {
		t.Errorf("err = %v; want missing api_key", err)
	}
}

func TestPingConnector_SatisfiesSCIMProvisionerInterface(t *testing.T) {
	var _ access.SCIMProvisioner = New()
}
