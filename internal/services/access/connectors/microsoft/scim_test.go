package microsoft

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

func withMicrosoftSCIMTestServer(t *testing.T, srv *httptest.Server) *M365AccessConnector {
	t.Helper()
	conn := New()
	conn.scimURLOverride = srv.URL
	conn.scimBearerTokenFor = func(_ context.Context, _ Config, _ Secrets) (string, error) {
		return "test-token", nil
	}
	prev := SetSCIMClientForTest(access.NewSCIMClient().WithHTTPClient(srv.Client()))
	t.Cleanup(func() { SetSCIMClientForTest(prev) })
	return conn
}

func TestMicrosoftConnector_PushSCIMUser_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withMicrosoftSCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), validConfig(), validSecrets(), access.SCIMUser{
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
	if !strings.HasSuffix(c.Path, "/Users") {
		t.Errorf("path = %q; want suffix /Users", c.Path)
	}
	if c.Auth != "Bearer test-token" {
		t.Errorf("auth = %q; want %q", c.Auth, "Bearer test-token")
	}
	if !strings.Contains(c.Body, `"externalId":"user-1"`) {
		t.Errorf("body missing externalId; body = %s", c.Body)
	}
}

func TestMicrosoftConnector_PushSCIMGroup_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withMicrosoftSCIMTestServer(t, srv)

	if err := conn.PushSCIMGroup(context.Background(), validConfig(), validSecrets(), access.SCIMGroup{
		ExternalID:  "g-1",
		DisplayName: "Engineering",
		MemberIDs:   []string{"u-1", "u-2"},
	}); err != nil {
		t.Fatalf("PushSCIMGroup: %v", err)
	}
	if !strings.HasSuffix(captured[0].Path, "/Groups") {
		t.Errorf("path = %q; want suffix /Groups", captured[0].Path)
	}
	if !strings.Contains(captured[0].Body, `"value":"u-1"`) {
		t.Errorf("body missing member ids; body = %s", captured[0].Body)
	}
}

func TestMicrosoftConnector_DeleteSCIMResource_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSCIMTestServer(t, http.StatusNoContent, &captured)
	conn := withMicrosoftSCIMTestServer(t, srv)

	if err := conn.DeleteSCIMResource(context.Background(), validConfig(), validSecrets(), "Users", "user-9"); err != nil {
		t.Fatalf("DeleteSCIMResource: %v", err)
	}
	if captured[0].Method != http.MethodDelete {
		t.Errorf("method = %q; want DELETE", captured[0].Method)
	}
	if !strings.HasSuffix(captured[0].Path, "/Users/user-9") {
		t.Errorf("path = %q; want suffix /Users/user-9", captured[0].Path)
	}
}

func TestMicrosoftConnector_DeleteSCIMResource_404IsIdempotent(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSCIMTestServer(t, http.StatusNotFound, &captured)
	conn := withMicrosoftSCIMTestServer(t, srv)

	if err := conn.DeleteSCIMResource(context.Background(), validConfig(), validSecrets(), "Users", "user-gone"); err != nil {
		t.Errorf("DeleteSCIMResource returned %v; want nil (404 must be a no-op success)", err)
	}
}

func TestMicrosoftConnector_PushSCIMUser_ServerErrorSurfaces(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSCIMTestServer(t, http.StatusInternalServerError, &captured)
	conn := withMicrosoftSCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), validConfig(), validSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if err == nil {
		t.Fatal("PushSCIMUser returned nil; want server-error sentinel")
	}
	if !errors.Is(err, access.ErrSCIMRemoteServer) {
		t.Errorf("err = %v; want it to wrap access.ErrSCIMRemoteServer", err)
	}
}

func TestMicrosoftConnector_PushSCIMUser_UnauthorizedSurfaces(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSCIMTestServer(t, http.StatusUnauthorized, &captured)
	conn := withMicrosoftSCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), validConfig(), validSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteUnauthorized) {
		t.Errorf("err = %v; want it to wrap access.ErrSCIMRemoteUnauthorized", err)
	}
}

func TestMicrosoftConnector_PushSCIMUser_InvalidConfigSurfaces(t *testing.T) {
	conn := New()
	conn.scimBearerTokenFor = func(_ context.Context, _ Config, _ Secrets) (string, error) {
		return "tok", nil
	}
	err := conn.PushSCIMUser(context.Background(),
		map[string]interface{}{}, // missing tenant_id / client_id
		validSecrets(),
		access.SCIMUser{ExternalID: "u", UserName: "u"},
	)
	if err == nil {
		t.Error("PushSCIMUser returned nil; want config-invalid error")
	}
}

func TestMicrosoftConnector_PushSCIMUser_TokenAcquisitionErrorSurfaces(t *testing.T) {
	conn := New()
	conn.scimURLOverride = "http://127.0.0.1:1"
	conn.scimBearerTokenFor = func(_ context.Context, _ Config, _ Secrets) (string, error) {
		return "", errors.New("oauth dial failed")
	}
	err := conn.PushSCIMUser(context.Background(), validConfig(), validSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if err == nil || !strings.Contains(err.Error(), "oauth dial failed") {
		t.Errorf("err = %v; want token acquisition surface", err)
	}
}

func TestMicrosoftConnector_DeleteSCIMResource_RejectsBadResourceType(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSCIMTestServer(t, http.StatusOK, &captured)
	conn := withMicrosoftSCIMTestServer(t, srv)

	err := conn.DeleteSCIMResource(context.Background(), validConfig(), validSecrets(), "Devices", "x")
	if !errors.Is(err, access.ErrSCIMConfigInvalid) {
		t.Errorf("err = %v; want ErrSCIMConfigInvalid", err)
	}
}

func TestMicrosoftConnector_SatisfiesSCIMProvisionerInterface(t *testing.T) {
	var _ access.SCIMProvisioner = New()
}
