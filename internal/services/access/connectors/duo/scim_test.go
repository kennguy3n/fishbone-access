package duo

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

type scimRoundtrip struct {
	Method string
	Path   string
	Auth   string
	Date   string
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
			Date:   r.Header.Get("Date"),
			Body:   string(body),
		})
		mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func duoSCIMConfig() map[string]interface{} {
	return map[string]interface{}{"api_hostname": "api-test.duosecurity.com"}
}

func duoSCIMSecrets() map[string]interface{} {
	return map[string]interface{}{
		"integration_key": "ikey-XXXX",
		"secret_key":      "skey-XXXX",
	}
}

func withDuoSCIMTestServer(t *testing.T, srv *httptest.Server) *DuoAccessConnector {
	t.Helper()
	conn := New()
	conn.urlOverride = srv.URL
	conn.nowFn = func() time.Time {
		return time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	}
	prev := SetSCIMInnerTransportForTest(srv.Client().Transport)
	t.Cleanup(func() { SetSCIMInnerTransportForTest(prev) })
	return conn
}

func TestDuoConnector_PushSCIMUser_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withDuoSCIMTestServer(t, srv)

	if err := conn.PushSCIMUser(context.Background(), duoSCIMConfig(), duoSCIMSecrets(), access.SCIMUser{
		ExternalID: "u-1",
		UserName:   "alice@example.com",
		Email:      "alice@example.com",
		Active:     true,
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
	if !strings.HasSuffix(c.Path, "/admin/v1/Users") {
		t.Errorf("path = %q; want /admin/v1/Users suffix", c.Path)
	}
	if !strings.HasPrefix(c.Auth, "Basic ") {
		t.Errorf("auth = %q; want Basic-prefixed signature", c.Auth)
	}
	if c.Auth == "Basic placeholder" {
		t.Errorf("auth = %q; signing transport must rewrite the placeholder", c.Auth)
	}
	if c.Date == "" {
		t.Errorf("Date header missing; HMAC requires it")
	}
}

func TestDuoConnector_PushSCIMGroup_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withDuoSCIMTestServer(t, srv)

	if err := conn.PushSCIMGroup(context.Background(), duoSCIMConfig(), duoSCIMSecrets(), access.SCIMGroup{
		ExternalID:  "g",
		DisplayName: "Eng",
		MemberIDs:   []string{"u-1"},
	}); err != nil {
		t.Fatalf("PushSCIMGroup: %v", err)
	}
	if !strings.HasSuffix(captured[0].Path, "/admin/v1/Groups") {
		t.Errorf("path = %q; want /admin/v1/Groups suffix", captured[0].Path)
	}
}

func TestDuoConnector_DeleteSCIMResource_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSCIMTestServer(t, http.StatusNoContent, &captured)
	conn := withDuoSCIMTestServer(t, srv)

	if err := conn.DeleteSCIMResource(context.Background(), duoSCIMConfig(), duoSCIMSecrets(), "Users", "u-9"); err != nil {
		t.Fatalf("DeleteSCIMResource: %v", err)
	}
	if !strings.HasSuffix(captured[0].Path, "/admin/v1/Users/u-9") {
		t.Errorf("path = %q; want /admin/v1/Users/u-9 suffix", captured[0].Path)
	}
}

func TestDuoConnector_DeleteSCIMResource_404IsIdempotent(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSCIMTestServer(t, http.StatusNotFound, &captured)
	conn := withDuoSCIMTestServer(t, srv)

	if err := conn.DeleteSCIMResource(context.Background(), duoSCIMConfig(), duoSCIMSecrets(), "Users", "u-gone"); err != nil {
		t.Errorf("DeleteSCIMResource returned %v; want nil", err)
	}
}

func TestDuoConnector_PushSCIMUser_ServerErrorSurfaces(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSCIMTestServer(t, http.StatusInternalServerError, &captured)
	conn := withDuoSCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), duoSCIMConfig(), duoSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteServer) {
		t.Errorf("err = %v; want ErrSCIMRemoteServer", err)
	}
}

func TestDuoConnector_PushSCIMUser_UnauthorizedSurfaces(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSCIMTestServer(t, http.StatusUnauthorized, &captured)
	conn := withDuoSCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), duoSCIMConfig(), duoSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteUnauthorized) {
		t.Errorf("err = %v; want ErrSCIMRemoteUnauthorized", err)
	}
}

func TestDuoConnector_PushSCIMUser_InvalidConfigSurfaces(t *testing.T) {
	conn := New()
	err := conn.PushSCIMUser(context.Background(),
		map[string]interface{}{}, // missing api_hostname
		duoSCIMSecrets(),
		access.SCIMUser{ExternalID: "u", UserName: "u"},
	)
	if err == nil {
		t.Error("PushSCIMUser returned nil; want config-invalid error")
	}
}

func TestDuoConnector_SatisfiesSCIMProvisionerInterface(t *testing.T) {
	var _ access.SCIMProvisioner = New()
}
