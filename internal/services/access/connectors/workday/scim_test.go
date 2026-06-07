package workday

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

func newWorkdaySCIMTestServer(t *testing.T, status int, capture *[]scimRoundtrip) *httptest.Server {
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

func workdaySCIMConfig() map[string]interface{} {
	return map[string]interface{}{"host": "wd5-impl-services1.workday.com", "tenant": "acme"}
}
func workdaySCIMSecrets() map[string]interface{} {
	return map[string]interface{}{"access_token": "workday-token"}
}

func withWorkdaySCIMTestServer(t *testing.T, srv *httptest.Server) *WorkdayAccessConnector {
	t.Helper()
	conn := New()
	conn.urlOverride = srv.URL
	prev := SetSCIMClientForTest(access.NewSCIMClient().WithHTTPClient(srv.Client()))
	t.Cleanup(func() { SetSCIMClientForTest(prev) })
	return conn
}

func TestWorkdayConnector_PushSCIMUser_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newWorkdaySCIMTestServer(t, http.StatusCreated, &captured)
	conn := withWorkdaySCIMTestServer(t, srv)

	if err := conn.PushSCIMUser(context.Background(), workdaySCIMConfig(), workdaySCIMSecrets(), access.SCIMUser{
		ExternalID: "u1", UserName: "alice@example.com", DisplayName: "Alice", Email: "alice@example.com", Active: true,
	}); err != nil {
		t.Fatalf("PushSCIMUser: %v", err)
	}
	if !strings.HasSuffix(captured[0].Path, "/ccx/api/scim/v2/acme/Users") {
		t.Errorf("path = %q; want suffix /ccx/api/scim/v2/acme/Users", captured[0].Path)
	}
	if captured[0].Auth != "Bearer workday-token" {
		t.Errorf("auth = %q; want Bearer workday-token", captured[0].Auth)
	}
}

func TestWorkdayConnector_PushSCIMGroup_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newWorkdaySCIMTestServer(t, http.StatusCreated, &captured)
	conn := withWorkdaySCIMTestServer(t, srv)

	if err := conn.PushSCIMGroup(context.Background(), workdaySCIMConfig(), workdaySCIMSecrets(), access.SCIMGroup{
		ExternalID: "g1", DisplayName: "Engineering",
	}); err != nil {
		t.Fatalf("PushSCIMGroup: %v", err)
	}
	if !strings.HasSuffix(captured[0].Path, "/ccx/api/scim/v2/acme/Groups") {
		t.Errorf("path = %q; want suffix /ccx/api/scim/v2/acme/Groups", captured[0].Path)
	}
}

func TestWorkdayConnector_DeleteSCIMResource_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newWorkdaySCIMTestServer(t, http.StatusNoContent, &captured)
	conn := withWorkdaySCIMTestServer(t, srv)

	if err := conn.DeleteSCIMResource(context.Background(), workdaySCIMConfig(), workdaySCIMSecrets(), "Users", "u9"); err != nil {
		t.Fatalf("DeleteSCIMResource: %v", err)
	}
	if captured[0].Method != http.MethodDelete {
		t.Errorf("method = %q; want DELETE", captured[0].Method)
	}
}

func TestWorkdayConnector_DeleteSCIMResource_404IsIdempotent(t *testing.T) {
	var captured []scimRoundtrip
	srv := newWorkdaySCIMTestServer(t, http.StatusNotFound, &captured)
	conn := withWorkdaySCIMTestServer(t, srv)

	if err := conn.DeleteSCIMResource(context.Background(), workdaySCIMConfig(), workdaySCIMSecrets(), "Users", "u-gone"); err != nil {
		t.Errorf("DeleteSCIMResource returned %v; want nil", err)
	}
}

func TestWorkdayConnector_PushSCIMUser_ServerErrorSurfaces(t *testing.T) {
	var captured []scimRoundtrip
	srv := newWorkdaySCIMTestServer(t, http.StatusInternalServerError, &captured)
	conn := withWorkdaySCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), workdaySCIMConfig(), workdaySCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteServer) {
		t.Errorf("err = %v; want wrap of access.ErrSCIMRemoteServer", err)
	}
}

func TestWorkdayConnector_PushSCIMUser_UnauthorizedSurfaces(t *testing.T) {
	var captured []scimRoundtrip
	srv := newWorkdaySCIMTestServer(t, http.StatusUnauthorized, &captured)
	conn := withWorkdaySCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), workdaySCIMConfig(), workdaySCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteUnauthorized) {
		t.Errorf("err = %v; want wrap of access.ErrSCIMRemoteUnauthorized", err)
	}
}

func TestWorkdayConnector_PushSCIMUser_MissingTokenSurfaces(t *testing.T) {
	conn := New()
	err := conn.PushSCIMUser(context.Background(), workdaySCIMConfig(), map[string]interface{}{}, access.SCIMUser{ExternalID: "u", UserName: "u"})
	if err == nil {
		t.Error("PushSCIMUser returned nil; want missing-token error")
	}
}

func TestWorkdayConnector_SatisfiesSCIMProvisionerInterface(t *testing.T) {
	var _ access.SCIMProvisioner = New()
}
