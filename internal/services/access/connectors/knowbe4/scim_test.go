package knowbe4

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

type knowbe4SCIMRoundtrip struct {
	Method string
	Path   string
	Auth   string
	Body   string
}

func newKnowbe4SCIMTestServer(t *testing.T, status int, capture *[]knowbe4SCIMRoundtrip) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		*capture = append(*capture, knowbe4SCIMRoundtrip{
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

func knowbe4SCIMConfig() map[string]interface{} { return map[string]interface{}{"region": "us"} }
func knowbe4SCIMSecrets() map[string]interface{} {
	return map[string]interface{}{"token": "v1-token", "scim_token": "scim-1"}
}

func withKnowbe4SCIMTestServer(t *testing.T, srv *httptest.Server) *KnowBe4AccessConnector {
	t.Helper()
	conn := New()
	conn.urlOverride = srv.URL
	prev := SetSCIMClientForTest(access.NewSCIMClient().WithHTTPClient(srv.Client()))
	t.Cleanup(func() { SetSCIMClientForTest(prev) })
	return conn
}

func TestKnowBe4_PushSCIMUser_HappyPath(t *testing.T) {
	var captured []knowbe4SCIMRoundtrip
	srv := newKnowbe4SCIMTestServer(t, http.StatusCreated, &captured)
	conn := withKnowbe4SCIMTestServer(t, srv)
	if err := conn.PushSCIMUser(context.Background(), knowbe4SCIMConfig(), knowbe4SCIMSecrets(), access.SCIMUser{
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

func TestKnowBe4_PushSCIMGroup_HappyPath(t *testing.T) {
	var captured []knowbe4SCIMRoundtrip
	srv := newKnowbe4SCIMTestServer(t, http.StatusCreated, &captured)
	conn := withKnowbe4SCIMTestServer(t, srv)
	if err := conn.PushSCIMGroup(context.Background(), knowbe4SCIMConfig(), knowbe4SCIMSecrets(), access.SCIMGroup{
		ExternalID: "g1", DisplayName: "Engineering",
	}); err != nil {
		t.Fatalf("PushSCIMGroup: %v", err)
	}
	if !strings.HasSuffix(captured[0].Path, "/Groups") {
		t.Errorf("path=%q; want suffix /Groups", captured[0].Path)
	}
}

func TestKnowBe4_DeleteSCIMResource_HappyPath(t *testing.T) {
	var captured []knowbe4SCIMRoundtrip
	srv := newKnowbe4SCIMTestServer(t, http.StatusNoContent, &captured)
	conn := withKnowbe4SCIMTestServer(t, srv)
	if err := conn.DeleteSCIMResource(context.Background(), knowbe4SCIMConfig(), knowbe4SCIMSecrets(), "Users", "u9"); err != nil {
		t.Fatalf("DeleteSCIMResource: %v", err)
	}
	if captured[0].Method != http.MethodDelete {
		t.Errorf("method=%q; want DELETE", captured[0].Method)
	}
}

func TestKnowBe4_DeleteSCIMResource_404IsIdempotent(t *testing.T) {
	var captured []knowbe4SCIMRoundtrip
	srv := newKnowbe4SCIMTestServer(t, http.StatusNotFound, &captured)
	conn := withKnowbe4SCIMTestServer(t, srv)
	if err := conn.DeleteSCIMResource(context.Background(), knowbe4SCIMConfig(), knowbe4SCIMSecrets(), "Users", "missing"); err != nil {
		t.Errorf("Delete on 404 returned %v; want nil", err)
	}
}

func TestKnowBe4_PushSCIMUser_ServerErrorSurfaces(t *testing.T) {
	var captured []knowbe4SCIMRoundtrip
	srv := newKnowbe4SCIMTestServer(t, http.StatusInternalServerError, &captured)
	conn := withKnowbe4SCIMTestServer(t, srv)
	err := conn.PushSCIMUser(context.Background(), knowbe4SCIMConfig(), knowbe4SCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteServer) {
		t.Errorf("err=%v; want wrap of access.ErrSCIMRemoteServer", err)
	}
}

func TestKnowBe4_PushSCIMUser_UnauthorizedSurfaces(t *testing.T) {
	var captured []knowbe4SCIMRoundtrip
	srv := newKnowbe4SCIMTestServer(t, http.StatusUnauthorized, &captured)
	conn := withKnowbe4SCIMTestServer(t, srv)
	err := conn.PushSCIMUser(context.Background(), knowbe4SCIMConfig(), knowbe4SCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteUnauthorized) {
		t.Errorf("err=%v; want wrap of access.ErrSCIMRemoteUnauthorized", err)
	}
}

func TestKnowBe4_PushSCIMUser_MissingSCIMTokenIsValidationError(t *testing.T) {
	conn := New()
	err := conn.PushSCIMUser(context.Background(), knowbe4SCIMConfig(), map[string]interface{}{"token": "v1-token"}, access.SCIMUser{ExternalID: "u", UserName: "u"})
	if err == nil || !strings.Contains(err.Error(), "scim_token is required") {
		t.Errorf("err=%v; want scim_token-required validation error", err)
	}
}

func TestKnowBe4_SatisfiesSCIMProvisionerInterface(_ *testing.T) {
	var _ access.SCIMProvisioner = (*KnowBe4AccessConnector)(nil)
}
