package slack_enterprise

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

func newSlackEnterpriseSCIMTestServer(t *testing.T, status int, capture *[]scimRoundtrip) *httptest.Server {
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

func slackEnterpriseSCIMConfig() map[string]interface{} {
	return map[string]interface{}{}
}

func slackEnterpriseSCIMSecrets() map[string]interface{} {
	return map[string]interface{}{"token": "xoxp-grid-token"}
}

func withSlackEnterpriseSCIMTestServer(t *testing.T, srv *httptest.Server) *SlackEnterpriseAccessConnector {
	t.Helper()
	conn := New()
	conn.urlOverride = srv.URL
	prev := SetSCIMClientForTest(access.NewSCIMClient().WithHTTPClient(srv.Client()))
	t.Cleanup(func() { SetSCIMClientForTest(prev) })
	return conn
}

func TestSlackEnterpriseConnector_PushSCIMUser_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSlackEnterpriseSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withSlackEnterpriseSCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), slackEnterpriseSCIMConfig(), slackEnterpriseSCIMSecrets(), access.SCIMUser{
		ExternalID:  "U1",
		UserName:    "alice@example.com",
		DisplayName: "Alice",
		Email:       "alice@example.com",
		Active:      true,
	})
	if err != nil {
		t.Fatalf("PushSCIMUser: %v", err)
	}
	if len(captured) != 1 {
		t.Fatalf("captured = %d; want 1", len(captured))
	}
	if !strings.HasSuffix(captured[0].Path, "/scim/v2/Users") {
		t.Errorf("path = %q; want suffix /scim/v2/Users", captured[0].Path)
	}
	if captured[0].Auth != "Bearer xoxp-grid-token" {
		t.Errorf("auth = %q; want Bearer xoxp-grid-token", captured[0].Auth)
	}
}

func TestSlackEnterpriseConnector_PushSCIMGroup_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSlackEnterpriseSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withSlackEnterpriseSCIMTestServer(t, srv)

	if err := conn.PushSCIMGroup(context.Background(), slackEnterpriseSCIMConfig(), slackEnterpriseSCIMSecrets(), access.SCIMGroup{
		ExternalID:  "G1",
		DisplayName: "Engineering",
		MemberIDs:   []string{"U1"},
	}); err != nil {
		t.Fatalf("PushSCIMGroup: %v", err)
	}
	if !strings.HasSuffix(captured[0].Path, "/scim/v2/Groups") {
		t.Errorf("path = %q; want suffix /scim/v2/Groups", captured[0].Path)
	}
}

func TestSlackEnterpriseConnector_DeleteSCIMResource_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSlackEnterpriseSCIMTestServer(t, http.StatusNoContent, &captured)
	conn := withSlackEnterpriseSCIMTestServer(t, srv)

	if err := conn.DeleteSCIMResource(context.Background(), slackEnterpriseSCIMConfig(), slackEnterpriseSCIMSecrets(), "Users", "U9"); err != nil {
		t.Fatalf("DeleteSCIMResource: %v", err)
	}
	if captured[0].Method != http.MethodDelete {
		t.Errorf("method = %q; want DELETE", captured[0].Method)
	}
}

func TestSlackEnterpriseConnector_DeleteSCIMResource_404IsIdempotent(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSlackEnterpriseSCIMTestServer(t, http.StatusNotFound, &captured)
	conn := withSlackEnterpriseSCIMTestServer(t, srv)

	if err := conn.DeleteSCIMResource(context.Background(), slackEnterpriseSCIMConfig(), slackEnterpriseSCIMSecrets(), "Users", "U-gone"); err != nil {
		t.Errorf("DeleteSCIMResource returned %v; want nil", err)
	}
}

func TestSlackEnterpriseConnector_PushSCIMUser_ServerErrorSurfaces(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSlackEnterpriseSCIMTestServer(t, http.StatusBadGateway, &captured)
	conn := withSlackEnterpriseSCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), slackEnterpriseSCIMConfig(), slackEnterpriseSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteServer) {
		t.Errorf("err = %v; want wrap of access.ErrSCIMRemoteServer", err)
	}
}

func TestSlackEnterpriseConnector_PushSCIMUser_UnauthorizedSurfaces(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSlackEnterpriseSCIMTestServer(t, http.StatusUnauthorized, &captured)
	conn := withSlackEnterpriseSCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), slackEnterpriseSCIMConfig(), slackEnterpriseSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteUnauthorized) {
		t.Errorf("err = %v; want wrap of access.ErrSCIMRemoteUnauthorized", err)
	}
}

func TestSlackEnterpriseConnector_PushSCIMUser_MissingTokenSurfaces(t *testing.T) {
	conn := New()
	err := conn.PushSCIMUser(context.Background(), slackEnterpriseSCIMConfig(), map[string]interface{}{}, access.SCIMUser{ExternalID: "u", UserName: "u"})
	if err == nil {
		t.Error("PushSCIMUser returned nil; want missing-token error")
	}
}

func TestSlackEnterpriseConnector_SatisfiesSCIMProvisionerInterface(t *testing.T) {
	var _ access.SCIMProvisioner = New()
}
