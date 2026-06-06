package slack

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

type slackSCIMRoundtrip struct {
	Method string
	Path   string
	Auth   string
	Body   string
}

func newSlackSCIMTestServer(t *testing.T, status int, capture *[]slackSCIMRoundtrip) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		*capture = append(*capture, slackSCIMRoundtrip{
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

func slackSCIMConfig() map[string]interface{} {
	return map[string]interface{}{"team_id": "T1"}
}

func slackSCIMSecrets() map[string]interface{} {
	return map[string]interface{}{
		"bot_token":  "xoxb-bot-token",
		"scim_token": "xoxs-scim-token",
	}
}

func withSlackSCIMTestServer(t *testing.T, srv *httptest.Server) *SlackAccessConnector {
	t.Helper()
	conn := New()
	conn.urlOverride = srv.URL
	prev := SetSCIMClientForTest(access.NewSCIMClient().WithHTTPClient(srv.Client()))
	t.Cleanup(func() { SetSCIMClientForTest(prev) })
	return conn
}

func TestSlackConnector_PushSCIMUser_HappyPath(t *testing.T) {
	var captured []slackSCIMRoundtrip
	srv := newSlackSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withSlackSCIMTestServer(t, srv)

	if err := conn.PushSCIMUser(context.Background(), slackSCIMConfig(), slackSCIMSecrets(), access.SCIMUser{
		ExternalID:  "U1",
		UserName:    "alice@example.com",
		DisplayName: "Alice",
		Email:       "alice@example.com",
		Active:      true,
	}); err != nil {
		t.Fatalf("PushSCIMUser: %v", err)
	}
	if len(captured) != 1 {
		t.Fatalf("captured = %d; want 1", len(captured))
	}
	if !strings.HasSuffix(captured[0].Path, "/scim/v2/Users") {
		t.Errorf("path = %q; want suffix /scim/v2/Users", captured[0].Path)
	}
	if captured[0].Auth != "Bearer xoxs-scim-token" {
		t.Errorf("auth = %q; want Bearer xoxs-scim-token", captured[0].Auth)
	}
}

func TestSlackConnector_PushSCIMGroup_HappyPath(t *testing.T) {
	var captured []slackSCIMRoundtrip
	srv := newSlackSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withSlackSCIMTestServer(t, srv)

	if err := conn.PushSCIMGroup(context.Background(), slackSCIMConfig(), slackSCIMSecrets(), access.SCIMGroup{
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

func TestSlackConnector_DeleteSCIMResource_HappyPath(t *testing.T) {
	var captured []slackSCIMRoundtrip
	srv := newSlackSCIMTestServer(t, http.StatusNoContent, &captured)
	conn := withSlackSCIMTestServer(t, srv)

	if err := conn.DeleteSCIMResource(context.Background(), slackSCIMConfig(), slackSCIMSecrets(), "Users", "U9"); err != nil {
		t.Fatalf("DeleteSCIMResource: %v", err)
	}
	if captured[0].Method != http.MethodDelete {
		t.Errorf("method = %q; want DELETE", captured[0].Method)
	}
}

func TestSlackConnector_DeleteSCIMResource_404IsIdempotent(t *testing.T) {
	var captured []slackSCIMRoundtrip
	srv := newSlackSCIMTestServer(t, http.StatusNotFound, &captured)
	conn := withSlackSCIMTestServer(t, srv)

	if err := conn.DeleteSCIMResource(context.Background(), slackSCIMConfig(), slackSCIMSecrets(), "Users", "U-gone"); err != nil {
		t.Errorf("DeleteSCIMResource returned %v; want nil", err)
	}
}

func TestSlackConnector_PushSCIMUser_ServerErrorSurfaces(t *testing.T) {
	var captured []slackSCIMRoundtrip
	srv := newSlackSCIMTestServer(t, http.StatusBadGateway, &captured)
	conn := withSlackSCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), slackSCIMConfig(), slackSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteServer) {
		t.Errorf("err = %v; want wrap of access.ErrSCIMRemoteServer", err)
	}
}

func TestSlackConnector_PushSCIMUser_UnauthorizedSurfaces(t *testing.T) {
	var captured []slackSCIMRoundtrip
	srv := newSlackSCIMTestServer(t, http.StatusUnauthorized, &captured)
	conn := withSlackSCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), slackSCIMConfig(), slackSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteUnauthorized) {
		t.Errorf("err = %v; want wrap of access.ErrSCIMRemoteUnauthorized", err)
	}
}

func TestSlackConnector_PushSCIMUser_MissingTokenSurfaces(t *testing.T) {
	conn := New()
	secrets := map[string]interface{}{"bot_token": "xoxb-bot-token"}
	err := conn.PushSCIMUser(context.Background(), slackSCIMConfig(), secrets, access.SCIMUser{ExternalID: "u", UserName: "u"})
	if err == nil {
		t.Error("PushSCIMUser returned nil; want missing-scim-token error")
	}
	if !strings.Contains(err.Error(), "scim_token") {
		t.Errorf("err = %v; want mention of scim_token", err)
	}
}

func TestSlackConnector_SatisfiesSCIMProvisionerInterface(t *testing.T) {
	var _ access.SCIMProvisioner = New()
}
