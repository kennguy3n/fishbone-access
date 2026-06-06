package aws

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

func newAWSSCIMTestServer(t *testing.T, status int, capture *[]scimRoundtrip) *httptest.Server {
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

func awsSCIMConfig(baseURL string) map[string]interface{} {
	return map[string]interface{}{"scim_base_url": baseURL}
}

func awsSCIMSecrets() map[string]interface{} {
	return map[string]interface{}{"scim_bearer_token": "aws-scim-token"}
}

func withAWSSCIMTestServer(t *testing.T, srv *httptest.Server) *AWSAccessConnector {
	t.Helper()
	conn := New()
	prev := SetSCIMClientForTest(access.NewSCIMClient().WithHTTPClient(srv.Client()))
	t.Cleanup(func() { SetSCIMClientForTest(prev) })
	return conn
}

func TestAWSConnector_PushSCIMUser_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newAWSSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withAWSSCIMTestServer(t, srv)

	if err := conn.PushSCIMUser(context.Background(), awsSCIMConfig(srv.URL+"/scim/v2"), awsSCIMSecrets(), access.SCIMUser{
		ExternalID: "u1", UserName: "alice@example.com", DisplayName: "Alice", Email: "alice@example.com", Active: true,
	}); err != nil {
		t.Fatalf("PushSCIMUser: %v", err)
	}
	if !strings.HasSuffix(captured[0].Path, "/scim/v2/Users") {
		t.Errorf("path = %q; want suffix /scim/v2/Users", captured[0].Path)
	}
	if captured[0].Auth != "Bearer aws-scim-token" {
		t.Errorf("auth = %q; want Bearer aws-scim-token", captured[0].Auth)
	}
}

func TestAWSConnector_PushSCIMGroup_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newAWSSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withAWSSCIMTestServer(t, srv)

	if err := conn.PushSCIMGroup(context.Background(), awsSCIMConfig(srv.URL+"/scim/v2"), awsSCIMSecrets(), access.SCIMGroup{
		ExternalID: "g1", DisplayName: "Engineering",
	}); err != nil {
		t.Fatalf("PushSCIMGroup: %v", err)
	}
	if !strings.HasSuffix(captured[0].Path, "/scim/v2/Groups") {
		t.Errorf("path = %q; want suffix /scim/v2/Groups", captured[0].Path)
	}
}

func TestAWSConnector_DeleteSCIMResource_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newAWSSCIMTestServer(t, http.StatusNoContent, &captured)
	conn := withAWSSCIMTestServer(t, srv)

	if err := conn.DeleteSCIMResource(context.Background(), awsSCIMConfig(srv.URL+"/scim/v2"), awsSCIMSecrets(), "Users", "u9"); err != nil {
		t.Fatalf("DeleteSCIMResource: %v", err)
	}
	if captured[0].Method != http.MethodDelete {
		t.Errorf("method = %q; want DELETE", captured[0].Method)
	}
}

func TestAWSConnector_DeleteSCIMResource_404IsIdempotent(t *testing.T) {
	var captured []scimRoundtrip
	srv := newAWSSCIMTestServer(t, http.StatusNotFound, &captured)
	conn := withAWSSCIMTestServer(t, srv)

	if err := conn.DeleteSCIMResource(context.Background(), awsSCIMConfig(srv.URL+"/scim/v2"), awsSCIMSecrets(), "Users", "u-gone"); err != nil {
		t.Errorf("DeleteSCIMResource returned %v; want nil", err)
	}
}

func TestAWSConnector_PushSCIMUser_ServerErrorSurfaces(t *testing.T) {
	var captured []scimRoundtrip
	srv := newAWSSCIMTestServer(t, http.StatusInternalServerError, &captured)
	conn := withAWSSCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), awsSCIMConfig(srv.URL+"/scim/v2"), awsSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteServer) {
		t.Errorf("err = %v; want wrap of access.ErrSCIMRemoteServer", err)
	}
}

func TestAWSConnector_PushSCIMUser_UnauthorizedSurfaces(t *testing.T) {
	var captured []scimRoundtrip
	srv := newAWSSCIMTestServer(t, http.StatusUnauthorized, &captured)
	conn := withAWSSCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), awsSCIMConfig(srv.URL+"/scim/v2"), awsSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteUnauthorized) {
		t.Errorf("err = %v; want wrap of access.ErrSCIMRemoteUnauthorized", err)
	}
}

func TestAWSConnector_PushSCIMUser_MissingTokenSurfaces(t *testing.T) {
	conn := New()
	err := conn.PushSCIMUser(context.Background(), awsSCIMConfig("https://example.com/scim/v2"), map[string]interface{}{}, access.SCIMUser{ExternalID: "u", UserName: "u"})
	if err == nil {
		t.Error("PushSCIMUser returned nil; want missing-token error")
	}
}

func TestAWSConnector_PushSCIMUser_MissingBaseURLSurfaces(t *testing.T) {
	conn := New()
	err := conn.PushSCIMUser(context.Background(), map[string]interface{}{}, awsSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if err == nil {
		t.Error("PushSCIMUser returned nil; want missing-base-url error")
	}
}

func TestAWSConnector_SatisfiesSCIMProvisionerInterface(t *testing.T) {
	var _ access.SCIMProvisioner = New()
}
