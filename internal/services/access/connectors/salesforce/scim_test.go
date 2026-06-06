package salesforce

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

func newSalesforceSCIMTestServer(t *testing.T, status int, capture *[]scimRoundtrip) *httptest.Server {
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

func salesforceSCIMSecrets() map[string]interface{} {
	return map[string]interface{}{"access_token": "sf-token"}
}

func withSalesforceSCIMTestServer(t *testing.T, srv *httptest.Server) *SalesforceAccessConnector {
	t.Helper()
	conn := New()
	conn.urlOverride = srv.URL
	prev := SetSCIMClientForTest(access.NewSCIMClient().WithHTTPClient(srv.Client()))
	t.Cleanup(func() { SetSCIMClientForTest(prev) })
	return conn
}

func salesforceSCIMConfig(serverURL string) map[string]interface{} {
	return map[string]interface{}{"instance_url": serverURL}
}

func TestSalesforceConnector_PushSCIMUser_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSalesforceSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withSalesforceSCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), salesforceSCIMConfig(srv.URL), salesforceSCIMSecrets(), access.SCIMUser{
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
	if !strings.HasSuffix(c.Path, "/services/scim/v2/Users") {
		t.Errorf("path = %q; want suffix /services/scim/v2/Users", c.Path)
	}
	if c.Auth != "Bearer sf-token" {
		t.Errorf("auth = %q; want %q", c.Auth, "Bearer sf-token")
	}
}

func TestSalesforceConnector_PushSCIMGroup_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSalesforceSCIMTestServer(t, http.StatusCreated, &captured)
	conn := withSalesforceSCIMTestServer(t, srv)

	if err := conn.PushSCIMGroup(context.Background(), salesforceSCIMConfig(srv.URL), salesforceSCIMSecrets(), access.SCIMGroup{
		ExternalID:  "g-1",
		DisplayName: "Engineering",
		MemberIDs:   []string{"u-1"},
	}); err != nil {
		t.Fatalf("PushSCIMGroup: %v", err)
	}
	if !strings.HasSuffix(captured[0].Path, "/services/scim/v2/Groups") {
		t.Errorf("path = %q; want suffix /services/scim/v2/Groups", captured[0].Path)
	}
}

func TestSalesforceConnector_DeleteSCIMResource_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSalesforceSCIMTestServer(t, http.StatusNoContent, &captured)
	conn := withSalesforceSCIMTestServer(t, srv)

	if err := conn.DeleteSCIMResource(context.Background(), salesforceSCIMConfig(srv.URL), salesforceSCIMSecrets(), "Users", "user-9"); err != nil {
		t.Fatalf("DeleteSCIMResource: %v", err)
	}
	if captured[0].Method != http.MethodDelete {
		t.Errorf("method = %q; want DELETE", captured[0].Method)
	}
}

func TestSalesforceConnector_DeleteSCIMResource_404IsIdempotent(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSalesforceSCIMTestServer(t, http.StatusNotFound, &captured)
	conn := withSalesforceSCIMTestServer(t, srv)

	if err := conn.DeleteSCIMResource(context.Background(), salesforceSCIMConfig(srv.URL), salesforceSCIMSecrets(), "Users", "user-gone"); err != nil {
		t.Errorf("DeleteSCIMResource returned %v; want nil", err)
	}
}

func TestSalesforceConnector_PushSCIMUser_ServerErrorSurfaces(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSalesforceSCIMTestServer(t, http.StatusBadGateway, &captured)
	conn := withSalesforceSCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), salesforceSCIMConfig(srv.URL), salesforceSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteServer) {
		t.Errorf("err = %v; want wrap of access.ErrSCIMRemoteServer", err)
	}
}

func TestSalesforceConnector_PushSCIMUser_UnauthorizedSurfaces(t *testing.T) {
	var captured []scimRoundtrip
	srv := newSalesforceSCIMTestServer(t, http.StatusUnauthorized, &captured)
	conn := withSalesforceSCIMTestServer(t, srv)

	err := conn.PushSCIMUser(context.Background(), salesforceSCIMConfig(srv.URL), salesforceSCIMSecrets(), access.SCIMUser{ExternalID: "u", UserName: "u"})
	if !errors.Is(err, access.ErrSCIMRemoteUnauthorized) {
		t.Errorf("err = %v; want wrap of access.ErrSCIMRemoteUnauthorized", err)
	}
}

func TestSalesforceConnector_PushSCIMUser_InvalidConfigSurfaces(t *testing.T) {
	conn := New()
	err := conn.PushSCIMUser(context.Background(),
		map[string]interface{}{}, // missing instance_url
		salesforceSCIMSecrets(),
		access.SCIMUser{ExternalID: "u", UserName: "u"},
	)
	if err == nil {
		t.Error("PushSCIMUser returned nil; want config-invalid error")
	}
}

func TestSalesforceConnector_SatisfiesSCIMProvisionerInterface(t *testing.T) {
	var _ access.SCIMProvisioner = New()
}
