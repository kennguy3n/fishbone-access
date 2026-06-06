package asana

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

type noNetworkRoundTripper struct{}

func (noNetworkRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return nil, errors.New("network call attempted")
}

func validConfig() map[string]interface{} { return map[string]interface{}{"workspace_gid": "12345"} }
func validSecrets() map[string]interface{} {
	return map[string]interface{}{"access_token": "1/abcdef1234567890"}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_RejectsMissing(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), map[string]interface{}{}, validSecrets()); err == nil {
		t.Error("missing workspace")
	}
	if err := c.Validate(context.Background(), validConfig(), map[string]interface{}{}); err == nil {
		t.Error("missing token")
	}
}

func TestValidate_PureLocal(t *testing.T) {
	prev := http.DefaultTransport
	http.DefaultTransport = noNetworkRoundTripper{}
	t.Cleanup(func() { http.DefaultTransport = prev })
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestRegistryIntegration(t *testing.T) {
	if got, _ := access.GetAccessConnector(ProviderName); got == nil {
		t.Fatal("not registered")
	}
}

func TestSync_PaginatesUsers(t *testing.T) {
	page := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page++
		if page == 1 {
			_, _ = w.Write([]byte(`{"data":[{"gid":"u1","name":"Alice","email":"a@b.com"}],"next_page":{"offset":"OFF"}}`))
			return
		}
		if r.URL.Query().Get("offset") != "OFF" {
			t.Errorf("offset = %q", r.URL.Query().Get("offset"))
		}
		_, _ = w.Write([]byte(`{"data":[{"gid":"u2","name":"Bob","email":"b@b.com"}],"next_page":{"offset":""}}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var got []*access.Identity
	err := c.SyncIdentities(context.Background(), validConfig(), validSecrets(), "", func(b []*access.Identity, _ string) error {
		got = append(got, b...)
		return nil
	})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d", len(got))
	}
}

func TestConnect_FailureSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.Connect(context.Background(), validConfig(), validSecrets()); err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("Connect err = %v; want 403", err)
	}
}

func TestGetCredentialsMetadata(t *testing.T) {
	md, err := New().GetCredentialsMetadata(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if md["workspace_gid"] != "12345" {
		t.Errorf("workspace_gid = %v", md["workspace_gid"])
	}
}

// ---------- advanced capability tests ----------

func newAdvancedTestConnector(srv *httptest.Server) *AsanaAccessConnector {
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	return c
}

func TestProvisionAccess_HappyPath(t *testing.T) {
	var captured struct {
		method string
		path   string
		body   string
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.method = r.Method
		captured.path = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		captured.body = string(b)
		_, _ = w.Write([]byte(`{"data":{"gid":"tm-1"}}`))
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	grant := access.AccessGrant{UserExternalID: "u1", ResourceExternalID: "team-1"}
	if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
		t.Fatalf("ProvisionAccess: %v", err)
	}
	if captured.method != http.MethodPost {
		t.Errorf("method = %q", captured.method)
	}
	if !strings.HasSuffix(captured.path, "/teams/team-1/addUser") {
		t.Errorf("path = %q", captured.path)
	}
	if !strings.Contains(captured.body, `"user":"u1"`) {
		t.Errorf("body missing user field: %s", captured.body)
	}
}

func TestProvisionAccess_AlreadyMemberIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errors":[{"message":"user already a member of team"}]}`))
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	grant := access.AccessGrant{UserExternalID: "u1", ResourceExternalID: "team-1"}
	if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
		t.Fatalf("already-member 403 should be idempotent; got %v", err)
	}
}

func TestProvisionAccess_FailureSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errors":[{"message":"not authorized"}]}`))
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	grant := access.AccessGrant{UserExternalID: "u1", ResourceExternalID: "team-1"}
	if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), grant); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected 403; got %v", err)
	}
}

func TestRevokeAccess_HappyPath(t *testing.T) {
	var captured struct {
		method string
		path   string
		body   string
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.method = r.Method
		captured.path = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		captured.body = string(b)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	grant := access.AccessGrant{UserExternalID: "u1", ResourceExternalID: "team-1"}
	if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
		t.Fatalf("RevokeAccess: %v", err)
	}
	if captured.method != http.MethodPost {
		t.Errorf("method = %q", captured.method)
	}
	if !strings.HasSuffix(captured.path, "/teams/team-1/removeUser") {
		t.Errorf("path = %q", captured.path)
	}
	if !strings.Contains(captured.body, `"user":"u1"`) {
		t.Errorf("body missing user: %s", captured.body)
	}
}

func TestRevokeAccess_404Idempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errors":[{"message":"team not found"}]}`))
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	grant := access.AccessGrant{UserExternalID: "u1", ResourceExternalID: "team-1"}
	if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
		t.Fatalf("404 should be idempotent; got %v", err)
	}
}

func TestRevokeAccess_FailureSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	grant := access.AccessGrant{UserExternalID: "u1", ResourceExternalID: "team-1"}
	if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), grant); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected 403; got %v", err)
	}
}

func TestListEntitlements_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/users/u1/team_memberships") {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"data":[{"gid":"tm1","team":{"gid":"t1","name":"Eng"}},{"gid":"tm2","team":{"gid":"t2","name":"Ops"}}]}`))
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	got, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "u1")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(got) != 2 || got[0].ResourceExternalID != "t1" || got[1].ResourceExternalID != "t2" {
		t.Fatalf("got = %+v", got)
	}
	for _, e := range got {
		if e.Role != "member" || e.Source != "direct" {
			t.Errorf("shape = %+v", e)
		}
	}
}

func TestListEntitlements_Pagination(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			_, _ = w.Write([]byte(`{"data":[{"gid":"tm1","team":{"gid":"t1"}}],"next_page":{"offset":"OFF"}}`))
			return
		}
		if r.URL.Query().Get("offset") != "OFF" {
			t.Errorf("offset = %q", r.URL.Query().Get("offset"))
		}
		_, _ = w.Write([]byte(`{"data":[{"gid":"tm2","team":{"gid":"t2"}}]}`))
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	got, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "u1")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if calls != 2 || len(got) != 2 {
		t.Fatalf("calls=%d ents=%d", calls, len(got))
	}
}

func TestListEntitlements_RejectsEmptyUser(t *testing.T) {
	if _, err := New().ListEntitlements(context.Background(), validConfig(), validSecrets(), ""); err == nil {
		t.Fatal("empty user should error")
	}
}

func TestProvisionAndRevoke_RejectMissing(t *testing.T) {
	c := New()
	if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{ResourceExternalID: "t1"}); err == nil {
		t.Error("provision should reject missing user")
	}
	if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{UserExternalID: "u1"}); err == nil {
		t.Error("provision should reject missing resource")
	}
	if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{ResourceExternalID: "t1"}); err == nil {
		t.Error("revoke should reject missing user")
	}
}
