package msteams

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

type noNetworkRoundTripper struct{}

func (noNetworkRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return nil, errors.New("network call attempted")
}

func validConfig() map[string]interface{} {
	return map[string]interface{}{"tenant_id": "tenant-1", "team_id": "team-1"}
}

func validSecrets() map[string]interface{} {
	return map[string]interface{}{"client_id": "id-12345678", "client_secret": "secret-1234567890"}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_RejectsMissing(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), map[string]interface{}{"tenant_id": "x"}, validSecrets()); err == nil {
		t.Error("missing team_id")
	}
	if err := c.Validate(context.Background(), validConfig(), map[string]interface{}{}); err == nil {
		t.Error("missing secrets")
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

func TestConnect_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fake-token" {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		_, _ = w.Write([]byte(`{"id":"team-1","displayName":"Team"}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "fake-token", nil }
	if err := c.Connect(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
}

func TestConnect_FailureSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
	if err := c.Connect(context.Background(), validConfig(), validSecrets()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("Connect err = %v", err)
	}
}

func TestSync_DecodesMembers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/teams/team-1/members") {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"value":[{"id":"m1","userId":"u1","displayName":"Alice","email":"a@b.com","roles":["owner"]}]}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
	var got []*access.Identity
	err := c.SyncIdentities(context.Background(), validConfig(), validSecrets(), "", func(b []*access.Identity, _ string) error {
		got = append(got, b...)
		return nil
	})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(got) != 1 || got[0].ExternalID != "u1" {
		t.Fatalf("got = %+v", got)
	}
}

func TestGetSSOMetadata_ReturnsTenantSAML(t *testing.T) {
	md, err := New().GetSSOMetadata(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if md == nil || !strings.Contains(md.MetadataURL, "tenant-1") || md.Protocol != "saml" {
		t.Fatalf("md = %+v", md)
	}
}

// ---------- advanced capability tests ----------

func newAdvancedTestConnector(srv *httptest.Server) *MSTeamsAccessConnector {
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
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
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"membership-99"}`))
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	grant := access.AccessGrant{UserExternalID: "user-1", ResourceExternalID: "team-1", Role: "member"}
	if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
		t.Fatalf("ProvisionAccess: %v", err)
	}
	if captured.method != http.MethodPost {
		t.Errorf("method = %q", captured.method)
	}
	if !strings.HasSuffix(captured.path, "/teams/team-1/members") {
		t.Errorf("path = %q", captured.path)
	}
	if !strings.Contains(captured.body, "#microsoft.graph.aadUserConversationMember") {
		t.Errorf("body missing odata.type: %s", captured.body)
	}
	if !strings.Contains(captured.body, "users('user-1')") {
		t.Errorf("body missing user@odata.bind: %s", captured.body)
	}
	if !strings.Contains(captured.body, `"member"`) {
		t.Errorf("body missing role: %s", captured.body)
	}
}

func TestProvisionAccess_OwnerRole(t *testing.T) {
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	grant := access.AccessGrant{UserExternalID: "u1", ResourceExternalID: "team-1", Role: "owner"}
	if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
		t.Fatalf("ProvisionAccess: %v", err)
	}
	if !strings.Contains(body, `"owner"`) {
		t.Errorf("expected owner role; body = %s", body)
	}
}

func TestProvisionAccess_409Idempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":{"code":"Conflict","message":"already a member"}}`))
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	grant := access.AccessGrant{UserExternalID: "u1", ResourceExternalID: "team-1", Role: "member"}
	if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
		t.Fatalf("409 should be idempotent success; got %v", err)
	}
}

func TestProvisionAccess_400AlreadyExistsIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"code":"BadRequest","message":"User is already a member of the team."}}`))
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	grant := access.AccessGrant{UserExternalID: "u1", ResourceExternalID: "team-1", Role: "member"}
	if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
		t.Fatalf("400 'already a member' should be idempotent success; got %v", err)
	}
}

func TestProvisionAccess_PermissionFailureSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"Forbidden"}}`))
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	grant := access.AccessGrant{UserExternalID: "u1", ResourceExternalID: "team-1", Role: "member"}
	if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), grant); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected 403 error; got %v", err)
	}
}

func TestRevokeAccess_HappyPath(t *testing.T) {
	var captured struct {
		method string
		path   string
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/teams/team-1/members"):
			_, _ = w.Write([]byte(`{"value":[{"id":"membership-77","userId":"u1","email":"a@b.com","roles":["member"]}]}`))
		case r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/teams/team-1/members/membership-77"):
			captured.method = r.Method
			captured.path = r.URL.Path
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	grant := access.AccessGrant{UserExternalID: "u1", ResourceExternalID: "team-1"}
	if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
		t.Fatalf("RevokeAccess: %v", err)
	}
	if captured.method != http.MethodDelete {
		t.Errorf("expected DELETE; got %q", captured.method)
	}
}

func TestRevokeAccess_404IdempotentOnDelete(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"value":[{"id":"m1","userId":"u1","roles":["member"]}]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	grant := access.AccessGrant{UserExternalID: "u1", ResourceExternalID: "team-1"}
	if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
		t.Fatalf("404 on DELETE should be idempotent; got %v", err)
	}
}

func TestRevokeAccess_UserNotInTeamIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"value":[{"id":"other","userId":"someone-else","roles":["member"]}]}`))
			return
		}
		t.Errorf("DELETE should not have been called; got %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	grant := access.AccessGrant{UserExternalID: "u1", ResourceExternalID: "team-1"}
	if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
		t.Fatalf("missing user should be idempotent; got %v", err)
	}
}

func TestRevokeAccess_DeleteFailureSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"value":[{"id":"m1","userId":"u1","roles":["member"]}]}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"Forbidden"}}`))
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	grant := access.AccessGrant{UserExternalID: "u1", ResourceExternalID: "team-1"}
	err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), grant)
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected 403 error; got %v", err)
	}
}

func TestListEntitlements_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/users/u1/joinedTeams") {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"value":[{"id":"team-1","displayName":"Eng"},{"id":"team-2","displayName":"Ops"}]}`))
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	got, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "u1")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 entitlements; got %d", len(got))
	}
	if got[0].ResourceExternalID != "team-1" || got[1].ResourceExternalID != "team-2" {
		t.Errorf("got = %+v", got)
	}
	for _, e := range got {
		if e.Role != "member" || e.Source != "direct" {
			t.Errorf("unexpected entitlement shape: %+v", e)
		}
	}
}

func TestListEntitlements_Pagination(t *testing.T) {
	calls := 0
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			_, _ = w.Write([]byte(`{"value":[{"id":"team-1"}],"@odata.nextLink":"` + srv.URL + `/users/u1/joinedTeams?$skiptoken=A"}`))
			return
		}
		_, _ = w.Write([]byte(`{"value":[{"id":"team-2"}]}`))
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	got, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "u1")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if calls != 2 || len(got) != 2 {
		t.Fatalf("calls=%d entitlements=%d", calls, len(got))
	}
}

func TestListEntitlements_RejectsEmptyUser(t *testing.T) {
	if _, err := New().ListEntitlements(context.Background(), validConfig(), validSecrets(), ""); err == nil {
		t.Fatal("empty user should error")
	}
}

func TestProvisionAndRevoke_RejectMissingUser(t *testing.T) {
	c := New()
	grant := access.AccessGrant{ResourceExternalID: "team-1"}
	if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), grant); err == nil {
		t.Error("provision should reject missing UserExternalID")
	}
	if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), grant); err == nil {
		t.Error("revoke should reject missing UserExternalID")
	}
}

// TestBaseOpsEscapeTeamID is a regression test for the bug where the base ops
// (Connect/SyncIdentities) concatenated cfg.TeamID into the URL path raw while
// the advanced ops escaped it. TeamID is not charset-validated, so a value with
// URL-special characters must be percent-escaped identically everywhere. The
// "/" in the team id is the discriminator: url.PathEscape encodes it as %2F,
// whereas raw concatenation leaves it as a path separator.
func TestBaseOpsEscapeTeamID(t *testing.T) {
	const teamID = "te/am"
	wantPath := "/teams/" + url.PathEscape(teamID) // "/teams/te%2Fam"
	cfg := map[string]interface{}{"tenant_id": "tenant-1", "team_id": teamID}

	t.Run("Connect", func(t *testing.T) {
		var gotPath string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.EscapedPath()
			_, _ = w.Write([]byte(`{"id":"x","displayName":"Team"}`))
		}))
		t.Cleanup(srv.Close)
		c := New()
		c.urlOverride = srv.URL
		c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
		if err := c.Connect(context.Background(), cfg, validSecrets()); err != nil {
			t.Fatalf("Connect: %v", err)
		}
		if gotPath != wantPath {
			t.Errorf("Connect path = %q; want %q (TeamID must be PathEscaped)", gotPath, wantPath)
		}
	})

	t.Run("SyncIdentities", func(t *testing.T) {
		var gotPath string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.EscapedPath()
			_, _ = w.Write([]byte(`{"value":[]}`))
		}))
		t.Cleanup(srv.Close)
		c := New()
		c.urlOverride = srv.URL
		c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
		err := c.SyncIdentities(context.Background(), cfg, validSecrets(), "",
			func(_ []*access.Identity, _ string) error { return nil })
		if err != nil {
			t.Fatalf("SyncIdentities: %v", err)
		}
		if gotPath != wantPath+"/members" {
			t.Errorf("SyncIdentities path = %q; want %q (TeamID must be PathEscaped)", gotPath, wantPath+"/members")
		}
	})
}
