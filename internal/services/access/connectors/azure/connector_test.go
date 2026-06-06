package azure

import (
	"context"
	"errors"
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
	return map[string]interface{}{"tenant_id": "tenant-1", "subscription_id": "sub-1"}
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
		t.Error("missing subscription_id")
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
		_, _ = w.Write([]byte(`{"value":[]}`))
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
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
	if err := c.Connect(context.Background(), validConfig(), validSecrets()); err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("Connect err = %v", err)
	}
}

func TestSync_DecodesUsersAndPaginates(t *testing.T) {
	page := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page++
		if page == 1 {
			next := "/users?$skiptoken=NEXT"
			_, _ = w.Write([]byte(`{"value":[{"id":"u1","displayName":"Alice","userPrincipalName":"alice@uney.com","mail":"alice@uney.com","accountEnabled":true}],"@odata.nextLink":"` + r.Header.Get("X-Server-URL") + next + `"}`))
			// Caller will resync from path with "/users?$skiptoken=NEXT" — strip happens server-side.
			return
		}
		_, _ = w.Write([]byte(`{"value":[{"id":"u2","displayName":"Bob","userPrincipalName":"bob@uney.com","accountEnabled":false}]}`))
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
	if len(got) < 1 || got[0].DisplayName != "Alice" {
		t.Fatalf("got = %+v", got)
	}
}

// TestSync_FollowsAbsoluteNextLinkOnDifferentHost guards the doJSON
// absolute-URL handling: when Graph returns an @odata.nextLink whose
// host/format differs from baseURL(), the connector must follow it
// verbatim rather than mangling it. The page-1 server advertises a
// nextLink pointing at a *second* server; the old TrimPrefix-then-
// re-prepend logic would have produced "<baseURL><absolute nextLink>"
// and never reached page two.
func TestSync_FollowsAbsoluteNextLinkOnDifferentHost(t *testing.T) {
	page2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RequestURI(), "://") {
			t.Errorf("page-2 request target leaked absolute URL: %q", r.URL.RequestURI())
		}
		_, _ = w.Write([]byte(`{"value":[{"id":"u2","displayName":"Bob","userPrincipalName":"bob@uney.com","accountEnabled":false}]}`))
	}))
	t.Cleanup(page2.Close)

	page1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Absolute nextLink on a DIFFERENT host than baseURL().
		_, _ = w.Write([]byte(`{"value":[{"id":"u1","displayName":"Alice","userPrincipalName":"alice@uney.com","mail":"alice@uney.com","accountEnabled":true}],"@odata.nextLink":"` + page2.URL + `/users?$skiptoken=NEXT"}`))
	}))
	t.Cleanup(page1.Close)

	c := New()
	c.urlOverride = page1.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }

	var got []*access.Identity
	if err := c.SyncIdentities(context.Background(), validConfig(), validSecrets(), "", func(b []*access.Identity, _ string) error {
		got = append(got, b...)
		return nil
	}); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(got) != 2 || got[0].ExternalID != "u1" || got[1].ExternalID != "u2" {
		t.Fatalf("got = %+v; want both pages [u1 u2]", got)
	}
}

func TestCount_ParsesPlainInt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/users/$count") {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`42`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
	n, err := c.CountIdentities(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("CountIdentities: %v", err)
	}
	if n != 42 {
		t.Errorf("count = %d; want 42", n)
	}
}

func TestGetCredentialsMetadata_NoNetwork(t *testing.T) {
	c := New()
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) {
		return "", errors.New("disabled")
	}
	c.urlOverride = "http://127.0.0.1:1"
	md, err := c.GetCredentialsMetadata(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("GetCredentialsMetadata: %v", err)
	}
	if md["tenant_id"] != "tenant-1" {
		t.Errorf("tenant_id = %v", md["tenant_id"])
	}
}

// TestGetCredentialsMetadata_PicksEarliestExpiry guards against a regression
// where the earliest-expiry search would silently emit an empty
// client_secret_expires_at if the first PasswordCredential happened to have
// an empty EndDateTime (a non-expiring credential). Microsoft Graph does
// not guarantee ordering of passwordCredentials, so this scenario is
// reachable in production whenever an app has a non-expiring + expiring
// credential pair.
func TestGetCredentialsMetadata_PicksEarliestExpiry(t *testing.T) {
	cases := []struct {
		name             string
		applicationsResp string
		want             string // empty => field must be absent
	}{
		{
			name: "first credential has empty endDateTime",
			applicationsResp: `{"value":[{"passwordCredentials":[
				{"endDateTime":"","displayName":"perpetual"},
				{"endDateTime":"2030-01-01T00:00:00Z","displayName":"later"},
				{"endDateTime":"2027-06-15T00:00:00Z","displayName":"earlier"}
			]}]}`,
			want: "2027-06-15T00:00:00Z",
		},
		{
			name: "all credentials have empty endDateTime",
			applicationsResp: `{"value":[{"passwordCredentials":[
				{"endDateTime":"","displayName":"a"},
				{"endDateTime":"","displayName":"b"}
			]}]}`,
			want: "",
		},
		{
			name: "single expiring credential",
			applicationsResp: `{"value":[{"passwordCredentials":[
				{"endDateTime":"2028-12-31T23:59:59Z","displayName":"only"}
			]}]}`,
			want: "2028-12-31T23:59:59Z",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !strings.HasPrefix(r.URL.Path, "/applications") {
					t.Fatalf("unexpected path %q", r.URL.Path)
				}
				_, _ = w.Write([]byte(tc.applicationsResp))
			}))
			t.Cleanup(srv.Close)
			c := New()
			c.urlOverride = srv.URL
			c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
			md, err := c.GetCredentialsMetadata(context.Background(), validConfig(), validSecrets())
			if err != nil {
				t.Fatalf("GetCredentialsMetadata: %v", err)
			}
			got, present := md["client_secret_expires_at"]
			if tc.want == "" {
				if present {
					t.Errorf("client_secret_expires_at = %v; want field absent", got)
				}
				return
			}
			if got != tc.want {
				t.Errorf("client_secret_expires_at = %v; want %q", got, tc.want)
			}
		})
	}
}

// TestGetCredentialsMetadata_EscapesClientIDInFilter guards against an OData
// filter-injection regression where a client_id containing a single quote
// would break out of the OData string literal in the $filter. The fix
// doubles single quotes per OData rules and URL-encodes the literal, so the
// embedded value remains a valid OData string and the underlying request
// path is well-formed.
func TestGetCredentialsMetadata_EscapesClientIDInFilter(t *testing.T) {
	const evilClientID = "abc' or 1 eq 1 or '1' eq '1"
	var captured string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"value":[]}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
	secrets := map[string]interface{}{"client_id": evilClientID, "client_secret": "secret-1234567890"}
	if _, err := c.GetCredentialsMetadata(context.Background(), validConfig(), secrets); err != nil {
		t.Fatalf("GetCredentialsMetadata: %v", err)
	}
	// Server-side decoded query must contain the original value with single
	// quotes doubled, and never the unescaped raw value.
	q, err := url.ParseQuery(captured)
	if err != nil {
		t.Fatalf("parse query %q: %v", captured, err)
	}
	got := q.Get("$filter")
	wantDoubled := "abc'' or 1 eq 1 or ''1'' eq ''1"
	wantFilter := "appId eq '" + wantDoubled + "'"
	if got != wantFilter {
		t.Errorf("$filter = %q; want %q", got, wantFilter)
	}
	// The decoded literal must start and end with a single quote and have
	// every embedded quote doubled, so the OData parser treats the entire
	// payload as one string and never re-enters operator context.
	if !strings.HasPrefix(got, "appId eq '") || !strings.HasSuffix(got, "'") {
		t.Errorf("$filter is not bounded by single quotes: %q", got)
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(got, "appId eq '"), "'")
	for i := 0; i < len(inner); i++ {
		if inner[i] != '\'' {
			continue
		}
		if i+1 >= len(inner) || inner[i+1] != '\'' {
			t.Errorf("unescaped single quote at position %d in %q", i, inner)
			break
		}
		i++ // skip the paired quote
	}
}

func TestProvisionAccess_PutsRoleAssignment(t *testing.T) {
	cases := []struct {
		name   string
		status int
	}{
		{"created", http.StatusCreated},
		{"conflict_idempotent", http.StatusConflict},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var seenMethod, seenPath string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seenMethod, seenPath = r.Method, r.URL.Path
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(`{}`))
			}))
			t.Cleanup(srv.Close)
			c := New()
			c.urlOverride = srv.URL
			c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
			err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
				UserExternalID:     "principal-1",
				ResourceExternalID: "/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/reader",
			})
			if err != nil {
				t.Fatalf("ProvisionAccess: %v", err)
			}
			if seenMethod != http.MethodPut {
				t.Fatalf("method = %q", seenMethod)
			}
			wantPrefix := "/subscriptions/sub-1/providers/Microsoft.Authorization/roleAssignments/"
			if !strings.HasPrefix(seenPath, wantPrefix) {
				t.Fatalf("path = %q want prefix %q", seenPath, wantPrefix)
			}
		})
	}
}

func TestProvisionAccess_4xxFailsPermanently(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "p", ResourceExternalID: "r",
	})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected 403 error, got %v", err)
	}
}

func TestRevokeAccess_DeletesRoleAssignment(t *testing.T) {
	cases := []struct {
		name   string
		status int
	}{
		{"deleted", http.StatusOK},
		{"not_found_idempotent", http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var seenMethod string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seenMethod = r.Method
				w.WriteHeader(tc.status)
			}))
			t.Cleanup(srv.Close)
			c := New()
			c.urlOverride = srv.URL
			c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
			err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
				UserExternalID: "p", ResourceExternalID: "r",
			})
			if err != nil {
				t.Fatalf("RevokeAccess: %v", err)
			}
			if seenMethod != http.MethodDelete {
				t.Fatalf("method = %q", seenMethod)
			}
		})
	}
}

func TestRevokeAccess_4xxFailsPermanently(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
	err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "p", ResourceExternalID: "r",
	})
	if err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("expected 400 error, got %v", err)
	}
}

func TestListEntitlements_FiltersByPrincipal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("$filter"); got != "principalId eq 'principal-1'" {
			t.Fatalf("$filter = %q", got)
		}
		_, _ = w.Write([]byte(`{"value":[{"id":"ra1","name":"ra1","properties":{"roleDefinitionId":"role-1","principalId":"principal-1","scope":"/subscriptions/sub-1"}}]}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
	got, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "principal-1")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(got) != 1 || got[0].ResourceExternalID != "role-1" || got[0].Source != "direct" {
		t.Fatalf("got = %+v", got)
	}
}

func TestListEntitlements_EscapesPrincipalIDInFilter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A single quote in the principal id must be doubled per OData
		// so it cannot break out of the filter string literal.
		if got := r.URL.Query().Get("$filter"); got != "principalId eq 'p''1 or 1 eq 1'" {
			t.Fatalf("$filter = %q", got)
		}
		_, _ = w.Write([]byte(`{"value":[]}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
	if _, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "p'1 or 1 eq 1"); err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
}

// TestListEntitlements_FollowsNextLinkAcrossPages exercises the
// @odata.nextLink pagination loop and the urlOverride re-anchoring so a
// principal with role assignments spread across pages is fully
// enumerated (mirrors the audit.go re-anchor behavior).
func TestListEntitlements_FollowsNextLinkAcrossPages(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("$skiptoken") == "PAGE2" {
			_, _ = w.Write([]byte(`{"value":[{"id":"ra2","name":"ra2","properties":{"roleDefinitionId":"role-2","principalId":"principal-1","scope":"/subscriptions/sub-1"}}]}`))
			return
		}
		// First page advertises an absolute ARM nextLink; the connector
		// must re-anchor it to the test server via urlOverride.
		next := defaultARMBaseURL + "/subscriptions/sub-1/providers/Microsoft.Authorization/roleAssignments?api-version=" + armAPIVersion + "&$skiptoken=PAGE2"
		_, _ = w.Write([]byte(`{"nextLink":"` + next + `","value":[{"id":"ra1","name":"ra1","properties":{"roleDefinitionId":"role-1","principalId":"principal-1","scope":"/subscriptions/sub-1"}}]}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
	got, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "principal-1")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(got) != 2 || got[0].ResourceExternalID != "role-1" || got[1].ResourceExternalID != "role-2" {
		t.Fatalf("expected 2 roles across 2 pages, got = %+v", got)
	}
}

func TestListEntitlements_4xxReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
	if _, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "principal-1"); err == nil {
		t.Fatal("expected error on 401")
	}
}

// TestArmRoleAssignmentName_StableEncoding pins the deterministic role-assignment
// name to a golden value. The name is a persisted contract: ProvisionAccess
// writes an Azure role assignment under this name and RevokeAccess must derive
// the identical name to delete it. Changing the encoding would make RevokeAccess
// issue DELETE against a non-existent name (404 -> idempotent "success") while
// the real grant lingers. This golden value MUST NOT be updated to match a code
// change — if this test fails, the encoding regressed and revocation of
// previously-created assignments is broken.
func TestArmRoleAssignmentName_StableEncoding(t *testing.T) {
	const (
		scope     = "/subscriptions/00000000-0000-0000-0000-000000000001"
		principal = "11111111-1111-1111-1111-111111111111"
		roleDefID = "22222222-2222-2222-2222-222222222222"
		wantGUID  = "8b59bd6d-9357-5d05-d558-ea3de781e89f"
	)
	if got := armRoleAssignmentName(scope, principal, roleDefID); got != wantGUID {
		t.Fatalf("armRoleAssignmentName encoding changed (breaks revocation of existing assignments): got %q, want %q", got, wantGUID)
	}
	// Determinism: same inputs -> same name across calls.
	if a, b := armRoleAssignmentName(scope, principal, roleDefID), armRoleAssignmentName(scope, principal, roleDefID); a != b {
		t.Fatalf("armRoleAssignmentName not deterministic: %q != %q", a, b)
	}
}
