package cloudflare

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

type noNetworkRoundTripper struct{}

func (noNetworkRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return nil, errors.New("network call attempted from a no-network test path")
}

func validConfig() map[string]interface{} {
	return map[string]interface{}{"account_id": "acct-123"}
}

func validSecrets() map[string]interface{} {
	return map[string]interface{}{"api_token": "tok-abc"}
}

func TestValidate_HappyPath(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_RejectsMissingFields(t *testing.T) {
	c := New()
	cases := []struct {
		name string
		cfg  map[string]interface{}
		sec  map[string]interface{}
	}{
		{"missing account_id", map[string]interface{}{}, validSecrets()},
		{"missing token + key", validConfig(), map[string]interface{}{}},
		{"api_key without email", validConfig(), map[string]interface{}{"api_key": "k"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := c.Validate(context.Background(), tc.cfg, tc.sec); err == nil {
				t.Errorf("Validate(%s) returned nil; want error", tc.name)
			}
		})
	}
}

func TestValidate_DoesNotMakeNetworkCalls(t *testing.T) {
	prevDefault := http.DefaultTransport
	http.DefaultTransport = noNetworkRoundTripper{}
	t.Cleanup(func() { http.DefaultTransport = prevDefault })
	c := New()
	if err := c.Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate made a network call or failed: %v", err)
	}
}

func TestRegistryIntegration(t *testing.T) {
	got, err := access.GetAccessConnector(ProviderName)
	if err != nil {
		t.Fatalf("GetAccessConnector(%q): %v", ProviderName, err)
	}
	if _, ok := got.(*CloudflareAccessConnector); !ok {
		t.Fatalf("registered type = %T, want *CloudflareAccessConnector", got)
	}
}

func TestConnect_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok-abc" {
			t.Errorf("auth = %q; want Bearer tok-abc", r.Header.Get("Authorization"))
		}
		_, _ = w.Write([]byte(`{"success":true,"result":[],"result_info":{"total_count":0}}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.Connect(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
}

func TestConnect_FailureSurfacesAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"errors":[{"message":"bad token"}]}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.Connect(context.Background(), validConfig(), validSecrets())
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("Connect err = %v; want 401", err)
	}
}

func TestSyncIdentities_PaginatesAndDecodes(t *testing.T) {
	page := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page++
		if page == 1 {
			_, _ = w.Write([]byte(`{
				"success": true,
				"result": [{"id":"m1","status":"accepted","user":{"id":"u1","email":"a@b.com","first_name":"A","last_name":"B"}}],
				"result_info": {"page":1,"per_page":50,"total_pages":2,"total_count":2,"count":1}
			}`))
			return
		}
		_, _ = w.Write([]byte(`{
			"success": true,
			"result": [{"id":"m2","status":"pending","user":{"id":"u2","email":"c@d.com"}}],
			"result_info": {"page":2,"per_page":50,"total_pages":2,"total_count":2,"count":1}
		}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	var all []*access.Identity
	err := c.SyncIdentities(context.Background(), validConfig(), validSecrets(), "", func(batch []*access.Identity, next string) error {
		all = append(all, batch...)
		return nil
	})
	if err != nil {
		t.Fatalf("SyncIdentities: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("len(all) = %d; want 2", len(all))
	}
	if all[0].Email != "a@b.com" {
		t.Errorf("all[0].Email = %q; want a@b.com", all[0].Email)
	}
	if all[1].Status != "pending" {
		t.Errorf("all[1].Status = %q; want pending", all[1].Status)
	}
}

func TestSyncIdentities_FailureSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.SyncIdentities(context.Background(), validConfig(), validSecrets(), "", func([]*access.Identity, string) error { return nil })
	if err == nil {
		t.Error("SyncIdentities returned nil; want server error")
	}
}

func TestGetCredentialsMetadata_VerifiesToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/user/tokens/verify") {
			t.Errorf("path = %q; want /user/tokens/verify", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"result":{"id":"t1","status":"active","expires_on":"2030-01-01T00:00:00Z"}}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	md, err := c.GetCredentialsMetadata(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("GetCredentialsMetadata: %v", err)
	}
	if md["token_id"] != "t1" {
		t.Errorf("token_id = %v; want t1", md["token_id"])
	}
	if md["expires_on"] != "2030-01-01T00:00:00Z" {
		t.Errorf("expires_on = %v", md["expires_on"])
	}
}

// ---------- advanced capability tests ----------

func TestProvisionAccess_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{UserExternalID: "user@example.com", ResourceExternalID: "role-1"})
	if err != nil {
		t.Fatalf("ProvisionAccess: %v", err)
	}
}

func TestProvisionAccess_Idempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"errors":[{"message":"already a member"}]}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{UserExternalID: "user@example.com", ResourceExternalID: "role-1"})
	if err != nil {
		t.Fatalf("ProvisionAccess idempotent: %v", err)
	}
}

func TestProvisionAccess_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errors":[{"message":"forbidden"}]}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{UserExternalID: "user@example.com", ResourceExternalID: "role-1"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("want 403, got %v", err)
	}
}

func TestRevokeAccess_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.RawQuery, "per_page=") {
			_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"m-abc","status":"accepted","user":{"id":"u-1","email":"user@example.com"}}],"result_info":{"page":1,"per_page":50,"total_pages":1,"total_count":1,"count":1}}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{UserExternalID: "user@example.com", ResourceExternalID: "role-1"})
	if err != nil {
		t.Fatalf("RevokeAccess: %v", err)
	}
}

func TestRevokeAccess_Idempotent(t *testing.T) {
	// Empty member list — the email is not present, so the revoke is a
	// no-op success (idempotent contract for 404/not-found).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.RawQuery, "per_page=") {
			_, _ = w.Write([]byte(`{"success":true,"result":[],"result_info":{"page":1,"per_page":50,"total_pages":1,"total_count":0,"count":0}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{UserExternalID: "user@example.com", ResourceExternalID: "role-1"})
	if err != nil {
		t.Fatalf("RevokeAccess idempotent: %v", err)
	}
}

func TestRevokeAccess_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.RawQuery, "per_page=") {
			_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"m-abc","status":"accepted","user":{"id":"u-1","email":"user@example.com"}}],"result_info":{"page":1,"per_page":50,"total_pages":1,"total_count":1,"count":1}}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{UserExternalID: "user@example.com", ResourceExternalID: "role-1"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("want 403, got %v", err)
	}
}

func TestListEntitlements_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.RawQuery, "per_page=") {
			_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"m-abc","status":"accepted","user":{"id":"u-1","email":"u-1@example.com"}}],"result_info":{"page":1,"per_page":50,"total_pages":1,"total_count":1,"count":1}}`))
			return
		}
		_, _ = w.Write([]byte(`{"result":{"roles":[{"id":"r1","name":"Admin"}]}}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	got, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "u-1@example.com")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d, want 1", len(got))
	}
}

func TestListEntitlements_Empty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.RawQuery, "per_page=") {
			_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"m-abc","status":"accepted","user":{"id":"u-1","email":"u-1@example.com"}}],"result_info":{"page":1,"per_page":50,"total_pages":1,"total_count":1,"count":1}}`))
			return
		}
		_, _ = w.Write([]byte(`{"result":{"roles":[]}}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	got, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "u-1@example.com")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d entitlements, want 0", len(got))
	}
}

// legacyAPIKeySecrets configures a Cloudflare global API key + email
// instead of an API token. The Secrets.validate() contract still accepts
// this mode (legacy auth), so ProvisionAccess / RevokeAccess /
// ListEntitlements must all route through newRequest, which is the only
// place that knows how to fall back to X-Auth-Email / X-Auth-Key headers.
func legacyAPIKeyConfig() map[string]interface{} {
	return map[string]interface{}{"account_id": "acct-123", "email": "admin@example.com"}
}

func legacyAPIKeySecrets() map[string]interface{} {
	return map[string]interface{}{"api_key": "legacy-key-xyz"}
}

// TestProvisionAccess_LegacyAPIKeyAuth is a regression test for the bug
// where ProvisionAccess hardcoded Authorization: Bearer + secrets.APIToken
// and silently sent an empty Bearer header on legacy api_key auth.
func TestProvisionAccess_LegacyAPIKeyAuth(t *testing.T) {
	var gotAuth, gotEmail, gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotEmail = r.Header.Get("X-Auth-Email")
		gotKey = r.Header.Get("X-Auth-Key")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(), legacyAPIKeyConfig(), legacyAPIKeySecrets(), access.AccessGrant{UserExternalID: "user@example.com", ResourceExternalID: "role-1"})
	if err != nil {
		t.Fatalf("ProvisionAccess (legacy api_key): %v", err)
	}
	if gotAuth != "" {
		t.Errorf("Authorization header = %q; want empty under legacy api_key auth", gotAuth)
	}
	if gotEmail != "admin@example.com" {
		t.Errorf("X-Auth-Email = %q; want admin@example.com", gotEmail)
	}
	if gotKey != "legacy-key-xyz" {
		t.Errorf("X-Auth-Key = %q; want legacy-key-xyz", gotKey)
	}
}

// TestRevokeAccess_LegacyAPIKeyAuth mirrors the regression test for the
// DELETE path. The legacy headers must fire on BOTH the /members?
// lookup and the /members/{id} DELETE.
func TestRevokeAccess_LegacyAPIKeyAuth(t *testing.T) {
	var gotEmail, gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotEmail = r.Header.Get("X-Auth-Email")
		gotKey = r.Header.Get("X-Auth-Key")
		if r.Method == http.MethodGet && strings.Contains(r.URL.RawQuery, "per_page=") {
			_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"m-abc","status":"accepted","user":{"id":"u-1","email":"user@example.com"}}],"result_info":{"page":1,"per_page":50,"total_pages":1,"total_count":1,"count":1}}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.RevokeAccess(context.Background(), legacyAPIKeyConfig(), legacyAPIKeySecrets(), access.AccessGrant{UserExternalID: "user@example.com", ResourceExternalID: "role-1"})
	if err != nil {
		t.Fatalf("RevokeAccess (legacy api_key): %v", err)
	}
	if gotEmail != "admin@example.com" || gotKey != "legacy-key-xyz" {
		t.Errorf("legacy headers wrong: email=%q key=%q", gotEmail, gotKey)
	}
}

// TestSyncIdentities_StoresEmailAsExternalID locks in the Option-2 fix
// for the three-way UserExternalID semantics mismatch. The Cloudflare
// Add-Account-Member API takes an email in the body; the per-member
// CRUD endpoints take a member-ID (distinct from user.id) in the URL.
// Storing email as ExternalID is what makes ProvisionAccess work
// directly and lets RevokeAccess / ListEntitlements resolve the
// member-ID via findMemberIDByEmail.
func TestSyncIdentities_StoresEmailAsExternalID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{
			"success": true,
			"result": [{"id":"member-abc","status":"accepted","user":{"id":"user-uuid-xyz","email":"alice@example.com"}}],
			"result_info": {"page":1,"per_page":50,"total_pages":1,"total_count":1,"count":1}
		}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	var got []*access.Identity
	err := c.SyncIdentities(context.Background(), validConfig(), validSecrets(), "", func(batch []*access.Identity, next string) error {
		got = append(got, batch...)
		return nil
	})
	if err != nil {
		t.Fatalf("SyncIdentities: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len(got) = %d; want 1", len(got))
	}
	if got[0].ExternalID != "alice@example.com" {
		t.Errorf("ExternalID = %q; want %q (email, NOT user.id, per Option-2 fix)", got[0].ExternalID, "alice@example.com")
	}
	if got[0].ExternalID == "user-uuid-xyz" {
		t.Errorf("ExternalID is still the user UUID — Option-2 fix did not land")
	}
	if got[0].Email != "alice@example.com" {
		t.Errorf("Email = %q; want alice@example.com", got[0].Email)
	}
}

// TestRevokeAccess_ResolvesMemberIDFromEmail verifies the two-call
// shape introduced by the Option-2 fix: a paginated GET on /members?
// to find the member whose user.email matches grant.UserExternalID,
// followed by a DELETE on /members/{member_id}. The member-ID must
// come from the lookup response, NOT from grant.UserExternalID.
func TestRevokeAccess_ResolvesMemberIDFromEmail(t *testing.T) {
	var deleteURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.RawQuery, "per_page=") {
			_, _ = w.Write([]byte(`{
				"success": true,
				"result": [
					{"id":"member-other","status":"accepted","user":{"id":"u-x","email":"other@example.com"}},
					{"id":"member-target-id-xyz","status":"accepted","user":{"id":"u-1","email":"alice@example.com"}}
				],
				"result_info": {"page":1,"per_page":50,"total_pages":1,"total_count":2,"count":2}
			}`))
			return
		}
		deleteURL = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{UserExternalID: "alice@example.com", ResourceExternalID: "role-1"})
	if err != nil {
		t.Fatalf("RevokeAccess: %v", err)
	}
	if !strings.HasSuffix(deleteURL, "/members/member-target-id-xyz") {
		t.Errorf("DELETE URL = %q; want suffix /members/member-target-id-xyz (the resolved member-ID, not the email)", deleteURL)
	}
	if strings.Contains(deleteURL, "alice@example.com") || strings.Contains(deleteURL, "alice%40example.com") {
		t.Errorf("DELETE URL = %q; must NOT contain the email — the fix is to use the resolved member-ID", deleteURL)
	}
}

// TestRevokeAccess_PaginatesMemberLookup verifies the lookup helper
// walks every page of /members? until it finds the email or exhausts
// the result set.
func TestRevokeAccess_PaginatesMemberLookup(t *testing.T) {
	var deleteURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.RawQuery, "per_page=") {
			if strings.Contains(r.URL.RawQuery, "page=1") {
				_, _ = w.Write([]byte(`{
					"success": true,
					"result": [{"id":"member-other","status":"accepted","user":{"id":"u-x","email":"other@example.com"}}],
					"result_info": {"page":1,"per_page":50,"total_pages":2,"total_count":2,"count":1}
				}`))
				return
			}
			_, _ = w.Write([]byte(`{
				"success": true,
				"result": [{"id":"member-page-2","status":"accepted","user":{"id":"u-1","email":"alice@example.com"}}],
				"result_info": {"page":2,"per_page":50,"total_pages":2,"total_count":2,"count":1}
			}`))
			return
		}
		deleteURL = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{UserExternalID: "alice@example.com", ResourceExternalID: "role-1"})
	if err != nil {
		t.Fatalf("RevokeAccess: %v", err)
	}
	if !strings.HasSuffix(deleteURL, "/members/member-page-2") {
		t.Errorf("DELETE URL = %q; want suffix /members/member-page-2 (found on page 2)", deleteURL)
	}
}

// TestListEntitlements_ResolvesMemberIDFromEmail verifies the same
// two-call shape for ListEntitlements: lookup the member-ID by email
// on /members?, then GET /members/{member_id}.
func TestListEntitlements_ResolvesMemberIDFromEmail(t *testing.T) {
	var getURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.RawQuery, "per_page=") {
			_, _ = w.Write([]byte(`{
				"success": true,
				"result": [{"id":"member-resolved-id","status":"accepted","user":{"id":"u-1","email":"alice@example.com"}}],
				"result_info": {"page":1,"per_page":50,"total_pages":1,"total_count":1,"count":1}
			}`))
			return
		}
		getURL = r.URL.Path
		_, _ = w.Write([]byte(`{"result":{"roles":[{"id":"r-admin","name":"Admin"}]}}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	got, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "alice@example.com")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(got) != 1 || got[0].ResourceExternalID != "r-admin" {
		t.Fatalf("ListEntitlements got = %+v; want one Admin entitlement", got)
	}
	if !strings.HasSuffix(getURL, "/members/member-resolved-id") {
		t.Errorf("GET URL = %q; want suffix /members/member-resolved-id", getURL)
	}
}

// TestListEntitlements_EmailNotFoundReturnsEmpty verifies that an
// unknown email is treated as "no entitlements" rather than an error.
// This matches the contract where SyncIdentities → ListEntitlements
// is best-effort: a deleted member shouldn't panic the caller.
func TestListEntitlements_EmailNotFoundReturnsEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{
			"success": true,
			"result": [],
			"result_info": {"page":1,"per_page":50,"total_pages":1,"total_count":0,"count":0}
		}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	got, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "ghost@example.com")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d entitlements; want 0 for unknown email", len(got))
	}
}

// TestRevokeAccess_LookupErrorPropagates verifies that a 5xx on the
// member-lookup call propagates as an error rather than being
// swallowed (paralleling the Salesforce fix). Without this, a stale
// API token or a Cloudflare outage during the lookup would make a
// revoke silently no-op while the platform records it as completed.
func TestRevokeAccess_LookupErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"errors":[{"message":"internal"}]}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{UserExternalID: "alice@example.com", ResourceExternalID: "role-1"})
	if err == nil {
		t.Fatal("RevokeAccess returned nil on 500 lookup; want error")
	}
	if !strings.Contains(err.Error(), "member lookup") {
		t.Errorf("err = %v; want it wrapped with %q", err, "member lookup")
	}
}
