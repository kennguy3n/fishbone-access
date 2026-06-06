package docusign

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// Regression: account_id is mandatory for the account-scoped eSignature
// user/group endpoints. A config without account_id must fail fast rather
// than silently producing un-scoped URLs that 404 against the real API.
// (SCIM provisioning intentionally does not require account_id, so this is
// enforced per-call, not in Validate.)
func TestSyncIdentities_RequiresAccountID(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"users":[]}`))
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	err := c.SyncIdentities(context.Background(),
		map[string]interface{}{"account_environment": "production"},
		validSecrets(), "",
		func(_ []*access.Identity, _ string) error { return nil })
	if err == nil {
		t.Fatal("expected SyncIdentities to fail when account_id is missing")
	}
	// The guard must short-circuit before any HTTP call; without it the
	// connector would issue a request to an un-scoped /accounts//users path.
	if calls != 0 {
		t.Fatalf("made %d HTTP call(s); want 0 (account_id must be validated first)", calls)
	}
}

// Regression: user/group endpoints must include the
// /restapi/v2.1/accounts/{accountId} segment. Without it the request path is
// /restapi/v2.1/users/... which does not exist on the real DocuSign API.
func TestProvisionAccess_AccountScopedPath(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(),
		access.AccessGrant{UserExternalID: "u1", ResourceExternalID: "g9"})
	if err != nil {
		t.Fatalf("ProvisionAccess: %v", err)
	}
	want := "/restapi/v2.1/accounts/acct-guid-123/users/u1/groups"
	if gotPath != want {
		t.Fatalf("request path = %q; want %q", gotPath, want)
	}
}
