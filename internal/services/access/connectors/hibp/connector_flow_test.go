package hibp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// hibpSubscriptionServer returns an httptest server that answers the
// /api/v3/subscription/status probe with the documented JSON envelope so
// Connect succeeds.
func hibpSubscriptionServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v3/subscription/status" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("hibp-api-key") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"SubscriptionName":"Pwned 5","Description":"Test","SubscribedUntil":"2099-01-01T00:00:00Z","Rpm":600}`))
	}))
	return srv
}

// TestHIBPConnectorFlow_LifecycleSentinel locks the documented
// audit-only contract for the HIBP connector: Validate is pure-local,
// Connect probes /api/v3/subscription/status with the hibp-api-key
// header, SyncIdentities is a no-op (HIBP has no per-tenant identity
// directory), and the three provisioning verbs return the documented
// ErrNotImplemented sentinel rather than silently succeeding. This is
// the canonical lifecycle for a breach-search / audit data source.
func TestHIBPConnectorFlow_LifecycleSentinel(t *testing.T) {
	srv := hibpSubscriptionServer(t)
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := validConfig()
	secrets := validSecrets()

	if err := c.Validate(context.Background(), cfg, secrets); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if err := c.Connect(context.Background(), cfg, secrets); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	n, err := c.CountIdentities(context.Background(), cfg, secrets)
	if err != nil {
		t.Fatalf("CountIdentities: %v", err)
	}
	if n != 0 {
		t.Fatalf("CountIdentities = %d; want 0 for audit-only HIBP", n)
	}

	calls := 0
	if err := c.SyncIdentities(context.Background(), cfg, secrets, "", func(b []*access.Identity, next string) error {
		calls++
		if len(b) != 0 || next != "" {
			t.Errorf("handler args = len(b)=%d next=%q; want 0,\"\"", len(b), next)
		}
		return nil
	}); err != nil {
		t.Fatalf("SyncIdentities: %v", err)
	}
	if calls != 1 {
		t.Fatalf("SyncIdentities handler calls = %d; want exactly 1 (empty batch)", calls)
	}

	grant := access.AccessGrant{UserExternalID: "alice@example.com"}
	if err := c.ProvisionAccess(context.Background(), cfg, secrets, grant); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("ProvisionAccess err = %v; want ErrNotImplemented sentinel", err)
	}
	if err := c.RevokeAccess(context.Background(), cfg, secrets, grant); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("RevokeAccess err = %v; want ErrNotImplemented sentinel", err)
	}
	ents, err := c.ListEntitlements(context.Background(), cfg, secrets, "alice@example.com")
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("ListEntitlements err = %v; want ErrNotImplemented sentinel", err)
	}
	if len(ents) != 0 {
		t.Fatalf("ListEntitlements returned %d entitlements; want 0 alongside the sentinel", len(ents))
	}

	md, err := c.GetSSOMetadata(context.Background(), cfg, secrets)
	if err != nil {
		t.Fatalf("GetSSOMetadata: %v", err)
	}
	if md != nil {
		t.Fatalf("GetSSOMetadata = %#v; want nil for HIBP (no federation surface)", md)
	}
}

// TestHIBPConnectorFlow_ConnectForbidden asserts the 403 path on the
// subscription probe surfaces upstream so callers can distinguish hard
// auth failures from documented no-ops.
func TestHIBPConnectorFlow_ConnectForbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.Connect(context.Background(), validConfig(), validSecrets()); err == nil {
		t.Fatal("Connect expected error on 403")
	}
}
