package cloudflare

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// TestConnectorFlow_FullLifecycle exercises the Cloudflare connector end
// to end: Validate → ProvisionAccess (twice, second is idempotent) →
// ListEntitlements (sees the new grant) → RevokeAccess (twice, second is
// idempotent) → ListEntitlements (empty). The mock server keeps a
// `provisioned` flag and gates its responses on it so the same handler
// can serve every stage of the lifecycle.
func TestConnectorFlow_FullLifecycle(t *testing.T) {
	var provisioned atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/members"):
			provisioned.Store(true)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"success":true,"result":{"id":"m-abc"}}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/members/m-abc"):
			if provisioned.Load() {
				_, _ = w.Write([]byte(`{"success":true,"result":{"id":"m-abc","status":"accepted","roles":[{"id":"role-1","name":"Admin"}],"user":{"id":"u-1","email":"user@example.com"}}}`))
				return
			}
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"success":false,"errors":[{"message":"not found"}]}`))
		case r.Method == http.MethodGet && strings.Contains(r.URL.RawQuery, "per_page="):
			if provisioned.Load() {
				_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"m-abc","status":"accepted","roles":[{"id":"role-1","name":"Admin"}],"user":{"id":"u-1","email":"user@example.com"}}],"result_info":{"page":1,"per_page":50,"total_pages":1,"total_count":1,"count":1}}`))
				return
			}
			_, _ = w.Write([]byte(`{"success":true,"result":[],"result_info":{"page":1,"per_page":50,"total_pages":1,"total_count":0,"count":0}}`))
		case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/members/m-abc"):
			provisioned.Store(false)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"success":true}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"success":true}`))
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	if err := c.Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	grant := access.AccessGrant{UserExternalID: "user@example.com", ResourceExternalID: "role-1"}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	ents, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "user@example.com")
	if err != nil {
		t.Fatalf("ListEntitlements after provision: %v", err)
	}
	if len(ents) == 0 {
		t.Fatalf("ListEntitlements after provision: got 0, want >=1")
	}
	for i := 0; i < 2; i++ {
		if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
			t.Fatalf("RevokeAccess[%d]: %v", i, err)
		}
	}
	ents, _ = c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "user@example.com")
	if len(ents) != 0 {
		t.Fatalf("ListEntitlements after revoke: got %d, want 0", len(ents))
	}
}

// TestConnectorFlow_ProvisionFailsOn403 confirms that a hard 4xx from
// Cloudflare propagates as an error to the worker (which will then
// emit a permanent fail per docs/architecture.md).
func TestConnectorFlow_ProvisionFailsOn403(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errors":[{"code":403,"message":"forbidden"}]}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "user@example.com", ResourceExternalID: "role-1",
	})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("ProvisionAccess: want 403 error, got %v", err)
	}
}

// TestProvisionAccess_IdempotentOnConflictAndCasing verifies the
// idempotency check delegates to access.IsIdempotentProvisionStatus
// rather than a case-sensitive single-phrase substring match. Cloudflare
// can signal "already a member" via a 409 Conflict or a 400 with mixed
// casing / alternate phrasing; all must collapse to idempotent success so
// re-provisioning an existing member doesn't surface a spurious error.
func TestProvisionAccess_IdempotentOnConflictAndCasing(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"409 conflict", http.StatusConflict, `{"errors":[{"message":"member exists"}]}`},
		{"400 capitalized phrase", http.StatusBadRequest, `{"errors":[{"message":"User is Already A Member of this account"}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			t.Cleanup(srv.Close)
			c := New()
			c.urlOverride = srv.URL
			c.httpClient = func() httpDoer { return srv.Client() }
			err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
				UserExternalID: "user@example.com", ResourceExternalID: "role-1",
			})
			if err != nil {
				t.Fatalf("ProvisionAccess(%s): want idempotent success, got %v", tc.name, err)
			}
		})
	}
}
