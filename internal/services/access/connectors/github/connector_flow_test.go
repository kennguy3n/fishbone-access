package github

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// TestConnectorFlow_FullLifecycle exercises the GitHub connector end
// to end through PUT /orgs/{org}/teams/{slug}/memberships/{user} for
// provision, the same DELETE for revoke, and the (org memberships +
// team memberships) read for ListEntitlements.
func TestConnectorFlow_FullLifecycle(t *testing.T) {
	var inTeam atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/teams/backend/memberships/alice"):
			inTeam.Store(true)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"role":"member","state":"active"}`))
		case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/teams/backend/memberships/alice"):
			inTeam.Store(false)
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/memberships/alice") && !strings.Contains(r.URL.Path, "/teams/"):
			_, _ = w.Write([]byte(`{"role":"admin","state":"active"}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/teams"):
			_, _ = w.Write([]byte(`[{"slug":"backend"}]`))
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/teams/backend/memberships/alice"):
			if inTeam.Load() {
				_, _ = w.Write([]byte(`{"role":"member"}`))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	if err := c.Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	grant := access.AccessGrant{UserExternalID: "alice", ResourceExternalID: "backend", Role: "member"}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	ents, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "alice")
	if err != nil {
		t.Fatalf("ListEntitlements after provision: %v", err)
	}
	if len(ents) < 2 {
		t.Fatalf("ListEntitlements after provision: got %d entries, want >=2", len(ents))
	}
	for i := 0; i < 2; i++ {
		if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
			t.Fatalf("RevokeAccess[%d]: %v", i, err)
		}
	}
	ents, _ = c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "alice")
	for _, e := range ents {
		if e.ResourceExternalID == "backend" {
			t.Fatalf("ListEntitlements after revoke: still has backend team")
		}
	}
}

func TestConnectorFlow_ProvisionFailsOn403(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"forbidden"}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "alice", ResourceExternalID: "backend",
	})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("ProvisionAccess: want 403, got %v", err)
	}
}
