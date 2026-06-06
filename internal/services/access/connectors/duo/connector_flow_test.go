package duo

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// TestConnectorFlow_FullLifecycle exercises the full advanced-capability
// lifecycle for the Duo connector with a single httptest.Server mocking
// /admin/v1/users (sync) and /admin/v1/users/{id}/groups (provision/revoke/list).
func TestConnectorFlow_FullLifecycle(t *testing.T) {
	var assigned bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/groups") && r.Method == http.MethodPost:
			assigned = true
			_, _ = w.Write([]byte(`{"stat":"OK"}`))
		case strings.HasPrefix(r.URL.Path, "/admin/v1/users/u-1/groups/") && r.Method == http.MethodDelete:
			if !assigned {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			assigned = false
			w.WriteHeader(http.StatusOK)
		case strings.HasSuffix(r.URL.Path, "/groups") && r.Method == http.MethodGet:
			if assigned {
				_ = json.NewEncoder(w).Encode(duoUserGroupsResponse{
					Stat:     "OK",
					Response: []duoUserGroup{{GroupID: "g-1", Name: "Engineering"}},
				})
			} else {
				_ = json.NewEncoder(w).Encode(duoUserGroupsResponse{Stat: "OK", Response: []duoUserGroup{}})
			}
		default:
			_, _ = w.Write([]byte(`{"stat":"OK"}`))
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	c.nowFn = func() time.Time { return time.Date(2026, 5, 9, 8, 0, 0, 0, time.UTC) }

	if err := c.Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	grant := access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "g-1"}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}

	ents, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "u-1")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(ents) == 0 {
		t.Fatalf("expected provisioned grant to appear, got 0")
	}

	for i := 0; i < 2; i++ {
		if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
			t.Fatalf("RevokeAccess[%d]: %v", i, err)
		}
	}

	ents, _ = c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "u-1")
	if len(ents) != 0 {
		t.Fatalf("ListEntitlements after revoke: got %d, want 0", len(ents))
	}
}

// TestConnectorFlow_ConnectFailsWithBadCredentials ensures Connect surfaces an
// error when the provider rejects the credentials.
func TestConnectorFlow_ConnectFailsWithBadCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"stat":"FAIL","code":40103}`))
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	c.nowFn = func() time.Time { return time.Date(2026, 5, 9, 8, 0, 0, 0, time.UTC) }

	if err := c.Connect(context.Background(), validConfig(), validSecrets()); err == nil {
		t.Fatal("Connect with 401: expected error, got nil")
	}
}
