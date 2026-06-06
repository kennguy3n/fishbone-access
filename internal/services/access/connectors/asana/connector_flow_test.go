package asana

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// TestConnectorFlow_FullLifecycle drives the Asana connector through
// Validate → ProvisionAccess (×2 idempotent) → ListEntitlements (≥1) →
// RevokeAccess (×2 idempotent) → ListEntitlements (0) using POST
// /teams/{gid}/addUser, POST /teams/{gid}/removeUser, and GET
// /users/{gid}/team_memberships against an httptest.Server.
func TestConnectorFlow_FullLifecycle(t *testing.T) {
	var inTeam atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/teams/team-1/addUser"):
			if inTeam.Load() {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"errors":[{"message":"user already a member of team"}]}`))
				return
			}
			inTeam.Store(true)
			_, _ = w.Write([]byte(`{"data":{"gid":"tm1","team":{"gid":"team-1"}}}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/teams/team-1/removeUser"):
			if !inTeam.Load() {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"errors":[{"message":"not found"}]}`))
				return
			}
			inTeam.Store(false)
			_, _ = w.Write([]byte(`{"data":{}}`))
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/users/u1/team_memberships"):
			if inTeam.Load() {
				_, _ = w.Write([]byte(`{"data":[{"gid":"tm1","team":{"gid":"team-1","name":"Eng"}}]}`))
				return
			}
			_, _ = w.Write([]byte(`{"data":[]}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)

	if err := c.Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	grant := access.AccessGrant{UserExternalID: "u1", ResourceExternalID: "team-1", Role: "member"}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	ents, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "u1")
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
	ents, _ = c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "u1")
	if len(ents) != 0 {
		t.Fatalf("ListEntitlements after revoke: got %d, want 0", len(ents))
	}
}

func TestConnectorFlow_ProvisionFailsOn403(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errors":[{"message":"not authorized"}]}`))
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "u1", ResourceExternalID: "team-1",
	})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected 403; got %v", err)
	}
}
