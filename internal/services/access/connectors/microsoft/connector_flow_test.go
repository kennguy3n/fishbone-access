package microsoft

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// TestConnectorFlow_FullLifecycle exercises the Microsoft Graph connector
// lifecycle: ProvisionAccess (POST appRoleAssignments), RevokeAccess (GET +
// DELETE), ListEntitlements (GET). Connect/SyncIdentities are covered by
// connector_test.go; we focus the flow test on the advanced capabilities.
func TestConnectorFlow_FullLifecycle(t *testing.T) {
	var assigned bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/users/u-1/appRoleAssignments"):
			assigned = true
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"a-1"}`))
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/users/u-1/appRoleAssignments"):
			page := graphAppRoleAssignmentsPage{}
			if assigned {
				page.Value = []graphAppRoleAssignment{
					{ID: "a-1", PrincipalID: "u-1", ResourceID: "sp-1", AppRoleID: "appRole-A"},
				}
			}
			_ = json.NewEncoder(w).Encode(page)
		case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/appRoleAssignments/"):
			if !assigned {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			assigned = false
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) httpDoer {
		return &serverFirstFakeClient{base: srv.URL, http: srv.Client()}
	}

	if err := c.Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	grant := access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "sp-1", Role: "appRole-A"}
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

// TestConnectorFlow_ProvisionFailsOn403 covers the failure path: a 4xx
// response from the provider is surfaced to the caller.
func TestConnectorFlow_ProvisionFailsOn403(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"Authorization_RequestDenied"}}`))
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) httpDoer {
		return &serverFirstFakeClient{base: srv.URL, http: srv.Client()}
	}

	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "u-1", ResourceExternalID: "sp-1", Role: "appRole-A",
	})
	if err == nil {
		t.Fatal("ProvisionAccess with 403: expected error, got nil")
	}
}
