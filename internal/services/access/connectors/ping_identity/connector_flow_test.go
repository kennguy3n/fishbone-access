package ping_identity

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// TestConnectorFlow_FullLifecycle exercises the full advanced-capability
// lifecycle for the Ping Identity connector via /as/token (oauth) and
// /v1/environments/{env}/users/{u}/groupMemberships endpoints.
func TestConnectorFlow_FullLifecycle(t *testing.T) {
	var assigned bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/as/token"):
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok", "token_type": "Bearer", "expires_in": "3600"})
		case strings.HasSuffix(r.URL.Path, "/groupMemberships") && r.Method == http.MethodPost:
			assigned = true
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{}`))
		case strings.Contains(r.URL.Path, "/groupMemberships/group-1") && r.Method == http.MethodDelete:
			if !assigned {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			assigned = false
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(r.URL.Path, "/groupMemberships") && r.Method == http.MethodGet:
			resp := pingGroupMembershipsResponse{}
			if assigned {
				resp.Embedded.GroupMemberships = []pingGroupMembership{{ID: "group-1", Name: "Engineers"}}
			}
			_ = json.NewEncoder(w).Encode(resp)
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

	grant := access.AccessGrant{UserExternalID: "user-1", ResourceExternalID: "group-1"}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}

	ents, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "user-1")
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

	ents, _ = c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "user-1")
	if len(ents) != 0 {
		t.Fatalf("ListEntitlements after revoke: got %d, want 0", len(ents))
	}
}

func TestConnectorFlow_ConnectFailsWithBadCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	if err := c.Connect(context.Background(), validConfig(), validSecrets()); err == nil {
		t.Fatal("Connect with 401: expected error, got nil")
	}
}
