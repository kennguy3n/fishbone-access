package auth0

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
// lifecycle for the Auth0 connector with a single httptest.Server mocking
// /oauth/token, /api/v2/users (sync), and /api/v2/users/{id}/roles
// (provision, revoke, list).
func TestConnectorFlow_FullLifecycle(t *testing.T) {
	var assigned bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/oauth/token":
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok", "token_type": "Bearer", "expires_in": "3600"})
		case strings.HasSuffix(r.URL.Path, "/roles") && r.Method == http.MethodPost:
			assigned = true
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(r.URL.Path, "/roles") && r.Method == http.MethodDelete:
			if !assigned {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			assigned = false
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(r.URL.Path, "/roles") && r.Method == http.MethodGet:
			if assigned {
				_ = json.NewEncoder(w).Encode([]map[string]string{{"id": "rol_admin", "name": "Admin"}})
			} else {
				_, _ = w.Write([]byte(`[]`))
			}
		case strings.HasPrefix(r.URL.Path, "/api/v2/users") && r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`[]`))
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
	if err := c.Connect(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	grant := access.AccessGrant{UserExternalID: "auth0|u-1", ResourceExternalID: "rol_admin"}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}

	ents, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "auth0|u-1")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(ents) == 0 {
		t.Fatalf("ListEntitlements: expected provisioned grant to appear, got 0")
	}

	for i := 0; i < 2; i++ {
		if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
			t.Fatalf("RevokeAccess[%d]: %v", i, err)
		}
	}

	ents, _ = c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "auth0|u-1")
	if len(ents) != 0 {
		t.Fatalf("ListEntitlements after revoke: expected empty, got %d", len(ents))
	}
}

// TestConnectorFlow_ConnectFailsWithBadCredentials ensures Connect surfaces an
// error when the OAuth token endpoint rejects the credentials.
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
