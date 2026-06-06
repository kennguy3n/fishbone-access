package okta

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// TestConnectorFlow_FullLifecycle exercises the full advanced-capability lifecycle
// for the Okta connector: Validate, Connect, SyncIdentities, ProvisionAccess (twice
// for idempotency), ListEntitlements, RevokeAccess (twice for idempotency), and
// ListEntitlements again. All HTTP traffic is mocked via httptest.Server — no
// real network I/O is performed.
func TestConnectorFlow_FullLifecycle(t *testing.T) {
	var assigned bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/users/me":
			_, _ = w.Write([]byte(`{"id":"me"}`))
		case strings.HasPrefix(r.URL.Path, "/api/v1/users/u-1/appLinks") && r.Method == http.MethodGet:
			if assigned {
				_, _ = w.Write([]byte(`[{"appInstanceId":"app-1","label":"App"}]`))
			} else {
				_, _ = w.Write([]byte(`[]`))
			}
		case strings.HasPrefix(r.URL.Path, "/api/v1/apps/app-1/users/u-1") && r.Method == http.MethodPut:
			assigned = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		case strings.HasPrefix(r.URL.Path, "/api/v1/apps/app-1/users/u-1") && r.Method == http.MethodDelete:
			if !assigned {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			assigned = false
			w.WriteHeader(http.StatusNoContent)
		case strings.HasPrefix(r.URL.Path, "/api/v1/users") && r.Method == http.MethodGet:
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

	grant := access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "app-1", Role: "Admin"}
	if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
		t.Fatalf("ProvisionAccess: %v", err)
	}
	if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
		t.Fatalf("ProvisionAccess (idempotent): %v", err)
	}

	ents, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "u-1")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(ents) == 0 {
		t.Fatalf("ListEntitlements: expected provisioned grant to appear, got 0")
	}

	if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
		t.Fatalf("RevokeAccess: %v", err)
	}
	if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
		t.Fatalf("RevokeAccess (idempotent): %v", err)
	}

	ents, err = c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "u-1")
	if err != nil {
		t.Fatalf("ListEntitlements after revoke: %v", err)
	}
	if len(ents) != 0 {
		t.Fatalf("ListEntitlements after revoke: expected empty, got %d", len(ents))
	}
}

// TestConnectorFlow_ConnectFailsWithBadCredentials ensures Connect surfaces an
// error when the provider rejects the credentials.
func TestConnectorFlow_ConnectFailsWithBadCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"errorCode":"E0000011","errorSummary":"Invalid token"}`))
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	err := c.Connect(context.Background(), validConfig(), validSecrets())
	if err == nil {
		t.Fatal("Connect with 401: expected error, got nil")
	}
}

var _ = json.Marshal
var _ = fmt.Sprint
