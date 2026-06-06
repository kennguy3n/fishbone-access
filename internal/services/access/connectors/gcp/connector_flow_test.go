package gcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// TestConnectorFlow_FullLifecycle exercises the GCP IAM connector lifecycle
// (read-modify-write of project IAM policy bindings via getIamPolicy/
// setIamPolicy) against a stateful httptest mock.
func TestConnectorFlow_FullLifecycle(t *testing.T) {
	type binding struct {
		Role    string   `json:"role"`
		Members []string `json:"members"`
	}
	type policy struct {
		Etag     string    `json:"etag"`
		Bindings []binding `json:"bindings"`
	}

	var mu sync.Mutex
	state := policy{Etag: "Bw1", Bindings: []binding{}}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case strings.HasSuffix(r.URL.Path, ":getIamPolicy"):
			_ = json.NewEncoder(w).Encode(state)
		case strings.HasSuffix(r.URL.Path, ":setIamPolicy"):
			var req struct {
				Policy policy `json:"policy"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			state = req.Policy
			state.Etag += "x"
			_ = json.NewEncoder(w).Encode(state)
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }

	if err := c.Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	grant := access.AccessGrant{UserExternalID: "alice@example.com", ResourceExternalID: "roles/viewer"}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}

	ents, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "alice@example.com")
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

	ents, _ = c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "alice@example.com")
	if len(ents) != 0 {
		t.Fatalf("ListEntitlements after revoke: got %d, want 0", len(ents))
	}
}

func TestConnectorFlow_ProvisionFailsOn403(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }

	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "alice@example.com", ResourceExternalID: "roles/viewer",
	})
	if err == nil {
		t.Fatal("ProvisionAccess with 403: expected error, got nil")
	}
}
