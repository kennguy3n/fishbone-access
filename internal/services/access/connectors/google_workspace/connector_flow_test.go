package google_workspace

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// TestConnectorFlow_FullLifecycle exercises Google Workspace's group member
// lifecycle (POST → GET → DELETE) against a single httptest mock.
func TestConnectorFlow_FullLifecycle(t *testing.T) {
	var assigned bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/members"):
			assigned = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/members/"):
			if !assigned {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			assigned = false
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/groups"):
			page := directoryGroupsPage{}
			if assigned {
				page.Groups = []directoryGroup{{ID: "g-1", Email: "engineering@example.com", Name: "Engineering"}}
			}
			_ = json.NewEncoder(w).Encode(page)
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) (httpDoer, error) {
		return &fakeDirectoryClient{base: srv.URL, c: srv.Client()}, nil
	}

	if err := c.Validate(context.Background(), validConfig(), validSecrets(t)); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	grant := access.AccessGrant{UserExternalID: "alice@example.com", ResourceExternalID: "engineering@example.com", Role: "MEMBER"}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(t), grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}

	ents, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(t), "alice@example.com")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(ents) == 0 {
		t.Fatalf("expected provisioned grant to appear, got 0")
	}

	for i := 0; i < 2; i++ {
		if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(t), grant); err != nil {
			t.Fatalf("RevokeAccess[%d]: %v", i, err)
		}
	}

	ents, _ = c.ListEntitlements(context.Background(), validConfig(), validSecrets(t), "alice@example.com")
	if len(ents) != 0 {
		t.Fatalf("ListEntitlements after revoke: got %d, want 0", len(ents))
	}
}

func TestConnectorFlow_ProvisionFailsOn403(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":403,"status":"PERMISSION_DENIED"}}`))
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) (httpDoer, error) {
		return &fakeDirectoryClient{base: srv.URL, c: srv.Client()}, nil
	}

	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(t), access.AccessGrant{
		UserExternalID: "alice@example.com", ResourceExternalID: "engineering@example.com", Role: "MEMBER",
	})
	if err == nil {
		t.Fatal("ProvisionAccess with 403: expected error, got nil")
	}
}
