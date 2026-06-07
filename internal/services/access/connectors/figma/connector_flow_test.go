package figma

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func TestConnectorFlow_FullLifecycle(t *testing.T) {
	var inProject atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/projects/p1/members"):
			if inProject.Load() {
				w.WriteHeader(http.StatusConflict)
				return
			}
			inProject.Store(true)
			_, _ = w.Write([]byte(`{"id":"m1"}`))
		case r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/projects/p1/members/u1"):
			if !inProject.Load() {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			inProject.Store(false)
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/teams/123/projects"):
			_, _ = w.Write([]byte(`{"projects":[{"id":"p1","name":"P1"}]}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/projects/p1/members"):
			if inProject.Load() {
				_, _ = w.Write([]byte(`{"members":[{"id":"u1","role":"editor"}]}`))
				return
			}
			_, _ = w.Write([]byte(`{"members":[]}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	if err := c.Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	grant := access.AccessGrant{UserExternalID: "u1", ResourceExternalID: "p1", Role: "editor"}
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
		t.Fatalf("got 0 entitlements after provision")
	}
	for i := 0; i < 2; i++ {
		if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
			t.Fatalf("RevokeAccess[%d]: %v", i, err)
		}
	}
	ents, _ = c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "u1")
	if len(ents) != 0 {
		t.Fatalf("got %d entitlements after revoke; want 0", len(ents))
	}
}

func TestConnectorFlow_ProvisionFailsOn403(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "u1", ResourceExternalID: "p1",
	})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("want 403; got %v", err)
	}
}
