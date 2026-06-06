package box

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
	var collab atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/2.0/collaborations"):
			if collab.Load() {
				w.WriteHeader(http.StatusConflict)
				return
			}
			collab.Store(true)
			_, _ = w.Write([]byte(`{"id":"C1"}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/2.0/folders/200/collaborations"):
			if collab.Load() {
				_, _ = w.Write([]byte(`{"entries":[{"id":"C1","role":"editor","accessible_by":{"id":"100","type":"user"}}]}`))
				return
			}
			_, _ = w.Write([]byte(`{"entries":[]}`))
		case r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/2.0/collaborations/C1"):
			if !collab.Load() {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			collab.Store(false)
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/2.0/users/100/memberships"):
			if collab.Load() {
				_, _ = w.Write([]byte(`{"entries":[{"id":"m1","role":"member","group":{"id":"folder-200","name":"G"}}]}`))
				return
			}
			_, _ = w.Write([]byte(`{"entries":[]}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/2.0/users/me"):
			_, _ = w.Write([]byte(`{"id":"me"}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	if err := c.Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	grant := access.AccessGrant{UserExternalID: "100", ResourceExternalID: "200", Role: "editor"}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	ents, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "100")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(ents) == 0 {
		t.Fatalf("got 0 after provision")
	}
	for i := 0; i < 2; i++ {
		if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
			t.Fatalf("RevokeAccess[%d]: %v", i, err)
		}
	}
	ents, _ = c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "100")
	if len(ents) != 0 {
		t.Fatalf("got %d after revoke", len(ents))
	}
}

func TestConnectorFlow_ProvisionFailsOn403(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "100", ResourceExternalID: "200",
	})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("want 403; got %v", err)
	}
}
