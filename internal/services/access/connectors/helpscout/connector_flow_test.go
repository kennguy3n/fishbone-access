package helpscout

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
	var member atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/teams/20/members/10"):
			if member.Load() {
				w.WriteHeader(http.StatusConflict)
				return
			}
			member.Store(true)
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/teams/20/members/10"):
			if !member.Load() {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			member.Store(false)
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/teams/20/members"):
			if member.Load() {
				_, _ = w.Write([]byte(`{"_embedded":{"users":[{"id":10}]},"page":{"size":50,"totalElements":1,"totalPages":1,"number":1}}`))
				return
			}
			_, _ = w.Write([]byte(`{"_embedded":{"users":[]},"page":{"size":50,"totalElements":0,"totalPages":1,"number":1}}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/teams"):
			_, _ = w.Write([]byte(`{"_embedded":{"teams":[{"id":20,"name":"T"}]},"page":{"size":50,"totalElements":1,"totalPages":1,"number":1}}`))
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/users"):
			_, _ = w.Write([]byte(`{"_embedded":{"users":[]},"page":{"size":1,"totalElements":0,"totalPages":1,"number":1}}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	if err := c.Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	grant := access.AccessGrant{UserExternalID: "10", ResourceExternalID: "20"}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	ents, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "10")
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
	ents, _ = c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "10")
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
		UserExternalID: "10", ResourceExternalID: "20",
	})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("want 403; got %v", err)
	}
}
