package docusign

import (
	"context"
	"encoding/json"
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
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/users/u1/groups"):
			if member.Load() {
				w.WriteHeader(http.StatusConflict)
				return
			}
			member.Store(true)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/users/u1/groups"):
			if !member.Load() {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			member.Store(false)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/users/u1/groups"):
			groups := []map[string]string{}
			if member.Load() {
				groups = append(groups, map[string]string{"groupId": "g5", "groupName": "Admins"})
			}
			payload, _ := json.Marshal(map[string]interface{}{"groups": groups})
			_, _ = w.Write(payload)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/users"):
			_, _ = w.Write([]byte(`{"users":[],"resultSetSize":"0"}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	if err := c.Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	grant := access.AccessGrant{UserExternalID: "u1", ResourceExternalID: "g5"}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	ents, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "u1")
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
	ents, _ = c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "u1")
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
		UserExternalID: "u1", ResourceExternalID: "g5",
	})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("want 403; got %v", err)
	}
}
