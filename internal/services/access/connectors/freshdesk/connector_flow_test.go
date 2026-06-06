package freshdesk

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func TestConnectorFlow_FullLifecycle(t *testing.T) {
	var mu sync.Mutex
	groups := []int64{1, 2}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/api/v2/agents/42"):
			mu.Lock()
			out := append([]int64(nil), groups...)
			mu.Unlock()
			payload, _ := json.Marshal(map[string]interface{}{"id": 42, "group_ids": out})
			_, _ = w.Write(payload)
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/api/v2/agents/42"):
			b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			var body struct {
				GroupIDs []int64 `json:"group_ids"`
			}
			_ = json.Unmarshal(b, &body)
			mu.Lock()
			groups = body.GroupIDs
			mu.Unlock()
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/api/v2/agents/me"):
			_, _ = w.Write([]byte(`{"id":1}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	if err := c.Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	grant := access.AccessGrant{UserExternalID: "42", ResourceExternalID: "3"}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	ents, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "42")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	found := false
	for _, e := range ents {
		if e.ResourceExternalID == "3" {
			found = true
		}
	}
	if !found {
		t.Fatalf("group 3 not in entitlements: %+v", ents)
	}
	for i := 0; i < 2; i++ {
		if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
			t.Fatalf("RevokeAccess[%d]: %v", i, err)
		}
	}
	ents, _ = c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "42")
	for _, e := range ents {
		if e.ResourceExternalID == "3" {
			t.Fatalf("group 3 still present after revoke: %+v", ents)
		}
	}
}

func TestConnectorFlow_ProvisionFailsOn403(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "42", ResourceExternalID: "3",
	})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("want 403; got %v", err)
	}
}
