package intercom

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
	admins := []string{"1", "2"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/teams/5"):
			mu.Lock()
			out := append([]string(nil), admins...)
			mu.Unlock()
			payload, _ := json.Marshal(map[string]interface{}{"id": "5", "admin_ids": out})
			_, _ = w.Write(payload)
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/teams/5"):
			b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			var body struct {
				AdminIDs []string `json:"admin_ids"`
			}
			_ = json.Unmarshal(b, &body)
			mu.Lock()
			admins = body.AdminIDs
			mu.Unlock()
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/teams"):
			mu.Lock()
			out := append([]string(nil), admins...)
			mu.Unlock()
			payload, _ := json.Marshal(map[string]interface{}{"teams": []map[string]interface{}{{"id": "5", "admin_ids": out}}})
			_, _ = w.Write(payload)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/admins"):
			_, _ = w.Write([]byte(`{"type":"admin.list","admins":[]}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	if err := c.Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	grant := access.AccessGrant{UserExternalID: "3", ResourceExternalID: "5"}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	ents, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "3")
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
	ents, _ = c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "3")
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
		UserExternalID: "3", ResourceExternalID: "5",
	})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("want 403; got %v", err)
	}
}
