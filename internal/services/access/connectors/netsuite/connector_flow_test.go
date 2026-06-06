package netsuite

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
	roles := []string{"R1"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/record/v1/employee/42"):
			mu.Lock()
			items := make([]map[string]string, 0, len(roles))
			for _, id := range roles {
				items = append(items, map[string]string{"id": id})
			}
			mu.Unlock()
			payload, _ := json.Marshal(map[string]interface{}{"id": "42", "roles": map[string]interface{}{"items": items}})
			_, _ = w.Write(payload)
		case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/record/v1/employee/42"):
			b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			var body struct {
				Roles struct {
					Items []struct {
						ID string `json:"id"`
					} `json:"items"`
				} `json:"roles"`
			}
			_ = json.Unmarshal(b, &body)
			mu.Lock()
			roles = roles[:0]
			for _, it := range body.Roles.Items {
				roles = append(roles, it.ID)
			}
			mu.Unlock()
			_, _ = w.Write([]byte(`{}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	if err := c.Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	grant := access.AccessGrant{UserExternalID: "42", ResourceExternalID: "R2"}
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
		if e.ResourceExternalID == "R2" {
			found = true
		}
	}
	if !found {
		t.Fatalf("R2 missing after provision")
	}
	for i := 0; i < 2; i++ {
		if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
			t.Fatalf("RevokeAccess[%d]: %v", i, err)
		}
	}
	ents, _ = c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "42")
	for _, e := range ents {
		if e.ResourceExternalID == "R2" {
			t.Fatalf("R2 still present after revoke")
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
		UserExternalID: "42", ResourceExternalID: "R2",
	})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("want 403; got %v", err)
	}
}
