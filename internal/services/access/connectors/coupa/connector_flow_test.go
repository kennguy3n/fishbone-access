package coupa

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

func coupaValidConfig() map[string]interface{} {
	return map[string]interface{}{"instance": "acme"}
}
func coupaValidSecrets() map[string]interface{} {
	return map[string]interface{}{"api_key": "coupa-key-AAAA"}
}

func TestCoupaConnectorFlow_FullLifecycle(t *testing.T) {
	const login = "alice@example.com"
	const role = "Buyer"

	var mu sync.Mutex
	active := false
	roles := []string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-COUPA-API-KEY") == "" {
			t.Errorf("missing api key")
		}
		users := "/api/users"
		deact := users + "/" + login + "/deactivate"
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == users:
			if active {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"errors":["login already exists"]}`))
				return
			}
			active = true
			roles = []string{role}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"login":"` + login + `"}`))
		case r.Method == http.MethodPut && r.URL.Path == deact:
			if !active {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			active = false
			roles = nil
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodGet && r.URL.Path == users:
			out := []map[string]interface{}{}
			if active {
				rs := []map[string]interface{}{}
				for _, n := range roles {
					rs = append(rs, map[string]interface{}{"id": 1, "name": n})
				}
				out = append(out, map[string]interface{}{
					"login": login, "active": true, "roles": rs,
				})
			}
			_ = json.NewEncoder(w).Encode(out)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := coupaValidConfig()
	secrets := coupaValidSecrets()
	grant := access.AccessGrant{UserExternalID: login, ResourceExternalID: role}

	if err := c.Validate(context.Background(), cfg, secrets); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	ents, err := c.ListEntitlements(context.Background(), cfg, secrets, login)
	if err != nil {
		t.Fatalf("ListEntitlements after provision: %v", err)
	}
	if len(ents) != 1 || ents[0].ResourceExternalID != role {
		t.Fatalf("ents = %#v, want 1 with role=%s", ents, role)
	}
	for i := 0; i < 2; i++ {
		if err := c.RevokeAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("RevokeAccess[%d]: %v", i, err)
		}
	}
	ents, err = c.ListEntitlements(context.Background(), cfg, secrets, login)
	if err != nil {
		t.Fatalf("ListEntitlements after revoke: %v", err)
	}
	if len(ents) != 0 {
		t.Fatalf("expected empty, got %#v", ents)
	}
}

func TestCoupaConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		coupaValidConfig(), coupaValidSecrets(),
		access.AccessGrant{UserExternalID: "alice@example.com", ResourceExternalID: "Buyer"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
