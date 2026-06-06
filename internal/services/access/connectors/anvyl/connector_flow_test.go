package anvyl

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

func anvylValidConfig() map[string]interface{} { return map[string]interface{}{} }
func anvylValidSecrets() map[string]interface{} {
	return map[string]interface{}{"token": "anvyl-token-AAAA"}
}

func TestAnvylConnectorFlow_FullLifecycle(t *testing.T) {
	const email = "alice@example.com"
	const role = "member"

	var mu sync.Mutex
	state := "" // current role assigned to email; "" => not provisioned
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("auth missing")
		}
		users := "/api/v1/users"
		user := users + "/" + email
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == users:
			if state != "" {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"error":"user already exists"}`))
				return
			}
			state = role
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"data":{"id":"` + email + `","email":"` + email + `","role":"` + role + `"}}`))
		case r.Method == http.MethodDelete && r.URL.Path == user:
			if state == "" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			state = ""
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == user:
			if state == "" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]string{"id": email, "email": email, "role": state},
			})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := anvylValidConfig()
	secrets := anvylValidSecrets()
	grant := access.AccessGrant{UserExternalID: email, ResourceExternalID: role}

	if err := c.Validate(context.Background(), cfg, secrets); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	ents, err := c.ListEntitlements(context.Background(), cfg, secrets, email)
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
	ents, err = c.ListEntitlements(context.Background(), cfg, secrets, email)
	if err != nil {
		t.Fatalf("ListEntitlements after revoke: %v", err)
	}
	if len(ents) != 0 {
		t.Fatalf("expected empty, got %#v", ents)
	}
}

func TestAnvylConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		anvylValidConfig(), anvylValidSecrets(),
		access.AccessGrant{UserExternalID: "alice@example.com", ResourceExternalID: "member"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
