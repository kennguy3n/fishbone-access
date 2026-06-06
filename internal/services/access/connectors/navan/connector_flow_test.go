package navan

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

func navanValidConfig() map[string]interface{} { return map[string]interface{}{} }
func navanValidSecrets() map[string]interface{} {
	return map[string]interface{}{"token": "navan-token-AAAA"}
}

func TestNavanConnectorFlow_FullLifecycle(t *testing.T) {
	const userID = "alice@example.com"
	const role = "manager"

	var mu sync.Mutex
	role4User := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("auth missing")
		}
		usersPath := "/api/v1/users"
		userPath := usersPath + "/" + userID
		rolesPath := userPath + "/roles"
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == usersPath:
			if role4User != "" {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"message":"user already exists"}`))
				return
			}
			role4User = role
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"` + userID + `"}`))
		case r.Method == http.MethodDelete && r.URL.Path == userPath:
			if role4User == "" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			role4User = ""
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == rolesPath:
			roles := []map[string]string{}
			if role4User != "" {
				roles = append(roles, map[string]string{"id": role4User, "name": role4User})
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"roles": roles})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := navanValidConfig()
	secrets := navanValidSecrets()
	grant := access.AccessGrant{UserExternalID: userID, ResourceExternalID: role}

	if err := c.Validate(context.Background(), cfg, secrets); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	ents, err := c.ListEntitlements(context.Background(), cfg, secrets, userID)
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
	ents, err = c.ListEntitlements(context.Background(), cfg, secrets, userID)
	if err != nil {
		t.Fatalf("ListEntitlements after revoke: %v", err)
	}
	if len(ents) != 0 {
		t.Fatalf("expected empty, got %#v", ents)
	}
}

func TestNavanConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		navanValidConfig(), navanValidSecrets(),
		access.AccessGrant{UserExternalID: "alice@example.com", ResourceExternalID: "manager"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
