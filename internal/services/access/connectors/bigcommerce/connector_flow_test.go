package bigcommerce

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func bigcommerceValidConfig() map[string]interface{} {
	return map[string]interface{}{"store_hash": "acme"}
}
func bigcommerceValidSecrets() map[string]interface{} {
	return map[string]interface{}{"token": "bc_token_demo"}
}

func TestBigCommerceConnectorFlow_FullLifecycle(t *testing.T) {
	const userID = "987"
	const userEmail = "alice@example.com"
	const role = "manager"

	var mu sync.Mutex
	state := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Auth-Token") == "" {
			t.Errorf("X-Auth-Token header missing")
		}
		users := "/stores/acme/v2/users"
		userPath := "/stores/acme/v2/users/" + userID
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == users:
			if state != "" {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"errors":[{"status":409,"title":"user already exists"}]}`))
				return
			}
			state = role
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":` + userID + `,"email":"` + userEmail + `","role":"` + role + `"}`))
		case r.Method == http.MethodDelete && r.URL.Path == userPath:
			if state == "" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			state = ""
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == userPath:
			if state == "" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write([]byte(`{"id":` + userID + `,"email":"` + userEmail + `","role":"` + state + `"}`))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := bigcommerceValidConfig()
	secrets := bigcommerceValidSecrets()
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
	if len(ents) != 1 || ents[0].ResourceExternalID != role || ents[0].Source != "direct" {
		t.Fatalf("ents = %#v, want 1 with role=%s source=direct", ents, role)
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

func TestBigCommerceConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		bigcommerceValidConfig(), bigcommerceValidSecrets(),
		access.AccessGrant{UserExternalID: "alice@example.com", ResourceExternalID: "manager"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
