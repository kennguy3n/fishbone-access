package copper

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func copperValidConfig() map[string]interface{} { return map[string]interface{}{} }
func copperValidSecrets() map[string]interface{} {
	return map[string]interface{}{"api_key": "key-AAAA", "email": "ops@example.com"}
}

func TestCopperConnectorFlow_FullLifecycle(t *testing.T) {
	const userID = "12345"
	const roleID = "admin"
	hasRole := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, h := range []string{"X-PW-AccessToken", "X-PW-Application", "X-PW-UserEmail"} {
			if r.Header.Get(h) == "" {
				t.Errorf("missing %s header", h)
			}
		}
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/developer_api/v1/users/"+userID:
			if hasRole {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"message":"already has role"}`))
				return
			}
			hasRole = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/developer_api/v1/users/"+userID+"/roles/"+roleID:
			if !hasRole {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			hasRole = false
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/developer_api/v1/users/"+userID:
			payload := map[string]interface{}{"id": userID, "role_id": ""}
			if hasRole {
				payload["role_id"] = roleID
			}
			_ = json.NewEncoder(w).Encode(payload)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := copperValidConfig()
	secrets := copperValidSecrets()
	grant := access.AccessGrant{UserExternalID: userID, ResourceExternalID: roleID}

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
	if len(ents) != 1 || ents[0].ResourceExternalID != roleID {
		t.Fatalf("ents = %#v, want 1 with role=%s", ents, roleID)
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

func TestCopperConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		copperValidConfig(), copperValidSecrets(),
		access.AccessGrant{UserExternalID: "12345", ResourceExternalID: "admin"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
