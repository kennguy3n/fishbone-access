package close

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func closeValidConfig() map[string]interface{}  { return map[string]interface{}{} }
func closeValidSecrets() map[string]interface{} { return map[string]interface{}{"api_key": "key-AAAA"} }

func TestCloseConnectorFlow_FullLifecycle(t *testing.T) {
	const userID = "user-1"
	const roleID = "admin"
	const assignmentID = "ra-1"
	hasAssignment := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Basic ") {
			t.Errorf("missing basic auth")
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/role_assignment/":
			if hasAssignment {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"errors":["already exists"]}`))
				return
			}
			hasAssignment = true
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"id": assignmentID, "user_id": userID, "role_id": roleID,
			})
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/role_assignment/"+assignmentID+"/":
			if !hasAssignment {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			hasAssignment = false
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/role_assignment/":
			data := []map[string]interface{}{}
			if hasAssignment {
				data = append(data, map[string]interface{}{
					"id": assignmentID, "user_id": userID, "role_id": roleID,
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": data})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := closeValidConfig()
	secrets := closeValidSecrets()
	// ResourceExternalID is the role id so the (user, resource) pair round-trips
	// consistently through Provision → List → Revoke per docs/architecture.md §2.
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
		t.Fatalf("ents = %#v, want 1 with roleID=%s", ents, roleID)
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

func TestCloseConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		closeValidConfig(), closeValidSecrets(),
		access.AccessGrant{UserExternalID: "user-1", ResourceExternalID: "admin"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
