package square

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

func squareValidConfig() map[string]interface{} { return map[string]interface{}{} }
func squareValidSecrets() map[string]interface{} {
	return map[string]interface{}{"token": "square-token-AAAA"}
}

func TestSquareConnectorFlow_FullLifecycle(t *testing.T) {
	const userID = "tm_alice"
	const role = "manager"

	var mu sync.Mutex
	status := ""
	roleID := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("auth missing")
		}
		members := "/v2/team-members"
		member := members + "/" + userID
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == members:
			if status == "ACTIVE" {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"errors":[{"code":"CONFLICT","detail":"team member already exists"}]}`))
				return
			}
			status = "ACTIVE"
			roleID = role
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"team_member":{"id":"` + userID + `","reference_id":"` + userID + `","status":"ACTIVE","job_assignment":{"role_id":"` + role + `"}}}`))
		case r.Method == http.MethodPut && r.URL.Path == member:
			if status != "ACTIVE" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			status = "INACTIVE"
			roleID = ""
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"team_member":{"id":"` + userID + `","status":"INACTIVE"}}`))
		case r.Method == http.MethodPost && r.URL.Path == member:
			t.Errorf("RevokeAccess used POST on %s; Square UpdateTeamMember requires PUT", member)
			w.WriteHeader(http.StatusMethodNotAllowed)
		case r.Method == http.MethodGet && r.URL.Path == member:
			if status == "" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"team_member": map[string]interface{}{
					"id":             userID,
					"reference_id":   userID,
					"status":         status,
					"job_assignment": map[string]string{"role_id": roleID},
				},
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
	cfg := squareValidConfig()
	secrets := squareValidSecrets()
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

func TestSquareConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		squareValidConfig(), squareValidSecrets(),
		access.AccessGrant{UserExternalID: "tm_alice", ResourceExternalID: "manager"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
