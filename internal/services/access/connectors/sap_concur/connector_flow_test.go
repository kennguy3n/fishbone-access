package sap_concur

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

func sapConcurValidConfig() map[string]interface{} { return map[string]interface{}{} }
func sapConcurValidSecrets() map[string]interface{} {
	return map[string]interface{}{"access_token": "concur-token-AAAA"}
}

func TestSAPConcurConnectorFlow_FullLifecycle(t *testing.T) {
	const userID = "alice@example.com"
	const role = "expense_approver"

	var mu sync.Mutex
	role4User := ""
	active := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("auth missing")
		}
		users := "/api/v3.0/common/users"
		deact := users + "/" + userID + "/deactivate"
		roles := users + "/" + userID + "/roles"
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == users:
			if active {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"message":"login already exists"}`))
				return
			}
			role4User = role
			active = true
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"ID":"` + userID + `"}`))
		case r.Method == http.MethodPost && r.URL.Path == deact:
			if !active {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			active = false
			role4User = ""
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodGet && r.URL.Path == roles:
			items := []map[string]string{}
			if role4User != "" {
				items = append(items, map[string]string{"RoleId": role4User, "Name": role4User})
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"Roles": items})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := sapConcurValidConfig()
	secrets := sapConcurValidSecrets()
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

func TestSAPConcurConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		sapConcurValidConfig(), sapConcurValidSecrets(),
		access.AccessGrant{UserExternalID: "alice@example.com", ResourceExternalID: "expense_approver"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
