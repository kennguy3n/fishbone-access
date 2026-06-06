package wazuh

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func wazuhValidConfig() map[string]interface{} {
	return map[string]interface{}{"endpoint": "https://wazuh.corp.example"}
}
func wazuhValidSecrets() map[string]interface{} {
	return map[string]interface{}{"token": "wazuh-tok-AAAA"}
}

func TestWazuhConnectorFlow_FullLifecycle(t *testing.T) {
	const userID = "5"
	const roleID = "3"

	var mu sync.Mutex
	state := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("auth missing")
		}
		userRolesPath := "/security/users/" + userID + "/roles"
		userPath := "/security/users/" + userID
		mu.Lock()
		defer mu.Unlock()
		q, _ := url.ParseQuery(r.URL.RawQuery)
		switch {
		case r.Method == http.MethodPost && r.URL.Path == userRolesPath && q.Get("role_ids") == roleID:
			if state {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"error":3008,"message":"role already attached"}`))
				return
			}
			state = true
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodDelete && r.URL.Path == userRolesPath && q.Get("role_ids") == roleID:
			if !state {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			state = false
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == userPath:
			if !state {
				_, _ = w.Write([]byte(`{"data":{"affected_items":[{"id":` + userID + `,"roles":[]}]}}`))
				return
			}
			_, _ = w.Write([]byte(`{"data":{"affected_items":[{"id":` + userID + `,"roles":[` + roleID + `]}]}}`))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := wazuhValidConfig()
	secrets := wazuhValidSecrets()
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
	if len(ents) != 1 || ents[0].ResourceExternalID != roleID || ents[0].Source != "direct" {
		t.Fatalf("ents = %#v, want 1 with id=%s source=direct", ents, roleID)
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

func TestWazuhConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		wazuhValidConfig(), wazuhValidSecrets(),
		access.AccessGrant{UserExternalID: "5", ResourceExternalID: "3"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
