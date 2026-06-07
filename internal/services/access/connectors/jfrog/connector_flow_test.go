package jfrog

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func jfrogFlowCfg(srv string) map[string]interface{} {
	return map[string]interface{}{"base_url": srv}
}
func jfrogFlowSecrets() map[string]interface{} {
	return map[string]interface{}{"access_token": "jfrog.tok"}
}

func TestConnectorFlow_FullLifecycle(t *testing.T) {
	const user = "alice"
	const group = "developers"
	member := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("missing auth")
		}
		path := "/access/api/v2/users/" + user + "/groups/" + group
		listPath := "/access/api/v2/users/" + user + "/groups"
		switch {
		case r.Method == http.MethodPut && r.URL.Path == path:
			if member {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"errors":[{"message":"user already a member"}]}`))
				return
			}
			member = true
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete && r.URL.Path == path:
			if !member {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			member = false
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == listPath:
			groups := []map[string]string{}
			if member {
				groups = append(groups, map[string]string{"name": group})
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"groups": groups})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.httpClient = func() httpDoer { return srv.Client() }
	grant := access.AccessGrant{UserExternalID: user, ResourceExternalID: group}
	cfg := jfrogFlowCfg(srv.URL)
	secrets := jfrogFlowSecrets()
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	ents, err := c.ListEntitlements(context.Background(), cfg, secrets, user)
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(ents) != 1 || ents[0].ResourceExternalID != group {
		t.Fatalf("ents = %#v", ents)
	}
	for i := 0; i < 2; i++ {
		if err := c.RevokeAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("RevokeAccess[%d]: %v", i, err)
		}
	}
	ents, err = c.ListEntitlements(context.Background(), cfg, secrets, user)
	if err != nil {
		t.Fatalf("ListEntitlements after revoke: %v", err)
	}
	if len(ents) != 0 {
		t.Fatalf("expected empty, got %d", len(ents))
	}
}

func TestConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(), jfrogFlowCfg(srv.URL), jfrogFlowSecrets(),
		access.AccessGrant{UserExternalID: "u", ResourceExternalID: "g"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
