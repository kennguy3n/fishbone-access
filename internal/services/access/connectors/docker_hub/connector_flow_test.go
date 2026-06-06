package docker_hub

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func TestConnectorFlow_FullLifecycle(t *testing.T) {
	const user = "alice"
	const group = "developers"
	const org = "acme"
	member := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v2/users/login":
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "jwt"})
		case r.Method == http.MethodPost && r.URL.Path == "/v2/orgs/"+org+"/groups/"+group+"/members":
			if member {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"detail":"member already exists"}`))
				return
			}
			member = true
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodDelete && r.URL.Path == "/v2/orgs/"+org+"/groups/"+group+"/members/"+user:
			if !member {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			member = false
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/v2/orgs/"+org+"/members/"+user+"/groups":
			results := []map[string]interface{}{}
			if member {
				results = append(results, map[string]interface{}{"name": group, "id": 1})
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"results": results})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := map[string]interface{}{"organization": org}
	secrets := map[string]interface{}{"username": "u", "password": "p"}
	grant := access.AccessGrant{UserExternalID: user, ResourceExternalID: group}
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
		t.Fatalf("expected 0, got %d", len(ents))
	}
}

func TestConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/users/login" {
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "jwt"})
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := map[string]interface{}{"organization": "acme"}
	err := c.ProvisionAccess(context.Background(), cfg,
		map[string]interface{}{"username": "u", "password": "p"},
		access.AccessGrant{UserExternalID: "u", ResourceExternalID: "g"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
