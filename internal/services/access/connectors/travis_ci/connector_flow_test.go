package travis_ci

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
	const userID = "42"
	const repoID = "100"
	active := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "token ") {
			t.Errorf("auth header missing/invalid: %q", r.Header.Get("Authorization"))
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/repo/"+repoID+"/activate":
			if active {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"error":"already activated"}`))
				return
			}
			active = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"active":true}`))
		case r.Method == http.MethodPost && r.URL.Path == "/repo/"+repoID+"/deactivate":
			if !active {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"error":"not found"}`))
				return
			}
			active = false
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"active":false}`))
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/user/"+userID+"/repos"):
			if active {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"repositories": []map[string]interface{}{
						{"id": 100, "slug": "acme/web", "active": true},
					},
				})
			} else {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"repositories": []interface{}{},
				})
			}
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	secrets := map[string]interface{}{"token": "tok"}
	cfg := map[string]interface{}{}
	grant := access.AccessGrant{UserExternalID: userID, ResourceExternalID: repoID}

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
	if len(ents) != 1 || ents[0].ResourceExternalID != repoID {
		t.Fatalf("ents = %#v", ents)
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
		t.Fatalf("expected empty, got %d", len(ents))
	}
}

func TestConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(), map[string]interface{}{},
		map[string]interface{}{"token": "tok"},
		access.AccessGrant{UserExternalID: "u", ResourceExternalID: "r"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
