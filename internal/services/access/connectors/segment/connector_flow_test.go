package segment

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func segmentValidConfig() map[string]interface{}  { return map[string]interface{}{} }
func segmentValidSecrets() map[string]interface{} { return map[string]interface{}{"token": "tok-AAAA"} }

func TestSegmentConnectorFlow_FullLifecycle(t *testing.T) {
	const userID = "alice@example.com"
	const role = "Workspace Member"
	hasUser := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/vnd.segment.v1+json" {
			t.Errorf("Accept = %q", r.Header.Get("Accept"))
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("missing bearer token")
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/users":
			if hasUser {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"error":"user already exists"}`))
				return
			}
			hasUser = true
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodGet && r.URL.Path == "/users/"+userID:
			if !hasUser {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"user": map[string]interface{}{
						"id":    userID,
						"email": userID,
						"permissions": []map[string]interface{}{
							{"role_name": role, "role_id": "r-1"},
						},
					},
				},
			})
		case r.Method == http.MethodDelete && r.URL.Path == "/users/"+userID:
			if !hasUser {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			hasUser = false
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := segmentValidConfig()
	secrets := segmentValidSecrets()
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

func TestSegmentConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		segmentValidConfig(), segmentValidSecrets(),
		access.AccessGrant{UserExternalID: "u@example.com", ResourceExternalID: "Workspace Member"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
