package salesloft

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
	const userID = "user-42"
	const roleID = "role-9"
	isMember := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			t.Errorf("auth header missing")
		}
		putPath := "/v2/users/" + userID + "/roles/" + roleID
		listPath := "/v2/users/" + userID + "/roles"
		switch {
		case r.Method == http.MethodPut && r.URL.Path == putPath:
			if isMember {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"error":"already assigned"}`))
				return
			}
			isMember = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodDelete && r.URL.Path == putPath:
			if !isMember {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"error":"not assigned"}`))
				return
			}
			isMember = false
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodGet && r.URL.Path == listPath:
			data := []map[string]interface{}{}
			if isMember {
				data = append(data, map[string]interface{}{
					"id":   roleID,
					"name": "Admin",
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": data})
		default:
			// Validate probes and other endpoints — accept gracefully.
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": []interface{}{}})
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := validConfig()
	secrets := validSecrets()
	grant := access.AccessGrant{UserExternalID: userID, ResourceExternalID: roleID}

	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	ents, err := c.ListEntitlements(context.Background(), cfg, secrets, userID)
	if err != nil {
		t.Fatalf("ListEntitlements after provision: %v", err)
	}
	if len(ents) != 1 {
		t.Fatalf("ents len = %d, want 1: %#v", len(ents), ents)
	}
	if ents[0].ResourceExternalID != roleID {
		t.Fatalf("ents[0].ResourceExternalID = %q, want %q (must round-trip grant.ResourceExternalID)",
			ents[0].ResourceExternalID, roleID)
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

// TestListEntitlements_FiltersNullID verifies that a role entry whose
// JSON "id" is null is dropped rather than emitted as a bogus
// ResourceExternalID of "<nil>".
func TestListEntitlements_FiltersNullID(t *testing.T) {
	const userID = "user-7"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/users/"+userID+"/roles" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": []map[string]interface{}{
				{"id": nil, "name": "ghost"},
				{"id": "role-ok", "name": "Real Role"},
			},
		})
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	ents, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), userID)
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(ents) != 1 || ents[0].ResourceExternalID != "role-ok" {
		t.Fatalf("got %#v, want only role-ok (null id must be filtered)", ents)
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
	err := c.ProvisionAccess(context.Background(),
		validConfig(),
		validSecrets(),
		access.AccessGrant{UserExternalID: "user-42", ResourceExternalID: "role-9"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
