package clio

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
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("auth header missing: %q", r.Header.Get("Authorization"))
		}
		putPath := "/api/v4/users/" + userID + "/permissions/" + roleID
		listPath := "/api/v4/users/" + userID + "/permissions"
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
					"name": "Power User",
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
	cfg := validConfig()
	secrets := validSecrets()
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

// TestListEntitlements_SkipsNullID verifies that an entitlement whose JSON
// "id" is null is skipped rather than emitted as the literal "<nil>".
// Because the id field is typed interface{}, fmt.Sprintf("%v", nil) yields
// "<nil>", which would slip past the empty-string guard and produce a
// bogus ResourceExternalID.
func TestListEntitlements_SkipsNullID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": []map[string]interface{}{
			{"id": nil, "name": "Ghost"},
			{"id": "role-9", "name": "Power User"},
		}})
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	ents, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "user-42")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	for _, e := range ents {
		if e.ResourceExternalID == "<nil>" || e.ResourceExternalID == "" {
			t.Fatalf("emitted entitlement with bogus id %q (null id must be skipped)", e.ResourceExternalID)
		}
	}
	if len(ents) != 1 || ents[0].ResourceExternalID != "role-9" {
		t.Fatalf("entitlements = %+v, want exactly [role-9]", ents)
	}
}
