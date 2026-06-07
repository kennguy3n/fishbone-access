package mixpanel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func mixpanelValidConfig() map[string]interface{} {
	return map[string]interface{}{"organization_id": "org-1"}
}

func mixpanelValidSecrets() map[string]interface{} {
	return map[string]interface{}{
		"service_account_user":   "svc",
		"service_account_secret": "sec",
	}
}

func TestMixpanelConnectorFlow_FullLifecycle(t *testing.T) {
	const email = "alice@example.com"
	const role = "member"
	hasMember := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Basic ") {
			t.Errorf("missing basic auth")
		}
		listPath := "/api/app/organizations/org-1/members"
		switch {
		case r.Method == http.MethodPost && r.URL.Path == listPath:
			if hasMember {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"error":"already member"}`))
				return
			}
			hasMember = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":42,"email":"` + email + `","role":"` + role + `"}`))
		case r.Method == http.MethodDelete && r.URL.Path == listPath:
			if r.URL.Query().Get("email") != email {
				t.Errorf("delete email = %q", r.URL.Query().Get("email"))
			}
			if !hasMember {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			hasMember = false
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == listPath:
			members := []map[string]interface{}{}
			if hasMember {
				members = append(members, map[string]interface{}{
					"id":    42,
					"email": email,
					"role":  role,
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"members": members})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := mixpanelValidConfig()
	secrets := mixpanelValidSecrets()
	grant := access.AccessGrant{UserExternalID: email, ResourceExternalID: role}

	if err := c.Validate(context.Background(), cfg, secrets); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	ents, err := c.ListEntitlements(context.Background(), cfg, secrets, email)
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
	ents, err = c.ListEntitlements(context.Background(), cfg, secrets, email)
	if err != nil {
		t.Fatalf("ListEntitlements after revoke: %v", err)
	}
	if len(ents) != 0 {
		t.Fatalf("expected empty, got %#v", ents)
	}
}

// TestMixpanelListEntitlements_MatchesByID is a regression test ensuring
// ListEntitlements resolves a member by the numeric id that SyncIdentities
// emits as ExternalID (fmt.Sprintf("%d", m.ID)), not only by email. Matching
// email alone meant a caller passing the SyncIdentities-emitted id found
// nothing, diverging from the make/malwarebytes/midjourney/mistral peers.
func TestMixpanelListEntitlements_MatchesByID(t *testing.T) {
	const email = "alice@example.com"
	const role = "admin"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/app/organizations/org-1/members" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"members": []map[string]interface{}{
			{"id": 42, "email": email, "role": role},
		}})
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := mixpanelValidConfig()
	secrets := mixpanelValidSecrets()

	// Lookup by the numeric id SyncIdentities emits.
	byID, err := c.ListEntitlements(context.Background(), cfg, secrets, "42")
	if err != nil {
		t.Fatalf("ListEntitlements by id: %v", err)
	}
	if len(byID) != 1 || byID[0].ResourceExternalID != role {
		t.Fatalf("by id = %#v; want 1 with role=%s", byID, role)
	}
	// Lookup by email must still work.
	byEmail, err := c.ListEntitlements(context.Background(), cfg, secrets, email)
	if err != nil {
		t.Fatalf("ListEntitlements by email: %v", err)
	}
	if len(byEmail) != 1 || byEmail[0].ResourceExternalID != role {
		t.Fatalf("by email = %#v; want 1 with role=%s", byEmail, role)
	}
}

func TestMixpanelConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		mixpanelValidConfig(), mixpanelValidSecrets(),
		access.AccessGrant{UserExternalID: "a@example.com", ResourceExternalID: "member"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
