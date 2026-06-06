package sentry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// TestSentryConnectorFlow_FullLifecycle exercises the advanced-cap
// contract for the Sentry /api/0/organizations/{org}/members API:
//
//   - ProvisionAccess  -> POST   /api/0/organizations/{org}/members/
//   - RevokeAccess     -> DELETE /api/0/organizations/{org}/members/{email}/
//   - ListEntitlements -> GET    /api/0/organizations/{org}/members/{email}/
//
// Idempotent on (UserExternalID, ResourceExternalID) per docs/architecture.md §2.
func TestSentryConnectorFlow_FullLifecycle(t *testing.T) {
	const orgSlug = "acme"
	const email = "alice@example.com"
	const role = "member"

	var mu sync.Mutex
	state := "" // "" = absent, role = present
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer ") {
			t.Errorf("authorization header missing/invalid: %q", got)
		}
		listPath := "/api/0/organizations/" + orgSlug + "/members/"
		memberPath := listPath + email + "/"
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == listPath:
			if state != "" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"detail":"already exists"}`))
				return
			}
			state = role
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"email":"` + email + `","role":"` + role + `"}`))
		case r.Method == http.MethodDelete && r.URL.Path == memberPath:
			if state == "" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			state = ""
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == memberPath:
			if state == "" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"email":"` + email + `","role":"` + state + `","teams":["alpha"]}`))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := map[string]interface{}{"organization_slug": orgSlug}
	secrets := map[string]interface{}{"auth_token": "sntrys_xxxx"}
	grant := access.AccessGrant{UserExternalID: email, ResourceExternalID: orgSlug, Role: role}

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
	if len(ents) < 1 || ents[0].ResourceExternalID != orgSlug || ents[0].Source != "direct" {
		t.Fatalf("ents = %#v, want at least 1 with org=%s source=direct", ents, orgSlug)
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
		t.Fatalf("expected empty entitlements, got %#v", ents)
	}
}

func TestSentryConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		map[string]interface{}{"organization_slug": "acme"},
		map[string]interface{}{"auth_token": "sntrys_xxxx"},
		access.AccessGrant{UserExternalID: "alice@example.com", ResourceExternalID: "acme"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v, want 403", err)
	}
}
