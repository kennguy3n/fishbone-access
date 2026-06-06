package snyk

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// TestSnykConnectorFlow_FullLifecycle exercises the advanced-cap
// contract for the Snyk REST org-membership API:
//
//   - ProvisionAccess  -> PATCH  /rest/orgs/{orgID}/members/{userID}
//   - RevokeAccess     -> DELETE /rest/orgs/{orgID}/members/{userID}
//   - ListEntitlements -> GET    /rest/orgs/{orgID}/members/{userID}
//
// Idempotent on (UserExternalID, ResourceExternalID) per docs/architecture.md §2.
func TestSnykConnectorFlow_FullLifecycle(t *testing.T) {
	const orgID = "org_uuid_alpha"
	const userID = "user_alice_uuid"
	const role = "collaborator"

	var mu sync.Mutex
	state := "" // "" = absent, role = present
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "token ") {
			t.Errorf("authorization header must use 'token ' prefix; got %q", got)
		}
		memberPath := "/rest/orgs/" + orgID + "/members/" + userID
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodPatch && r.URL.Path == memberPath:
			state = role
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":{"attributes":{"role":"` + role + `"},"type":"org-membership"}}`))
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
			_, _ = w.Write([]byte(`{"data":{"attributes":{"role":"` + state + `"}}}`))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := map[string]interface{}{"org_id": orgID}
	secrets := map[string]interface{}{"api_token": "snAAAA1234bbbbCCCC"}
	grant := access.AccessGrant{UserExternalID: userID, ResourceExternalID: orgID, Role: role}

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
	if len(ents) != 1 || ents[0].ResourceExternalID != orgID || ents[0].Source != "direct" {
		t.Fatalf("ents = %#v, want 1 with org=%s source=direct", ents, orgID)
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
		t.Fatalf("expected empty entitlements, got %#v", ents)
	}
}

func TestSnykConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		map[string]interface{}{"org_id": "org_uuid"},
		map[string]interface{}{"api_token": "snAAAA1234bbbbCCCC"},
		access.AccessGrant{UserExternalID: "user_alice", ResourceExternalID: "org_uuid"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v, want 403", err)
	}
}
