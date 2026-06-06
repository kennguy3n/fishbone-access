package vercel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func vercelValidConfig() map[string]interface{} {
	return map[string]interface{}{"team_id": "team_abc"}
}
func vercelValidSecrets() map[string]interface{} {
	return map[string]interface{}{"api_token": "vercel-token-AAAA"}
}

func TestVercelConnectorFlow_FullLifecycle(t *testing.T) {
	const userID = "u-42"
	const role = "DEVELOPER"
	isMember := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("auth missing")
		}
		// Vercel versions these endpoints independently: invite (POST)
		// and remove (DELETE) live under /v1, while listing members is
		// only served from the /v2 (and newer) collection endpoint.
		postPath := "/v1/teams/team_abc/members"
		listPath := "/v2/teams/team_abc/members"
		delPath := postPath + "/" + userID
		switch {
		case r.Method == http.MethodPost && r.URL.Path == postPath:
			if isMember {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"error":"already a member"}`))
				return
			}
			isMember = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodDelete && r.URL.Path == delPath:
			if !isMember {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			isMember = false
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == listPath:
			members := []map[string]string{}
			if isMember {
				members = append(members, map[string]string{"uid": userID, "role": role, "email": "alice@example.com"})
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
	cfg := vercelValidConfig()
	secrets := vercelValidSecrets()
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

// TestVercelListEntitlements_UsesV2MembersEndpoint pins ListEntitlements to
// the v2 member-collection endpoint. Vercel exposes no /v1 member-list
// endpoint, so a v1 GET 404s on the real API and the connector would
// silently report "no entitlements". The mock serves the member list only
// at /v2 and 404s any /v1 GET, so this test fails if the read regresses to
// /v1.
func TestVercelListEntitlements_UsesV2MembersEndpoint(t *testing.T) {
	const userID = "u-77"
	const role = "VIEWER"
	v1ListHit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v2/teams/team_abc/members":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"members": []map[string]string{{"uid": userID, "role": role, "email": "bob@example.com"}},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/teams/team_abc/members":
			v1ListHit = true
			w.WriteHeader(http.StatusNotFound)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	ents, err := c.ListEntitlements(context.Background(),
		vercelValidConfig(), vercelValidSecrets(), userID)
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if v1ListHit {
		t.Fatalf("ListEntitlements queried the non-existent /v1 member-list endpoint")
	}
	if len(ents) != 1 || ents[0].ResourceExternalID != role {
		t.Fatalf("ents = %#v, want 1 with role=%s", ents, role)
	}
}

func TestVercelConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		vercelValidConfig(), vercelValidSecrets(),
		access.AccessGrant{UserExternalID: "u-42", ResourceExternalID: "DEVELOPER"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
