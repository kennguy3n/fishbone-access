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
		postPath := "/v1/teams/team_abc/members"
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
		case r.Method == http.MethodGet && r.URL.Path == postPath:
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
