package digitalocean

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func doValidConfig() map[string]interface{} { return map[string]interface{}{} }
func doValidSecrets() map[string]interface{} {
	return map[string]interface{}{"api_token": "dop_v1_abcdef"}
}

func TestDigitalOceanConnectorFlow_FullLifecycle(t *testing.T) {
	const userEmail = "alice@example.com"
	const teamID = "team-9"
	isMember := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("auth header missing: %q", r.Header.Get("Authorization"))
		}
		postPath := "/v2/teams/" + teamID + "/members"
		delPath := "/v2/teams/" + teamID + "/members/" + userEmail
		switch {
		case r.Method == http.MethodPost && r.URL.Path == postPath:
			if isMember {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"message":"already a member"}`))
				return
			}
			isMember = true
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodDelete && r.URL.Path == delPath:
			if !isMember {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"message":"not found"}`))
				return
			}
			isMember = false
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/v2/teams":
			members := []map[string]string{}
			if isMember {
				members = append(members, map[string]string{"email": userEmail, "uuid": "u-1"})
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"teams": []map[string]interface{}{{
					"id":      teamID,
					"members": members,
				}},
			})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := doValidConfig()
	secrets := doValidSecrets()
	grant := access.AccessGrant{UserExternalID: userEmail, ResourceExternalID: teamID}

	if err := c.Validate(context.Background(), cfg, secrets); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	ents, err := c.ListEntitlements(context.Background(), cfg, secrets, userEmail)
	if err != nil {
		t.Fatalf("ListEntitlements after provision: %v", err)
	}
	if len(ents) != 1 || ents[0].ResourceExternalID != teamID {
		t.Fatalf("ents = %#v, want 1 with teamID=%s", ents, teamID)
	}
	for i := 0; i < 2; i++ {
		if err := c.RevokeAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("RevokeAccess[%d]: %v", i, err)
		}
	}
	ents, err = c.ListEntitlements(context.Background(), cfg, secrets, userEmail)
	if err != nil {
		t.Fatalf("ListEntitlements after revoke: %v", err)
	}
	if len(ents) != 0 {
		t.Fatalf("expected empty, got %#v", ents)
	}
}

func TestDigitalOceanConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		doValidConfig(), doValidSecrets(),
		access.AccessGrant{UserExternalID: "alice@example.com", ResourceExternalID: "team-9"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
