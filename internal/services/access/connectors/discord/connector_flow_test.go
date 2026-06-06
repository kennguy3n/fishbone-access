package discord

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
	const guildID = "1234567890"
	const userID = "987654321"
	const roleID = "55555"
	hasRole := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bot ") {
			t.Errorf("auth header missing: %q", r.Header.Get("Authorization"))
		}
		memberPath := "/api/v10/guilds/" + guildID + "/members/" + userID
		rolePath := memberPath + "/roles/" + roleID
		switch {
		case r.Method == http.MethodGet && r.URL.Path == memberPath:
			roles := []string{}
			if hasRole {
				roles = append(roles, roleID)
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"roles": roles,
				"user":  map[string]interface{}{"id": userID},
			})
		case r.Method == http.MethodPut && r.URL.Path == rolePath:
			if hasRole {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"message":"role already assigned"}`))
				return
			}
			hasRole = true
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete && r.URL.Path == rolePath:
			if !hasRole {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"message":"role not present"}`))
				return
			}
			hasRole = false
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := map[string]interface{}{"guild_id": guildID}
	secrets := map[string]interface{}{"bot_token": "tok"}
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
	if len(ents) != 1 || ents[0].ResourceExternalID != roleID {
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
		map[string]interface{}{"guild_id": "1234567890"},
		map[string]interface{}{"bot_token": "tok"},
		access.AccessGrant{UserExternalID: "987654321", ResourceExternalID: "55555"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
