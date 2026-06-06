package zoho_crm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// TestConnectorFlow_FullLifecycle exercises the advanced-capability
// lifecycle for Zoho CRM with a single httptest.Server.
func TestConnectorFlow_FullLifecycle(t *testing.T) {
	const userID = "u-1"
	const roleID = "r-100"
	role := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Zoho-oauthtoken ") {
			t.Errorf("auth header = %q", r.Header.Get("Authorization"))
		}
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/users/"+userID:
			var body struct {
				Users []struct {
					Role struct {
						ID string `json:"id"`
					} `json:"role"`
				} `json:"users"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if len(body.Users) == 0 {
				t.Errorf("missing users body")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			incoming := body.Users[0].Role.ID
			if incoming == zohoRevokeSentinelRole {
				if role == "" {
					// Already revoked.
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"code":"INVALID_DATA","message":"the related id does not exist"}`))
					return
				}
				role = ""
				w.WriteHeader(http.StatusOK)
				return
			}
			if role == incoming {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"code":"SUCCESS","message":"role updated"}`))
				return
			}
			role = incoming
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == "/users/"+userID:
			resp := map[string]interface{}{"users": []map[string]interface{}{}}
			if role != "" {
				resp["users"] = []map[string]interface{}{
					{"id": userID, "role": map[string]string{"id": role, "name": "Admin"}},
				}
			}
			_ = json.NewEncoder(w).Encode(resp)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	secrets := map[string]interface{}{"access_token": "tok"}
	cfg := map[string]interface{}{}
	if err := c.Validate(context.Background(), cfg, secrets); err != nil {
		t.Fatalf("Validate: %v", err)
	}

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
	if len(ents) != 1 || ents[0].ResourceExternalID != roleID {
		t.Fatalf("ListEntitlements after provision: got %#v", ents)
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
		t.Fatalf("ListEntitlements after revoke: expected empty, got %d", len(ents))
	}
}

func TestConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"code":"NO_PERMISSION","message":"forbidden"}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	grant := access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "r-1"}
	err := c.ProvisionAccess(context.Background(), map[string]interface{}{},
		map[string]interface{}{"access_token": "tok"}, grant)
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected 403 error, got %v", err)
	}
}
