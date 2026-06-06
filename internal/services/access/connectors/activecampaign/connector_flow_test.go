package activecampaign

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func acValidConfig() map[string]interface{}  { return map[string]interface{}{"account": "acme"} }
func acValidSecrets() map[string]interface{} { return map[string]interface{}{"api_key": "tok-AAAA"} }

func TestActiveCampaignConnectorFlow_FullLifecycle(t *testing.T) {
	const userID = "42"
	const groupID = "7"
	const ugID = "ug-1"
	hasMembership := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Api-Token") == "" {
			t.Errorf("missing Api-Token header")
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/3/userGroups":
			if hasMembership {
				w.WriteHeader(http.StatusUnprocessableEntity)
				_, _ = w.Write([]byte(`{"errors":[{"title":"User already in group"}]}`))
				return
			}
			hasMembership = true
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"userGroup": map[string]interface{}{"id": ugID, "user": userID, "userGroup": groupID},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/api/3/userGroups":
			ugs := []map[string]interface{}{}
			if hasMembership {
				q := r.URL.Query()
				if q.Get("filters[user]") == userID {
					ugs = append(ugs, map[string]interface{}{
						"id": ugID, "user": userID, "userGroup": groupID,
					})
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"userGroups": ugs})
		case r.Method == http.MethodDelete && r.URL.Path == "/api/3/userGroups/"+ugID:
			if !hasMembership {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			hasMembership = false
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := acValidConfig()
	secrets := acValidSecrets()
	grant := access.AccessGrant{UserExternalID: userID, ResourceExternalID: groupID}

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
	if len(ents) != 1 || ents[0].ResourceExternalID != groupID {
		t.Fatalf("ents = %#v, want 1 with groupID=%s", ents, groupID)
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

func TestActiveCampaignConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		acValidConfig(), acValidSecrets(),
		access.AccessGrant{UserExternalID: "42", ResourceExternalID: "7"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
