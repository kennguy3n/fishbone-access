package terraform

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func tfFlowConfig() map[string]interface{} {
	return map[string]interface{}{"organization": "acme"}
}
func tfFlowSecrets() map[string]interface{} {
	return map[string]interface{}{"token": "tf.token"}
}

func TestConnectorFlow_FullLifecycle(t *testing.T) {
	const userID = "user-1"
	const teamID = "team-1"
	member := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("missing auth")
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/teams/"+teamID+"/relationships/users":
			if member {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"errors":[{"detail":"user already a member"}]}`))
				return
			}
			member = true
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v2/teams/"+teamID+"/relationships/users":
			if !member {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			member = false
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/users/"+userID+"/team-memberships":
			data := []map[string]interface{}{}
			if member {
				data = append(data, map[string]interface{}{
					"id":         "ms-1",
					"attributes": map[string]interface{}{"name": "Developers"},
					"relationships": map[string]interface{}{
						"team": map[string]interface{}{
							"data": map[string]interface{}{"id": teamID, "type": "teams"},
						},
					},
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
	grant := access.AccessGrant{UserExternalID: userID, ResourceExternalID: teamID}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), tfFlowConfig(), tfFlowSecrets(), grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	ents, err := c.ListEntitlements(context.Background(), tfFlowConfig(), tfFlowSecrets(), userID)
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(ents) != 1 || ents[0].ResourceExternalID != teamID {
		t.Fatalf("ents = %#v", ents)
	}
	for i := 0; i < 2; i++ {
		if err := c.RevokeAccess(context.Background(), tfFlowConfig(), tfFlowSecrets(), grant); err != nil {
			t.Fatalf("RevokeAccess[%d]: %v", i, err)
		}
	}
	ents, err = c.ListEntitlements(context.Background(), tfFlowConfig(), tfFlowSecrets(), userID)
	if err != nil {
		t.Fatalf("ListEntitlements after revoke: %v", err)
	}
	if len(ents) != 0 {
		t.Fatalf("expected empty, got %d", len(ents))
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
	err := c.ProvisionAccess(context.Background(), tfFlowConfig(), tfFlowSecrets(),
		access.AccessGrant{UserExternalID: "u", ResourceExternalID: "t"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
