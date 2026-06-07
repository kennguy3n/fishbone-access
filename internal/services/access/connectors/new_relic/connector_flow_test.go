package new_relic

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func TestConnectorFlow_FullLifecycle(t *testing.T) {
	const userID = "u-1"
	const groupID = "g-1"
	const groupName = "Admins"
	inGroup := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/graphql" || r.Method != http.MethodPost {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.Header.Get("API-Key") == "" {
			t.Errorf("missing API-Key")
		}
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Query     string                 `json:"query"`
			Variables map[string]interface{} `json:"variables"`
		}
		_ = json.Unmarshal(body, &req)
		switch {
		case strings.Contains(req.Query, "userManagementAddUsersToGroups"):
			if inGroup {
				_, _ = w.Write([]byte(`{"data":{"userManagementAddUsersToGroups":{"groups":[{"id":"` + groupID + `","displayName":"` + groupName + `"}]}}}`))
				return
			}
			inGroup = true
			_, _ = w.Write([]byte(`{"data":{"userManagementAddUsersToGroups":{"groups":[{"id":"` + groupID + `","displayName":"` + groupName + `"}]}}}`))
		case strings.Contains(req.Query, "userManagementRemoveUsersFromGroups"):
			if !inGroup {
				_, _ = w.Write([]byte(`{"data":{"userManagementRemoveUsersFromGroups":{"groups":[]}},"errors":[{"message":"user is not a member"}]}`))
				return
			}
			inGroup = false
			_, _ = w.Write([]byte(`{"data":{"userManagementRemoveUsersFromGroups":{"groups":[]}}}`))
		default:
			groups := []map[string]string{}
			if inGroup {
				groups = append(groups, map[string]string{"id": groupID, "displayName": groupName})
			}
			payload := map[string]interface{}{
				"data": map[string]interface{}{
					"actor": map[string]interface{}{
						"organization": map[string]interface{}{
							"userManagement": map[string]interface{}{
								"authenticationDomains": map[string]interface{}{
									"authenticationDomains": []map[string]interface{}{{
										"users": map[string]interface{}{
											"users": []map[string]interface{}{{
												"id":     userID,
												"groups": map[string]interface{}{"groups": groups},
											}},
										},
									}},
								},
							},
						},
					},
				},
			}
			_ = json.NewEncoder(w).Encode(payload)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	secrets := map[string]interface{}{"api_key": "tok"}
	cfg := map[string]interface{}{}
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
		map[string]interface{}{},
		map[string]interface{}{"api_key": "tok"},
		access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "g-1"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
