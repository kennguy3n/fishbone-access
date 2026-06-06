package circleci

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
	const projectID = "proj-1"
	const contextID = "ctx-1"
	const restrictionID = "r-1"
	bound := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Circle-Token") == "" {
			t.Errorf("missing Circle-Token")
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/context/"+contextID+"/restrictions":
			if bound {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"message":"restriction already exists"}`))
				return
			}
			bound = true
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"` + restrictionID + `"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/context/"+contextID+"/restrictions":
			items := []map[string]string{}
			if bound {
				items = append(items, map[string]string{
					"id":                restrictionID,
					"context_id":        contextID,
					"project_id":        projectID,
					"restriction_type":  "project",
					"restriction_value": projectID,
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"items": items})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/context/restrictions":
			items := []map[string]string{}
			if bound {
				items = append(items, map[string]string{
					"id":                restrictionID,
					"context_id":        contextID,
					"project_id":        projectID,
					"restriction_type":  "project",
					"restriction_value": projectID,
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"items": items})
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v2/context/"+contextID+"/restrictions/"+restrictionID:
			bound = false
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
	secrets := map[string]interface{}{"token": "tok"}
	cfg := map[string]interface{}{}
	grant := access.AccessGrant{UserExternalID: projectID, ResourceExternalID: contextID}

	if err := c.Validate(context.Background(), cfg, secrets); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	ents, err := c.ListEntitlements(context.Background(), cfg, secrets, projectID)
	if err != nil {
		t.Fatalf("ListEntitlements after provision: %v", err)
	}
	if len(ents) != 1 || ents[0].ResourceExternalID != contextID {
		t.Fatalf("ents = %#v", ents)
	}
	for i := 0; i < 2; i++ {
		if err := c.RevokeAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("RevokeAccess[%d]: %v", i, err)
		}
	}
	ents, err = c.ListEntitlements(context.Background(), cfg, secrets, projectID)
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
	err := c.ProvisionAccess(context.Background(), map[string]interface{}{},
		map[string]interface{}{"token": "tok"},
		access.AccessGrant{UserExternalID: "proj-1", ResourceExternalID: "ctx-1"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
