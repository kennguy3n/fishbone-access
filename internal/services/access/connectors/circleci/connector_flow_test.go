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

// TestListEntitlements_FollowsPagination guards against only reading the
// first page of context restrictions. The /api/v2/context/restrictions
// endpoint returns a next_page_token; entitlements on later pages must be
// followed via the page-token query param or they are silently dropped.
func TestListEntitlements_FollowsPagination(t *testing.T) {
	const projectID = "proj-pg"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/context/restrictions" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if r.URL.Query().Get("project_id") != projectID {
			t.Errorf("project_id = %q", r.URL.Query().Get("project_id"))
		}
		switch r.URL.Query().Get("page-token") {
		case "":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"items": []map[string]string{{
					"id": "r-1", "context_id": "ctx-A",
					"restriction_type": "project", "restriction_value": projectID,
				}},
				"next_page_token": "tok2",
			})
		case "tok2":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"items": []map[string]string{{
					"id": "r-2", "context_id": "ctx-B",
					"restriction_type": "project", "restriction_value": projectID,
				}},
			})
		default:
			t.Errorf("unexpected page-token %q", r.URL.Query().Get("page-token"))
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	ents, err := c.ListEntitlements(context.Background(), map[string]interface{}{},
		map[string]interface{}{"token": "tok"}, projectID)
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(ents) != 2 {
		t.Fatalf("len = %d, want 2 (second page not followed?): %#v", len(ents), ents)
	}
	got := map[string]bool{}
	for _, e := range ents {
		got[e.ResourceExternalID] = true
	}
	if !got["ctx-A"] || !got["ctx-B"] {
		t.Errorf("missing a context across pages: %#v", ents)
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
