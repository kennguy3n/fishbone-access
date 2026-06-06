package basecamp

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
	const email = "ada@example.com"
	const personID = 42
	const projectID = "100"
	isMember := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("auth header missing: %q", r.Header.Get("Authorization"))
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/projects/"+projectID+"/people/new.json":
			if isMember {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"error":"already on project"}`))
				return
			}
			isMember = true
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/projects/"+projectID+"/people/"):
			isMember = false
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/projects/"+projectID+"/people.json":
			people := []map[string]interface{}{}
			if isMember {
				people = append(people, map[string]interface{}{
					"id":            personID,
					"email_address": email,
					"admin":         false,
					"owner":         false,
				})
			}
			_ = json.NewEncoder(w).Encode(people)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := map[string]interface{}{"account_id": "1234", "project_id": projectID}
	secrets := map[string]interface{}{"access_token": "tok"}
	grant := access.AccessGrant{UserExternalID: email, ResourceExternalID: projectID}

	if err := c.Validate(context.Background(), cfg, secrets); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	ents, err := c.ListEntitlements(context.Background(), cfg, secrets, email)
	if err != nil {
		t.Fatalf("ListEntitlements after provision: %v", err)
	}
	if len(ents) != 1 || ents[0].ResourceExternalID != projectID {
		t.Fatalf("ents = %#v", ents)
	}
	for i := 0; i < 2; i++ {
		if err := c.RevokeAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("RevokeAccess[%d]: %v", i, err)
		}
	}
	ents, err = c.ListEntitlements(context.Background(), cfg, secrets, email)
	if err != nil {
		t.Fatalf("ListEntitlements after revoke: %v", err)
	}
	if len(ents) != 0 {
		t.Fatalf("expected empty, got %#v", ents)
	}
}

// TestRevokeAccess_FindsUserOnSecondPage guards against the pagination
// gap where listBasecampProjectPeople only fetched the first page: a user
// on a later page would be invisible to findBasecampPersonID, so
// RevokeAccess would return idempotent-success without deleting them.
func TestRevokeAccess_FindsUserOnSecondPage(t *testing.T) {
	const email = "ada@example.com"
	const personID = 42
	const projectID = "100"
	var srvURL string
	deleted := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/projects/"+projectID+"/people/"):
			deleted = strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/projects/"+projectID+"/people/"), ".json")
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/projects/"+projectID+"/people.json":
			if r.URL.Query().Get("page") == "2" {
				// Target user lives on the second page only.
				_ = json.NewEncoder(w).Encode([]map[string]interface{}{
					{"id": personID, "email_address": email},
				})
				return
			}
			w.Header().Set("Link", "<"+srvURL+"/projects/"+projectID+"/people.json?page=2>; rel=\"next\"")
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 1, "email_address": "other@example.com"},
			})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)
	srvURL = srv.URL
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := map[string]interface{}{"account_id": "1234", "project_id": projectID}
	secrets := map[string]interface{}{"access_token": "tok"}
	grant := access.AccessGrant{UserExternalID: email, ResourceExternalID: projectID}
	if err := c.RevokeAccess(context.Background(), cfg, secrets, grant); err != nil {
		t.Fatalf("RevokeAccess: %v", err)
	}
	if deleted != "42" {
		t.Fatalf("expected DELETE of person 42 found on page 2, got deleted=%q", deleted)
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
		map[string]interface{}{"account_id": "1234", "project_id": "100"},
		map[string]interface{}{"access_token": "tok"},
		access.AccessGrant{UserExternalID: "ada@example.com", ResourceExternalID: "100"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
