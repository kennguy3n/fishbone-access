package teamwork

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
	const userID = "77"
	const projectID = "10001"
	isMember := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Basic ") {
			t.Errorf("auth header missing: %q", r.Header.Get("Authorization"))
		}
		path := "/projects/api/v3/projects/" + projectID + "/people.json"
		switch {
		case r.Method == http.MethodGet && r.URL.Path == path:
			people := []map[string]interface{}{}
			if isMember {
				people = append(people, map[string]interface{}{
					"id":            77,
					"email-address": "ada@example.com",
					"administrator": false,
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"people": people})
		case r.Method == http.MethodPut && r.URL.Path == path:
			body, _ := io.ReadAll(r.Body)
			switch {
			case strings.Contains(string(body), `"add"`):
				if isMember {
					w.WriteHeader(http.StatusConflict)
					_, _ = w.Write([]byte(`{"error":"already a member"}`))
					return
				}
				isMember = true
				w.WriteHeader(http.StatusOK)
			case strings.Contains(string(body), `"remove"`):
				isMember = false
				w.WriteHeader(http.StatusOK)
			default:
				t.Errorf("unexpected PUT body: %s", string(body))
				w.WriteHeader(http.StatusBadRequest)
			}
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := map[string]interface{}{"subdomain": "acme", "project_id": projectID}
	secrets := map[string]interface{}{"api_key": "key-1"}
	grant := access.AccessGrant{UserExternalID: userID, ResourceExternalID: projectID}

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
	if len(ents) != 1 || ents[0].ResourceExternalID != projectID {
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
		map[string]interface{}{"subdomain": "acme", "project_id": "10001"},
		map[string]interface{}{"api_key": "key-1"},
		access.AccessGrant{UserExternalID: "77", ResourceExternalID: "10001"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
