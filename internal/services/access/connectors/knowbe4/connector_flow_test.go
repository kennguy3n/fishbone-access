package knowbe4

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
	const userID = "777"
	const groupID = "9"
	isMember := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("auth header missing: %q", r.Header.Get("Authorization"))
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/groups/"+groupID+"/members":
			members := []map[string]interface{}{}
			if isMember {
				members = append(members, map[string]interface{}{"id": 777, "email": "ada@example.com"})
			}
			_ = json.NewEncoder(w).Encode(members)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/groups/"+groupID+"/members":
			// KnowBe4 user ids are numeric; the provision body must send
			// user_id as a JSON number, not a quoted string.
			var probe map[string]json.RawMessage
			if err := json.NewDecoder(r.Body).Decode(&probe); err != nil {
				t.Errorf("decode provision body: %v", err)
			} else if got := strings.TrimSpace(string(probe["user_id"])); got != "777" {
				t.Errorf("user_id = %s; want numeric 777 (no quotes)", got)
			}
			if isMember {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"error":"already a member"}`))
				return
			}
			isMember = true
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/groups/"+groupID+"/members/"+userID:
			isMember = false
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
	cfg := map[string]interface{}{"region": "us", "group_id": groupID}
	secrets := map[string]interface{}{"token": "tok"}
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

// TestListEntitlements_Paginates verifies ListEntitlements walks every page
// of /v1/groups/{id}/members: page 1 is a full page (pageSize members) that
// does not contain the user, and the user only appears on page 2. A
// single-page fetch would wrongly report no entitlement.
func TestListEntitlements_Paginates(t *testing.T) {
	const groupID = "9"
	const userID = "5555"
	var sawPages []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/v1/groups/"+groupID+"/members") {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		page := r.URL.Query().Get("page")
		sawPages = append(sawPages, page)
		members := []map[string]interface{}{}
		switch page {
		case "1":
			// Full page that does NOT contain the user, forcing a page 2.
			for i := 0; i < pageSize; i++ {
				members = append(members, map[string]interface{}{"id": 1000 + i, "email": "x@example.com"})
			}
		case "2":
			members = append(members, map[string]interface{}{"id": 5555, "email": "needle@example.com"})
		}
		_ = json.NewEncoder(w).Encode(members)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	ents, err := c.ListEntitlements(context.Background(),
		map[string]interface{}{"region": "us", "group_id": groupID},
		map[string]interface{}{"token": "tok"}, userID)
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(ents) != 1 || ents[0].ResourceExternalID != groupID {
		t.Fatalf("ents = %#v; want 1 with group %s", ents, groupID)
	}
	if len(sawPages) != 2 || sawPages[0] != "1" || sawPages[1] != "2" {
		t.Fatalf("requested pages = %v; want [1 2]", sawPages)
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
		map[string]interface{}{"region": "us", "group_id": "9"},
		map[string]interface{}{"token": "tok"},
		access.AccessGrant{UserExternalID: "777", ResourceExternalID: "9"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
