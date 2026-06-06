package wrike

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
	const userID = "KX1234"
	const groupID = "G-9"
	isMember := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("auth header missing: %q", r.Header.Get("Authorization"))
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v4/groups/"+groupID:
			members := []string{}
			if isMember {
				members = append(members, userID)
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []map[string]interface{}{{
					"id":        groupID,
					"title":     "Admins",
					"memberIds": members,
				}},
			})
		case r.Method == http.MethodPut && r.URL.Path == "/api/v4/groups/"+groupID:
			body, _ := io.ReadAll(r.Body)
			switch {
			case strings.Contains(string(body), "addMembers"):
				if isMember {
					w.WriteHeader(http.StatusConflict)
					_, _ = w.Write([]byte(`{"errorDescription":"already a member"}`))
					return
				}
				isMember = true
				_, _ = w.Write([]byte(`{"data":[{"id":"` + groupID + `"}]}`))
			case strings.Contains(string(body), "removeMembers"):
				isMember = false
				_, _ = w.Write([]byte(`{"data":[{"id":"` + groupID + `"}]}`))
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
	cfg := map[string]interface{}{"host": "app-us2.wrike.com", "group_id": groupID}
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

// TestConnectorFlow_RevokeBypassesPreCheck guards against regressing the bug
// where RevokeAccess silently no-opped whenever the /groups/{id} pre-check
// fetch failed with a transient error. With the pre-check removed, a flaky
// group-fetch endpoint must NOT prevent the destructive PUT removeMembers
// from being issued. We simulate a hard failure on the GET endpoint, assert
// no GET is ever made (the pre-check is gone), and assert exactly one PUT
// removeMembers fires.
func TestConnectorFlow_RevokeBypassesPreCheck(t *testing.T) {
	const userID = "KX1234"
	const groupID = "G-9"
	var getCount, putCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v4/groups/"+groupID:
			getCount++
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"errorDescription":"backend unavailable"}`))
		case r.Method == http.MethodPut && r.URL.Path == "/api/v4/groups/"+groupID:
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), "removeMembers") {
				t.Errorf("expected removeMembers body, got %s", string(body))
			}
			if !strings.Contains(string(body), userID) {
				t.Errorf("expected user id %q in body, got %s", userID, string(body))
			}
			putCount++
			_, _ = w.Write([]byte(`{"data":[{"id":"` + groupID + `"}]}`))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.RevokeAccess(context.Background(),
		map[string]interface{}{"host": "app-us2.wrike.com", "group_id": groupID},
		map[string]interface{}{"token": "tok"},
		access.AccessGrant{UserExternalID: userID, ResourceExternalID: groupID}); err != nil {
		t.Fatalf("RevokeAccess with flaky pre-check endpoint: %v", err)
	}
	if getCount != 0 {
		t.Fatalf("expected zero pre-check GETs (pre-check removed), got %d", getCount)
	}
	if putCount != 1 {
		t.Fatalf("expected exactly one PUT removeMembers, got %d", putCount)
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
		map[string]interface{}{"host": "app-us2.wrike.com", "group_id": "G-9"},
		map[string]interface{}{"token": "tok"},
		access.AccessGrant{UserExternalID: "KX1234", ResourceExternalID: "G-9"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
