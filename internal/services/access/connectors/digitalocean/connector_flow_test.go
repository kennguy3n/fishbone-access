package digitalocean

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func doValidConfig() map[string]interface{} { return map[string]interface{}{} }
func doValidSecrets() map[string]interface{} {
	return map[string]interface{}{"api_token": "dop_v1_abcdef"}
}

func TestDigitalOceanConnectorFlow_FullLifecycle(t *testing.T) {
	const userEmail = "alice@example.com"
	const teamID = "team-9"
	isMember := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("auth header missing: %q", r.Header.Get("Authorization"))
		}
		postPath := "/v2/teams/" + teamID + "/members"
		delPath := "/v2/teams/" + teamID + "/members/" + userEmail
		switch {
		case r.Method == http.MethodPost && r.URL.Path == postPath:
			if isMember {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"message":"already a member"}`))
				return
			}
			isMember = true
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodDelete && r.URL.Path == delPath:
			if !isMember {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"message":"not found"}`))
				return
			}
			isMember = false
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/v2/teams":
			members := []map[string]string{}
			if isMember {
				members = append(members, map[string]string{"email": userEmail, "uuid": "u-1"})
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"teams": []map[string]interface{}{{
					"id":      teamID,
					"members": members,
				}},
			})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := doValidConfig()
	secrets := doValidSecrets()
	grant := access.AccessGrant{UserExternalID: userEmail, ResourceExternalID: teamID}

	if err := c.Validate(context.Background(), cfg, secrets); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	ents, err := c.ListEntitlements(context.Background(), cfg, secrets, userEmail)
	if err != nil {
		t.Fatalf("ListEntitlements after provision: %v", err)
	}
	if len(ents) != 1 || ents[0].ResourceExternalID != teamID {
		t.Fatalf("ents = %#v, want 1 with teamID=%s", ents, teamID)
	}
	for i := 0; i < 2; i++ {
		if err := c.RevokeAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("RevokeAccess[%d]: %v", i, err)
		}
	}
	ents, err = c.ListEntitlements(context.Background(), cfg, secrets, userEmail)
	if err != nil {
		t.Fatalf("ListEntitlements after revoke: %v", err)
	}
	if len(ents) != 0 {
		t.Fatalf("expected empty, got %#v", ents)
	}
}

// TestListEntitlements_PaginatesTeams guards against the regression
// where ListEntitlements fetched only the first page of /v2/teams and
// ignored links.pages.next, so a user whose team lived on a later page
// got an empty (false "no access") entitlement set. The target user
// here is only a member of a team returned on page 2.
func TestListEntitlements_PaginatesTeams(t *testing.T) {
	const userEmail = "carol@example.com"
	var page1, page2 int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/teams" {
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("page") == "2" {
			page2++
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"teams": []map[string]interface{}{{
					"id":      "team-late",
					"members": []map[string]string{{"email": userEmail, "uuid": "u-c"}},
				}},
			})
			return
		}
		page1++
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"teams": []map[string]interface{}{{
				"id":      "team-early",
				"members": []map[string]string{{"email": "someone@else.com", "uuid": "u-x"}},
			}},
			"links": map[string]interface{}{
				"pages": map[string]interface{}{"next": "https://api.digitalocean.com/v2/teams?page=2&per_page=200"},
			},
		})
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	ents, err := c.ListEntitlements(context.Background(), doValidConfig(), doValidSecrets(), userEmail)
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if page1 == 0 || page2 == 0 {
		t.Fatalf("expected both pages fetched: page1=%d page2=%d", page1, page2)
	}
	if len(ents) != 1 || ents[0].ResourceExternalID != "team-late" {
		t.Fatalf("ents = %#v, want 1 with team-late", ents)
	}
}

// TestNextPath pins the pagination-link normalization. The result is
// re-joined onto baseURL(), so every form must come back host-rooted
// (leading slash). A relative link without a leading slash previously
// passed through verbatim and produced a malformed URL when concatenated
// onto the host.
func TestNextPath(t *testing.T) {
	cases := []struct {
		name string
		next string
		want string
	}{
		{"empty", "", ""},
		{"absolute", "https://api.digitalocean.com/v2/teams?page=2&per_page=200", "/v2/teams?page=2&per_page=200"},
		{"rooted relative", "/v2/teams?page=2", "/v2/teams?page=2"},
		{"bare relative", "v2/teams?page=2", "/v2/teams?page=2"},
		{"absolute no query", "https://api.digitalocean.com/v2/teams", "/v2/teams"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := nextPath(tc.next); got != tc.want {
				t.Fatalf("nextPath(%q) = %q, want %q", tc.next, got, tc.want)
			}
		})
	}
}

// TestListEntitlements_PaginatesRelativeNextLink proves the full
// pagination loop survives a relative next link (no scheme/host, no
// leading slash). Without the nextPath leading-slash fix, page 2 would
// be requested at a malformed URL and never reached.
func TestListEntitlements_PaginatesRelativeNextLink(t *testing.T) {
	const userEmail = "dave@example.com"
	var page2 int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/teams" {
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("page") == "2" {
			page2++
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"teams": []map[string]interface{}{{
					"id":      "team-rel",
					"members": []map[string]string{{"email": userEmail, "uuid": "u-d"}},
				}},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"teams": []map[string]interface{}{{
				"id":      "team-first",
				"members": []map[string]string{{"email": "nobody@else.com", "uuid": "u-z"}},
			}},
			"links": map[string]interface{}{
				"pages": map[string]interface{}{"next": "v2/teams?page=2&per_page=200"},
			},
		})
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	ents, err := c.ListEntitlements(context.Background(), doValidConfig(), doValidSecrets(), userEmail)
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if page2 == 0 {
		t.Fatalf("page 2 was never fetched via the relative next link")
	}
	if len(ents) != 1 || ents[0].ResourceExternalID != "team-rel" {
		t.Fatalf("ents = %#v, want 1 with team-rel", ents)
	}
}

// TestSyncIdentities_MaxPageCap proves the team-members page walk is
// bounded. The server returns a perpetual links.pages.next (circular
// cursor); without the maxEntitlementPages cap the loop would never
// terminate. The escape hatch only fires past the cap, so asserting
// exactly maxEntitlementPages requests guards the fix.
func TestSyncIdentities_MaxPageCap(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		next := ""
		if hits < maxEntitlementPages+50 {
			next = "https://api.digitalocean.com/v2/team/members?page=loop"
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"members": []map[string]interface{}{},
			"links":   map[string]interface{}{"pages": map[string]interface{}{"next": next}},
		})
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.SyncIdentities(context.Background(), doValidConfig(), doValidSecrets(), "",
		func([]*access.Identity, string) error { return nil })
	if err != nil {
		t.Fatalf("SyncIdentities: %v", err)
	}
	if hits != maxEntitlementPages {
		t.Fatalf("made %d requests, want exactly %d (page walk must be capped)", hits, maxEntitlementPages)
	}
}

func TestDigitalOceanConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		doValidConfig(), doValidSecrets(),
		access.AccessGrant{UserExternalID: "alice@example.com", ResourceExternalID: "team-9"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
