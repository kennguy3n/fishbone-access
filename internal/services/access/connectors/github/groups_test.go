package github

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// TestSyncGroups_HappyPathPaginates verifies that /orgs/{org}/teams
// is paginated via the Link rel="next" header and the connector
// rewrites the absolute URL onto the httptest server.
func TestSyncGroups_HappyPathPaginates(t *testing.T) {
	var srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/orgs/acme/teams" && r.URL.Query().Get("page") == "":
			w.Header().Set("Link", fmt.Sprintf(`<%s/orgs/acme/teams?per_page=100&page=2>; rel="next"`, defaultBaseURL))
			_, _ = w.Write([]byte(`[
				{"id":1,"slug":"eng","name":"Engineering"},
				{"id":2,"slug":"design","name":"Design"}
			]`))
		case r.URL.Path == "/orgs/acme/teams" && r.URL.Query().Get("page") == "2":
			_, _ = w.Write([]byte(`[{"id":3,"slug":"ops","name":"Ops"}]`))
		default:
			t.Errorf("unexpected request: %s?%s", r.URL.Path, r.URL.RawQuery)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	var got []*access.Identity
	err := c.SyncGroups(context.Background(), validConfig(), validSecrets(), "",
		func(b []*access.Identity, _ string) error {
			got = append(got, b...)
			return nil
		},
	)
	if err != nil {
		t.Fatalf("SyncGroups: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("groups = %d; want 3", len(got))
	}
	for _, g := range got {
		if g.Type != access.IdentityTypeGroup {
			t.Errorf("identity %q has type %q; want group", g.ExternalID, g.Type)
		}
	}
}

// TestSyncGroups_FailureSurfacesStatus verifies a 401 response (e.g.
// invalid PAT) is surfaced as an error.
func TestSyncGroups_FailureSurfacesStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"Bad credentials"}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	err := c.SyncGroups(context.Background(), validConfig(), validSecrets(), "",
		func(_ []*access.Identity, _ string) error { return nil },
	)
	if err == nil {
		t.Fatal("expected error on 401")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error %q missing status code", err.Error())
	}
}

// TestSyncGroupMembers_HappyPath verifies the connector resolves a
// numeric team ID to a slug via the legacy /teams/{id} endpoint and
// then paginates /orgs/{org}/teams/{slug}/members.
func TestSyncGroupMembers_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/teams/42":
			_, _ = w.Write([]byte(`{"id":42,"slug":"eng","name":"Engineering"}`))
		case "/orgs/acme/teams/eng/members":
			_, _ = w.Write([]byte(`[{"id":101,"login":"alice"},{"id":102,"login":"bob"}]`))
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	var members []string
	err := c.SyncGroupMembers(context.Background(), validConfig(), validSecrets(), "42", "",
		func(ids []string, _ string) error {
			members = append(members, ids...)
			return nil
		},
	)
	if err != nil {
		t.Fatalf("SyncGroupMembers: %v", err)
	}
	// Member IDs must be logins (matching SyncIdentities' ExternalID) so
	// group membership reconciles against identity records.
	if len(members) != 2 || members[0] != "alice" || members[1] != "bob" {
		t.Fatalf("members = %v; want [alice bob]", members)
	}
}

// TestSyncGroupMembers_AcceptsSlugDirectly verifies that a
// non-numeric external ID is treated as the slug already and skips
// the /teams/{id} resolution call.
func TestSyncGroupMembers_AcceptsSlugDirectly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/teams/") {
			t.Errorf("team-id resolution should not run for slug input: %s", r.URL.Path)
		}
		if r.URL.Path == "/orgs/acme/teams/eng/members" {
			_, _ = w.Write([]byte(`[{"id":1,"login":"alice"}]`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	err := c.SyncGroupMembers(context.Background(), validConfig(), validSecrets(), "eng", "",
		func(_ []string, _ string) error { return nil },
	)
	if err != nil {
		t.Fatalf("SyncGroupMembers: %v", err)
	}
}

// TestSyncGroupMembers_RejectsEmptyGroupID is the failure-path test.
func TestSyncGroupMembers_RejectsEmptyGroupID(t *testing.T) {
	c := New()
	err := c.SyncGroupMembers(context.Background(), validConfig(), validSecrets(), "", "",
		func(_ []string, _ string) error { return nil },
	)
	if err == nil {
		t.Fatal("expected error on empty group external id")
	}
}

// TestCountGroups_StreamsTotal verifies the count helper streams
// every page and returns the cumulative total.
func TestCountGroups_StreamsTotal(t *testing.T) {
	calls := 0
	var srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		switch calls {
		case 1:
			w.Header().Set("Link", fmt.Sprintf(`<%s/orgs/acme/teams?per_page=100&page=2>; rel="next"`, defaultBaseURL))
			_, _ = w.Write([]byte(`[{"id":1,"slug":"a","name":"A"},{"id":2,"slug":"b","name":"B"}]`))
		default:
			_, _ = w.Write([]byte(`[{"id":3,"slug":"c","name":"C"}]`))
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	n, err := c.CountGroups(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("CountGroups: %v", err)
	}
	if n != 3 {
		t.Errorf("count = %d; want 3", n)
	}
}
