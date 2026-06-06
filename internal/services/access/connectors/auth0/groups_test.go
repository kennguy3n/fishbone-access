package auth0

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func auth0GroupsTestServer(t *testing.T, orgsPages [][]auth0Organization, membersPages map[string][]auth0OrgMembersPage) *httptest.Server {
	t.Helper()
	var (
		mu       sync.Mutex
		orgCalls int
		memCalls = map[string]int{}
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/oauth/token":
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok", "token_type": "Bearer", "expires_in": "3600"})
		case r.URL.Path == "/api/v2/organizations":
			mu.Lock()
			idx := orgCalls
			orgCalls++
			mu.Unlock()
			if idx >= len(orgsPages) {
				_, _ = w.Write([]byte(`[]`))
				return
			}
			_ = json.NewEncoder(w).Encode(orgsPages[idx])
		case strings.HasPrefix(r.URL.Path, "/api/v2/organizations/") && strings.HasSuffix(r.URL.Path, "/members"):
			orgID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v2/organizations/"), "/members")
			mu.Lock()
			idx := memCalls[orgID]
			memCalls[orgID] = idx + 1
			mu.Unlock()
			pages := membersPages[orgID]
			if idx >= len(pages) {
				_ = json.NewEncoder(w).Encode(auth0OrgMembersPage{})
				return
			}
			_ = json.NewEncoder(w).Encode(pages[idx])
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func withAuth0GroupsTestServer(t *testing.T, srv *httptest.Server) *Auth0AccessConnector {
	t.Helper()
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	return c
}

func TestAuth0Connector_SyncGroups_HappyPath(t *testing.T) {
	srv := auth0GroupsTestServer(t,
		[][]auth0Organization{
			{
				{ID: "org_1", Name: "engineering", DisplayName: "Engineering"},
				{ID: "org_2", Name: "support", DisplayName: ""},
			},
		},
		nil,
	)
	c := withAuth0GroupsTestServer(t, srv)

	var groups []*access.Identity
	if err := c.SyncGroups(context.Background(), validConfig(), validSecrets(), "", func(b []*access.Identity, _ string) error {
		groups = append(groups, b...)
		return nil
	}); err != nil {
		t.Fatalf("SyncGroups: %v", err)
	}
	if len(groups) != 2 {
		t.Fatalf("groups = %d; want 2", len(groups))
	}
	if groups[0].ExternalID != "org_1" || groups[0].DisplayName != "Engineering" {
		t.Errorf("groups[0] = %+v; want {ExternalID: org_1, DisplayName: Engineering}", groups[0])
	}
	if groups[1].DisplayName != "support" {
		t.Errorf("groups[1].DisplayName = %q; want fallback to name", groups[1].DisplayName)
	}
}

func TestAuth0Connector_SyncGroups_HandlerError(t *testing.T) {
	srv := auth0GroupsTestServer(t,
		[][]auth0Organization{{{ID: "org_1", Name: "x"}}},
		nil,
	)
	c := withAuth0GroupsTestServer(t, srv)

	err := c.SyncGroups(context.Background(), validConfig(), validSecrets(), "", func(_ []*access.Identity, _ string) error {
		return context.Canceled
	})
	if err != context.Canceled {
		t.Errorf("err = %v; want context.Canceled", err)
	}
}

func TestAuth0Connector_CountGroups_HappyPath(t *testing.T) {
	srv := auth0GroupsTestServer(t,
		[][]auth0Organization{{{ID: "org_1"}, {ID: "org_2"}, {ID: "org_3"}}},
		nil,
	)
	c := withAuth0GroupsTestServer(t, srv)

	n, err := c.CountGroups(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("CountGroups: %v", err)
	}
	if n != 3 {
		t.Errorf("CountGroups = %d; want 3", n)
	}
}

func TestAuth0Connector_SyncGroupMembers_PaginationAndStop(t *testing.T) {
	srv := auth0GroupsTestServer(t, nil, map[string][]auth0OrgMembersPage{
		"org_1": {
			{Members: []auth0OrganizationMember{{UserID: "auth0|u1"}, {UserID: "auth0|u2"}}, Next: "cur-2"},
			{Members: []auth0OrganizationMember{{UserID: "auth0|u3"}}, Next: ""},
		},
	})
	c := withAuth0GroupsTestServer(t, srv)

	var got []string
	if err := c.SyncGroupMembers(context.Background(), validConfig(), validSecrets(), "org_1", "", func(ids []string, _ string) error {
		got = append(got, ids...)
		return nil
	}); err != nil {
		t.Fatalf("SyncGroupMembers: %v", err)
	}
	want := []string{"auth0|u1", "auth0|u2", "auth0|u3"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("got = %v; want %v", got, want)
	}
}

func TestAuth0Connector_SyncGroupMembers_MissingGroupID(t *testing.T) {
	c := New()
	err := c.SyncGroupMembers(context.Background(), validConfig(), validSecrets(), "", "", func(_ []string, _ string) error { return nil })
	if err == nil {
		t.Error("SyncGroupMembers returned nil; want missing-id error")
	}
}

func TestAuth0Connector_SyncGroups_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	t.Cleanup(srv.Close)
	c := withAuth0GroupsTestServer(t, srv)

	err := c.SyncGroups(context.Background(), validConfig(), validSecrets(), "", func(_ []*access.Identity, _ string) error { return nil })
	if err == nil {
		t.Error("SyncGroups returned nil; want 401 error")
	}
}

func TestAuth0Connector_SatisfiesGroupSyncerInterface(t *testing.T) {
	var _ access.GroupSyncer = New()
}
