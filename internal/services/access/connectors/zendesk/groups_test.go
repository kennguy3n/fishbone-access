package zendesk

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

func newZendeskGroupsTestServer(t *testing.T, groupsPages []zendeskGroupsResponse, memberPages map[string][]zendeskGroupMembershipsResponse) *httptest.Server {
	t.Helper()
	var (
		mu       sync.Mutex
		grpCalls int
		memCalls = map[string]int{}
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/v2/groups.json"):
			mu.Lock()
			idx := grpCalls
			grpCalls++
			mu.Unlock()
			if idx >= len(groupsPages) {
				_ = json.NewEncoder(w).Encode(zendeskGroupsResponse{})
				return
			}
			_ = json.NewEncoder(w).Encode(groupsPages[idx])
		case strings.HasPrefix(r.URL.Path, "/api/v2/group_memberships.json"):
			groupID := r.URL.Query().Get("group_id")
			mu.Lock()
			idx := memCalls[groupID]
			memCalls[groupID] = idx + 1
			mu.Unlock()
			pages := memberPages[groupID]
			if idx >= len(pages) {
				_ = json.NewEncoder(w).Encode(zendeskGroupMembershipsResponse{})
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

func withZendeskGroupsTestServer(t *testing.T, srv *httptest.Server) *ZendeskAccessConnector {
	t.Helper()
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	return c
}

func zdValidConfig() map[string]interface{} { return map[string]interface{}{"subdomain": "acme"} }
func zdValidSecrets() map[string]interface{} {
	return map[string]interface{}{"email": "u@x", "api_token": "tok"}
}

func TestZendesk_SyncGroups_HappyPath(t *testing.T) {
	srv := newZendeskGroupsTestServer(t, []zendeskGroupsResponse{
		{Groups: []zendeskGroup{{ID: 1, Name: "Tier 1 Support"}, {ID: 2, Name: "Engineering"}}},
	}, nil)
	c := withZendeskGroupsTestServer(t, srv)

	var got []*access.Identity
	if err := c.SyncGroups(context.Background(), zdValidConfig(), zdValidSecrets(), "", func(b []*access.Identity, _ string) error {
		got = append(got, b...)
		return nil
	}); err != nil {
		t.Fatalf("SyncGroups: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got = %d; want 2", len(got))
	}
	if got[0].ExternalID != "1" || got[0].DisplayName != "Tier 1 Support" {
		t.Errorf("got[0] = %+v", got[0])
	}
}

func TestZendesk_SyncGroups_Pagination(t *testing.T) {
	// Build NextPage URLs that point at the test server itself so the
	// urlOverride rewrite path is exercised.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/v2/groups.json") && r.URL.Query().Get("page") == "":
			_ = json.NewEncoder(w).Encode(zendeskGroupsResponse{
				Groups:   []zendeskGroup{{ID: 1, Name: "A"}},
				NextPage: "https://acme.zendesk.com/api/v2/groups.json?page=2",
			})
		case strings.HasPrefix(r.URL.Path, "/api/v2/groups.json") && r.URL.Query().Get("page") == "2":
			_ = json.NewEncoder(w).Encode(zendeskGroupsResponse{
				Groups: []zendeskGroup{{ID: 2, Name: "B"}},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	c := withZendeskGroupsTestServer(t, srv)

	var got []string
	if err := c.SyncGroups(context.Background(), zdValidConfig(), zdValidSecrets(), "", func(b []*access.Identity, _ string) error {
		for _, g := range b {
			got = append(got, g.ExternalID)
		}
		return nil
	}); err != nil {
		t.Fatalf("SyncGroups: %v", err)
	}
	if strings.Join(got, ",") != "1,2" {
		t.Errorf("got = %v; want [1 2]", got)
	}
}

func TestZendesk_CountGroups_HappyPath(t *testing.T) {
	srv := newZendeskGroupsTestServer(t, []zendeskGroupsResponse{
		{Groups: []zendeskGroup{{ID: 1}, {ID: 2}, {ID: 3}}},
	}, nil)
	c := withZendeskGroupsTestServer(t, srv)
	n, err := c.CountGroups(context.Background(), zdValidConfig(), zdValidSecrets())
	if err != nil {
		t.Fatalf("CountGroups: %v", err)
	}
	if n != 3 {
		t.Errorf("CountGroups = %d; want 3", n)
	}
}

func TestZendesk_SyncGroupMembers_HappyPath(t *testing.T) {
	srv := newZendeskGroupsTestServer(t, nil, map[string][]zendeskGroupMembershipsResponse{
		"42": {{GroupMemberships: []zendeskGroupMembership{{UserID: 100, GroupID: 42}, {UserID: 200, GroupID: 42}}}},
	})
	c := withZendeskGroupsTestServer(t, srv)

	var got []string
	if err := c.SyncGroupMembers(context.Background(), zdValidConfig(), zdValidSecrets(), "42", "", func(ids []string, _ string) error {
		got = append(got, ids...)
		return nil
	}); err != nil {
		t.Fatalf("SyncGroupMembers: %v", err)
	}
	if strings.Join(got, ",") != "100,200" {
		t.Errorf("got = %v; want [100 200]", got)
	}
}

func TestZendesk_SyncGroupMembers_MissingGroupID(t *testing.T) {
	c := New()
	err := c.SyncGroupMembers(context.Background(), zdValidConfig(), zdValidSecrets(), "", "", func(_ []string, _ string) error { return nil })
	if err == nil {
		t.Error("SyncGroupMembers returned nil; want missing-id error")
	}
}

func TestZendesk_SyncGroups_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	c := withZendeskGroupsTestServer(t, srv)
	err := c.SyncGroups(context.Background(), zdValidConfig(), zdValidSecrets(), "", func(_ []*access.Identity, _ string) error { return nil })
	if err == nil {
		t.Error("SyncGroups returned nil; want 401 error")
	}
}

func TestZendesk_SatisfiesGroupSyncerInterface(t *testing.T) {
	var _ access.GroupSyncer = New()
}
