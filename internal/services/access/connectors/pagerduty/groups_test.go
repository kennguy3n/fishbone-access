package pagerduty

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

func newPagerDutyGroupsTestServer(t *testing.T, teamPages []pagerdutyTeamsResponse, memberPages map[string][]pagerdutyTeamMembersResponse) *httptest.Server {
	t.Helper()
	var (
		mu       sync.Mutex
		tmCalls  int
		memCalls = map[string]int{}
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/teams":
			mu.Lock()
			idx := tmCalls
			tmCalls++
			mu.Unlock()
			if idx >= len(teamPages) {
				_ = json.NewEncoder(w).Encode(pagerdutyTeamsResponse{})
				return
			}
			_ = json.NewEncoder(w).Encode(teamPages[idx])
		case strings.HasPrefix(r.URL.Path, "/teams/") && strings.HasSuffix(r.URL.Path, "/members"):
			gid := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/teams/"), "/members")
			mu.Lock()
			idx := memCalls[gid]
			memCalls[gid] = idx + 1
			mu.Unlock()
			pages := memberPages[gid]
			if idx >= len(pages) {
				_ = json.NewEncoder(w).Encode(pagerdutyTeamMembersResponse{})
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

func withPagerDutyGroupsTestServer(t *testing.T, srv *httptest.Server) *PagerDutyAccessConnector {
	t.Helper()
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	return c
}

func pdGroupsValidConfig() map[string]interface{} { return map[string]interface{}{} }
func pdGroupsValidSecrets() map[string]interface{} {
	return map[string]interface{}{"api_token": "tok-abcdef"}
}

func TestPagerDuty_SyncGroups_HappyPath(t *testing.T) {
	srv := newPagerDutyGroupsTestServer(t,
		[]pagerdutyTeamsResponse{
			{
				Teams: []pagerdutyTeam{
					{ID: "PT1", Name: "platform"},
					{ID: "PT2", Name: "support"},
				},
			},
		},
		nil,
	)
	c := withPagerDutyGroupsTestServer(t, srv)

	var groups []*access.Identity
	if err := c.SyncGroups(context.Background(), pdGroupsValidConfig(), pdGroupsValidSecrets(), "", func(b []*access.Identity, _ string) error {
		groups = append(groups, b...)
		return nil
	}); err != nil {
		t.Fatalf("SyncGroups: %v", err)
	}
	if len(groups) != 2 {
		t.Fatalf("groups = %d; want 2", len(groups))
	}
	if groups[0].ExternalID != "PT1" || groups[0].DisplayName != "platform" {
		t.Errorf("groups[0] = %+v", groups[0])
	}
}

func TestPagerDuty_SyncGroups_Pagination(t *testing.T) {
	srv := newPagerDutyGroupsTestServer(t,
		[]pagerdutyTeamsResponse{
			{Teams: []pagerdutyTeam{{ID: "PT1", Name: "a"}}, More: true},
			{Teams: []pagerdutyTeam{{ID: "PT2", Name: "b"}}, More: false},
		},
		nil,
	)
	c := withPagerDutyGroupsTestServer(t, srv)

	var got []*access.Identity
	if err := c.SyncGroups(context.Background(), pdGroupsValidConfig(), pdGroupsValidSecrets(), "", func(b []*access.Identity, _ string) error {
		got = append(got, b...)
		return nil
	}); err != nil {
		t.Fatalf("SyncGroups: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got = %d; want 2 across pages", len(got))
	}
}

func TestPagerDuty_CountGroups_HappyPath(t *testing.T) {
	srv := newPagerDutyGroupsTestServer(t,
		[]pagerdutyTeamsResponse{
			{Teams: []pagerdutyTeam{{ID: "PT1"}, {ID: "PT2"}, {ID: "PT3"}}},
		},
		nil,
	)
	c := withPagerDutyGroupsTestServer(t, srv)

	n, err := c.CountGroups(context.Background(), pdGroupsValidConfig(), pdGroupsValidSecrets())
	if err != nil {
		t.Fatalf("CountGroups: %v", err)
	}
	if n != 3 {
		t.Errorf("CountGroups = %d; want 3", n)
	}
}

func TestPagerDuty_SyncGroupMembers_HappyPath(t *testing.T) {
	srv := newPagerDutyGroupsTestServer(t, nil, map[string][]pagerdutyTeamMembersResponse{
		"PT1": {
			{
				Members: []pagerdutyTeamMember{
					{User: struct {
						ID string `json:"id"`
					}{ID: "PU1"}, Role: "manager"},
					{User: struct {
						ID string `json:"id"`
					}{ID: "PU2"}, Role: "responder"},
				},
			},
		},
	})
	c := withPagerDutyGroupsTestServer(t, srv)

	var got []string
	if err := c.SyncGroupMembers(context.Background(), pdGroupsValidConfig(), pdGroupsValidSecrets(), "PT1", "", func(ids []string, _ string) error {
		got = append(got, ids...)
		return nil
	}); err != nil {
		t.Fatalf("SyncGroupMembers: %v", err)
	}
	want := []string{"PU1", "PU2"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("got = %v; want %v", got, want)
	}
}

func TestPagerDuty_SyncGroupMembers_MissingGroupID(t *testing.T) {
	c := New()
	err := c.SyncGroupMembers(context.Background(), pdGroupsValidConfig(), pdGroupsValidSecrets(), "", "", func(_ []string, _ string) error { return nil })
	if err == nil {
		t.Error("SyncGroupMembers returned nil; want missing-id error")
	}
}

func TestPagerDuty_SyncGroups_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	c := withPagerDutyGroupsTestServer(t, srv)

	err := c.SyncGroups(context.Background(), pdGroupsValidConfig(), pdGroupsValidSecrets(), "", func(_ []*access.Identity, _ string) error { return nil })
	if err == nil {
		t.Error("SyncGroups returned nil; want 401 error")
	}
}

func TestPagerDuty_SatisfiesGroupSyncerInterface(t *testing.T) {
	var _ access.GroupSyncer = New()
}
