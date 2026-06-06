package jira

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

func newJiraGroupsTestServer(t *testing.T, groupsPages []jiraGroupBulkResponse, memberPages map[string][]jiraGroupMemberResponse) *httptest.Server {
	t.Helper()
	var (
		mu       sync.Mutex
		grpCalls int
		memCalls = map[string]int{}
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/rest/api/3/group/bulk"):
			mu.Lock()
			idx := grpCalls
			grpCalls++
			mu.Unlock()
			if idx >= len(groupsPages) {
				_ = json.NewEncoder(w).Encode(jiraGroupBulkResponse{IsLast: true})
				return
			}
			_ = json.NewEncoder(w).Encode(groupsPages[idx])
		case strings.HasSuffix(r.URL.Path, "/rest/api/3/group/member"):
			groupID := r.URL.Query().Get("groupId")
			mu.Lock()
			idx := memCalls[groupID]
			memCalls[groupID] = idx + 1
			mu.Unlock()
			pages := memberPages[groupID]
			if idx >= len(pages) {
				_ = json.NewEncoder(w).Encode(jiraGroupMemberResponse{IsLast: true})
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

func withJiraGroupsTestServer(t *testing.T, srv *httptest.Server) *JiraAccessConnector {
	t.Helper()
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	return c
}

func jiraValidConfig() map[string]interface{} {
	return map[string]interface{}{"cloud_id": "00000000-0000-0000-0000-000000000000", "site_url": "https://acme.atlassian.net"}
}
func jiraValidSecrets() map[string]interface{} {
	return map[string]interface{}{"api_token": "tok", "email": "u@x"}
}

func TestJira_SyncGroups_HappyPath(t *testing.T) {
	srv := newJiraGroupsTestServer(t, []jiraGroupBulkResponse{
		{Values: []jiraGroupRow{{GroupID: "g-1", Name: "engineering"}, {GroupID: "g-2", Name: "support"}}, IsLast: true},
	}, nil)
	c := withJiraGroupsTestServer(t, srv)

	var got []*access.Identity
	if err := c.SyncGroups(context.Background(), jiraValidConfig(), jiraValidSecrets(), "", func(b []*access.Identity, _ string) error {
		got = append(got, b...)
		return nil
	}); err != nil {
		t.Fatalf("SyncGroups: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got = %d; want 2", len(got))
	}
	if got[0].ExternalID != "g-1" || got[0].DisplayName != "engineering" {
		t.Errorf("got[0] = %+v", got[0])
	}
}

func TestJira_SyncGroups_Pagination(t *testing.T) {
	srv := newJiraGroupsTestServer(t, []jiraGroupBulkResponse{
		{Values: []jiraGroupRow{{GroupID: "g-1", Name: "A"}}, IsLast: false},
		{Values: []jiraGroupRow{{GroupID: "g-2", Name: "B"}}, IsLast: true},
	}, nil)
	c := withJiraGroupsTestServer(t, srv)

	var got []string
	if err := c.SyncGroups(context.Background(), jiraValidConfig(), jiraValidSecrets(), "", func(b []*access.Identity, _ string) error {
		for _, g := range b {
			got = append(got, g.ExternalID)
		}
		return nil
	}); err != nil {
		t.Fatalf("SyncGroups: %v", err)
	}
	if strings.Join(got, ",") != "g-1,g-2" {
		t.Errorf("got = %v; want [g-1 g-2]", got)
	}
}

func TestJira_CountGroups_HappyPath(t *testing.T) {
	srv := newJiraGroupsTestServer(t, []jiraGroupBulkResponse{
		{Values: []jiraGroupRow{{GroupID: "g-1"}, {GroupID: "g-2"}, {GroupID: "g-3"}}, IsLast: true},
	}, nil)
	c := withJiraGroupsTestServer(t, srv)
	n, err := c.CountGroups(context.Background(), jiraValidConfig(), jiraValidSecrets())
	if err != nil {
		t.Fatalf("CountGroups: %v", err)
	}
	if n != 3 {
		t.Errorf("CountGroups = %d; want 3", n)
	}
}

func TestJira_SyncGroupMembers_HappyPath(t *testing.T) {
	srv := newJiraGroupsTestServer(t, nil, map[string][]jiraGroupMemberResponse{
		"g-1": {{Values: []jiraGroupMemberRow{{AccountID: "acc-1"}, {AccountID: "acc-2"}}, IsLast: true}},
	})
	c := withJiraGroupsTestServer(t, srv)

	var got []string
	if err := c.SyncGroupMembers(context.Background(), jiraValidConfig(), jiraValidSecrets(), "g-1", "", func(ids []string, _ string) error {
		got = append(got, ids...)
		return nil
	}); err != nil {
		t.Fatalf("SyncGroupMembers: %v", err)
	}
	if strings.Join(got, ",") != "acc-1,acc-2" {
		t.Errorf("got = %v; want [acc-1 acc-2]", got)
	}
}

func TestJira_SyncGroupMembers_MissingGroupID(t *testing.T) {
	c := New()
	err := c.SyncGroupMembers(context.Background(), jiraValidConfig(), jiraValidSecrets(), "", "", func(_ []string, _ string) error { return nil })
	if err == nil {
		t.Error("SyncGroupMembers returned nil; want missing-id error")
	}
}

func TestJira_SyncGroups_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	c := withJiraGroupsTestServer(t, srv)
	err := c.SyncGroups(context.Background(), jiraValidConfig(), jiraValidSecrets(), "", func(_ []*access.Identity, _ string) error { return nil })
	if err == nil {
		t.Error("SyncGroups returned nil; want 401 error")
	}
}

func TestJira_SatisfiesGroupSyncerInterface(t *testing.T) {
	var _ access.GroupSyncer = New()
}
