package dropbox

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func newDropboxGroupsTestServer(t *testing.T, groupPages []dropboxGroupsListResponse, memberPages map[string][]dropboxGroupMembersResponse) *httptest.Server {
	t.Helper()
	var (
		mu       sync.Mutex
		grpCalls int
		memCalls = map[string]int{}
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		switch r.URL.Path {
		case "/2/team/groups/list", "/2/team/groups/list/continue":
			mu.Lock()
			idx := grpCalls
			grpCalls++
			mu.Unlock()
			if idx >= len(groupPages) {
				_ = json.NewEncoder(w).Encode(dropboxGroupsListResponse{})
				return
			}
			_ = json.NewEncoder(w).Encode(groupPages[idx])
		case "/2/team/groups/members/list", "/2/team/groups/members/list/continue":
			var payload struct {
				Group struct {
					GroupID string `json:"group_id"`
				} `json:"group"`
				Cursor string `json:"cursor"`
			}
			_ = json.Unmarshal(raw, &payload)
			gid := payload.Group.GroupID
			if gid == "" {
				for k := range memberPages {
					gid = k
					break
				}
			}
			mu.Lock()
			idx := memCalls[gid]
			memCalls[gid] = idx + 1
			mu.Unlock()
			pages := memberPages[gid]
			if idx >= len(pages) {
				_ = json.NewEncoder(w).Encode(dropboxGroupMembersResponse{})
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

func withDropboxGroupsTestServer(t *testing.T, srv *httptest.Server) *DropboxAccessConnector {
	t.Helper()
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	return c
}

func dropboxGroupsValidConfig() map[string]interface{} { return map[string]interface{}{} }
func dropboxGroupsValidSecrets() map[string]interface{} {
	return map[string]interface{}{"access_token": "sl.AAAA"}
}

func TestDropbox_SyncGroups_HappyPath(t *testing.T) {
	srv := newDropboxGroupsTestServer(t,
		[]dropboxGroupsListResponse{
			{
				Groups: []dropboxGroupSummary{
					{GroupID: "g:1", GroupName: "engineering"},
					{GroupID: "g:2", GroupName: "support"},
				},
			},
		},
		nil,
	)
	c := withDropboxGroupsTestServer(t, srv)

	var groups []*access.Identity
	if err := c.SyncGroups(context.Background(), dropboxGroupsValidConfig(), dropboxGroupsValidSecrets(), "", func(b []*access.Identity, _ string) error {
		groups = append(groups, b...)
		return nil
	}); err != nil {
		t.Fatalf("SyncGroups: %v", err)
	}
	if len(groups) != 2 {
		t.Fatalf("groups = %d; want 2", len(groups))
	}
	if groups[0].ExternalID != "g:1" || groups[0].DisplayName != "engineering" {
		t.Errorf("groups[0] = %+v", groups[0])
	}
}

func TestDropbox_SyncGroups_Pagination(t *testing.T) {
	srv := newDropboxGroupsTestServer(t,
		[]dropboxGroupsListResponse{
			{Groups: []dropboxGroupSummary{{GroupID: "g:1", GroupName: "a"}}, Cursor: "c1", HasMore: true},
			{Groups: []dropboxGroupSummary{{GroupID: "g:2", GroupName: "b"}}, HasMore: false},
		},
		nil,
	)
	c := withDropboxGroupsTestServer(t, srv)

	var got []*access.Identity
	if err := c.SyncGroups(context.Background(), dropboxGroupsValidConfig(), dropboxGroupsValidSecrets(), "", func(b []*access.Identity, _ string) error {
		got = append(got, b...)
		return nil
	}); err != nil {
		t.Fatalf("SyncGroups: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got = %d; want 2 across pages", len(got))
	}
}

func TestDropbox_CountGroups_HappyPath(t *testing.T) {
	srv := newDropboxGroupsTestServer(t,
		[]dropboxGroupsListResponse{
			{Groups: []dropboxGroupSummary{{GroupID: "g:1"}, {GroupID: "g:2"}, {GroupID: "g:3"}}},
		},
		nil,
	)
	c := withDropboxGroupsTestServer(t, srv)

	n, err := c.CountGroups(context.Background(), dropboxGroupsValidConfig(), dropboxGroupsValidSecrets())
	if err != nil {
		t.Fatalf("CountGroups: %v", err)
	}
	if n != 3 {
		t.Errorf("CountGroups = %d; want 3", n)
	}
}

func TestDropbox_SyncGroupMembers_HappyPath(t *testing.T) {
	page := dropboxGroupMembersResponse{
		Members: []dropboxGroupMember{
			{Profile: dropboxProfile{TeamMemberID: "dbmid:1"}},
			{Profile: dropboxProfile{TeamMemberID: "dbmid:2"}},
		},
	}
	srv := newDropboxGroupsTestServer(t, nil, map[string][]dropboxGroupMembersResponse{
		"g:1": {page},
	})
	c := withDropboxGroupsTestServer(t, srv)

	var got []string
	if err := c.SyncGroupMembers(context.Background(), dropboxGroupsValidConfig(), dropboxGroupsValidSecrets(), "g:1", "", func(ids []string, _ string) error {
		got = append(got, ids...)
		return nil
	}); err != nil {
		t.Fatalf("SyncGroupMembers: %v", err)
	}
	want := []string{"dbmid:1", "dbmid:2"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("got = %v; want %v", got, want)
	}
}

func TestDropbox_SyncGroupMembers_MissingGroupID(t *testing.T) {
	c := New()
	err := c.SyncGroupMembers(context.Background(), dropboxGroupsValidConfig(), dropboxGroupsValidSecrets(), "", "", func(_ []string, _ string) error { return nil })
	if err == nil {
		t.Error("SyncGroupMembers returned nil; want missing-id error")
	}
}

func TestDropbox_SyncGroups_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	c := withDropboxGroupsTestServer(t, srv)

	err := c.SyncGroups(context.Background(), dropboxGroupsValidConfig(), dropboxGroupsValidSecrets(), "", func(_ []*access.Identity, _ string) error { return nil })
	if err == nil {
		t.Error("SyncGroups returned nil; want 401 error")
	}
}

func TestDropbox_SatisfiesGroupSyncerInterface(t *testing.T) {
	var _ access.GroupSyncer = New()
}
