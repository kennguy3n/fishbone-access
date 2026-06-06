package box

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

func newBoxGroupsTestServer(t *testing.T, groupPages []boxGroupsResponse, memberPages map[string][]boxMembershipsResponse) *httptest.Server {
	t.Helper()
	var (
		mu       sync.Mutex
		grpCalls int
		memCalls = map[string]int{}
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/2.0/groups":
			mu.Lock()
			idx := grpCalls
			grpCalls++
			mu.Unlock()
			if idx >= len(groupPages) {
				_ = json.NewEncoder(w).Encode(boxGroupsResponse{})
				return
			}
			_ = json.NewEncoder(w).Encode(groupPages[idx])
		case strings.HasPrefix(r.URL.Path, "/2.0/groups/") && strings.HasSuffix(r.URL.Path, "/memberships"):
			gid := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/2.0/groups/"), "/memberships")
			mu.Lock()
			idx := memCalls[gid]
			memCalls[gid] = idx + 1
			mu.Unlock()
			pages := memberPages[gid]
			if idx >= len(pages) {
				_ = json.NewEncoder(w).Encode(boxMembershipsResponse{})
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

func withBoxGroupsTestServer(t *testing.T, srv *httptest.Server) *BoxAccessConnector {
	t.Helper()
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	return c
}

func boxGroupsValidConfig() map[string]interface{} { return map[string]interface{}{} }
func boxGroupsValidSecrets() map[string]interface{} {
	return map[string]interface{}{"access_token": "tok-abc"}
}

func TestBox_SyncGroups_HappyPath(t *testing.T) {
	srv := newBoxGroupsTestServer(t,
		[]boxGroupsResponse{
			{
				TotalCount: 2,
				Entries: []boxGroup{
					{ID: "100", Name: "engineering"},
					{ID: "200", Name: "support"},
				},
			},
		},
		nil,
	)
	c := withBoxGroupsTestServer(t, srv)

	var groups []*access.Identity
	if err := c.SyncGroups(context.Background(), boxGroupsValidConfig(), boxGroupsValidSecrets(), "", func(b []*access.Identity, _ string) error {
		groups = append(groups, b...)
		return nil
	}); err != nil {
		t.Fatalf("SyncGroups: %v", err)
	}
	if len(groups) != 2 {
		t.Fatalf("groups = %d; want 2", len(groups))
	}
	if groups[0].ExternalID != "100" || groups[0].DisplayName != "engineering" {
		t.Errorf("groups[0] = %+v", groups[0])
	}
}

func TestBox_SyncGroups_Pagination(t *testing.T) {
	first := make([]boxGroup, pageSize)
	for i := range first {
		first[i] = boxGroup{ID: "g-" + strings.Repeat("x", i+1), Name: "a"}
	}
	srv := newBoxGroupsTestServer(t,
		[]boxGroupsResponse{
			{TotalCount: pageSize + 1, Entries: first},
			{TotalCount: pageSize + 1, Offset: pageSize, Entries: []boxGroup{{ID: "tail", Name: "b"}}},
		},
		nil,
	)
	c := withBoxGroupsTestServer(t, srv)

	var got []*access.Identity
	if err := c.SyncGroups(context.Background(), boxGroupsValidConfig(), boxGroupsValidSecrets(), "", func(b []*access.Identity, _ string) error {
		got = append(got, b...)
		return nil
	}); err != nil {
		t.Fatalf("SyncGroups: %v", err)
	}
	if len(got) != pageSize+1 {
		t.Fatalf("got = %d; want %d across pages", len(got), pageSize+1)
	}
}

func TestBox_CountGroups_HappyPath(t *testing.T) {
	srv := newBoxGroupsTestServer(t,
		[]boxGroupsResponse{
			{TotalCount: 3, Entries: []boxGroup{{ID: "1"}, {ID: "2"}, {ID: "3"}}},
		},
		nil,
	)
	c := withBoxGroupsTestServer(t, srv)

	n, err := c.CountGroups(context.Background(), boxGroupsValidConfig(), boxGroupsValidSecrets())
	if err != nil {
		t.Fatalf("CountGroups: %v", err)
	}
	if n != 3 {
		t.Errorf("CountGroups = %d; want 3", n)
	}
}

func TestBox_SyncGroupMembers_HappyPath(t *testing.T) {
	srv := newBoxGroupsTestServer(t, nil, map[string][]boxMembershipsResponse{
		"100": {
			{
				TotalCount: 2,
				Entries: []boxMembership{
					{ID: "m1", User: struct {
						ID    string `json:"id"`
						Login string `json:"login"`
					}{ID: "u-1", Login: "a@b.com"}},
					{ID: "m2", User: struct {
						ID    string `json:"id"`
						Login string `json:"login"`
					}{ID: "u-2", Login: "c@d.com"}},
				},
			},
		},
	})
	c := withBoxGroupsTestServer(t, srv)

	var got []string
	if err := c.SyncGroupMembers(context.Background(), boxGroupsValidConfig(), boxGroupsValidSecrets(), "100", "", func(ids []string, _ string) error {
		got = append(got, ids...)
		return nil
	}); err != nil {
		t.Fatalf("SyncGroupMembers: %v", err)
	}
	want := []string{"u-1", "u-2"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("got = %v; want %v", got, want)
	}
}

func TestBox_SyncGroupMembers_MissingGroupID(t *testing.T) {
	c := New()
	err := c.SyncGroupMembers(context.Background(), boxGroupsValidConfig(), boxGroupsValidSecrets(), "", "", func(_ []string, _ string) error { return nil })
	if err == nil {
		t.Error("SyncGroupMembers returned nil; want missing-id error")
	}
}

func TestBox_SyncGroups_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	c := withBoxGroupsTestServer(t, srv)

	err := c.SyncGroups(context.Background(), boxGroupsValidConfig(), boxGroupsValidSecrets(), "", func(_ []*access.Identity, _ string) error { return nil })
	if err == nil {
		t.Error("SyncGroups returned nil; want 401 error")
	}
}

func TestBox_SatisfiesGroupSyncerInterface(t *testing.T) {
	var _ access.GroupSyncer = New()
}
