package zoom

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

func newZoomGroupsTestServer(t *testing.T, groupPages []zoomGroupsResponse, memberPages map[string][]zoomGroupMembersResponse) *httptest.Server {
	t.Helper()
	var (
		mu       sync.Mutex
		grpCalls int
		memCalls = map[string]int{}
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/groups":
			mu.Lock()
			idx := grpCalls
			grpCalls++
			mu.Unlock()
			if idx >= len(groupPages) {
				_ = json.NewEncoder(w).Encode(zoomGroupsResponse{})
				return
			}
			_ = json.NewEncoder(w).Encode(groupPages[idx])
		case strings.HasPrefix(r.URL.Path, "/groups/") && strings.HasSuffix(r.URL.Path, "/members"):
			gid := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/groups/"), "/members")
			mu.Lock()
			idx := memCalls[gid]
			memCalls[gid] = idx + 1
			mu.Unlock()
			pages := memberPages[gid]
			if idx >= len(pages) {
				_ = json.NewEncoder(w).Encode(zoomGroupMembersResponse{})
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

func withZoomGroupsTestServer(t *testing.T, srv *httptest.Server) *ZoomAccessConnector {
	t.Helper()
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
	return c
}

func TestZoom_SyncGroups_HappyPath(t *testing.T) {
	srv := newZoomGroupsTestServer(t,
		[]zoomGroupsResponse{
			{
				PageCount: 1, PageNumber: 1, TotalRecords: 2,
				Groups: []zoomGroup{
					{ID: "g-1", Name: "engineering"},
					{ID: "g-2", Name: "support"},
				},
			},
		},
		nil,
	)
	c := withZoomGroupsTestServer(t, srv)

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
	if groups[0].ExternalID != "g-1" || groups[0].DisplayName != "engineering" {
		t.Errorf("groups[0] = %+v", groups[0])
	}
}

func TestZoom_SyncGroups_Pagination(t *testing.T) {
	srv := newZoomGroupsTestServer(t,
		[]zoomGroupsResponse{
			{PageCount: 2, PageNumber: 1, Groups: []zoomGroup{{ID: "g-1", Name: "a"}}},
			{PageCount: 2, PageNumber: 2, Groups: []zoomGroup{{ID: "g-2", Name: "b"}}},
		},
		nil,
	)
	c := withZoomGroupsTestServer(t, srv)

	var got []*access.Identity
	if err := c.SyncGroups(context.Background(), validConfig(), validSecrets(), "", func(b []*access.Identity, _ string) error {
		got = append(got, b...)
		return nil
	}); err != nil {
		t.Fatalf("SyncGroups: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got = %d; want 2 across pages", len(got))
	}
}

func TestZoom_CountGroups_HappyPath(t *testing.T) {
	srv := newZoomGroupsTestServer(t,
		[]zoomGroupsResponse{
			{PageCount: 1, PageNumber: 1, Groups: []zoomGroup{{ID: "g1"}, {ID: "g2"}, {ID: "g3"}}},
		},
		nil,
	)
	c := withZoomGroupsTestServer(t, srv)

	n, err := c.CountGroups(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("CountGroups: %v", err)
	}
	if n != 3 {
		t.Errorf("CountGroups = %d; want 3", n)
	}
}

func TestZoom_SyncGroupMembers_HappyPath(t *testing.T) {
	srv := newZoomGroupsTestServer(t, nil, map[string][]zoomGroupMembersResponse{
		"g-1": {
			{PageCount: 1, PageNumber: 1, Members: []zoomGroupMember{{ID: "u-1"}, {ID: "u-2"}}},
		},
	})
	c := withZoomGroupsTestServer(t, srv)

	var got []string
	if err := c.SyncGroupMembers(context.Background(), validConfig(), validSecrets(), "g-1", "", func(ids []string, _ string) error {
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

func TestZoom_SyncGroupMembers_MissingGroupID(t *testing.T) {
	c := New()
	err := c.SyncGroupMembers(context.Background(), validConfig(), validSecrets(), "", "", func(_ []string, _ string) error { return nil })
	if err == nil {
		t.Error("SyncGroupMembers returned nil; want missing-id error")
	}
}

func TestZoom_SyncGroups_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	c := withZoomGroupsTestServer(t, srv)

	err := c.SyncGroups(context.Background(), validConfig(), validSecrets(), "", func(_ []*access.Identity, _ string) error { return nil })
	if err == nil {
		t.Error("SyncGroups returned nil; want 401 error")
	}
}

func TestZoom_SatisfiesGroupSyncerInterface(t *testing.T) {
	var _ access.GroupSyncer = New()
}
