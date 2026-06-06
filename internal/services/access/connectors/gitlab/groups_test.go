package gitlab

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

func newGitLabGroupsTestServer(t *testing.T, subgroupPages [][]gitlabSubgroup, memberPages map[string][][]gitlabMember) *httptest.Server {
	t.Helper()
	var (
		mu       sync.Mutex
		subCalls int
		memCalls = map[string]int{}
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/subgroups"):
			mu.Lock()
			idx := subCalls
			subCalls++
			mu.Unlock()
			if idx >= len(subgroupPages) {
				_, _ = w.Write([]byte(`[]`))
				return
			}
			if idx+1 < len(subgroupPages) {
				w.Header().Set("X-Next-Page", "2")
			}
			_ = json.NewEncoder(w).Encode(subgroupPages[idx])
		case strings.Contains(r.URL.Path, "/groups/") && strings.HasSuffix(r.URL.Path, "/members"):
			parts := strings.Split(r.URL.Path, "/")
			groupID := ""
			for i, p := range parts {
				if p == "groups" && i+1 < len(parts) {
					groupID = parts[i+1]
					break
				}
			}
			mu.Lock()
			idx := memCalls[groupID]
			memCalls[groupID] = idx + 1
			mu.Unlock()
			pages := memberPages[groupID]
			if idx >= len(pages) {
				_, _ = w.Write([]byte(`[]`))
				return
			}
			if idx+1 < len(pages) {
				w.Header().Set("X-Next-Page", "2")
			}
			_ = json.NewEncoder(w).Encode(pages[idx])
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func withGitLabGroupsTestServer(t *testing.T, srv *httptest.Server) *GitLabAccessConnector {
	t.Helper()
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	return c
}

func TestGitLab_SyncGroups_HappyPath(t *testing.T) {
	srv := newGitLabGroupsTestServer(t,
		[][]gitlabSubgroup{
			{
				{ID: 11, Name: "platform", FullPath: "12345/platform"},
				{ID: 12, Name: "", FullPath: "12345/security"},
			},
		},
		nil,
	)
	c := withGitLabGroupsTestServer(t, srv)

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
	if groups[0].ExternalID != "11" || groups[0].DisplayName != "platform" {
		t.Errorf("groups[0] = %+v", groups[0])
	}
	if groups[1].DisplayName != "12345/security" {
		t.Errorf("groups[1].DisplayName = %q; want fallback to full_path", groups[1].DisplayName)
	}
}

func TestGitLab_SyncGroups_Pagination(t *testing.T) {
	srv := newGitLabGroupsTestServer(t,
		[][]gitlabSubgroup{
			{{ID: 1, Name: "a"}},
			{{ID: 2, Name: "b"}},
		},
		nil,
	)
	c := withGitLabGroupsTestServer(t, srv)

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

func TestGitLab_CountGroups_HappyPath(t *testing.T) {
	srv := newGitLabGroupsTestServer(t,
		[][]gitlabSubgroup{{{ID: 1}, {ID: 2}, {ID: 3}}},
		nil,
	)
	c := withGitLabGroupsTestServer(t, srv)

	n, err := c.CountGroups(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("CountGroups: %v", err)
	}
	if n != 3 {
		t.Errorf("CountGroups = %d; want 3", n)
	}
}

func TestGitLab_SyncGroupMembers_HappyPath(t *testing.T) {
	srv := newGitLabGroupsTestServer(t, nil, map[string][][]gitlabMember{
		"77": {
			{{ID: 1, Username: "alice"}, {ID: 2, Username: "bob"}},
		},
	})
	c := withGitLabGroupsTestServer(t, srv)

	var got []string
	if err := c.SyncGroupMembers(context.Background(), validConfig(), validSecrets(), "77", "", func(ids []string, _ string) error {
		got = append(got, ids...)
		return nil
	}); err != nil {
		t.Fatalf("SyncGroupMembers: %v", err)
	}
	want := []string{"1", "2"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("got = %v; want %v", got, want)
	}
}

func TestGitLab_SyncGroupMembers_MissingGroupID(t *testing.T) {
	c := New()
	err := c.SyncGroupMembers(context.Background(), validConfig(), validSecrets(), "", "", func(_ []string, _ string) error { return nil })
	if err == nil {
		t.Error("SyncGroupMembers returned nil; want missing-id error")
	}
}

func TestGitLab_SyncGroups_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	c := withGitLabGroupsTestServer(t, srv)

	err := c.SyncGroups(context.Background(), validConfig(), validSecrets(), "", func(_ []*access.Identity, _ string) error { return nil })
	if err == nil {
		t.Error("SyncGroups returned nil; want 401 error")
	}
}

func TestGitLab_SatisfiesGroupSyncerInterface(t *testing.T) {
	var _ access.GroupSyncer = New()
}
