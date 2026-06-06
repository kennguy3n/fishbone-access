package salesforce

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

func newSalesforceGroupsTestServer(t *testing.T, permSetPages []sfPermissionSetQueryResponse, assignmentPages map[string][]sfAssignmentQueryResponse) *httptest.Server {
	t.Helper()
	var (
		mu         sync.Mutex
		permCursor int
		assnCursor = map[string]int{}
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/services/data/") && strings.HasSuffix(r.URL.Path, "/query"):
			soql := r.URL.Query().Get("q")
			switch {
			case strings.Contains(soql, "FROM PermissionSetAssignment"):
				lo := strings.Index(soql, "PermissionSetId = '")
				if lo < 0 {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				groupID := soql[lo+len("PermissionSetId = '"):]
				groupID = strings.TrimSuffix(groupID, "'")
				mu.Lock()
				idx := assnCursor[groupID]
				assnCursor[groupID] = idx + 1
				mu.Unlock()
				pages := assignmentPages[groupID]
				if idx >= len(pages) {
					_ = json.NewEncoder(w).Encode(sfAssignmentQueryResponse{Done: true})
					return
				}
				_ = json.NewEncoder(w).Encode(pages[idx])
			case strings.Contains(soql, "FROM PermissionSet"):
				mu.Lock()
				idx := permCursor
				permCursor++
				mu.Unlock()
				if idx >= len(permSetPages) {
					_ = json.NewEncoder(w).Encode(sfPermissionSetQueryResponse{Done: true})
					return
				}
				_ = json.NewEncoder(w).Encode(permSetPages[idx])
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		case strings.HasPrefix(r.URL.Path, "/services/data/") && strings.Contains(r.URL.Path, "/query/"):
			// queryMore continuation — read body keyed on path itself.
			key := r.URL.Path
			switch {
			case strings.Contains(key, "perm"):
				mu.Lock()
				idx := permCursor
				permCursor++
				mu.Unlock()
				if idx >= len(permSetPages) {
					_ = json.NewEncoder(w).Encode(sfPermissionSetQueryResponse{Done: true})
					return
				}
				_ = json.NewEncoder(w).Encode(permSetPages[idx])
			case strings.Contains(key, "assn"):
				groupID := r.URL.Query().Get("g")
				mu.Lock()
				idx := assnCursor[groupID]
				assnCursor[groupID] = idx + 1
				mu.Unlock()
				pages := assignmentPages[groupID]
				if idx >= len(pages) {
					_ = json.NewEncoder(w).Encode(sfAssignmentQueryResponse{Done: true})
					return
				}
				_ = json.NewEncoder(w).Encode(pages[idx])
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func withSalesforceGroupsTestServer(t *testing.T, srv *httptest.Server) *SalesforceAccessConnector {
	t.Helper()
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	return c
}

func sfValidConfig() map[string]interface{} {
	return map[string]interface{}{"instance_url": "https://example.my.salesforce.com"}
}
func sfValidSecrets() map[string]interface{} { return map[string]interface{}{"access_token": "tok"} }

func TestSalesforce_SyncGroups_HappyPath(t *testing.T) {
	srv := newSalesforceGroupsTestServer(t, []sfPermissionSetQueryResponse{
		{
			Records: []sfPermissionSetRow{
				{ID: "0PS001", Name: "Admins", Label: "Org Admins"},
				{ID: "0PS002", Name: "Engineers", Label: ""},
			},
			Done: true,
		},
	}, nil)
	c := withSalesforceGroupsTestServer(t, srv)

	var got []*access.Identity
	if err := c.SyncGroups(context.Background(), sfValidConfig(), sfValidSecrets(), "", func(b []*access.Identity, _ string) error {
		got = append(got, b...)
		return nil
	}); err != nil {
		t.Fatalf("SyncGroups: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len(got) = %d; want 2", len(got))
	}
	if got[0].ExternalID != "0PS001" || got[0].DisplayName != "Org Admins" {
		t.Errorf("got[0] = %+v", got[0])
	}
	if got[1].DisplayName != "Engineers" {
		t.Errorf("got[1].DisplayName = %q; want fallback to Name", got[1].DisplayName)
	}
}

func TestSalesforce_SyncGroups_Pagination(t *testing.T) {
	srv := newSalesforceGroupsTestServer(t, []sfPermissionSetQueryResponse{
		{
			Records:        []sfPermissionSetRow{{ID: "0PS001", Name: "A", Label: "A"}},
			Done:           false,
			NextRecordsURL: "/services/data/v59.0/query/perm-next",
		},
		{
			Records: []sfPermissionSetRow{{ID: "0PS002", Name: "B", Label: "B"}},
			Done:    true,
		},
	}, nil)
	c := withSalesforceGroupsTestServer(t, srv)

	var got []string
	if err := c.SyncGroups(context.Background(), sfValidConfig(), sfValidSecrets(), "", func(b []*access.Identity, _ string) error {
		for _, g := range b {
			got = append(got, g.ExternalID)
		}
		return nil
	}); err != nil {
		t.Fatalf("SyncGroups: %v", err)
	}
	want := "0PS001,0PS002"
	if strings.Join(got, ",") != want {
		t.Errorf("got = %v; want %v", got, want)
	}
}

func TestSalesforce_CountGroups_HappyPath(t *testing.T) {
	srv := newSalesforceGroupsTestServer(t, []sfPermissionSetQueryResponse{
		{Records: []sfPermissionSetRow{{ID: "0PS001"}, {ID: "0PS002"}, {ID: "0PS003"}}, Done: true},
	}, nil)
	c := withSalesforceGroupsTestServer(t, srv)
	n, err := c.CountGroups(context.Background(), sfValidConfig(), sfValidSecrets())
	if err != nil {
		t.Fatalf("CountGroups: %v", err)
	}
	if n != 3 {
		t.Errorf("CountGroups = %d; want 3", n)
	}
}

func TestSalesforce_SyncGroupMembers_HappyPath(t *testing.T) {
	srv := newSalesforceGroupsTestServer(t, nil, map[string][]sfAssignmentQueryResponse{
		"0PS001": {
			{
				Records: []sfAssignmentRow{
					{AssigneeID: "005x000000001"},
					{AssigneeID: "005x000000002"},
				},
				Done: true,
			},
		},
	})
	c := withSalesforceGroupsTestServer(t, srv)

	var got []string
	if err := c.SyncGroupMembers(context.Background(), sfValidConfig(), sfValidSecrets(), "0PS001", "", func(ids []string, _ string) error {
		got = append(got, ids...)
		return nil
	}); err != nil {
		t.Fatalf("SyncGroupMembers: %v", err)
	}
	want := []string{"005x000000001", "005x000000002"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("got = %v; want %v", got, want)
	}
}

func TestSalesforce_SyncGroupMembers_MissingGroupID(t *testing.T) {
	c := New()
	err := c.SyncGroupMembers(context.Background(), sfValidConfig(), sfValidSecrets(), "", "", func(_ []string, _ string) error { return nil })
	if err == nil {
		t.Error("SyncGroupMembers returned nil; want missing-id error")
	}
}

func TestSalesforce_SyncGroups_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	c := withSalesforceGroupsTestServer(t, srv)
	err := c.SyncGroups(context.Background(), sfValidConfig(), sfValidSecrets(), "", func(_ []*access.Identity, _ string) error { return nil })
	if err == nil {
		t.Error("SyncGroups returned nil; want 401 error")
	}
}

func TestSalesforce_SatisfiesGroupSyncerInterface(t *testing.T) {
	var _ access.GroupSyncer = New()
}
