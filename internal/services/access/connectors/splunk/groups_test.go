package splunk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func newSplunkTestServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *SplunkAccessConnector) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("missing Bearer auth")
		}
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	return srv, c
}

func TestSplunk_SyncGroups_HappyPath(t *testing.T) {
	_, c := newSplunkTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/services/authorization/roles") {
			t.Errorf("path = %q", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"entry": []map[string]interface{}{
				{"name": "admin", "content": map[string]interface{}{"capabilities": []string{"admin_all_objects"}}},
				{"name": "user", "content": map[string]interface{}{"capabilities": []string{"search"}}},
				{"name": "power", "content": map[string]interface{}{"capabilities": []string{"schedule_search"}}},
			},
			"paging": map[string]interface{}{"total": 3, "perPage": 100, "offset": 0},
		})
	})
	var got []*access.Identity
	if err := c.SyncGroups(context.Background(), validConfig(), validSecrets(), "", func(b []*access.Identity, _ string) error {
		got = append(got, b...)
		return nil
	}); err != nil {
		t.Fatalf("SyncGroups: %v", err)
	}
	if len(got) != 3 || got[0].ExternalID != "admin" {
		t.Errorf("groups = %+v", got)
	}
	if got[0].Type != access.IdentityTypeGroup {
		t.Errorf("type = %q", got[0].Type)
	}
}

func TestSplunk_SyncGroupMembers_FiltersByRole(t *testing.T) {
	_, c := newSplunkTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/services/authentication/users") {
			t.Errorf("path = %q; want users walk", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"entry": []map[string]interface{}{
				{"name": "alice", "content": map[string]interface{}{"roles": []string{"admin", "user"}}},
				{"name": "bob", "content": map[string]interface{}{"roles": []string{"user"}}},
				{"name": "carol", "content": map[string]interface{}{"roles": []string{"power", "admin"}}},
			},
			"paging": map[string]interface{}{"total": 3, "perPage": 100, "offset": 0},
		})
	})
	var ids []string
	if err := c.SyncGroupMembers(context.Background(), validConfig(), validSecrets(), "admin", "", func(m []string, _ string) error {
		ids = append(ids, m...)
		return nil
	}); err != nil {
		t.Fatalf("SyncGroupMembers: %v", err)
	}
	if len(ids) != 2 || ids[0] != "alice" || ids[1] != "carol" {
		t.Errorf("members = %v; want [alice carol]", ids)
	}
}

func TestSplunk_SyncGroupMembers_MissingGroupRejected(t *testing.T) {
	c := New()
	err := c.SyncGroupMembers(context.Background(), validConfig(), validSecrets(), "  ", "", func(_ []string, _ string) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "groupExternalID is required") {
		t.Errorf("err = %v", err)
	}
}

func TestSplunk_CountGroups(t *testing.T) {
	_, c := newSplunkTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"entry":  []map[string]interface{}{{"name": "a"}, {"name": "b"}, {"name": "c"}, {"name": "d"}, {"name": "e"}},
			"paging": map[string]interface{}{"total": 5, "perPage": 100, "offset": 0},
		})
	})
	n, err := c.CountGroups(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("CountGroups: %v", err)
	}
	if n != 5 {
		t.Errorf("count = %d; want 5", n)
	}
}

func TestSplunk_SyncGroups_ServerErrorPropagates(t *testing.T) {
	_, c := newSplunkTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"messages":[{"type":"ERROR","text":"boom"}]}`))
	})
	err := c.SyncGroups(context.Background(), validConfig(), validSecrets(), "", func(_ []*access.Identity, _ string) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("err = %v; want 500", err)
	}
}

// TestSplunk_SyncGroups_MaxPagesGuard verifies the defense-in-depth
// cap on pagination loops. A misconfigured / malicious upstream that
// returns a perpetually inflated paging.total combined with a non-
// empty page on every request would otherwise loop forever (the
// secondary len(page.Entry)==0 guard never trips). The cap surfaces a
// clear error so the worker fails fast instead of hanging.
func TestSplunk_SyncGroups_MaxPagesGuard(t *testing.T) {
	callCount := 0
	_, c := newSplunkTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		callCount++
		// Always return a non-empty page with an unreachable
		// total — the loop would never terminate without the cap.
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"entry": []map[string]interface{}{
				{"name": "r", "content": map[string]interface{}{"capabilities": []string{}}},
			},
			"paging": map[string]interface{}{"total": 1 << 30, "perPage": 100, "offset": 0},
		})
	})
	err := c.SyncGroups(context.Background(), validConfig(), validSecrets(), "", func(_ []*access.Identity, _ string) error { return nil })
	if err == nil {
		t.Fatalf("err = nil; want pagination cap error")
	}
	if !strings.Contains(err.Error(), "pagination exceeded") {
		t.Errorf("err = %q; want 'pagination exceeded' surface", err.Error())
	}
	// Sanity: the server saw exactly splunkGroupsMaxPages calls
	// (no more, no fewer).
	if callCount != splunkGroupsMaxPages {
		t.Errorf("callCount = %d; want %d", callCount, splunkGroupsMaxPages)
	}
}

func TestSplunk_SatisfiesGroupSyncerInterface(t *testing.T) {
	var _ access.GroupSyncer = New()
}
