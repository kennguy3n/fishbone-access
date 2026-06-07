package front

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func newFrontTeamsServer(t *testing.T, handler func(w http.ResponseWriter, r *http.Request, srvURL string)) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("expected Bearer auth")
		}
		handler(w, r, srv.URL)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestFront_SyncGroups_HappyPathTwoPages(t *testing.T) {
	calls := 0
	srv := newFrontTeamsServer(t, func(w http.ResponseWriter, r *http.Request, srvURL string) {
		if !strings.HasPrefix(r.URL.Path, "/teams") {
			t.Errorf("path = %q", r.URL.Path)
		}
		calls++
		page := map[string]interface{}{}
		if calls == 1 {
			page["_pagination"] = map[string]interface{}{"next": srvURL + "/teams?page_token=p2"}
			page["_results"] = []map[string]interface{}{
				{"id": "tm-a", "name": "Support"},
			}
		} else {
			page["_pagination"] = map[string]interface{}{"next": ""}
			page["_results"] = []map[string]interface{}{
				{"id": "tm-b", "name": "Sales"},
			}
		}
		b, _ := json.Marshal(page)
		_, _ = w.Write(b)
	})
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var got []*access.Identity
	if err := c.SyncGroups(context.Background(), validConfig(), validSecrets(), "", func(b []*access.Identity, _ string) error {
		got = append(got, b...)
		return nil
	}); err != nil {
		t.Fatalf("SyncGroups: %v", err)
	}
	if len(got) != 2 || got[0].ExternalID != "tm-a" || got[1].ExternalID != "tm-b" {
		t.Errorf("groups = %+v", got)
	}
	if got[0].Type != access.IdentityTypeGroup {
		t.Errorf("type = %q; want group", got[0].Type)
	}
}

func TestFront_SyncGroupMembers_HappyPath(t *testing.T) {
	srv := newFrontTeamsServer(t, func(w http.ResponseWriter, r *http.Request, _ string) {
		if !strings.HasSuffix(r.URL.Path, "/teams/tm-a/teammates") {
			t.Errorf("path = %q", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"_pagination": map[string]interface{}{"next": ""},
			"_results": []map[string]interface{}{
				{"id": "tu-1", "email": "alice@x.com"},
				{"id": "tu-2", "email": "bob@x.com"},
			},
		})
	})
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var ids []string
	if err := c.SyncGroupMembers(context.Background(), validConfig(), validSecrets(), "tm-a", "", func(m []string, _ string) error {
		ids = append(ids, m...)
		return nil
	}); err != nil {
		t.Fatalf("SyncGroupMembers: %v", err)
	}
	if len(ids) != 2 || ids[0] != "tu-1" || ids[1] != "tu-2" {
		t.Errorf("members = %v", ids)
	}
}

func TestFront_SyncGroupMembers_404Empty(t *testing.T) {
	srv := newFrontTeamsServer(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
		w.WriteHeader(http.StatusNotFound)
	})
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var batches [][]string
	if err := c.SyncGroupMembers(context.Background(), validConfig(), validSecrets(), "tm-gone", "", func(m []string, _ string) error {
		batches = append(batches, m)
		return nil
	}); err != nil {
		t.Errorf("404 should be empty; got %v", err)
	}
	// Exactly one terminal handler invocation with an empty batch.
	if len(batches) != 1 || len(batches[0]) != 0 {
		t.Errorf("batches = %v; want one empty-batch invocation", batches)
	}
	// Non-nil empty slice per GroupSyncer empty-batch contract —
	// downstream consumers that JSON-marshal the batch see `[]` rather
	// than `null`. See optional_interfaces.go.
	if batches[0] == nil {
		t.Error("batch is nil; want non-nil empty slice per GroupSyncer empty-batch contract (optional_interfaces.go)")
	}
}

func TestFront_SyncGroupMembers_MissingGroupRejected(t *testing.T) {
	c := New()
	err := c.SyncGroupMembers(context.Background(), validConfig(), validSecrets(), " ", "", func(_ []string, _ string) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "groupExternalID is required") {
		t.Errorf("err = %v", err)
	}
}

func TestFront_CountGroups_WalksPages(t *testing.T) {
	calls := 0
	srv := newFrontTeamsServer(t, func(w http.ResponseWriter, _ *http.Request, srvURL string) {
		calls++
		page := map[string]interface{}{"_pagination": map[string]interface{}{"next": ""}, "_results": []map[string]interface{}{}}
		if calls == 1 {
			page["_pagination"] = map[string]interface{}{"next": srvURL + "/teams?page_token=p2"}
			page["_results"] = []map[string]interface{}{{"id": "a", "name": "A"}, {"id": "b", "name": "B"}}
		} else {
			page["_results"] = []map[string]interface{}{{"id": "c", "name": "C"}}
		}
		b, _ := json.Marshal(page)
		_, _ = w.Write(b)
	})
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	n, err := c.CountGroups(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("CountGroups: %v", err)
	}
	if n != 3 {
		t.Errorf("count = %d; want 3", n)
	}
}

func TestFront_SyncGroups_ServerErrorPropagates(t *testing.T) {
	srv := newFrontTeamsServer(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprint(w, `{"_error":{"status":500}}`)
	})
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.SyncGroups(context.Background(), validConfig(), validSecrets(), "", func(_ []*access.Identity, _ string) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("err = %v; want 500", err)
	}
}

func TestFront_SatisfiesGroupSyncerInterface(t *testing.T) {
	var _ access.GroupSyncer = New()
}
