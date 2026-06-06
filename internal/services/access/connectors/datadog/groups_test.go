package datadog

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

func TestDatadog_SyncGroups_PaginatesAndMaps(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/api/v2/teams" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.Header.Get("DD-API-KEY") == "" {
			t.Errorf("missing DD-API-KEY")
		}
		body := map[string]interface{}{
			"data": []map[string]interface{}{},
			"meta": map[string]interface{}{"page": map[string]interface{}{"total_count": pageSize + 1}},
		}
		if calls == 1 {
			data := make([]map[string]interface{}, 0, pageSize)
			for i := 0; i < pageSize; i++ {
				data = append(data, map[string]interface{}{
					"id":         fmt.Sprintf("t-%d", i),
					"type":       "team",
					"attributes": map[string]interface{}{"name": fmt.Sprintf("Team %d", i), "handle": fmt.Sprintf("team-%d", i)},
				})
			}
			body["data"] = data
		} else {
			body["data"] = []map[string]interface{}{
				{"id": "t-last", "type": "team", "attributes": map[string]interface{}{"name": "Final Team", "handle": "final-team"}},
			}
		}
		b, _ := json.Marshal(body)
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	var collected []*access.Identity
	if err := c.SyncGroups(context.Background(), validConfig(), validSecrets(), "",
		func(b []*access.Identity, _ string) error { collected = append(collected, b...); return nil }); err != nil {
		t.Fatalf("SyncGroups: %v", err)
	}
	if len(collected) != pageSize+1 {
		t.Fatalf("len = %d; want %d", len(collected), pageSize+1)
	}
	if calls != 2 {
		t.Errorf("calls = %d; want 2", calls)
	}
	if collected[0].Type != access.IdentityTypeGroup {
		t.Errorf("type = %q; want group", collected[0].Type)
	}
}

func TestDatadog_SyncGroupMembers_PaginatesAndMaps(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if !strings.HasPrefix(r.URL.Path, "/api/v2/teams/team-1/memberships") {
			t.Errorf("path = %q", r.URL.Path)
		}
		body := map[string]interface{}{
			"data": []map[string]interface{}{},
			"meta": map[string]interface{}{"page": map[string]interface{}{"total_count": pageSize + 1}},
		}
		if calls == 1 {
			data := make([]map[string]interface{}, 0, pageSize)
			for i := 0; i < pageSize; i++ {
				data = append(data, map[string]interface{}{
					"id":            fmt.Sprintf("m-%d", i),
					"type":          "team_membership",
					"relationships": map[string]interface{}{"user": map[string]interface{}{"data": map[string]interface{}{"id": fmt.Sprintf("u-%d", i), "type": "users"}}},
				})
			}
			body["data"] = data
		} else {
			body["data"] = []map[string]interface{}{
				{"id": "m-last", "relationships": map[string]interface{}{"user": map[string]interface{}{"data": map[string]interface{}{"id": "u-last", "type": "users"}}}},
			}
		}
		b, _ := json.Marshal(body)
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	var ids []string
	if err := c.SyncGroupMembers(context.Background(), validConfig(), validSecrets(), "team-1", "",
		func(memberIDs []string, _ string) error { ids = append(ids, memberIDs...); return nil }); err != nil {
		t.Fatalf("SyncGroupMembers: %v", err)
	}
	if len(ids) != pageSize+1 {
		t.Fatalf("len = %d; want %d", len(ids), pageSize+1)
	}
	if calls != 2 {
		t.Errorf("calls = %d; want 2", calls)
	}
}

func TestDatadog_SyncGroups_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.SyncGroups(context.Background(), validConfig(), validSecrets(), "",
		func(_ []*access.Identity, _ string) error { return nil }); err == nil {
		t.Fatal("err = nil; want non-nil on 403")
	}
}

func TestDatadog_CountGroups_Streams(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"id":"t-1","attributes":{"name":"Eng"}},{"id":"t-2","attributes":{"name":"Sec"}}],"meta":{"page":{"total_count":2}}}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	got, err := c.CountGroups(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("CountGroups: %v", err)
	}
	if got != 2 {
		t.Errorf("count = %d; want 2", got)
	}
}
