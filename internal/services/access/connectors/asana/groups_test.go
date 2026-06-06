package asana

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func TestAsana_SyncGroups_PaginatesAndMaps(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if !strings.HasPrefix(r.URL.Path, "/organizations/12345/teams") {
			t.Errorf("path = %q", r.URL.Path)
		}
		if calls == 1 {
			_, _ = w.Write([]byte(`{"data":[{"gid":"t-1","name":"Eng"}],"next_page":{"offset":"OFF"}}`))
			return
		}
		if r.URL.Query().Get("offset") != "OFF" {
			t.Errorf("offset = %q", r.URL.Query().Get("offset"))
		}
		_, _ = w.Write([]byte(`{"data":[{"gid":"t-2","name":"Ops"}],"next_page":{}}`))
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
	if len(collected) != 2 {
		t.Fatalf("len = %d; want 2", len(collected))
	}
	if collected[0].Type != access.IdentityTypeGroup {
		t.Errorf("type = %q; want group", collected[0].Type)
	}
	if calls != 2 {
		t.Errorf("calls = %d; want 2", calls)
	}
}

func TestAsana_SyncGroupMembers_PaginatesAndMaps(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if !strings.HasPrefix(r.URL.Path, "/teams/t-1/users") {
			t.Errorf("path = %q", r.URL.Path)
		}
		if calls == 1 {
			_, _ = w.Write([]byte(`{"data":[{"gid":"u-1"},{"gid":"u-2"}],"next_page":{"offset":"OFF"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":[{"gid":"u-3"}]}`))
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	var ids []string
	if err := c.SyncGroupMembers(context.Background(), validConfig(), validSecrets(), "t-1", "",
		func(memberIDs []string, _ string) error { ids = append(ids, memberIDs...); return nil }); err != nil {
		t.Fatalf("SyncGroupMembers: %v", err)
	}
	if len(ids) != 3 {
		t.Fatalf("len = %d; want 3", len(ids))
	}
	if calls != 2 {
		t.Errorf("calls = %d; want 2", calls)
	}
}

func TestAsana_SyncGroups_Failure(t *testing.T) {
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

func TestAsana_CountGroups_Streams(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"gid":"t-1","name":"A"},{"gid":"t-2","name":"B"}],"next_page":{}}`))
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

func TestAsana_SyncGroupMembers_RejectsEmpty(t *testing.T) {
	if err := New().SyncGroupMembers(context.Background(), validConfig(), validSecrets(), "  ", "",
		func(_ []string, _ string) error { return nil }); err == nil {
		t.Fatal("err = nil; want non-nil for empty group id")
	}
}
