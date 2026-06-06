package hubspot

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func TestHubSpot_SyncGroups_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/settings/v3/users/teams" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer ") {
			t.Errorf("auth header = %q", got)
		}
		_, _ = w.Write([]byte(`{"results":[
			{"id":"t-1","name":"Sales","userIds":["u-1","u-2"]},
			{"id":"t-2","name":"Support","userIds":["u-3"],"secondaryUserIds":["u-4"]}
		]}`))
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
	if collected[0].ExternalID != "t-1" || collected[0].DisplayName != "Sales" {
		t.Errorf("first = %+v", collected[0])
	}
	if collected[0].Type != access.IdentityTypeGroup {
		t.Errorf("type = %q; want group", collected[0].Type)
	}
}

func TestHubSpot_SyncGroupMembers_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/settings/v3/users/teams/t-1" {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"id":"t-1","name":"Sales","userIds":["u-1","u-2"],"secondaryUserIds":["u-3"]}`))
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
}

func TestHubSpot_SyncGroups_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.SyncGroups(context.Background(), validConfig(), validSecrets(), "",
		func(_ []*access.Identity, _ string) error { return nil }); err == nil {
		t.Fatal("err = nil; want non-nil on 401")
	}
}

func TestHubSpot_CountGroups_Streams(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"results":[{"id":"t-1","name":"A"},{"id":"t-2","name":"B"},{"id":"t-3","name":"C"}]}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	got, err := c.CountGroups(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("CountGroups: %v", err)
	}
	if got != 3 {
		t.Errorf("count = %d; want 3", got)
	}
}

func TestHubSpot_SyncGroupMembers_RejectsEmpty(t *testing.T) {
	if err := New().SyncGroupMembers(context.Background(), validConfig(), validSecrets(), "  ", "",
		func(_ []string, _ string) error { return nil }); err == nil {
		t.Fatal("err = nil; want non-nil for empty group id")
	}
}
