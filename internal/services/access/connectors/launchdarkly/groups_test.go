package launchdarkly

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func ldGroupsConfig() map[string]interface{}  { return map[string]interface{}{} }
func ldGroupsSecrets() map[string]interface{} { return map[string]interface{}{"api_key": "ld-key"} }

func TestLaunchDarkly_SyncGroups_HappyPath_TwoPages(t *testing.T) {
	pageOne := strings.Repeat(`{"key":"core","name":"Core"},`, pageSize)
	pageOne = "[" + strings.TrimRight(pageOne, ",") + "]"
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/teams" {
			t.Errorf("path=%q; want /api/v2/teams", r.URL.Path)
		}
		hits++
		switch hits {
		case 1:
			_, _ = fmt.Fprintf(w, `{"totalCount":%d,"items":%s}`, pageSize+1, pageOne)
		case 2:
			_, _ = w.Write([]byte(`{"totalCount":101,"items":[{"key":"ops","name":"Ops"}]}`))
		default:
			t.Errorf("unexpected page %d", hits)
		}
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	var got []*access.Identity
	if err := c.SyncGroups(context.Background(), ldGroupsConfig(), ldGroupsSecrets(), "",
		func(batch []*access.Identity, _ string) error {
			got = append(got, batch...)
			return nil
		}); err != nil {
		t.Fatalf("SyncGroups: %v", err)
	}
	if len(got) != pageSize+1 {
		t.Errorf("got %d groups; want %d", len(got), pageSize+1)
	}
	if got[0].Type != access.IdentityTypeGroup {
		t.Errorf("type = %s; want group", got[0].Type)
	}
	if got[pageSize].ExternalID != "ops" {
		t.Errorf("last id = %q; want ops", got[pageSize].ExternalID)
	}
}

func TestLaunchDarkly_SyncGroupMembers_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/v2/teams/core/members") {
			t.Errorf("path=%q; want /api/v2/teams/core/members prefix", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"totalCount":2,"items":[{"_id":"m1"},{"_id":"m2"}]}`))
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	var ids []string
	if err := c.SyncGroupMembers(context.Background(), ldGroupsConfig(), ldGroupsSecrets(), "core", "",
		func(batch []string, _ string) error {
			ids = append(ids, batch...)
			return nil
		}); err != nil {
		t.Fatalf("SyncGroupMembers: %v", err)
	}
	if fmt.Sprintf("%v", ids) != "[m1 m2]" {
		t.Errorf("ids = %v; want [m1 m2]", ids)
	}
}

func TestLaunchDarkly_CountGroups_WalksPages(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"totalCount":1,"items":[{"key":"a","name":"A"}]}`))
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	n, err := c.CountGroups(context.Background(), ldGroupsConfig(), ldGroupsSecrets())
	if err != nil {
		t.Fatalf("CountGroups: %v", err)
	}
	if n != 1 {
		t.Errorf("count = %d; want 1", n)
	}
}

func TestLaunchDarkly_SyncGroups_ServerErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	err := c.SyncGroups(context.Background(), ldGroupsConfig(), ldGroupsSecrets(), "",
		func(_ []*access.Identity, _ string) error { return nil })
	if err == nil {
		t.Error("err = nil; want non-nil for 500")
	}
}

func TestLaunchDarkly_SyncGroupMembers_MissingGroupID(t *testing.T) {
	c := New()
	err := c.SyncGroupMembers(context.Background(), ldGroupsConfig(), ldGroupsSecrets(), "", "",
		func(_ []string, _ string) error { return nil })
	if err == nil {
		t.Error("err = nil; want non-nil for empty group id")
	}
}

func TestLaunchDarkly_SatisfiesGroupSyncerInterface(_ *testing.T) {
	var _ access.GroupSyncer = New()
}
