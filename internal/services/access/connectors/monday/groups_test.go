package monday

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func mondayGroupsConfig() map[string]interface{}  { return map[string]interface{}{} }
func mondayGroupsSecrets() map[string]interface{} { return map[string]interface{}{"api_token": "tok-1"} }

// teamsPage returns a JSON GraphQL teams envelope with N teams.
func teamsPage(start, n int, name string) string {
	parts := make([]string, 0, n)
	for i := 0; i < n; i++ {
		parts = append(parts, fmt.Sprintf(`{"id":"%d","name":"%s%d","users":[]}`, start+i, name, start+i))
	}
	return `{"data":{"teams":[` + strings.Join(parts, ",") + `]}}`
}

func TestMonday_SyncGroups_HappyPath_TwoPages(t *testing.T) {
	var hits int
	pageOne := teamsPage(1, teamsPageSize, "Team")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "teams(") {
			t.Errorf("body=%q; want teams() graphql query", string(body))
		}
		hits++
		switch hits {
		case 1:
			_, _ = w.Write([]byte(pageOne))
		case 2:
			_, _ = w.Write([]byte(`{"data":{"teams":[{"id":"999","name":"Last","users":[]}]}}`))
		default:
			t.Errorf("unexpected page %d", hits)
		}
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	var got []*access.Identity
	if err := c.SyncGroups(context.Background(), mondayGroupsConfig(), mondayGroupsSecrets(), "",
		func(batch []*access.Identity, _ string) error {
			got = append(got, batch...)
			return nil
		}); err != nil {
		t.Fatalf("SyncGroups: %v", err)
	}
	if len(got) != teamsPageSize+1 {
		t.Errorf("got %d teams; want %d", len(got), teamsPageSize+1)
	}
	if got[0].Type != access.IdentityTypeGroup {
		t.Errorf("type = %s; want group", got[0].Type)
	}
	if got[teamsPageSize].ExternalID != "999" {
		t.Errorf("last id = %q; want 999", got[teamsPageSize].ExternalID)
	}
}

func TestMonday_SyncGroupMembers_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "teams(ids: [42]") {
			t.Errorf("body=%q; want teams(ids: [42] ...) graphql query", string(body))
		}
		_, _ = w.Write([]byte(`{"data":{"teams":[{"id":"42","users":[{"id":"100"},{"id":"200"}]}]}}`))
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	var ids []string
	if err := c.SyncGroupMembers(context.Background(), mondayGroupsConfig(), mondayGroupsSecrets(), "42", "",
		func(batch []string, _ string) error {
			ids = append(ids, batch...)
			return nil
		}); err != nil {
		t.Fatalf("SyncGroupMembers: %v", err)
	}
	if fmt.Sprintf("%v", ids) != "[100 200]" {
		t.Errorf("ids = %v; want [100 200]", ids)
	}
}

func TestMonday_CountGroups_WalksPages(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"teams":[{"id":"1","name":"T","users":[]}]}}`))
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	n, err := c.CountGroups(context.Background(), mondayGroupsConfig(), mondayGroupsSecrets())
	if err != nil {
		t.Fatalf("CountGroups: %v", err)
	}
	if n != 1 {
		t.Errorf("count = %d; want 1", n)
	}
}

func TestMonday_SyncGroups_GraphQLErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"errors":[{"message":"forbidden"}]}`))
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	err := c.SyncGroups(context.Background(), mondayGroupsConfig(), mondayGroupsSecrets(), "",
		func(_ []*access.Identity, _ string) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "forbidden") {
		t.Errorf("err=%v; want graphql error", err)
	}
}

// TestMonday_SyncGroupMembers_TeamGone_NonNilEmptyBatch covers the
// GroupSyncer empty-batch contract documented in
// access/optional_interfaces.go: when the upstream teams envelope is
// missing (`data.teams = []`) the handler must be invoked exactly once
// with a non-nil empty slice so downstream consumers that JSON-marshal
// the batch see `[]` rather than `null`.
func TestMonday_SyncGroupMembers_TeamGone_NonNilEmptyBatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"teams":[]}}`))
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	var batches [][]string
	if err := c.SyncGroupMembers(context.Background(), mondayGroupsConfig(), mondayGroupsSecrets(), "999", "",
		func(m []string, _ string) error {
			batches = append(batches, m)
			return nil
		}); err != nil {
		t.Fatalf("SyncGroupMembers: %v", err)
	}
	if len(batches) != 1 || len(batches[0]) != 0 {
		t.Errorf("batches = %v; want one empty-batch invocation", batches)
	}
	if batches[0] == nil {
		t.Error("batch is nil; want non-nil empty slice per GroupSyncer empty-batch contract (optional_interfaces.go)")
	}
}

func TestMonday_SyncGroupMembers_MissingGroupID(t *testing.T) {
	c := New()
	err := c.SyncGroupMembers(context.Background(), mondayGroupsConfig(), mondayGroupsSecrets(), "", "",
		func(_ []string, _ string) error { return nil })
	if err == nil {
		t.Error("err = nil; want non-nil for empty group id")
	}
}

func TestMonday_SatisfiesGroupSyncerInterface(_ *testing.T) {
	var _ access.GroupSyncer = New()
}
