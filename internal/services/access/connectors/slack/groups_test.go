package slack

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// TestSyncGroups_HappyPathPaginates verifies that /usergroups.list
// pages through response_metadata.next_cursor across two pages.
func TestSyncGroups_HappyPathPaginates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("cursor") {
		case "":
			_, _ = w.Write([]byte(`{
				"ok": true,
				"usergroups": [
					{"id":"S001","name":"Engineers"},
					{"id":"S002","name":"Designers","date_delete": 0}
				],
				"response_metadata": {"next_cursor": "page2"}
			}`))
		case "page2":
			_, _ = w.Write([]byte(`{
				"ok": true,
				"usergroups": [{"id":"S003","name":"Archived Team","date_delete": 1717000000}],
				"response_metadata": {"next_cursor": ""}
			}`))
		default:
			t.Errorf("unexpected cursor: %s", r.URL.Query().Get("cursor"))
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	var got []*access.Identity
	err := c.SyncGroups(context.Background(), nil, validSecrets(), "",
		func(b []*access.Identity, _ string) error {
			got = append(got, b...)
			return nil
		},
	)
	if err != nil {
		t.Fatalf("SyncGroups: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("groups = %d; want 3", len(got))
	}
	// Last group is archived → status should reflect.
	if got[2].Status != "archived" {
		t.Errorf("archived group status = %q; want archived", got[2].Status)
	}
}

// TestSyncGroups_APIErrorPropagates verifies that a Slack-API-level
// error envelope (`{"ok": false, "error": "..."}`) is surfaced as a
// Go error rather than silently dropping the batch.
func TestSyncGroups_APIErrorPropagates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok": false, "error": "invalid_auth"}`))
	}))
	t.Cleanup(server.Close)
	c := New()
	c.urlOverride = server.URL
	err := c.SyncGroups(context.Background(), nil, validSecrets(), "",
		func(_ []*access.Identity, _ string) error { return nil },
	)
	if err == nil {
		t.Fatal("expected API-level error to surface")
	}
	if !strings.Contains(err.Error(), "invalid_auth") {
		t.Errorf("error %q missing invalid_auth", err.Error())
	}
}

// TestSyncGroupMembers_HappyPath verifies the members endpoint
// yields the flat array of user IDs Slack returns.
func TestSyncGroupMembers_HappyPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/usergroups.users.list") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{
			"ok": true,
			"users": ["U001","U002","U003"],
			"response_metadata": {"next_cursor": ""}
		}`))
	}))
	t.Cleanup(server.Close)
	c := New()
	c.urlOverride = server.URL
	var members []string
	err := c.SyncGroupMembers(context.Background(), nil, validSecrets(), "S001", "",
		func(ids []string, _ string) error {
			members = append(members, ids...)
			return nil
		},
	)
	if err != nil {
		t.Fatalf("SyncGroupMembers: %v", err)
	}
	if len(members) != 3 {
		t.Fatalf("members = %d; want 3", len(members))
	}
}

// TestSyncGroupMembers_RejectsEmptyGroup is the failure path:
// callers must pass a non-empty group ID.
func TestSyncGroupMembers_RejectsEmptyGroup(t *testing.T) {
	c := New()
	err := c.SyncGroupMembers(context.Background(), nil, validSecrets(), "", "",
		func(_ []string, _ string) error { return nil },
	)
	if err == nil {
		t.Fatal("expected error on empty group external id")
	}
}

// TestCountGroups_StreamsTotal verifies the count helper tallies
// every batch (Slack doesn't expose a count probe).
func TestCountGroups_StreamsTotal(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		switch calls {
		case 1:
			_, _ = w.Write([]byte(`{"ok":true,"usergroups":[{"id":"S1"},{"id":"S2"}],"response_metadata":{"next_cursor":"x"}}`))
		default:
			_, _ = w.Write([]byte(`{"ok":true,"usergroups":[{"id":"S3"}],"response_metadata":{"next_cursor":""}}`))
		}
	}))
	t.Cleanup(server.Close)
	c := New()
	c.urlOverride = server.URL
	n, err := c.CountGroups(context.Background(), nil, validSecrets())
	if err != nil {
		t.Fatalf("CountGroups: %v", err)
	}
	if n != 3 {
		t.Errorf("count = %d; want 3", n)
	}
}
