package tailscale

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// tsACLAndUsersServer fakes both endpoints needed by GroupSyncer:
// the tailnet ACL fetch and the /users index fetch.
func tsACLAndUsersServer(t *testing.T, aclBody, usersBody string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/acl"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(aclBody))
		case strings.HasSuffix(r.URL.Path, "/users"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(usersBody))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func tsGroupConfig() map[string]interface{}  { return map[string]interface{}{"tailnet": "example.com"} }
func tsGroupSecrets() map[string]interface{} { return map[string]interface{}{"api_key": "v1"} }

const tsACLFixture = `{
  "groups": {
    "group:admins": ["alice@example.com", "bob@example.com"],
    "group:dev":    ["alice@example.com", "group:admins", "tag:ci"],
    "group:cycle":  ["group:cycle", "carol@example.com"]
  }
}`

const tsUsersFixture = `{
  "users": [
    {"id": "uid-alice", "loginName": "alice@example.com", "displayName": "Alice", "status": "active"},
    {"id": "uid-bob",   "loginName": "bob@example.com",   "displayName": "Bob",   "status": "active"},
    {"id": "uid-carol", "loginName": "carol@example.com", "displayName": "Carol", "status": "active"}
  ]
}`

func TestTailscale_CountGroups(t *testing.T) {
	srv := tsACLAndUsersServer(t, tsACLFixture, tsUsersFixture)
	conn := New()
	conn.urlOverride = srv.URL
	got, err := conn.CountGroups(context.Background(), tsGroupConfig(), tsGroupSecrets())
	if err != nil {
		t.Fatalf("CountGroups: %v", err)
	}
	if got != 3 {
		t.Errorf("CountGroups = %d; want 3", got)
	}
}

func TestTailscale_SyncGroups_EmitsAllACLGroups(t *testing.T) {
	srv := tsACLAndUsersServer(t, tsACLFixture, tsUsersFixture)
	conn := New()
	conn.urlOverride = srv.URL
	var got []*access.Identity
	err := conn.SyncGroups(context.Background(), tsGroupConfig(), tsGroupSecrets(), "", func(batch []*access.Identity, _ string) error {
		got = append(got, batch...)
		return nil
	})
	if err != nil {
		t.Fatalf("SyncGroups: %v", err)
	}
	names := make([]string, 0, len(got))
	for _, g := range got {
		names = append(names, g.ExternalID)
		if g.Type != access.IdentityTypeGroup {
			t.Errorf("group %q has type %v; want IdentityTypeGroup", g.ExternalID, g.Type)
		}
	}
	sort.Strings(names)
	want := []string{"group:admins", "group:cycle", "group:dev"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("group names = %v; want %v", names, want)
	}
}

func TestTailscale_SyncGroupMembers_FlatGroupResolvesEmailsToUserIDs(t *testing.T) {
	srv := tsACLAndUsersServer(t, tsACLFixture, tsUsersFixture)
	conn := New()
	conn.urlOverride = srv.URL
	var got []string
	err := conn.SyncGroupMembers(context.Background(), tsGroupConfig(), tsGroupSecrets(), "group:admins", "", func(ids []string, _ string) error {
		got = ids
		return nil
	})
	if err != nil {
		t.Fatalf("SyncGroupMembers: %v", err)
	}
	want := []string{"uid-alice", "uid-bob"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("members = %v; want %v", got, want)
	}
}

func TestTailscale_SyncGroupMembers_NestedGroupReferenceIsExpanded(t *testing.T) {
	srv := tsACLAndUsersServer(t, tsACLFixture, tsUsersFixture)
	conn := New()
	conn.urlOverride = srv.URL
	var got []string
	err := conn.SyncGroupMembers(context.Background(), tsGroupConfig(), tsGroupSecrets(), "group:dev", "", func(ids []string, _ string) error {
		got = ids
		return nil
	})
	if err != nil {
		t.Fatalf("SyncGroupMembers: %v", err)
	}
	// group:dev = [alice, group:admins, tag:ci]
	// → expanded → [alice] + [alice, bob] + (tag dropped)
	// → unique sorted IDs = [uid-alice, uid-bob]
	want := []string{"uid-alice", "uid-bob"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("members = %v; want %v (nested group expansion + tag drop)", got, want)
	}
}

func TestTailscale_SyncGroupMembers_TagReferenceIsDropped(t *testing.T) {
	aclOnlyTag := `{"groups": {"group:taggy": ["tag:ci", "tag:prod"]}}`
	srv := tsACLAndUsersServer(t, aclOnlyTag, tsUsersFixture)
	conn := New()
	conn.urlOverride = srv.URL
	var got []string
	err := conn.SyncGroupMembers(context.Background(), tsGroupConfig(), tsGroupSecrets(), "group:taggy", "", func(ids []string, _ string) error {
		got = ids
		return nil
	})
	if err != nil {
		t.Fatalf("SyncGroupMembers: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("members = %v; want empty (all tag references dropped)", got)
	}
}

func TestTailscale_SyncGroupMembers_CycleTerminates(t *testing.T) {
	srv := tsACLAndUsersServer(t, tsACLFixture, tsUsersFixture)
	conn := New()
	conn.urlOverride = srv.URL
	var got []string
	err := conn.SyncGroupMembers(context.Background(), tsGroupConfig(), tsGroupSecrets(), "group:cycle", "", func(ids []string, _ string) error {
		got = ids
		return nil
	})
	if err != nil {
		t.Fatalf("SyncGroupMembers: %v", err)
	}
	if len(got) != 1 || got[0] != "uid-carol" {
		t.Errorf("members = %v; want [uid-carol] (cycle broken, real member resolved)", got)
	}
}

func TestTailscale_SyncGroupMembers_MissingGroupReturnsEmpty(t *testing.T) {
	srv := tsACLAndUsersServer(t, tsACLFixture, tsUsersFixture)
	conn := New()
	conn.urlOverride = srv.URL
	called := false
	var receivedBatch []string
	err := conn.SyncGroupMembers(context.Background(), tsGroupConfig(), tsGroupSecrets(), "group:does-not-exist", "", func(ids []string, _ string) error {
		called = true
		receivedBatch = ids
		if len(ids) != 0 {
			t.Errorf("members = %v; want empty for missing group", ids)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("SyncGroupMembers: %v", err)
	}
	if !called {
		t.Error("handler was not invoked; want invocation with empty membership")
	}
	// Non-nil empty slice per GroupSyncer empty-batch contract —
	// downstream consumers that JSON-marshal the batch see `[]` rather
	// than `null`. See optional_interfaces.go.
	if receivedBatch == nil {
		t.Error("batch is nil; want non-nil empty slice per GroupSyncer empty-batch contract (optional_interfaces.go)")
	}
}

func TestTailscale_SyncGroupMembers_EmptyGroupIDIsValidationError(t *testing.T) {
	srv := tsACLAndUsersServer(t, tsACLFixture, tsUsersFixture)
	conn := New()
	conn.urlOverride = srv.URL
	err := conn.SyncGroupMembers(context.Background(), tsGroupConfig(), tsGroupSecrets(), "", "", func([]string, string) error { return nil })
	if err == nil {
		t.Error("err = nil; want validation error on empty groupExternalID")
	}
}

func TestTailscale_SatisfiesGroupSyncerInterface(_ *testing.T) {
	var _ access.GroupSyncer = (*TailscaleAccessConnector)(nil)
}
