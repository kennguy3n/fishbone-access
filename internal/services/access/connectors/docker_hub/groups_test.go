package docker_hub

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

func dockerHubLoginAndGroupsServer(t *testing.T, handler func(w http.ResponseWriter, r *http.Request, srvURL string)) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/users/login" {
			_, _ = w.Write([]byte(`{"token":"jwt-test-token"}`))
			return
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "JWT ") {
			t.Errorf("expected JWT auth, got %q", r.Header.Get("Authorization"))
		}
		handler(w, r, srv.URL)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDockerHub_SyncGroups_HappyPathTwoPages(t *testing.T) {
	calls := 0
	srv := dockerHubLoginAndGroupsServer(t, func(w http.ResponseWriter, r *http.Request, srvURL string) {
		if !strings.HasPrefix(r.URL.Path, "/v2/orgs/acme/groups") {
			t.Errorf("path = %q", r.URL.Path)
		}
		calls++
		body := map[string]interface{}{"count": 3}
		if calls == 1 {
			body["next"] = srvURL + "/v2/orgs/acme/groups?page=2&page_size=" + fmt.Sprintf("%d", pageSize)
			body["results"] = []map[string]interface{}{
				{"id": 11, "uuid": "g-eng", "name": "engineering", "description": "Engineering team"},
			}
		} else {
			body["next"] = ""
			body["results"] = []map[string]interface{}{
				{"id": 12, "uuid": "g-sec", "name": "security", "description": "Security team"},
			}
		}
		b, _ := json.Marshal(body)
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
	if len(got) != 2 || got[0].ExternalID != "engineering" || got[1].ExternalID != "security" {
		t.Errorf("groups = %+v", got)
	}
	if got[0].Type != access.IdentityTypeGroup {
		t.Errorf("type = %q; want group", got[0].Type)
	}
	if got[0].RawData["uuid"].(string) != "g-eng" {
		t.Errorf("uuid raw = %v", got[0].RawData["uuid"])
	}
}

func TestDockerHub_SyncGroupMembers_HappyPath(t *testing.T) {
	srv := dockerHubLoginAndGroupsServer(t, func(w http.ResponseWriter, r *http.Request, _ string) {
		if !strings.Contains(r.URL.Path, "/v2/orgs/acme/groups/engineering/members") {
			t.Errorf("path = %q", r.URL.Path)
		}
		body := map[string]interface{}{
			"count": 2,
			"next":  "",
			"results": []map[string]interface{}{
				{"username": "alice", "id": "u1"},
				{"username": "bob", "id": "u2"},
			},
		}
		b, _ := json.Marshal(body)
		_, _ = w.Write(b)
	})
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var ids []string
	if err := c.SyncGroupMembers(context.Background(), validConfig(), validSecrets(), "engineering", "", func(m []string, _ string) error {
		ids = append(ids, m...)
		return nil
	}); err != nil {
		t.Fatalf("SyncGroupMembers: %v", err)
	}
	if len(ids) != 2 || ids[0] != "alice" || ids[1] != "bob" {
		t.Errorf("members = %v", ids)
	}
}

func TestDockerHub_SyncGroupMembers_MissingGroupRejected(t *testing.T) {
	c := New()
	err := c.SyncGroupMembers(context.Background(), validConfig(), validSecrets(), "", "", func(_ []string, _ string) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "groupExternalID is required") {
		t.Errorf("err = %v; want missing-group rejection", err)
	}
}

func TestDockerHub_CountGroups_UsesCountField(t *testing.T) {
	srv := dockerHubLoginAndGroupsServer(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
		_, _ = w.Write([]byte(`{"count":42,"next":"","results":[]}`))
	})
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	n, err := c.CountGroups(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("CountGroups: %v", err)
	}
	if n != 42 {
		t.Errorf("count = %d; want 42", n)
	}
}

func TestDockerHub_CountGroups_FallsBackToWalkWhenCountZero(t *testing.T) {
	calls := 0
	srv := dockerHubLoginAndGroupsServer(t, func(w http.ResponseWriter, _ *http.Request, srvURL string) {
		calls++
		body := map[string]interface{}{"count": 0}
		if calls == 1 {
			body["next"] = srvURL + "/v2/orgs/acme/groups?page=2"
			body["results"] = []map[string]interface{}{{"name": "g1"}, {"name": "g2"}}
		} else {
			body["next"] = ""
			body["results"] = []map[string]interface{}{{"name": "g3"}}
		}
		b, _ := json.Marshal(body)
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
		t.Errorf("count = %d; want 3 (walk fallback)", n)
	}
}

func TestDockerHub_SyncGroups_ServerErrorPropagates(t *testing.T) {
	srv := dockerHubLoginAndGroupsServer(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"detail":"boom"}`))
	})
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.SyncGroups(context.Background(), validConfig(), validSecrets(), "", func(_ []*access.Identity, _ string) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("err = %v; want 500", err)
	}
}

func TestDockerHub_SatisfiesGroupSyncerInterface(t *testing.T) {
	var _ access.GroupSyncer = New()
}
