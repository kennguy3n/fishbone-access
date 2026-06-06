package intercom

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func newIntercomTeamsServer(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("expected Bearer auth, got %q", r.Header.Get("Authorization"))
		}
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestIntercom_SyncGroups_HappyPath(t *testing.T) {
	srv := newIntercomTeamsServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/teams" {
			t.Errorf("path = %q; want /teams", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"teams": []map[string]interface{}{
				{"id": "t1", "name": "Support", "admin_ids": []string{"a1", "a2"}},
				{"id": "t2", "name": "Onboarding", "admin_ids": []string{"a3"}},
			},
		})
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
	if len(got) != 2 || got[0].ExternalID != "t1" || got[1].ExternalID != "t2" {
		t.Errorf("groups = %+v", got)
	}
	if got[0].Type != access.IdentityTypeGroup {
		t.Errorf("type = %q; want group", got[0].Type)
	}
	if got[0].RawData["admin_count"].(int) != 2 {
		t.Errorf("admin_count = %v", got[0].RawData["admin_count"])
	}
}

func TestIntercom_SyncGroupMembers_HappyPath(t *testing.T) {
	srv := newIntercomTeamsServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/teams/t1" {
			t.Errorf("path = %q; want /teams/t1", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"id": "t1", "name": "Support", "admin_ids": []string{"a1", "a2", "a3"},
		})
	})
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var ids []string
	if err := c.SyncGroupMembers(context.Background(), validConfig(), validSecrets(), "t1", "", func(m []string, _ string) error {
		ids = append(ids, m...)
		return nil
	}); err != nil {
		t.Fatalf("SyncGroupMembers: %v", err)
	}
	if len(ids) != 3 || ids[0] != "a1" || ids[2] != "a3" {
		t.Errorf("members = %v", ids)
	}
}

func TestIntercom_SyncGroupMembers_404ReturnsEmpty(t *testing.T) {
	srv := newIntercomTeamsServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var ids []string
	if err := c.SyncGroupMembers(context.Background(), validConfig(), validSecrets(), "tg-gone", "", func(m []string, _ string) error {
		ids = append(ids, m...)
		return nil
	}); err != nil {
		t.Errorf("404 should map to empty membership; got %v", err)
	}
	if len(ids) != 0 {
		t.Errorf("ids = %v; want empty", ids)
	}
}

func TestIntercom_SyncGroupMembers_MissingGroupRejected(t *testing.T) {
	c := New()
	err := c.SyncGroupMembers(context.Background(), validConfig(), validSecrets(), "  ", "", func(_ []string, _ string) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "groupExternalID is required") {
		t.Errorf("err = %v", err)
	}
}

func TestIntercom_CountGroups(t *testing.T) {
	srv := newIntercomTeamsServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"teams": []map[string]interface{}{
				{"id": "t1", "name": "A"},
				{"id": "t2", "name": "B"},
				{"id": "t3", "name": "C"},
			},
		})
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

func TestIntercom_SyncGroups_ServerErrorPropagates(t *testing.T) {
	srv := newIntercomTeamsServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"errors":[{"code":"server_error","message":"boom"}]}`))
	})
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.SyncGroups(context.Background(), validConfig(), validSecrets(), "", func(_ []*access.Identity, _ string) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("err = %v; want 500", err)
	}
}

func TestIntercom_SatisfiesGroupSyncerInterface(t *testing.T) {
	var _ access.GroupSyncer = New()
}
