package azure

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func TestAzure_SyncGroups_HappyPathTwoPages(t *testing.T) {
	var serverURL string
	page := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page++
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("missing auth header")
		}
		if !strings.HasPrefix(r.URL.Path, "/groups") {
			t.Errorf("path = %q", r.URL.Path)
		}
		switch page {
		case 1:
			next := serverURL + "/groups?$skiptoken=PAGE2"
			_, _ = fmt.Fprintf(w, `{"@odata.nextLink":%q,"value":[{"id":"g1","displayName":"Engineering","securityEnabled":true,"mailEnabled":false}]}`, next)
		default:
			_, _ = w.Write([]byte(`{"value":[{"id":"g2","displayName":"Sales","mail":"sales@uney.com"}]}`))
		}
	}))
	t.Cleanup(srv.Close)
	serverURL = srv.URL
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }

	var got []*access.Identity
	if err := c.SyncGroups(context.Background(), validConfig(), validSecrets(), "", func(b []*access.Identity, _ string) error {
		got = append(got, b...)
		return nil
	}); err != nil {
		t.Fatalf("SyncGroups: %v", err)
	}
	if len(got) != 2 || got[0].ExternalID != "g1" || got[1].ExternalID != "g2" {
		t.Errorf("groups = %+v; want [g1, g2]", got)
	}
	if got[0].Type != access.IdentityTypeGroup {
		t.Errorf("group type = %q; want group", got[0].Type)
	}
	if got[1].Email != "sales@uney.com" {
		t.Errorf("group[1].Email = %q; want sales@uney.com", got[1].Email)
	}
}

func TestAzure_SyncGroups_NextLinkStripsBaseURL(t *testing.T) {
	var serverURL string
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		// Second call must have the trimmed path, NOT the full nextLink URL.
		if calls == 2 {
			if strings.HasPrefix(r.URL.Path, "/http") || strings.Contains(r.URL.RequestURI(), "://") {
				t.Errorf("second call path leaked absolute URL: %q", r.URL.RequestURI())
			}
		}
		if calls == 1 {
			_, _ = fmt.Fprintf(w, `{"@odata.nextLink":"%s/groups?$skiptoken=X","value":[]}`, serverURL)
			return
		}
		_, _ = w.Write([]byte(`{"value":[]}`))
	}))
	t.Cleanup(srv.Close)
	serverURL = srv.URL
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }

	if err := c.SyncGroups(context.Background(), validConfig(), validSecrets(), "", func(_ []*access.Identity, _ string) error { return nil }); err != nil {
		t.Fatalf("SyncGroups: %v", err)
	}
	if calls != 2 {
		t.Errorf("calls = %d; want 2", calls)
	}
}

func TestAzure_SyncGroupMembers_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/groups/g-eng/members") {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"value":[{"id":"u1","@odata.type":"#microsoft.graph.user"},{"id":"u2","@odata.type":"#microsoft.graph.user"}]}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }

	var ids []string
	if err := c.SyncGroupMembers(context.Background(), validConfig(), validSecrets(), "g-eng", "", func(m []string, _ string) error {
		ids = append(ids, m...)
		return nil
	}); err != nil {
		t.Fatalf("SyncGroupMembers: %v", err)
	}
	if len(ids) != 2 || ids[0] != "u1" || ids[1] != "u2" {
		t.Errorf("members = %v; want [u1 u2]", ids)
	}
}

func TestAzure_SyncGroupMembers_MissingID(t *testing.T) {
	c := New()
	err := c.SyncGroupMembers(context.Background(), validConfig(), validSecrets(), "", "", func(_ []string, _ string) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "group external id is required") {
		t.Errorf("err = %v; want missing-id rejection", err)
	}
}

func TestAzure_CountGroups_ParsesPlainInt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/groups/$count") {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.Header.Get("ConsistencyLevel") != "eventual" {
			t.Errorf("missing ConsistencyLevel header")
		}
		_, _ = w.Write([]byte("42"))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
	n, err := c.CountGroups(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("CountGroups: %v", err)
	}
	if n != 42 {
		t.Errorf("count = %d; want 42", n)
	}
}

func TestAzure_SyncGroups_ServerErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":{"code":"InternalServerError"}}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
	err := c.SyncGroups(context.Background(), validConfig(), validSecrets(), "", func(_ []*access.Identity, _ string) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("err = %v; want 500", err)
	}
}

func TestAzure_SatisfiesGroupSyncerInterface(t *testing.T) {
	var _ access.GroupSyncer = New()
}
