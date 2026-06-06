package gcp

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func validConfigWithCustomer() map[string]interface{} {
	return map[string]interface{}{"project_id": "uney-prod", "customer_id": "C0abcd1234"}
}

func TestGCP_SyncGroups_HappyPathTwoPages(t *testing.T) {
	page := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("missing bearer auth")
		}
		if !strings.HasPrefix(r.URL.Path, "/v1/groups") {
			t.Errorf("path = %q", r.URL.Path)
		}
		if got := r.URL.Query().Get("parent"); got != "customers/C0abcd1234" {
			t.Errorf("parent = %q", got)
		}
		page++
		switch page {
		case 1:
			_, _ = fmt.Fprintf(w, `{"groups":[{"name":"groups/g1","displayName":"Engineering","groupKey":{"id":"eng@uney.com"}}],"nextPageToken":"PAGE2"}`)
		default:
			if got := r.URL.Query().Get("pageToken"); got != "PAGE2" {
				t.Errorf("pageToken = %q; want PAGE2", got)
			}
			_, _ = fmt.Fprintf(w, `{"groups":[{"name":"groups/g2","displayName":"Sales","groupKey":{"id":"sales@uney.com"}}]}`)
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
	var got []*access.Identity
	if err := c.SyncGroups(context.Background(), validConfigWithCustomer(), validSecrets(), "", func(b []*access.Identity, _ string) error {
		got = append(got, b...)
		return nil
	}); err != nil {
		t.Fatalf("SyncGroups: %v", err)
	}
	if len(got) != 2 || got[0].ExternalID != "groups/g1" || got[1].ExternalID != "groups/g2" {
		t.Errorf("groups = %+v; want g1, g2", got)
	}
	if got[0].Type != access.IdentityTypeGroup {
		t.Errorf("type = %q; want group", got[0].Type)
	}
}

func TestGCP_SyncGroups_MissingCustomerRejected(t *testing.T) {
	c := New()
	err := c.SyncGroups(context.Background(), validConfig(), validSecrets(), "", func(_ []*access.Identity, _ string) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "customer_id is required") {
		t.Errorf("err = %v; want missing customer rejection", err)
	}
}

func TestGCP_SyncGroupMembers_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/v1/groups/g1/memberships") {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"memberships":[{"name":"groups/g1/memberships/m1","preferredMemberKey":{"id":"alice@uney.com"},"type":"USER"},{"name":"groups/g1/memberships/m2","preferredMemberKey":{"id":"bob@uney.com"},"type":"USER"}]}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
	var ids []string
	if err := c.SyncGroupMembers(context.Background(), validConfigWithCustomer(), validSecrets(), "groups/g1", "", func(m []string, _ string) error {
		ids = append(ids, m...)
		return nil
	}); err != nil {
		t.Fatalf("SyncGroupMembers: %v", err)
	}
	if len(ids) != 2 || ids[0] != "alice@uney.com" || ids[1] != "bob@uney.com" {
		t.Errorf("members = %v; want [alice bob]", ids)
	}
}

func TestGCP_SyncGroupMembers_RawIDNormalized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Caller passed "g1" without prefix; should be normalised to "groups/g1".
		if !strings.Contains(r.URL.Path, "/v1/groups/g1/memberships") {
			t.Errorf("path = %q; want normalised groups/g1", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"memberships":[]}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
	if err := c.SyncGroupMembers(context.Background(), validConfigWithCustomer(), validSecrets(), "g1", "", func(_ []string, _ string) error { return nil }); err != nil {
		t.Fatalf("SyncGroupMembers: %v", err)
	}
}

func TestGCP_SyncGroupMembers_MissingID(t *testing.T) {
	c := New()
	err := c.SyncGroupMembers(context.Background(), validConfigWithCustomer(), validSecrets(), "", "", func(_ []string, _ string) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "groupExternalID is required") {
		t.Errorf("err = %v; want missing-id rejection", err)
	}
}

func TestGCP_CountGroups_WalksAllPages(t *testing.T) {
	page := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page++
		switch page {
		case 1:
			_, _ = w.Write([]byte(`{"groups":[{"name":"groups/a"},{"name":"groups/b"}],"nextPageToken":"P2"}`))
		default:
			_, _ = w.Write([]byte(`{"groups":[{"name":"groups/c"}]}`))
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
	n, err := c.CountGroups(context.Background(), validConfigWithCustomer(), validSecrets())
	if err != nil {
		t.Fatalf("CountGroups: %v", err)
	}
	if n != 3 {
		t.Errorf("count = %d; want 3", n)
	}
}

func TestGCP_SyncGroups_ServerErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":{"code":500,"message":"server fail"}}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
	err := c.SyncGroups(context.Background(), validConfigWithCustomer(), validSecrets(), "", func(_ []*access.Identity, _ string) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "status 500") {
		t.Errorf("err = %v; want 500", err)
	}
}

func TestGCP_SatisfiesGroupSyncerInterface(t *testing.T) {
	var _ access.GroupSyncer = New()
}
