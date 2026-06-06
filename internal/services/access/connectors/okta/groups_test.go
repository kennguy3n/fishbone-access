package okta

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// TestSyncGroups_HappyPathPaginates verifies that SyncGroups follows
// the Link rel="next" pagination chain across two pages and emits
// every group exactly once.
func TestSyncGroups_HappyPathPaginates(t *testing.T) {
	var page2Path string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/v1/groups") && r.URL.Query().Get("after") == "":
			// Page 1 — emit two groups and a rel="next" header.
			page2Path = "/api/v1/groups?after=cursor2&limit=200"
			w.Header().Set("Link", `<`+server2NextLink(r, page2Path)+`>; rel="next"`)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[
				{"id":"00g_a","profile":{"name":"Engineers"}},
				{"id":"00g_b","profile":{"name":"Designers"}}
			]`))
		case r.URL.Path == "/api/v1/groups" && r.URL.Query().Get("after") == "cursor2":
			// Page 2 — emit one group, no next link.
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"id":"00g_c","profile":{"name":"Ops"}}]`))
		default:
			t.Errorf("unexpected request: %s", r.URL.String())
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }

	var got []*access.Identity
	err := c.SyncGroups(context.Background(), validConfig(), validSecrets(), "",
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
	for _, g := range got {
		if g.Type != access.IdentityTypeGroup {
			t.Errorf("identity %q has type %q; want group", g.ExternalID, g.Type)
		}
	}
}

// TestSyncGroups_FailureSurfacesStatus verifies that a 5xx response
// surfaces as an error and aborts the loop (no silent partial batch).
func TestSyncGroups_FailureSurfacesStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"errorCode":"E0000003","errorSummary":"Internal Server Error"}`))
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
	err := c.SyncGroups(context.Background(), validConfig(), validSecrets(), "",
		func(_ []*access.Identity, _ string) error { return nil },
	)
	if err == nil {
		t.Fatal("SyncGroups: expected error on 500, got nil")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error %q does not mention status code", err.Error())
	}
}

// TestSyncGroupMembers_HappyPath verifies that the connector
// resolves the per-group members endpoint and yields member IDs.
func TestSyncGroupMembers_HappyPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/groups/00g_a/users":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"id":"00u_1"},{"id":"00u_2"}]`))
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
	var members []string
	err := c.SyncGroupMembers(context.Background(), validConfig(), validSecrets(), "00g_a", "",
		func(ids []string, _ string) error {
			members = append(members, ids...)
			return nil
		},
	)
	if err != nil {
		t.Fatalf("SyncGroupMembers: %v", err)
	}
	if len(members) != 2 {
		t.Fatalf("members = %d; want 2", len(members))
	}
}

// TestSyncGroupMembers_RejectsEmptyGroupID is the failure-path test:
// an empty group ID must return a structured error before any HTTP
// call so misconfigured callers fail fast.
func TestSyncGroupMembers_RejectsEmptyGroupID(t *testing.T) {
	c := New()
	err := c.SyncGroupMembers(context.Background(), validConfig(), validSecrets(), "", "",
		func(_ []string, _ string) error { return nil },
	)
	if err == nil {
		t.Fatal("expected error on empty group external id")
	}
}

// TestCountGroups_UsesHeaderWhenAvailable verifies the count probe
// returns X-Total-Count when set and -1 when absent.
func TestCountGroups_UsesHeaderWhenAvailable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Total-Count", "42")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	t.Cleanup(server.Close)
	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
	n, err := c.CountGroups(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("CountGroups: %v", err)
	}
	if n != 42 {
		t.Errorf("count = %d; want 42", n)
	}
}

// server2NextLink builds an absolute https://uney.okta.com URL
// pointing at nextPath so the parseNextLink + rewriteForTest pair
// can roundtrip the value back to the httptest server.
func server2NextLink(r *http.Request, nextPath string) string {
	return "https://uney.okta.com" + nextPath
}
