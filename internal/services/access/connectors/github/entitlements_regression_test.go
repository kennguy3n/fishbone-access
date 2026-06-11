package github

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Regression: a malformed teams page must surface as an error. Previously the
// loop did `if json.Unmarshal(...) != nil { break }`, silently truncating the
// entitlement set and returning success — an access-control system must never
// under-report entitlements on a decode failure.
func TestListEntitlements_MalformedTeamsPageErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/memberships/alice") && !strings.Contains(r.URL.Path, "/teams/"):
			_, _ = w.Write([]byte(`{"role":"admin","state":"active"}`))
		case strings.HasSuffix(r.URL.Path, "/teams"):
			_, _ = w.Write([]byte(`[{"slug":"backend"`)) // truncated JSON
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	got, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "alice")
	if err == nil {
		t.Fatalf("expected decode error, got nil (entitlements=%v)", got)
	}
	if !strings.Contains(err.Error(), "decode teams") {
		t.Fatalf("err = %v; want a teams decode error", err)
	}
}

// Regression: a non-404 failure while listing teams must propagate, not be
// swallowed into a silently-truncated (successful) result.
func TestListEntitlements_TeamsServerErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/memberships/alice") && !strings.Contains(r.URL.Path, "/teams/"):
			_, _ = w.Write([]byte(`{"role":"admin","state":"active"}`))
		case strings.HasSuffix(r.URL.Path, "/teams"):
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	if _, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "alice"); err == nil {
		t.Fatal("expected error on teams HTTP 500, got nil")
	}
}

// A non-404 failure while probing a specific team's membership must likewise
// propagate rather than silently omitting that team.
func TestListEntitlements_TeamMembershipErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/teams/backend/memberships/alice"):
			w.WriteHeader(http.StatusInternalServerError)
		case strings.Contains(r.URL.Path, "/memberships/alice") && !strings.Contains(r.URL.Path, "/teams/"):
			_, _ = w.Write([]byte(`{"role":"admin","state":"active"}`))
		case strings.HasSuffix(r.URL.Path, "/teams"):
			_, _ = w.Write([]byte(`[{"slug":"backend"}]`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	if _, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "alice"); err == nil {
		t.Fatal("expected error on team membership HTTP 500, got nil")
	}
}
