package auth0

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCheckSSOEnforcement_Enforced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
		default:
			_, _ = w.Write([]byte(`[{"name":"corp-saml","strategy":"samlp"},{"name":"okta","strategy":"okta"}]`))
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	enforced, details, err := c.CheckSSOEnforcement(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	if !enforced {
		t.Errorf("enforced=false; want true (details=%q)", details)
	}
}

func TestCheckSSOEnforcement_NotEnforced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
		default:
			_, _ = w.Write([]byte(`[{"name":"corp-saml","strategy":"samlp"},{"name":"Username-Password","strategy":"auth0"}]`))
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	enforced, details, err := c.CheckSSOEnforcement(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	if enforced {
		t.Errorf("enforced=true; want false (details=%q)", details)
	}
	if details == "" {
		t.Error("details=\"\"; want a reason")
	}
}

// TestCheckSSOEnforcement_EnabledClientsArrayFixture is the
// Regression guard: real Auth0 tenants return the `enabled_clients`
// field on every connection as a JSON array of client-ID strings (not a
// bool). A previous revision of the probe declared the field as `*bool`,
// which caused json.Decoder.Decode to raise json.UnmarshalTypeError and the
// caller to map every Auth0 tenant to "unknown" sso-enforcement. This test
// exercises the realistic shape end-to-end so the bug cannot reappear.
func TestCheckSSOEnforcement_EnabledClientsArrayFixture(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
		default:
			// Mirror the real Auth0 GET /api/v2/connections payload:
			// every connection carries an `enabled_clients` array of
			// client-ID strings, plus assorted metadata fields the
			// probe deliberately ignores.
			_, _ = w.Write([]byte(`[
				{
					"id": "con_1",
					"name": "corp-saml",
					"strategy": "samlp",
					"enabled_clients": ["clientA", "clientB", "clientC"],
					"realms": ["corp-saml"],
					"is_domain_connection": false
				},
				{
					"id": "con_2",
					"name": "okta-prod",
					"strategy": "okta",
					"enabled_clients": ["clientA"],
					"realms": ["okta-prod"],
					"is_domain_connection": false
				}
			]`))
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	enforced, details, err := c.CheckSSOEnforcement(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("CheckSSOEnforcement decoded the realistic Auth0 fixture with an unexpected error: %v", err)
	}
	if !enforced {
		t.Errorf("enforced=false; want true on enterprise-only fixture (details=%q)", details)
	}
}

// TestCheckSSOEnforcement_PaginationHidesPasswordConnectionOnPageOne is the
// Regression guard for the bug where the probe only
// fetched the first 100 connections — a real Auth0 tenant with >100
// connections could hide a `Username-Password-Authentication` connection
// beyond page 0 and the probe would produce a false-positive "SSO
// enforced" verdict. The fix loops `?page=N&per_page=100` until the API
// returns a short page. This test serves a deterministic two-page fixture:
//   - page=0 is exactly 100 enterprise (samlp) connections, so the old
//     single-page probe would short-circuit and report enforced=true.
//   - page=1 contains a single auth0 (password) connection, which only the
//     loop will see.
//
// The assertion is enforced=false plus a details string naming the
// password connection — if the loop is broken, this test catches the
// regression immediately.
func TestCheckSSOEnforcement_PaginationHidesPasswordConnectionOnPageOne(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
			return
		}
		// Decide which page the client asked for so the response
		// matches the Auth0 v2 contract (page=N&per_page=100).
		page := r.URL.Query().Get("page")
		switch page {
		case "0":
			// Emit exactly 100 enterprise connections so a
			// single-page probe would short-circuit here and
			// report enforced=true.
			items := make([]string, 0, 100)
			for i := 0; i < 100; i++ {
				items = append(items, fmt.Sprintf(`{"name":"corp-saml-%d","strategy":"samlp"}`, i))
			}
			_, _ = w.Write([]byte("[" + strings.Join(items, ",") + "]"))
		case "1":
			// Page 1 carries the smoking gun: a password
			// connection only the paginated probe will see.
			_, _ = w.Write([]byte(`[{"name":"Username-Password-Authentication","strategy":"auth0"}]`))
		default:
			// Defensive: emit an empty page so a runaway probe
			// terminates rather than 500ing the test harness.
			_, _ = w.Write([]byte(`[]`))
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	enforced, details, err := c.CheckSSOEnforcement(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	if enforced {
		t.Errorf("enforced=true; want false (a password connection on page=1 must trigger not-enforced)")
	}
	if !strings.Contains(details, "Username-Password-Authentication") {
		t.Errorf("details = %q; want substring %q (proof the page=1 password connection reached the probe)",
			details, "Username-Password-Authentication")
	}
}

// TestCheckSSOEnforcement_PaginationStopsOnShortPage asserts the probe
// stops calling the API once the upstream returns a page with fewer
// than per_page records. Without this guard the loop would either
// run forever (no termination signal) or perform a wasted final
// request against a tenant that has zero remaining pages. The test
// counts the number of page requests the upstream served and asserts
// exactly two: page=0 (full) + page=1 (short, terminates the loop).
func TestCheckSSOEnforcement_PaginationStopsOnShortPage(t *testing.T) {
	var pageRequests []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
			return
		}
		page := r.URL.Query().Get("page")
		pageRequests = append(pageRequests, page)
		switch page {
		case "0":
			items := make([]string, 0, 100)
			for i := 0; i < 100; i++ {
				items = append(items, fmt.Sprintf(`{"name":"corp-saml-%d","strategy":"samlp"}`, i))
			}
			_, _ = w.Write([]byte("[" + strings.Join(items, ",") + "]"))
		case "1":
			// Short page (1 record < per_page=100) → loop should
			// terminate after this response.
			_, _ = w.Write([]byte(`[{"name":"okta-prod","strategy":"okta"}]`))
		default:
			t.Errorf("upstream received unexpected page=%q; loop should have terminated after the short page=1", page)
			_, _ = w.Write([]byte(`[]`))
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	enforced, details, err := c.CheckSSOEnforcement(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	if !enforced {
		t.Errorf("enforced=false; want true on enterprise-only multi-page fixture (details=%q)", details)
	}
	if len(pageRequests) != 2 {
		t.Errorf("upstream saw %d page requests (%v); want exactly 2 (page=0 full, page=1 short, then stop)",
			len(pageRequests), pageRequests)
	}
}

func TestCheckSSOEnforcement_HTTPFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if _, _, err := c.CheckSSOEnforcement(context.Background(), validConfig(), validSecrets()); err == nil {
		t.Fatal("err=nil; want non-nil on 403")
	}
}
