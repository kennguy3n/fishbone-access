package travis_ci

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

type noNetworkRoundTripper struct{}

func (noNetworkRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return nil, errors.New("network call attempted")
}

func validConfig() map[string]interface{} { return map[string]interface{}{} }
func validSecrets() map[string]interface{} {
	return map[string]interface{}{"token": "trvsAAAA1234bbbbCCCC"}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_RejectsMissing(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), validConfig(), map[string]interface{}{}); err == nil {
		t.Error("missing token")
	}
}

func TestValidate_PureLocal(t *testing.T) {
	prev := http.DefaultTransport
	http.DefaultTransport = noNetworkRoundTripper{}
	t.Cleanup(func() { http.DefaultTransport = prev })
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestRegistryIntegration(t *testing.T) {
	if got, _ := access.GetAccessConnector(ProviderName); got == nil {
		t.Fatal("not registered")
	}
}

func TestSync_PaginatesUsers(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if !strings.HasPrefix(r.Header.Get("Authorization"), "token ") {
			t.Errorf("expected token auth")
		}
		if r.URL.Path != "/users" {
			t.Errorf("path = %q", r.URL.Path)
		}
		offset := r.URL.Query().Get("offset")
		if calls == 1 && offset != "0" {
			t.Errorf("offset = %q", offset)
		}
		if calls == 2 && offset != fmt.Sprintf("%d", pageSize) {
			t.Errorf("offset = %q", offset)
		}
		body := map[string]interface{}{"@pagination": map[string]interface{}{"limit": pageSize, "offset": 0, "count": pageSize + 1}}
		if calls == 1 {
			items := make([]map[string]interface{}, 0, pageSize)
			for i := 0; i < pageSize; i++ {
				items = append(items, map[string]interface{}{"id": i + 1, "login": fmt.Sprintf("u%d", i+1), "name": "User", "email": fmt.Sprintf("u%d@x.com", i+1)})
			}
			body["users"] = items
		} else {
			body["users"] = []map[string]interface{}{{"id": 999, "login": "blocked", "name": "Last", "email": "last@x.com", "is_blocked": true}}
		}
		b, _ := json.Marshal(body)
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var got []*access.Identity
	err := c.SyncIdentities(context.Background(), validConfig(), validSecrets(), "", func(b []*access.Identity, _ string) error {
		got = append(got, b...)
		return nil
	})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(got) != pageSize+1 {
		t.Fatalf("len = %d", len(got))
	}
	if calls != 2 {
		t.Fatalf("calls = %d", calls)
	}
	if got[len(got)-1].Status != "blocked" {
		t.Errorf("status = %q", got[len(got)-1].Status)
	}
}

func TestConnect_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.Connect(context.Background(), validConfig(), validSecrets()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("Connect err = %v; want 401", err)
	}
}

func TestValidate_RejectsBadEndpoint(t *testing.T) {
	c := New()
	bad := map[string]string{
		"http scheme":      "http://api.travis-ci.com",
		"empty scheme":     "api.travis-ci.com",
		"file scheme":      "file:///etc/passwd",
		"ip literal":       "https://169.254.169.254",
		"v6 ip literal":    "https://[::1]",
		"with userinfo":    "https://attacker@api.travis-ci.com",
		"with path":        "https://api.travis-ci.com/internal",
		"with query":       "https://api.travis-ci.com?x=1",
		"with fragment":    "https://api.travis-ci.com#frag",
		"hyphen leading":   "https://-api.travis-ci.com",
		"underscore label": "https://bad_label.travis-ci.com",
		"empty host":       "https://",
		"unparseable":      "https://%zz",
	}
	for name, ep := range bad {
		t.Run(name, func(t *testing.T) {
			err := c.Validate(context.Background(), map[string]interface{}{"endpoint": ep}, validSecrets())
			if err == nil {
				t.Errorf("expected error for endpoint %q", ep)
			}
		})
	}
}

func TestValidate_AcceptsKnownEndpoints(t *testing.T) {
	c := New()
	for _, ep := range []string{
		"https://api.travis-ci.com",
		"https://api.travis-ci.com/",
		"https://api.travis-ci.org",
		"https://travis.enterprise.example",
	} {
		if err := c.Validate(context.Background(), map[string]interface{}{"endpoint": ep}, validSecrets()); err != nil {
			t.Errorf("Validate(%q): %v", ep, err)
		}
	}
}

func TestGetCredentialsMetadata_RedactsToken(t *testing.T) {
	md, err := New().GetCredentialsMetadata(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	short, _ := md["token_short"].(string)
	if short == "" || strings.Contains(short, "AAAA1234") {
		t.Errorf("token_short = %q", short)
	}
}

// TestListEntitlements_PaginatesAllPages verifies ListEntitlements walks every
// page of the user's active repos rather than only the first. With a user
// owning more than pageSize repos, fetching only offset=0 would silently
// truncate the entitlement set.
func TestListEntitlements_PaginatesAllPages(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if !strings.HasPrefix(r.URL.Path, "/user/") || !strings.HasSuffix(r.URL.Path, "/repos") {
			t.Errorf("path = %q", r.URL.Path)
		}
		offset := r.URL.Query().Get("offset")
		switch calls {
		case 1:
			if offset != "0" {
				t.Errorf("page1 offset = %q; want 0", offset)
			}
		case 2:
			if offset != fmt.Sprintf("%d", pageSize) {
				t.Errorf("page2 offset = %q; want %d", offset, pageSize)
			}
		default:
			t.Fatalf("unexpected request #%d", calls)
		}
		body := map[string]interface{}{"@pagination": map[string]interface{}{"limit": pageSize, "offset": 0, "count": pageSize + 1}}
		if calls == 1 {
			items := make([]map[string]interface{}, 0, pageSize)
			for i := 0; i < pageSize; i++ {
				items = append(items, map[string]interface{}{"id": i + 1, "slug": fmt.Sprintf("acme/r%d", i+1), "active": true})
			}
			body["repositories"] = items
		} else {
			body["repositories"] = []map[string]interface{}{{"id": 999, "slug": "acme/last", "active": true}}
		}
		b, _ := json.Marshal(body)
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	ents, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "user-1")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected 2 round trips, got %d", calls)
	}
	if len(ents) != pageSize+1 {
		t.Fatalf("len = %d; want %d (pagination truncated)", len(ents), pageSize+1)
	}
	if ents[len(ents)-1].ResourceExternalID != "999" {
		t.Errorf("last entitlement = %q; want 999", ents[len(ents)-1].ResourceExternalID)
	}
}
