package okta

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

type noNetworkRoundTripper struct{}

func (noNetworkRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return nil, errors.New("network call attempted from a no-network test path")
}

func validConfig() map[string]interface{} {
	return map[string]interface{}{"okta_domain": "uney.okta.com"}
}

func validSecrets() map[string]interface{} {
	return map[string]interface{}{"api_token": "00abcdef"}
}

func TestValidate_HappyPath(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_AcceptsCommonOktaTLDs(t *testing.T) {
	c := New()
	cases := []string{
		"foo.okta.com",
		"https://foo.okta.com",
		"https://bar.oktapreview.com/",
		"baz.okta-emea.com",
	}
	for _, d := range cases {
		t.Run(d, func(t *testing.T) {
			cfg := map[string]interface{}{"okta_domain": d}
			if err := c.Validate(context.Background(), cfg, validSecrets()); err != nil {
				t.Fatalf("Validate(%q): %v", d, err)
			}
		})
	}
}

func TestValidate_RejectsMissingFieldsAndBadDomain(t *testing.T) {
	c := New()
	cases := []struct {
		name    string
		cfg     map[string]interface{}
		secrets map[string]interface{}
	}{
		{"missing domain", map[string]interface{}{}, validSecrets()},
		{"bad domain", map[string]interface{}{"okta_domain": "evil.example.com"}, validSecrets()},
		{"missing token", validConfig(), map[string]interface{}{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := c.Validate(context.Background(), tc.cfg, tc.secrets); err == nil {
				t.Fatalf("Validate(%s) expected error", tc.name)
			}
		})
	}
}

func TestValidate_DoesNotMakeNetworkCalls(t *testing.T) {
	prev := http.DefaultTransport
	http.DefaultTransport = noNetworkRoundTripper{}
	t.Cleanup(func() { http.DefaultTransport = prev })

	c := New()
	if err := c.Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestRegistryIntegration(t *testing.T) {
	got, err := access.GetAccessConnector(ProviderName)
	if err != nil {
		t.Fatalf("GetAccessConnector(%q): %v", ProviderName, err)
	}
	if _, ok := got.(*OktaAccessConnector); !ok {
		t.Fatalf("registered type = %T, want *OktaAccessConnector", got)
	}
}

func TestProvisionAccess_AssignsAppUser(t *testing.T) {
	cases := []struct {
		name   string
		status int
	}{
		{"created", http.StatusOK},
		{"conflict_idempotent", http.StatusConflict},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var seenMethod, seenPath string
			var seenBody []byte
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seenMethod, seenPath = r.Method, r.URL.Path
				body := make([]byte, r.ContentLength)
				_, _ = r.Body.Read(body)
				seenBody = body
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(`{}`))
			}))
			t.Cleanup(server.Close)

			c := New()
			c.urlOverride = server.URL
			c.httpClient = func() httpDoer { return server.Client() }

			err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
				UserExternalID:     "u-1",
				ResourceExternalID: "app-1",
				Role:               "Admin",
			})
			if err != nil {
				t.Fatalf("ProvisionAccess: %v", err)
			}
			if seenMethod != http.MethodPost {
				t.Fatalf("method = %q, want POST", seenMethod)
			}
			if seenPath != "/api/v1/apps/app-1/users" {
				t.Fatalf("path = %q", seenPath)
			}
			var body oktaAppUserAssignment
			if err := json.Unmarshal(seenBody, &body); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if body.ID != "u-1" || body.Profile["role"] != "Admin" {
				t.Fatalf("body = %+v", body)
			}
		})
	}
}

func TestProvisionAccess_4xxFailsPermanently(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "u-1", ResourceExternalID: "app-1", Role: "Admin",
	})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected 403 error, got %v", err)
	}
}

func TestRevokeAccess_DeletesAppUser(t *testing.T) {
	cases := []struct {
		name   string
		status int
	}{
		{"deleted", http.StatusNoContent},
		{"not_found_idempotent", http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var seenMethod, seenPath string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seenMethod, seenPath = r.Method, r.URL.Path
				w.WriteHeader(tc.status)
			}))
			t.Cleanup(server.Close)

			c := New()
			c.urlOverride = server.URL
			c.httpClient = func() httpDoer { return server.Client() }
			err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
				UserExternalID: "u-1", ResourceExternalID: "app-1", Role: "Admin",
			})
			if err != nil {
				t.Fatalf("RevokeAccess: %v", err)
			}
			if seenMethod != http.MethodDelete {
				t.Fatalf("method = %q, want DELETE", seenMethod)
			}
			if seenPath != "/api/v1/apps/app-1/users/u-1" {
				t.Fatalf("path = %q", seenPath)
			}
		})
	}
}

func TestRevokeAccess_4xxFailsPermanently(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
	err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "u-1", ResourceExternalID: "app-1", Role: "Admin",
	})
	if err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("expected 400 error, got %v", err)
	}
}

func TestListEntitlements_PagesAppLinks(t *testing.T) {
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if !strings.HasPrefix(r.URL.Path, "/api/v1/users/u-1/appLinks") {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if r.URL.Query().Get("after") == "" {
			w.Header().Set("Link", `<https://uney.okta.com/api/v1/users/u-1/appLinks?after=p2>; rel="next"`)
			_ = json.NewEncoder(w).Encode([]oktaAppLink{{AppInstanceID: "app-1", AppName: "Salesforce", Label: "Salesforce Prod"}})
			return
		}
		_ = json.NewEncoder(w).Encode([]oktaAppLink{{AppInstanceID: "app-2", AppName: "Slack", Label: "Slack"}})
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
	got, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "u-1")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if hits != 2 {
		t.Fatalf("expected 2 page requests, got %d", hits)
	}
	if len(got) != 2 || got[0].ResourceExternalID != "app-1" || got[1].ResourceExternalID != "app-2" {
		t.Fatalf("got = %+v", got)
	}
	if got[0].Role != "Salesforce Prod" || got[0].Source != "direct" {
		t.Fatalf("entitlement[0] = %+v", got[0])
	}
}

func TestListEntitlements_4xxReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
	if _, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "u-1"); err == nil {
		t.Fatal("expected error on 401")
	}
}

func TestGetSSOMetadata(t *testing.T) {
	c := New()
	md, err := c.GetSSOMetadata(context.Background(), validConfig(), nil)
	if err != nil {
		t.Fatalf("GetSSOMetadata: %v", err)
	}
	if md.Protocol != "oidc" {
		t.Fatalf("Protocol = %q", md.Protocol)
	}
	if !strings.Contains(md.MetadataURL, "uney.okta.com") {
		t.Fatalf("MetadataURL = %q", md.MetadataURL)
	}
}

func TestParseNextLink(t *testing.T) {
	header := `<https://uney.okta.com/api/v1/users?after=abc>; rel="next", <https://uney.okta.com/api/v1/users>; rel="self"`
	got := parseNextLink(header)
	if got != "https://uney.okta.com/api/v1/users?after=abc" {
		t.Fatalf("parseNextLink = %q", got)
	}
	if parseNextLink("") != "" {
		t.Fatal("parseNextLink with empty should be empty")
	}
}

func TestSyncIdentities_PaginatesAndMaps(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("after") == "" {
			w.Header().Set("Link", `<https://uney.okta.com/api/v1/users?after=p2>; rel="next"`)
			users := []oktaUser{
				{
					ID:     "u1",
					Status: "ACTIVE",
					Profile: struct {
						Login     string `json:"login"`
						Email     string `json:"email"`
						FirstName string `json:"firstName"`
						LastName  string `json:"lastName"`
					}{Login: "alice@example.com", Email: "alice@example.com", FirstName: "Alice"},
				},
			}
			_ = json.NewEncoder(w).Encode(users)
			return
		}
		users := []oktaUser{
			{
				ID:     "u2",
				Status: "DEPROVISIONED",
				Profile: struct {
					Login     string `json:"login"`
					Email     string `json:"email"`
					FirstName string `json:"firstName"`
					LastName  string `json:"lastName"`
				}{Login: "bob@example.com", Email: "bob@example.com", LastName: "Bob"},
			},
		}
		_ = json.NewEncoder(w).Encode(users)
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }

	var collected []*access.Identity
	if err := c.SyncIdentities(context.Background(), validConfig(), validSecrets(), "", func(batch []*access.Identity, _ string) error {
		collected = append(collected, batch...)
		return nil
	}); err != nil {
		t.Fatalf("SyncIdentities: %v", err)
	}
	if len(collected) != 2 {
		t.Fatalf("collected %d, want 2", len(collected))
	}
	if collected[0].Email != "alice@example.com" {
		t.Fatalf("first = %+v", collected[0])
	}
	if collected[1].Status != "deprovisioned" {
		t.Fatalf("second status = %q", collected[1].Status)
	}
}

func TestSyncIdentitiesDelta_410ReturnsErrDeltaTokenExpired(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusGone)
		_, _ = w.Write([]byte(`{"errorCode":"E0000031"}`))
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }

	_, err := c.SyncIdentitiesDelta(context.Background(), validConfig(), validSecrets(), server.URL+"/api/v1/logs?since=stale", func(_ []*access.Identity, _ []string, _ string) error {
		return nil
	})
	if !errors.Is(err, access.ErrDeltaTokenExpired) {
		t.Fatalf("got %v, want ErrDeltaTokenExpired", err)
	}
}

func TestSyncIdentitiesDelta_400WithExpiredCursor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"errorCode":"E0000031","errorSummary":"since cursor expired"}`))
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }

	_, err := c.SyncIdentitiesDelta(context.Background(), validConfig(), validSecrets(), server.URL+"/api/v1/logs?since=stale", func(_ []*access.Identity, _ []string, _ string) error {
		return nil
	})
	if !errors.Is(err, access.ErrDeltaTokenExpired) {
		t.Fatalf("got %v, want ErrDeltaTokenExpired", err)
	}
}

func TestOkta_InitialDeltaCursor_BuildsValidLogsURL(t *testing.T) {
	c := New()
	cursor, err := c.InitialDeltaCursor(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("InitialDeltaCursor: %v", err)
	}
	if !strings.HasPrefix(cursor, "https://uney.okta.com/api/v1/logs?since=") {
		t.Errorf("seeded cursor %q missing logs URL prefix", cursor)
	}
	u, perr := url.Parse(cursor)
	if perr != nil {
		t.Fatalf("seeded cursor %q is not a valid URL: %v", cursor, perr)
	}
	since := u.Query().Get("since")
	parsed, terr := time.Parse(time.RFC3339, since)
	if terr != nil {
		t.Fatalf("since %q failed RFC3339 parse: %v", since, terr)
	}
	if time.Since(parsed) > 5*time.Second {
		t.Errorf("seeded since %q is more than 5s in the past", since)
	}
	if _, rerr := http.NewRequest(http.MethodGet, cursor, nil); rerr != nil {
		t.Errorf("http.NewRequest(seed) failed: %v", rerr)
	}
}
