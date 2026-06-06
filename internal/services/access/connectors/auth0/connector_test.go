package auth0

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

type noNetworkRoundTripper struct{}

func (noNetworkRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return nil, errors.New("network call attempted from a no-network test path")
}

func validConfig() map[string]interface{} {
	return map[string]interface{}{"domain": "uney.us.auth0.com"}
}

func validSecrets() map[string]interface{} {
	return map[string]interface{}{
		"client_id":     "abc",
		"client_secret": "shh",
	}
}

func TestValidate_HappyPath(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_MissingFields(t *testing.T) {
	c := New()
	cases := []struct {
		name    string
		cfg     map[string]interface{}
		secrets map[string]interface{}
	}{
		{"missing domain", map[string]interface{}{}, validSecrets()},
		{"bad domain", map[string]interface{}{"domain": "evil.example.com"}, validSecrets()},
		{"missing client_id", validConfig(), map[string]interface{}{"client_secret": "shh"}},
		{"missing client_secret", validConfig(), map[string]interface{}{"client_id": "abc"}},
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
	if _, ok := got.(*Auth0AccessConnector); !ok {
		t.Fatalf("registered type = %T, want *Auth0AccessConnector", got)
	}
}

func TestProvisionAccess_AssignsRole(t *testing.T) {
	cases := []struct {
		name   string
		status int
	}{
		{"created", http.StatusNoContent},
		{"conflict_idempotent", http.StatusConflict},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var seenMethod, seenPath string
			var seenBody []byte
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/oauth/token":
					_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
				default:
					seenMethod, seenPath = r.Method, r.URL.Path
					seenBody, _ = io.ReadAll(r.Body)
					w.WriteHeader(tc.status)
				}
			}))
			t.Cleanup(server.Close)

			c := New()
			c.urlOverride = server.URL
			c.httpClient = func() httpDoer { return server.Client() }
			err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
				UserExternalID:     "auth0|user-1",
				ResourceExternalID: "rol_admin",
			})
			if err != nil {
				t.Fatalf("ProvisionAccess: %v", err)
			}
			if seenMethod != http.MethodPost {
				t.Fatalf("method = %q", seenMethod)
			}
			if seenPath != "/api/v2/users/auth0|user-1/roles" {
				t.Fatalf("path = %q", seenPath)
			}
			var body struct {
				Roles []string `json:"roles"`
			}
			if err := json.Unmarshal(seenBody, &body); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if len(body.Roles) != 1 || body.Roles[0] != "rol_admin" {
				t.Fatalf("body roles = %+v", body.Roles)
			}
		})
	}
}

func TestProvisionAccess_4xxFailsPermanently(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "auth0|user-1", ResourceExternalID: "rol_admin",
	})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected 403 error, got %v", err)
	}
}

func TestRevokeAccess_RemovesRole(t *testing.T) {
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
				switch r.URL.Path {
				case "/oauth/token":
					_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
				default:
					seenMethod, seenPath = r.Method, r.URL.Path
					w.WriteHeader(tc.status)
				}
			}))
			t.Cleanup(server.Close)

			c := New()
			c.urlOverride = server.URL
			c.httpClient = func() httpDoer { return server.Client() }
			err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
				UserExternalID: "auth0|user-1", ResourceExternalID: "rol_admin",
			})
			if err != nil {
				t.Fatalf("RevokeAccess: %v", err)
			}
			if seenMethod != http.MethodDelete {
				t.Fatalf("method = %q", seenMethod)
			}
			if seenPath != "/api/v2/users/auth0|user-1/roles" {
				t.Fatalf("path = %q", seenPath)
			}
		})
	}
}

func TestRevokeAccess_4xxFailsPermanently(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
	err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "auth0|user-1", ResourceExternalID: "rol_admin",
	})
	if err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("expected 400 error, got %v", err)
	}
}

func TestListEntitlements_PagesRoles(t *testing.T) {
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
		default:
			hits++
			page := r.URL.Query().Get("page")
			if page == "0" {
				roles := make([]auth0Role, 100)
				for i := range roles {
					roles[i] = auth0Role{ID: "rol_a" + intToStr(i), Name: "RoleA" + intToStr(i)}
				}
				_ = json.NewEncoder(w).Encode(roles)
				return
			}
			_ = json.NewEncoder(w).Encode([]auth0Role{{ID: "rol_b1", Name: "RoleB1"}})
		}
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
	got, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "auth0|user-1")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if hits != 2 {
		t.Fatalf("hits = %d, want 2", hits)
	}
	if len(got) != 101 {
		t.Fatalf("len = %d, want 101", len(got))
	}
	if got[0].ResourceExternalID != "rol_a0" || got[0].Source != "direct" {
		t.Fatalf("got[0] = %+v", got[0])
	}
}

func TestListEntitlements_4xxReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
	if _, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "auth0|user-1"); err == nil {
		t.Fatal("expected error on 401")
	}
}

func intToStr(i int) string { return strconv.Itoa(i) }

func TestGetSSOMetadata(t *testing.T) {
	c := New()
	md, err := c.GetSSOMetadata(context.Background(), validConfig(), nil)
	if err != nil {
		t.Fatalf("GetSSOMetadata: %v", err)
	}
	if md.Protocol != "oidc" {
		t.Fatalf("Protocol = %q", md.Protocol)
	}
	if !strings.Contains(md.MetadataURL, "uney.us.auth0.com") {
		t.Fatalf("MetadataURL = %q", md.MetadataURL)
	}
	if !strings.HasSuffix(md.MetadataURL, "/.well-known/openid-configuration") {
		t.Fatalf("MetadataURL suffix = %q", md.MetadataURL)
	}
}

func TestGetCredentialsMetadata(t *testing.T) {
	c := New()
	md, err := c.GetCredentialsMetadata(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("GetCredentialsMetadata: %v", err)
	}
	if md["provider"] != ProviderName {
		t.Fatalf("provider = %v", md["provider"])
	}
	if md["client_id"] != "abc" {
		t.Fatalf("client_id = %v", md["client_id"])
	}
}

func TestSyncIdentities_PaginatesAndMaps(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"access_token": "tok",
				"token_type":   "Bearer",
			})
		case "/api/v2/users":
			page := r.URL.Query().Get("page")
			perPage := r.URL.Query().Get("per_page")
			if perPage != "100" {
				t.Errorf("per_page = %q, want 100", perPage)
			}
			if page == "0" {
				users := make([]auth0User, 100)
				for i := 0; i < 100; i++ {
					users[i] = auth0User{
						UserID: "auth0|p0u" + string(rune('a'+i%26)),
						Email:  "u@example.com",
						Name:   "First Last",
					}
				}
				_ = json.NewEncoder(w).Encode(users)
				return
			}
			users := []auth0User{
				{UserID: "auth0|p1u1", Email: "alice@example.com", Name: "Alice"},
				{UserID: "auth0|p1u2", Email: "bob@example.com", Name: "Bob", Blocked: true},
			}
			_ = json.NewEncoder(w).Encode(users)
		default:
			http.NotFound(w, r)
		}
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
	if len(collected) != 102 {
		t.Fatalf("collected %d, want 102", len(collected))
	}
	last := collected[len(collected)-1]
	if last.Email != "bob@example.com" {
		t.Fatalf("last email = %q", last.Email)
	}
	if last.Status != "disabled" {
		t.Fatalf("last status = %q", last.Status)
	}
}

func TestCountIdentities_ReadsTotal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
		case "/api/v2/users":
			if r.URL.Query().Get("include_totals") != "true" {
				t.Errorf("include_totals not set")
			}
			_, _ = w.Write([]byte(`{"total":42,"users":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }

	n, err := c.CountIdentities(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("CountIdentities: %v", err)
	}
	if n != 42 {
		t.Fatalf("CountIdentities = %d, want 42", n)
	}
}

func TestConnect_TokenFailureReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"access_denied"}`))
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }

	if err := c.Connect(context.Background(), validConfig(), validSecrets()); err == nil {
		t.Fatalf("Connect expected error on 401")
	}
}

func TestSyncIdentitiesDelta_ExpiredCursor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
		case "/api/v2/logs":
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"statusCode":400,"error":"Bad Request","message":"log_id is invalid or expired"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }

	_, err := c.SyncIdentitiesDelta(context.Background(), validConfig(), validSecrets(), "stale-id", func(_ []*access.Identity, _ []string, _ string) error {
		return nil
	})
	if !errors.Is(err, access.ErrDeltaTokenExpired) {
		t.Fatalf("got %v, want ErrDeltaTokenExpired", err)
	}
}

func TestVerifyPermissions_UnknownCapabilityReportedMissing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
		case "/api/v2/users":
			_, _ = w.Write([]byte(`[]`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }

	missing, err := c.VerifyPermissions(context.Background(), validConfig(), validSecrets(), []string{"sync_identity", "list_entitlements"})
	if err != nil {
		t.Fatalf("VerifyPermissions: %v", err)
	}
	if len(missing) != 1 || !strings.HasPrefix(missing[0], "list_entitlements") {
		t.Fatalf("missing = %v", missing)
	}
}

func TestAuth0_InitialDeltaCursor_CapturesMostRecentLogID(t *testing.T) {
	var seenLogQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
		case "/api/v2/logs":
			seenLogQuery = r.URL.RawQuery
			_, _ = w.Write([]byte(`[{"log_id":"log-baseline-12345","date":"2025-01-01T00:00:00.000Z","type":"ss"}]`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }

	cursor, err := c.InitialDeltaCursor(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("InitialDeltaCursor: %v", err)
	}
	if cursor != "log-baseline-12345" {
		t.Errorf("captured log_id = %q; want log-baseline-12345", cursor)
	}
	if !strings.Contains(seenLogQuery, "take=1") || !strings.Contains(seenLogQuery, "sort=date") {
		t.Errorf("probe query = %q; want take=1 & sort=date:-1 (minimal-bandwidth probe)", seenLogQuery)
	}
}

func TestAuth0_InitialDeltaCursor_EmptyLogsReturnsEmptyCursor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
		case "/api/v2/logs":
			_, _ = w.Write([]byte(`[]`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }

	cursor, err := c.InitialDeltaCursor(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("InitialDeltaCursor: %v", err)
	}
	if cursor != "" {
		t.Errorf("cursor = %q; want empty (no logs → no baseline)", cursor)
	}
}
