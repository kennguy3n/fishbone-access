package ping_identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const testEnvID = "f0e1d2c3-b4a5-6789-abcd-ef0123456789"

type noNetworkRoundTripper struct{}

func (noNetworkRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return nil, errors.New("network call attempted from a no-network test path")
}

func validConfig() map[string]interface{} {
	return map[string]interface{}{
		"environment_id": testEnvID,
		"region":         "NA",
	}
}

func validSecrets() map[string]interface{} {
	return map[string]interface{}{
		"client_id":     "worker-id",
		"client_secret": "worker-secret",
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
		{"missing env", map[string]interface{}{"region": "NA"}, validSecrets()},
		{"missing region", map[string]interface{}{"environment_id": testEnvID}, validSecrets()},
		{"bad region", map[string]interface{}{"environment_id": testEnvID, "region": "MARS"}, validSecrets()},
		{"missing client_id", validConfig(), map[string]interface{}{"client_secret": "y"}},
		{"missing client_secret", validConfig(), map[string]interface{}{"client_id": "x"}},
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
	if _, ok := got.(*PingIdentityAccessConnector); !ok {
		t.Fatalf("registered type = %T, want *PingIdentityAccessConnector", got)
	}
}

func TestProvisionAccess_AddsGroupMembership(t *testing.T) {
	cases := []struct {
		name   string
		status int
	}{
		{"created", http.StatusCreated},
		{"conflict_idempotent", http.StatusConflict},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var seenMethod, seenPath string
			var seenBody []byte
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/as/token") {
					_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
					return
				}
				seenMethod, seenPath = r.Method, r.URL.Path
				seenBody, _ = io.ReadAll(r.Body)
				w.WriteHeader(tc.status)
			}))
			t.Cleanup(server.Close)

			c := New()
			c.urlOverride = server.URL
			c.httpClient = func() httpDoer { return server.Client() }
			err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
				UserExternalID: "user-1", ResourceExternalID: "group-1",
			})
			if err != nil {
				t.Fatalf("ProvisionAccess: %v", err)
			}
			if seenMethod != http.MethodPost {
				t.Fatalf("method = %q", seenMethod)
			}
			wantPath := "/v1/environments/" + testEnvID + "/users/user-1/groupMemberships"
			if seenPath != wantPath {
				t.Fatalf("path = %q, want %q", seenPath, wantPath)
			}
			var body map[string]string
			if err := json.Unmarshal(seenBody, &body); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if body["id"] != "group-1" {
				t.Fatalf("body id = %q", body["id"])
			}
		})
	}
}

func TestProvisionAccess_4xxFailsPermanently(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/as/token") {
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "user-1", ResourceExternalID: "group-1",
	})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected 403, got %v", err)
	}
}

func TestRevokeAccess_DeletesGroupMembership(t *testing.T) {
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
				if strings.HasSuffix(r.URL.Path, "/as/token") {
					_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
					return
				}
				seenMethod, seenPath = r.Method, r.URL.Path
				w.WriteHeader(tc.status)
			}))
			t.Cleanup(server.Close)

			c := New()
			c.urlOverride = server.URL
			c.httpClient = func() httpDoer { return server.Client() }
			err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
				UserExternalID: "user-1", ResourceExternalID: "group-1",
			})
			if err != nil {
				t.Fatalf("RevokeAccess: %v", err)
			}
			if seenMethod != http.MethodDelete {
				t.Fatalf("method = %q", seenMethod)
			}
			wantPath := "/v1/environments/" + testEnvID + "/users/user-1/groupMemberships/group-1"
			if seenPath != wantPath {
				t.Fatalf("path = %q, want %q", seenPath, wantPath)
			}
		})
	}
}

func TestRevokeAccess_4xxFailsPermanently(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/as/token") {
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
	err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "user-1", ResourceExternalID: "group-1",
	})
	if err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("expected 400, got %v", err)
	}
}

func TestListEntitlements_PaginatesViaHALNext(t *testing.T) {
	hits := 0
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/as/token") {
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
			return
		}
		hits++
		if hits == 1 {
			next := server.URL + r.URL.Path + "?cursor=2"
			_ = json.NewEncoder(w).Encode(pingGroupMembershipsResponse{
				Embedded: pingGroupsEmbeddings{
					GroupMemberships: []pingGroupMembership{{ID: "g-1", Name: "Engineers"}},
				},
				Links: pingLinks{Next: &pingHref{Href: next}},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(pingGroupMembershipsResponse{
			Embedded: pingGroupsEmbeddings{
				GroupMemberships: []pingGroupMembership{{ID: "g-2", Name: "Ops"}},
			},
		})
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
	got, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "user-1")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if hits != 2 {
		t.Fatalf("hits = %d", hits)
	}
	if len(got) != 2 || got[0].ResourceExternalID != "g-1" || got[1].ResourceExternalID != "g-2" {
		t.Fatalf("got %+v", got)
	}
	if got[0].Source != "direct" {
		t.Fatalf("source = %q", got[0].Source)
	}
}

func TestListEntitlements_4xxReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/as/token") {
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
	if _, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "user-1"); err == nil {
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
	if !strings.Contains(md.MetadataURL, "auth.pingone.com") {
		t.Fatalf("MetadataURL = %q (missing region NA host)", md.MetadataURL)
	}
	if !strings.Contains(md.MetadataURL, testEnvID) {
		t.Fatalf("MetadataURL = %q (missing env id)", md.MetadataURL)
	}
}

func TestGetSSOMetadata_RegionRouting(t *testing.T) {
	c := New()
	cases := []struct {
		region string
		host   string
	}{
		{"NA", "auth.pingone.com"},
		{"EU", "auth.pingone.eu"},
		{"AP", "auth.pingone.asia"},
	}
	for _, tc := range cases {
		cfg := map[string]interface{}{"environment_id": testEnvID, "region": tc.region}
		md, err := c.GetSSOMetadata(context.Background(), cfg, nil)
		if err != nil {
			t.Fatalf("Region %s: GetSSOMetadata: %v", tc.region, err)
		}
		if !strings.Contains(md.MetadataURL, tc.host) {
			t.Fatalf("Region %s: MetadataURL = %q, want host %q", tc.region, md.MetadataURL, tc.host)
		}
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
	if md["client_id"] != "worker-id" {
		t.Fatalf("client_id = %v", md["client_id"])
	}
	if md["environment_id"] != testEnvID {
		t.Fatalf("environment_id = %v", md["environment_id"])
	}
}

func TestSyncIdentities_PaginatesAndMaps(t *testing.T) {
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/as/token"):
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
		case strings.HasSuffix(r.URL.Path, "/users"):
			cursor := r.URL.Query().Get("cursor")
			if cursor == "" {
				body := pingUsersResponse{
					Size:  100,
					Count: 100,
					Embedded: pingEmbedded{
						Users: []pingUser{{
							ID:    "u1",
							Email: "alice@example.com",
							Name:  pingName{Formatted: "Alice"},
						}},
					},
					Links: pingLinks{Next: &pingHref{Href: serverURL + fmt.Sprintf("/v1/environments/%s/users?cursor=p2&limit=100", testEnvID)}},
				}
				body.Embedded.Users[0].Enabled = mustEnabled(t, "ENABLED")
				_ = json.NewEncoder(w).Encode(body)
				return
			}
			body := pingUsersResponse{
				Embedded: pingEmbedded{
					Users: []pingUser{{
						ID:    "u2",
						Email: "bob@example.com",
						Name:  pingName{Formatted: "Bob"},
					}},
				},
			}
			body.Embedded.Users[0].Enabled = mustEnabled(t, "DISABLED")
			_ = json.NewEncoder(w).Encode(body)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	serverURL = server.URL

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
	if collected[1].Status != "disabled" {
		t.Fatalf("second status = %q", collected[1].Status)
	}
}

func TestCountIdentities_ReadsCount(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/as/token") {
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
			return
		}
		_, _ = w.Write([]byte(`{"size":1,"count":42,"_embedded":{"users":[]}}`))
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

func TestConnect_ReturnsErrorOnTokenFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }

	if err := c.Connect(context.Background(), validConfig(), validSecrets()); err == nil {
		t.Fatal("Connect expected error on token 401")
	}
}

func TestVerifyPermissions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/as/token") {
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
			return
		}
		_, _ = w.Write([]byte(`{"size":0,"_embedded":{"users":[]}}`))
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

func mustEnabled(t *testing.T, val string) pingEnabled {
	t.Helper()
	var e pingEnabled
	if err := e.UnmarshalJSON([]byte(`"` + val + `"`)); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}
	return e
}
