package lastpass

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

type noNetworkRoundTripper struct{}

func (noNetworkRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return nil, errors.New("network call attempted from a no-network test path")
}

func validConfig() map[string]interface{} {
	return map[string]interface{}{"account_number": "12345"}
}

func validSecrets() map[string]interface{} {
	return map[string]interface{}{"provisioning_hash": "deadbeef"}
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
		{"missing account", map[string]interface{}{}, validSecrets()},
		{"empty account", map[string]interface{}{"account_number": "  "}, validSecrets()},
		{"missing hash", validConfig(), map[string]interface{}{}},
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
	if _, ok := got.(*LastPassAccessConnector); !ok {
		t.Fatalf("registered type = %T, want *LastPassAccessConnector", got)
	}
}

func TestProvisionAccess_AddsToSharedGroup(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"ok", `{"status":"OK"}`},
		{"already_member_idempotent", `{"status":"FAIL","errors":["User already a member of group"]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var seen map[string]interface{}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen = decodeRequestBody(t, r)
				_, _ = w.Write([]byte(tc.body))
			}))
			t.Cleanup(server.Close)

			c := New()
			c.urlOverride = server.URL
			c.httpClient = func() httpDoer { return server.Client() }
			err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
				UserExternalID: "alice@example.com", ResourceExternalID: "Engineering",
			})
			if err != nil {
				t.Fatalf("ProvisionAccess: %v", err)
			}
			if seen["cmd"] != "batchchangegrp" {
				t.Fatalf("cmd = %v", seen["cmd"])
			}
			data, _ := seen["data"].(map[string]interface{})
			if data["op"] != "add" || data["groupname"] != "Engineering" || data["username"] != "alice@example.com" {
				t.Fatalf("data = %+v", data)
			}
		})
	}
}

func TestProvisionAccess_FailsOnUnknownError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"FAIL","errors":["bad credentials"]}`))
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "u@x", ResourceExternalID: "g",
	})
	if err == nil || !strings.Contains(err.Error(), "FAIL") {
		t.Fatalf("expected FAIL error, got %v", err)
	}
}

func TestRevokeAccess_RemovesFromSharedGroup(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"ok", `{"status":"OK"}`},
		{"not_member_idempotent", `{"status":"FAIL","errors":["User is not in the group"]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var seen map[string]interface{}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen = decodeRequestBody(t, r)
				_, _ = w.Write([]byte(tc.body))
			}))
			t.Cleanup(server.Close)

			c := New()
			c.urlOverride = server.URL
			c.httpClient = func() httpDoer { return server.Client() }
			err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
				UserExternalID: "alice@example.com", ResourceExternalID: "Engineering",
			})
			if err != nil {
				t.Fatalf("RevokeAccess: %v", err)
			}
			data, _ := seen["data"].(map[string]interface{})
			if data["op"] != "del" {
				t.Fatalf("op = %v, want del", data["op"])
			}
		})
	}
}

func TestRevokeAccess_FailsOnUnknownError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"FAIL","errors":["unauthorized"]}`))
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
	err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "u@x", ResourceExternalID: "g",
	})
	if err == nil || !strings.Contains(err.Error(), "FAIL") {
		t.Fatalf("expected FAIL error, got %v", err)
	}
}

func TestListEntitlements_FiltersFoldersByUser(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := decodeRequestBody(t, r)
		if body["cmd"] != "getsfdata" {
			t.Fatalf("cmd = %v", body["cmd"])
		}
		_ = json.NewEncoder(w).Encode(lastpassSharedFolderDataResponse{
			Folders: []lastpassSharedFolder{
				{
					SharedFolderID:   "sf-1",
					SharedFolderName: "Engineering",
					Users: []lastpassFolderMember{
						{Username: "alice@example.com", UserID: "uid1"},
					},
				},
				{
					SharedFolderID:   "sf-2",
					SharedFolderName: "Sales",
					Users: []lastpassFolderMember{
						{Username: "bob@example.com", UserID: "uid2"},
					},
				},
			},
		})
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
	got, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "alice@example.com")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(got) != 1 || got[0].ResourceExternalID != "sf-1" || got[0].Role != "Engineering" || got[0].Source != "direct" {
		t.Fatalf("got %+v", got)
	}
}

func TestListEntitlements_4xxReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
	if _, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "alice@example.com"); err == nil {
		t.Fatal("expected error on 403")
	}
}

func TestGetSSOMetadata_NilForVault(t *testing.T) {
	c := New()
	md, err := c.GetSSOMetadata(context.Background(), validConfig(), nil)
	if err != nil {
		t.Fatalf("GetSSOMetadata: %v", err)
	}
	if md != nil {
		t.Fatalf("md = %+v, want nil for vault", md)
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
	if md["account_number"] != "12345" {
		t.Fatalf("account_number = %v", md["account_number"])
	}
}

func decodeRequestBody(t *testing.T, r *http.Request) map[string]interface{} {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	return out
}

func TestSyncIdentities_PaginatesAndMaps(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		body := decodeRequestBody(t, r)
		if body["cid"] != "12345" || body["provhash"] != "deadbeef" || body["cmd"] != "getuserdata" {
			t.Errorf("payload = %v", body)
		}
		data, _ := body["data"].(map[string]interface{})
		offset, _ := data["pageoffset"].(float64)
		calls++
		if calls == 1 {
			if int(offset) != 0 {
				t.Errorf("first call offset = %v, want 0", offset)
			}
			users := []lastpassUser{
				{UserID: "uid1", Username: "alice@example.com", Email: "alice@example.com", FullName: "Alice", Disabled: false},
				{UserID: "uid2", Username: "bob@example.com", Email: "bob@example.com", FullName: "Bob", Disabled: true},
			}
			_ = json.NewEncoder(w).Encode(lastpassUserDataResponse{Total: 3, Users: users})
			return
		}
		if int(offset) != 2 {
			t.Errorf("second call offset = %v, want 2", offset)
		}
		users := []lastpassUser{
			{UserID: "uid3", Username: "carol@example.com", Email: "carol@example.com", FullName: "Carol"},
		}
		_ = json.NewEncoder(w).Encode(lastpassUserDataResponse{Total: 3, Users: users})
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
	if len(collected) != 3 {
		t.Fatalf("collected %d, want 3", len(collected))
	}
	if collected[1].Status != "disabled" {
		t.Fatalf("disabled user status = %q", collected[1].Status)
	}
}

func TestCountIdentities_ReadsTotal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"total": 42, "Users": []}`))
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

func TestConnect_FailsOnAPIFailEnvelope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"FAIL","error":"invalid hash"}`))
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }

	if err := c.Connect(context.Background(), validConfig(), validSecrets()); err == nil {
		t.Fatal("Connect expected error on FAIL envelope")
	}
}

func TestConnect_FailsOnNon2xx(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }

	if err := c.Connect(context.Background(), validConfig(), validSecrets()); err == nil {
		t.Fatal("Connect expected error on 500")
	}
}

func TestVerifyPermissions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"total":0,"Users":[]}`))
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
