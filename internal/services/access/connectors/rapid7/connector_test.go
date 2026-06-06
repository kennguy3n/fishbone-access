package rapid7

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

func validConfig() map[string]interface{} {
	return map[string]interface{}{"endpoint": "https://insightvm.corp.example"}
}
func validSecrets() map[string]interface{} {
	return map[string]interface{}{"username": "userAAAA1234bbbbCCCC", "password": "passDDDD5678eeeeFFFF"}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_RejectsMissing(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), validConfig(), map[string]interface{}{}); err == nil {
		t.Error("missing creds")
	}
	if err := c.Validate(context.Background(), map[string]interface{}{}, validSecrets()); err == nil {
		t.Error("missing endpoint")
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
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Basic ") {
			t.Errorf("expected Basic auth; got %q", got)
		}
		page := r.URL.Query().Get("page")
		body := map[string]interface{}{}
		var arr []map[string]interface{}
		if calls == 1 {
			if page != "0" {
				t.Errorf("page = %q", page)
			}
			for i := 0; i < pageSize; i++ {
				arr = append(arr, map[string]interface{}{
					"id":      i,
					"login":   fmt.Sprintf("u%d", i),
					"name":    fmt.Sprintf("U%d", i),
					"email":   fmt.Sprintf("u%d@x.com", i),
					"enabled": true,
				})
			}
			body["page"] = map[string]interface{}{"number": 0, "totalPages": 2}
		} else {
			if page != "1" {
				t.Errorf("page = %q", page)
			}
			arr = []map[string]interface{}{{"id": 999, "login": "last", "name": "Last", "email": "last@x.com", "enabled": false}}
			body["page"] = map[string]interface{}{"number": 1, "totalPages": 2}
		}
		body["resources"] = arr
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
	if len(got) != pageSize+1 || calls != 2 {
		t.Fatalf("got=%d calls=%d", len(got), calls)
	}
	if got[len(got)-1].Status != "disabled" {
		t.Errorf("last user status = %q; want disabled", got[len(got)-1].Status)
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

// --- advanced capabilities ---

func TestProvisionAccess_Idempotent409(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("method = %s; want PUT", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/api/3/sites/42/users/7") {
			t.Errorf("path = %s", r.URL.Path)
		}
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"message":"already a member"}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	grant := access.AccessGrant{UserExternalID: "7", ResourceExternalID: "42"}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	if calls != 2 {
		t.Errorf("calls = %d; want 2", calls)
	}
}

func TestProvisionAccess_Forbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	grant := access.AccessGrant{UserExternalID: "7", ResourceExternalID: "42"}
	if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), grant); err == nil {
		t.Fatal("expected error from 403; got nil")
	}
}

func TestProvisionAccess_MissingGrantPair(t *testing.T) {
	c := New()
	if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{ResourceExternalID: "42"}); err == nil {
		t.Error("expected error for missing UserExternalID")
	}
	if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{UserExternalID: "7"}); err == nil {
		t.Error("expected error for missing ResourceExternalID")
	}
}

func TestRevokeAccess_Idempotent404(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("method = %s; want DELETE", r.Method)
		}
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"not found"}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	grant := access.AccessGrant{UserExternalID: "7", ResourceExternalID: "42"}
	for i := 0; i < 2; i++ {
		if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
			t.Fatalf("RevokeAccess[%d]: %v", i, err)
		}
	}
	if calls != 2 {
		t.Errorf("calls = %d; want 2", calls)
	}
}

func TestRevokeAccess_TransientStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	grant := access.AccessGrant{UserExternalID: "7", ResourceExternalID: "42"}
	err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), grant)
	if err == nil || !strings.Contains(err.Error(), "transient") {
		t.Fatalf("RevokeAccess: expected transient error, got %v", err)
	}
}

func TestListEntitlements_PaginatesSites(t *testing.T) {
	pageCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/api/3/users/7/sites") {
			t.Errorf("path = %s", r.URL.Path)
		}
		body := map[string]interface{}{}
		if pageCount == 0 {
			if r.URL.Query().Get("page") != "0" {
				t.Errorf("page = %s", r.URL.Query().Get("page"))
			}
			body["resources"] = []map[string]interface{}{
				{"id": 1, "name": "Site A"},
				{"id": 2, "name": "Site B"},
			}
			body["page"] = map[string]interface{}{"number": 0, "totalPages": 2}
		} else {
			if r.URL.Query().Get("page") != "1" {
				t.Errorf("page = %s", r.URL.Query().Get("page"))
			}
			body["resources"] = []map[string]interface{}{{"id": 3, "name": "Site C"}}
			body["page"] = map[string]interface{}{"number": 1, "totalPages": 2}
		}
		pageCount++
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	ents, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "7")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(ents) != 3 {
		t.Fatalf("expected 3 entitlements; got %d", len(ents))
	}
	if ents[0].ResourceExternalID != "1" || ents[0].Role != "Site A" {
		t.Errorf("first entitlement = %#v", ents[0])
	}
}

func TestListEntitlements_RejectsEmptyUser(t *testing.T) {
	c := New()
	if _, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), ""); err == nil {
		t.Fatal("expected error for empty userExternalID")
	}
}

func TestListEntitlements_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if _, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "7"); err == nil {
		t.Fatal("expected error from 401")
	}
}

func TestGetCredentialsMetadata_RedactsToken(t *testing.T) {
	c := New()
	md, err := c.GetCredentialsMetadata(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}
	u, _ := md["username_short"].(string)
	p, _ := md["password_short"].(string)
	if !strings.Contains(u, "...") || strings.Contains(u, "AAAA1234") {
		t.Errorf("username redaction failed: %q", u)
	}
	if !strings.Contains(p, "...") || strings.Contains(p, "DDDD5678") {
		t.Errorf("password redaction failed: %q", p)
	}
}
