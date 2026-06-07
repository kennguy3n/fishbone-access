package copper

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
	return map[string]interface{}{"api_key": "cpr_AAAA1234bbbbCCCC", "email": "alice@example.com"}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_RejectsMissing(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), validConfig(), map[string]interface{}{"api_key": "k"}); err == nil {
		t.Error("missing email")
	}
	if err := c.Validate(context.Background(), validConfig(), map[string]interface{}{"email": "x@y.com"}); err == nil {
		t.Error("missing api_key")
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
		if r.Header.Get("X-PW-AccessToken") == "" || r.Header.Get("X-PW-Application") == "" {
			t.Error("expected Copper API headers")
		}
		if r.URL.Path != "/developer_api/v1/users" {
			t.Errorf("path = %q", r.URL.Path)
		}
		page := r.URL.Query().Get("page_number")
		var arr []map[string]interface{}
		if calls == 1 {
			if page != "1" {
				t.Errorf("page = %q", page)
			}
			for i := 0; i < pageSize; i++ {
				arr = append(arr, map[string]interface{}{"id": i + 1, "name": fmt.Sprintf("U%d", i), "email": fmt.Sprintf("u%d@x.com", i)})
			}
		} else {
			if page != "2" {
				t.Errorf("page = %q", page)
			}
			arr = []map[string]interface{}{{"id": 999, "name": "Last", "email": "last@x.com"}}
		}
		b, _ := json.Marshal(arr)
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

func TestGetCredentialsMetadata_RedactsToken(t *testing.T) {
	c := New()
	md, err := c.GetCredentialsMetadata(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}
	got, _ := md["key_short"].(string)
	if !strings.Contains(got, "...") || strings.Contains(got, "1234bbbb") {
		t.Errorf("redaction failed: %q", got)
	}
}

// TestListEntitlements_DeduplicatesRoles guards against the regression
// where a role id present in both the `roles` array and the singular
// `role_id` field produced two identical entitlements. Each distinct
// role must appear exactly once.
func TestListEntitlements_DeduplicatesRoles(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":"u-1","role_id":"admin","roles":["admin","viewer"]}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	got, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "u-1")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d entitlements, want 2 (deduped): %#v", len(got), got)
	}
	seen := map[string]int{}
	for _, e := range got {
		seen[e.Role]++
	}
	if seen["admin"] != 1 || seen["viewer"] != 1 {
		t.Fatalf("role counts = %v, want admin:1 viewer:1", seen)
	}
}
