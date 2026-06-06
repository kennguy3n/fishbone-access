package ga4

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

func validConfig() map[string]interface{} { return map[string]interface{}{"account": "12345"} }
func validSecrets() map[string]interface{} {
	return map[string]interface{}{"token": "ya29.AAAA1234bbbbCCCC"}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_RejectsMissing(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), map[string]interface{}{}); err == nil {
		t.Error("missing token")
	}
	if err := New().Validate(context.Background(), map[string]interface{}{}, validSecrets()); err == nil {
		t.Error("missing account")
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
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer ") {
			t.Errorf("expected Bearer auth; got %q", got)
		}
		if !strings.Contains(r.URL.Path, "/accounts/12345/userLinks") {
			t.Errorf("path = %q", r.URL.Path)
		}
		var arr []map[string]interface{}
		next := ""
		if calls == 1 {
			for i := 0; i < pageSize; i++ {
				arr = append(arr, map[string]interface{}{
					"name":         fmt.Sprintf("accounts/12345/userLinks/%d", i+1),
					"emailAddress": fmt.Sprintf("u%d@x.com", i),
					"directRoles":  []string{"predefinedRoles/read"},
				})
			}
			next = "page-2"
		} else {
			if got := r.URL.Query().Get("pageToken"); got != "page-2" {
				t.Errorf("pageToken = %q", got)
			}
			arr = []map[string]interface{}{{"name": "accounts/12345/userLinks/9999", "emailAddress": "last@x.com"}}
		}
		body := map[string]interface{}{"userLinks": arr}
		if next != "" {
			body["nextPageToken"] = next
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
	if len(got) != pageSize+1 || calls != 2 {
		t.Fatalf("got=%d calls=%d", len(got), calls)
	}
	if got[0].ExternalID != "u0@x.com" {
		t.Errorf("ExternalID must be emailAddress (matches advanced-cap UserExternalID contract), got %q", got[0].ExternalID)
	}
	if name, _ := got[0].RawData["name"].(string); name != "accounts/12345/userLinks/1" {
		t.Errorf("RawData[name] = %q, want resource name", name)
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
	md, err := New().GetCredentialsMetadata(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}
	got, _ := md["token_short"].(string)
	if !strings.Contains(got, "...") || strings.Contains(got, "AAAA1234") {
		t.Errorf("redaction failed: %q", got)
	}
}
