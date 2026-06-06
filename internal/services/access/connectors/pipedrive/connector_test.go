package pipedrive

import (
	"context"
	"errors"
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
	return map[string]interface{}{"api_token": "pdAAAA1234bbbbCCCC"}
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

// Pipedrive's /users normally returns all users in one shot, but we still
// exercise the start/next_start cursor branch to prove SyncIdentities loops.
func TestSync_PaginatesUsers(t *testing.T) {
	page := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page++
		// api_token must travel in the Authorization header, never the URL.
		if got := r.Header.Get("Authorization"); got == "" || !strings.HasPrefix(got, "Bearer ") {
			t.Errorf("Authorization header = %q; want Bearer <api_token>", got)
		}
		if r.URL.Query().Get("api_token") != "" {
			t.Errorf("api_token leaked into URL query: %q", r.URL.Query().Get("api_token"))
		}
		if page == 1 {
			_, _ = w.Write([]byte(`{"success":true,"data":[{"id":1,"name":"Alice","email":"a@b.com","active_flag":true,"is_admin":1}],"additional_data":{"pagination":{"start":0,"limit":100,"more_items_in_collection":true,"next_start":100}}}`))
			return
		}
		if r.URL.Query().Get("start") != "100" {
			t.Errorf("start = %q", r.URL.Query().Get("start"))
		}
		_, _ = w.Write([]byte(`{"success":true,"data":[{"id":2,"name":"Bob","email":"b@b.com","active_flag":false,"is_admin":0}],"additional_data":{"pagination":{"start":100,"limit":100,"more_items_in_collection":false}}}`))
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
	if len(got) != 2 {
		t.Fatalf("len = %d", len(got))
	}
	if page < 2 {
		t.Fatalf("expected pagination, calls = %d", page)
	}
	if got[1].Status != "inactive" {
		t.Errorf("expected u2 inactive, got %q", got[1].Status)
	}
}

func TestConnect_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		t.Fatalf("err: %v", err)
	}
	short, _ := md["token_short"].(string)
	if short == "" || strings.Contains(short, "AAAA1234") {
		t.Errorf("token_short = %q", short)
	}
}

// TestDoError_DoesNotLeakToken proves that when the underlying transport
// returns a *url.Error, the returned error string does not contain the
// api_token (defence-in-depth: the token now lives in the Authorization
// header, but the sanitizeURLError helper also strips the URL field).
func TestDoError_DoesNotLeakToken(t *testing.T) {
	c := New()
	c.urlOverride = "http://127.0.0.1:1" // unroutable, forces *url.Error
	c.httpClient = func() httpDoer { return &http.Client{Transport: http.DefaultTransport} }
	err := c.Connect(context.Background(), validConfig(), validSecrets())
	if err == nil {
		t.Fatal("expected error from unreachable host")
	}
	tok, _ := validSecrets()["api_token"].(string)
	if strings.Contains(err.Error(), tok) {
		t.Errorf("api_token leaked in error: %q", err.Error())
	}
}
