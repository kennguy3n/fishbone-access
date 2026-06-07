package google_workspace

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestCheckSSOEnforcement_Enforced asserts an Admin SDK SSO
// profile with enableSSO=true AND signInPage populated reports
// enforced=true.
func TestCheckSSOEnforcement_Enforced(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/customer/my_customer/sso") {
			t.Errorf("path=%q; want suffix /customer/my_customer/sso", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"enableSSO":true,"signInPage":"https://idp.example.com/sso","useDomainSpecificIssuer":true}`))
	}))
	t.Cleanup(server.Close)

	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) (httpDoer, error) {
		return &fakeDirectoryClient{base: server.URL, c: server.Client()}, nil
	}
	enforced, details, err := c.CheckSSOEnforcement(context.Background(), validConfig(), validSecrets(t))
	if err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	if !enforced {
		t.Errorf("enforced = false; want true")
	}
	if details == "" {
		t.Error("details empty; want a non-empty hint")
	}
}

// TestCheckSSOEnforcement_NotEnforced: enableSSO=false should
// report enforced=false with a hint about password sign-in.
func TestCheckSSOEnforcement_NotEnforced(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"enableSSO":false}`))
	}))
	t.Cleanup(server.Close)
	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) (httpDoer, error) {
		return &fakeDirectoryClient{base: server.URL, c: server.Client()}, nil
	}
	enforced, _, err := c.CheckSSOEnforcement(context.Background(), validConfig(), validSecrets(t))
	if err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	if enforced {
		t.Error("enforced = true; want false")
	}
}

// TestCheckSSOEnforcement_HTTPFailure: a 500 surfaces as a
// non-nil err so callers map it to "unknown".
func TestCheckSSOEnforcement_HTTPFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) (httpDoer, error) {
		return &fakeDirectoryClient{base: server.URL, c: server.Client()}, nil
	}
	if _, _, err := c.CheckSSOEnforcement(context.Background(), validConfig(), validSecrets(t)); err == nil {
		t.Fatal("err = nil; want non-nil on 500")
	}
}
