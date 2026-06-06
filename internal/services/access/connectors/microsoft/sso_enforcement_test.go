package microsoft

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCheckSSOEnforcement_Enforced(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/policies/authenticationFlowsPolicy") {
			t.Errorf("path=%q; want suffix /policies/authenticationFlowsPolicy", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"selfServiceSignUp":{"isEnabled":false}}`))
	}))
	t.Cleanup(server.Close)
	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) httpDoer {
		return &serverFirstFakeClient{base: server.URL, http: server.Client()}
	}
	enforced, _, err := c.CheckSSOEnforcement(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	if !enforced {
		t.Error("enforced=false; want true (self-service sign-up disabled)")
	}
}

func TestCheckSSOEnforcement_NotEnforced(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"selfServiceSignUp":{"isEnabled":true}}`))
	}))
	t.Cleanup(server.Close)
	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) httpDoer {
		return &serverFirstFakeClient{base: server.URL, http: server.Client()}
	}
	enforced, _, err := c.CheckSSOEnforcement(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	if enforced {
		t.Error("enforced=true; want false")
	}
}

func TestCheckSSOEnforcement_HTTPFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(server.Close)
	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) httpDoer {
		return &serverFirstFakeClient{base: server.URL, http: server.Client()}
	}
	if _, _, err := c.CheckSSOEnforcement(context.Background(), validConfig(), validSecrets()); err == nil {
		t.Fatal("err=nil; want non-nil on 403")
	}
}
