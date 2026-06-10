package notion

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Regression: ListEntitlements previously returned (nil, nil) both when the
// HTTP request failed and when the user response failed to decode, silently
// hiding real errors. Both must now propagate.
func TestListEntitlements_MalformedJSONErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/users/u-1" {
			_, _ = w.Write([]byte(`{"type": "person"`)) // truncated JSON
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	got, err := c.ListEntitlements(context.Background(), map[string]interface{}{}, validSecrets(), "u-1")
	if err == nil {
		t.Fatalf("expected decode error, got nil (entitlements=%v)", got)
	}
	if !strings.Contains(err.Error(), "decode") {
		t.Fatalf("err = %v; want a decode error", err)
	}
}

// Regression: a non-2xx upstream status must surface as an error rather than
// being swallowed into an empty entitlement set.
func TestListEntitlements_HTTPErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"object":"error","status":500}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	if _, err := c.ListEntitlements(context.Background(), map[string]interface{}{}, validSecrets(), "u-1"); err == nil {
		t.Fatal("expected error on HTTP 500, got nil")
	}
}
