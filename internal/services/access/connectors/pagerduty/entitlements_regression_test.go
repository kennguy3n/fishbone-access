package pagerduty

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Regression: ListEntitlements previously returned (nil, nil) when the user
// response failed to decode, silently hiding a malformed upstream payload.
// The error must now propagate, consistent with CountIdentities/SyncIdentities.
func TestListEntitlements_MalformedJSONErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/users/u-1") {
			_, _ = w.Write([]byte(`{"user": {"teams": [`)) // truncated JSON
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	got, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "u-1")
	if err == nil {
		t.Fatalf("expected decode error, got nil (entitlements=%v)", got)
	}
	if !strings.Contains(err.Error(), "decode") {
		t.Fatalf("err = %v; want a decode error", err)
	}
}
