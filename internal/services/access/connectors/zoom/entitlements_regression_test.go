package zoom

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Regression: ListEntitlements previously returned (nil, nil) when the groups
// response failed to decode, silently hiding a malformed upstream payload.
// CountIdentities / SyncIdentities propagate such errors, so ListEntitlements
// must too.
func TestListEntitlements_MalformedJSONErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/users/u-1/groups") {
			_, _ = w.Write([]byte(`{"groups": [ {"id": "g-1"`)) // truncated JSON
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }

	got, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "u-1")
	if err == nil {
		t.Fatalf("expected decode error, got nil (entitlements=%v)", got)
	}
	if !strings.Contains(err.Error(), "decode") {
		t.Fatalf("err = %v; want a decode error", err)
	}
}
