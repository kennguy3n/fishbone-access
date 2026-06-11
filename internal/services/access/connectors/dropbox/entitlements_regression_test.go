package dropbox

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Regression: ListEntitlements previously returned (nil, nil) when the member
// info response failed to decode, silently hiding a malformed upstream
// payload. The error must now propagate.
func TestListEntitlements_MalformedJSONErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/2/team/members/get_info_v2") {
			_, _ = w.Write([]byte(`{"role": {".tag":`)) // truncated JSON
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
