package rippling

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// Regression: SyncIdentities pagination cursor must be URL-encoded.
// Rippling returns an opaque cursor that can contain "+", "/", "=" and
// "&"; before the fix it was spliced raw into the query string, which
// corrupts the URL (the server decodes "+" as space and treats "&" as a
// parameter separator) and silently truncates the sync.
func TestSyncIdentities_CursorURLEncoded(t *testing.T) {
	const specialCursor = "a+b/c=d&e"
	page := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page++
		if page == 1 {
			_, _ = fmt.Fprintf(w,
				`{"results":[{"id":"u1","firstName":"A","lastName":"A","workEmail":"a@b.com","status":"ACTIVE"}],"nextCursor":%q}`,
				specialCursor)
			return
		}
		if got := r.URL.Query().Get("cursor"); got != specialCursor {
			t.Errorf("cursor = %q; want %q", got, specialCursor)
		}
		_, _ = w.Write([]byte(`{"results":[{"id":"u2","firstName":"B","lastName":"B","workEmail":"b@b.com","status":"ACTIVE"}],"nextCursor":""}`))
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
		t.Fatalf("SyncIdentities: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d; want 2 (cursor pagination truncated)", len(got))
	}
}
