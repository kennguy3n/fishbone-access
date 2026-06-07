package notion

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// Regression: SyncIdentities pagination cursor must be URL-encoded.
// Notion returns an opaque next_cursor that can contain "+", "/", "="
// and "&"; before the fix it was spliced raw into the start_cursor
// query parameter, which corrupts the URL and silently truncates the
// sync.
func TestSyncIdentities_CursorURLEncoded(t *testing.T) {
	const specialCursor = "a+b/c=d&e"
	page := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page++
		if page == 1 {
			_, _ = fmt.Fprintf(w,
				`{"results":[{"object":"user","id":"u1","type":"person","name":"A","person":{"email":"a@b.com"}}],"has_more":true,"next_cursor":%q}`,
				specialCursor)
			return
		}
		if got := r.URL.Query().Get("start_cursor"); got != specialCursor {
			t.Errorf("start_cursor = %q; want %q", got, specialCursor)
		}
		_, _ = w.Write([]byte(`{"results":[{"object":"user","id":"u2","type":"person","name":"B","person":{"email":"b@b.com"}}],"has_more":false,"next_cursor":null}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var got []*access.Identity
	err := c.SyncIdentities(context.Background(), nil, validSecrets(), "", func(b []*access.Identity, _ string) error {
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
