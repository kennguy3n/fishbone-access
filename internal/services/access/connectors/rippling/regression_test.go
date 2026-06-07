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

// Regression: Rippling's `next` field can be a bare opaque cursor OR a
// full next-page URL (link-style pagination). A bare token must be
// URL-encoded into &cursor=; a full URL must be followed verbatim (not
// URL-encoded into the cursor parameter, which would corrupt the link).
func TestRipplingPageURL(t *testing.T) {
	const base = "https://api.rippling.com"
	for _, tc := range []struct {
		name   string
		cursor string
		want   string
	}{
		{
			name:   "empty cursor first page",
			cursor: "",
			want:   "https://api.rippling.com/platform/api/employees?limit=100",
		},
		{
			name:   "bare token is query-escaped",
			cursor: "a+b/c=d&e",
			want:   "https://api.rippling.com/platform/api/employees?limit=100&cursor=a%2Bb%2Fc%3Dd%26e",
		},
		{
			name:   "absolute https url followed verbatim",
			cursor: "https://api.rippling.com/platform/api/employees?limit=100&cursor=opaque%2Btoken",
			want:   "https://api.rippling.com/platform/api/employees?limit=100&cursor=opaque%2Btoken",
		},
		{
			name:   "opaque token with colon is not treated as url",
			cursor: "2024:abc",
			want:   "https://api.rippling.com/platform/api/employees?limit=100&cursor=2024%3Aabc",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ripplingPageURL(base, tc.cursor); got != tc.want {
				t.Errorf("ripplingPageURL(%q) = %q; want %q", tc.cursor, got, tc.want)
			}
		})
	}
}

// Regression (end-to-end): when the first page returns a full next-page
// URL in `next`, the connector must follow it verbatim and continue
// pagination, not corrupt it by URL-encoding the whole link.
func TestSyncIdentities_FollowsFullNextURL(t *testing.T) {
	var page2Query string
	page := 0
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page++
		if page == 1 {
			_, _ = fmt.Fprintf(w,
				`{"results":[{"id":"u1","firstName":"A","lastName":"A","workEmail":"a@b.com","status":"ACTIVE"}],"nextCursor":"","next":%q}`,
				srvURL+"/platform/api/employees?limit=100&cursor=tok2")
			return
		}
		page2Query = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"results":[{"id":"u2","firstName":"B","lastName":"B","workEmail":"b@b.com","status":"ACTIVE"}],"nextCursor":"","next":""}`))
	}))
	t.Cleanup(srv.Close)
	srvURL = srv.URL
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
		t.Fatalf("len = %d; want 2 (full next URL not followed)", len(got))
	}
	if page2Query != "limit=100&cursor=tok2" {
		t.Errorf("page 2 query = %q; want %q (full URL was not followed verbatim)", page2Query, "limit=100&cursor=tok2")
	}
}
