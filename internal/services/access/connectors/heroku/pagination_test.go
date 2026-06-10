package heroku

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// rangePager serves a slice of pre-encoded JSON-array pages using Heroku's
// Range/Next-Range pagination contract: each response carries a Next-Range
// header until the final page, and the client echoes the value back in the
// Range request header.
type rangePager struct {
	pages [][]byte
}

func (p *rangePager) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idx := 0
		if rng := strings.TrimSpace(r.Header.Get("Range")); rng != "" {
			if _, err := fmt.Sscanf(rng, "page %d", &idx); err != nil {
				t.Errorf("unexpected Range header %q", rng)
			}
		}
		if idx < 0 || idx >= len(p.pages) {
			t.Fatalf("page index %d out of range (%d pages)", idx, len(p.pages))
		}
		if idx < len(p.pages)-1 {
			w.Header().Set("Next-Range", fmt.Sprintf("page %d", idx+1))
			w.WriteHeader(http.StatusPartialContent)
		}
		_, _ = w.Write(p.pages[idx])
	}
}

func newPagedConnector(t *testing.T, p *rangePager) *HerokuAccessConnector {
	srv := httptest.NewServer(p.handler(t))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	return c
}

// Regression: the Heroku audit reader capped the body at 1 MiB and read only a
// single response, silently dropping every event past the cap / first page.
// This proves a multi-page window totalling well over 1 MiB is read in full.
func TestFetchAuditLogs_MultiPageOverOneMiB(t *testing.T) {
	const pages = 4
	const perPage = 400
	pager := &rangePager{}
	wantIDs := map[string]bool{}
	for pg := 0; pg < pages; pg++ {
		evts := make([]map[string]interface{}, 0, perPage)
		for i := 0; i < perPage; i++ {
			id := fmt.Sprintf("evt-%d-%d", pg, i)
			wantIDs[id] = true
			evts = append(evts, map[string]interface{}{
				"id":         id,
				"type":       "membership",
				"action":     "add",
				"created_at": time.Date(2024, 6, 1, 0, 0, pg*perPage+i, 0, time.UTC).Format(time.RFC3339),
				"actor":      map[string]string{"id": "u-1", "email": "admin@example.com"},
				// Padding so the aggregate payload comfortably exceeds the old
				// 1 MiB truncation cap (4*400 events * ~800 bytes ≈ 1.3 MiB).
				"data": strings.Repeat("x", 800),
			})
		}
		raw, err := json.Marshal(evts)
		if err != nil {
			t.Fatalf("marshal page %d: %v", pg, err)
		}
		pager.pages = append(pager.pages, raw)
	}
	total := 0
	for _, pg := range pager.pages {
		total += len(pg)
	}
	if total <= 1<<20 {
		t.Fatalf("test fixture only %d bytes; must exceed 1 MiB to exercise truncation", total)
	}

	c := newPagedConnector(t, pager)
	var collected []*access.AuditLogEntry
	err := c.FetchAccessAuditLogs(context.Background(), herokuAuditConfig(), herokuAuditSecrets(),
		map[string]time.Time{},
		func(batch []*access.AuditLogEntry, _ time.Time, _ string) error {
			collected = append(collected, batch...)
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) != pages*perPage {
		t.Fatalf("collected %d events; want %d (events were truncated/dropped)", len(collected), pages*perPage)
	}
	for _, e := range collected {
		delete(wantIDs, e.EventID)
	}
	if len(wantIDs) != 0 {
		t.Fatalf("%d events missing from output, e.g. one of %v", len(wantIDs), firstKey(wantIDs))
	}
}

// Regression: a malformed page mid-stream must surface as an error, not be
// silently swallowed.
func TestFetchAuditLogs_MalformedPageErrors(t *testing.T) {
	pager := &rangePager{pages: [][]byte{
		[]byte(`[{"id":"evt-1","type":"membership","action":"add","created_at":"2024-06-01T11:00:00Z"}]`),
		[]byte(`{not json`),
	}}
	c := newPagedConnector(t, pager)
	err := c.FetchAccessAuditLogs(context.Background(), herokuAuditConfig(), herokuAuditSecrets(),
		map[string]time.Time{},
		func([]*access.AuditLogEntry, time.Time, string) error { return nil })
	if err == nil {
		t.Fatal("expected decode error from malformed page, got nil")
	}
	if !strings.Contains(err.Error(), "decode audit trail") {
		t.Fatalf("err = %v; want decode audit trail error", err)
	}
}

// Regression: SyncIdentities / CountIdentities read only the first members page
// and dropped every member beyond Heroku's default page size. This proves all
// pages are now followed.
func TestSyncAndCountIdentities_MultiPageMembers(t *testing.T) {
	const pages = 3
	const perPage = 200
	pager := &rangePager{}
	for pg := 0; pg < pages; pg++ {
		members := make([]map[string]interface{}, 0, perPage)
		for i := 0; i < perPage; i++ {
			n := pg*perPage + i
			members = append(members, map[string]interface{}{
				"id":    fmt.Sprintf("m-%d", n),
				"email": fmt.Sprintf("user%d@example.com", n),
				"role":  "member",
				"user":  map[string]string{"id": fmt.Sprintf("u-%d", n), "email": fmt.Sprintf("user%d@example.com", n)},
			})
		}
		raw, err := json.Marshal(members)
		if err != nil {
			t.Fatalf("marshal members page %d: %v", pg, err)
		}
		pager.pages = append(pager.pages, raw)
	}

	cfg := map[string]interface{}{"team_name": "acme"}
	c := newPagedConnector(t, pager)
	n, err := c.CountIdentities(context.Background(), cfg, validSecrets())
	if err != nil {
		t.Fatalf("CountIdentities: %v", err)
	}
	if n != pages*perPage {
		t.Fatalf("count = %d; want %d (members were truncated)", n, pages*perPage)
	}

	var synced []*access.Identity
	if err := c.SyncIdentities(context.Background(), cfg, validSecrets(), "", func(batch []*access.Identity, _ string) error {
		synced = append(synced, batch...)
		return nil
	}); err != nil {
		t.Fatalf("SyncIdentities: %v", err)
	}
	if len(synced) != pages*perPage {
		t.Fatalf("synced %d identities; want %d", len(synced), pages*perPage)
	}
}

func firstKey(m map[string]bool) string {
	for k := range m {
		return k
	}
	return ""
}
