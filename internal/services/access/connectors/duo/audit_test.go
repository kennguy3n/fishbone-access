package duo

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func TestFetchAccessAuditLogs_PaginatesAndMaps(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/admin/v2/logs/authentication") {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Basic ") {
			t.Errorf("missing duo basic signature: %q", got)
		}
		if r.Header.Get("Date") == "" {
			t.Errorf("missing Date header")
		}
		if mt := r.URL.Query().Get("mintime"); mt == "" {
			t.Errorf("missing mintime")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(duoAuthLogResponse{
			Stat: "OK",
			Response: struct {
				Authlogs []duoAuthLog `json:"authlogs"`
				Metadata duoAuthMeta  `json:"metadata"`
			}{
				Authlogs: []duoAuthLog{
					{
						Txid: "tx1", EventType: "authentication", Result: "success",
						ISOTimestamp: "2024-07-01T08:00:00.000Z",
						User:         duoAuthLogUser{Key: "u1", Name: "alice@example.com"},
						AccessDevice: duoAuthLogDevice{IP: "10.0.0.1"},
						Application:  duoAuthLogApplication{Key: "DI123", Name: "Corp VPN"},
					},
					{
						Txid: "tx2", EventType: "authentication", Result: "denied",
						ISOTimestamp: "2024-07-01T09:00:00Z",
						User:         duoAuthLogUser{Key: "u2", Name: "bob@example.com"},
					},
				},
			},
		})
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
	c.nowFn = func() time.Time { return time.Date(2024, 7, 1, 0, 0, 0, 0, time.UTC) }

	var collected []*access.AuditLogEntry
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Date(2024, 7, 1, 0, 0, 0, 0, time.UTC)},
		func(batch []*access.AuditLogEntry, _ time.Time, _ string) error {
			collected = append(collected, batch...)
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) != 2 {
		t.Fatalf("collected %d; want 2", len(collected))
	}
	if collected[0].ActorEmail != "alice@example.com" || collected[0].Outcome != "success" {
		t.Errorf("entry 0 = %+v", collected[0])
	}
	if collected[1].Outcome != "failure" {
		t.Errorf("entry 1 Outcome = %q; want failure", collected[1].Outcome)
	}
}

func TestFetchAccessAuditLogs_PassesNextOffsetCursor(t *testing.T) {
	// Page 1 returns next_offset=AAAA and one event; page 2 must echo
	// next_offset=AAAA back in the query string and returns the
	// terminating empty-cursor page.
	var pageCalls int
	var sawCursor string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pageCalls++
		w.Header().Set("Content-Type", "application/json")
		if pageCalls == 1 {
			if got := r.URL.Query().Get("next_offset"); got != "" {
				t.Errorf("page 1 next_offset = %q; want empty", got)
			}
			_ = json.NewEncoder(w).Encode(duoAuthLogResponse{
				Stat: "OK",
				Response: struct {
					Authlogs []duoAuthLog `json:"authlogs"`
					Metadata duoAuthMeta  `json:"metadata"`
				}{
					Authlogs: []duoAuthLog{{Txid: "tx1", EventType: "authentication", Result: "success", ISOTimestamp: "2024-07-01T08:00:00.000Z", User: duoAuthLogUser{Name: "alice@example.com"}}},
					Metadata: duoAuthMeta{NextOffset: "OFFSET-AAAA"},
				},
			})
			return
		}
		sawCursor = r.URL.Query().Get("next_offset")
		_ = json.NewEncoder(w).Encode(duoAuthLogResponse{
			Stat: "OK",
			Response: struct {
				Authlogs []duoAuthLog `json:"authlogs"`
				Metadata duoAuthMeta  `json:"metadata"`
			}{
				Authlogs: []duoAuthLog{{Txid: "tx2", EventType: "authentication", Result: "success", ISOTimestamp: "2024-07-01T08:00:00.000Z", User: duoAuthLogUser{Name: "bob@example.com"}}},
				Metadata: duoAuthMeta{NextOffset: ""},
			},
		})
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
	c.nowFn = func() time.Time { return time.Date(2024, 7, 1, 0, 0, 0, 0, time.UTC) }

	var collected []*access.AuditLogEntry
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Date(2024, 6, 30, 0, 0, 0, 0, time.UTC)},
		func(batch []*access.AuditLogEntry, _ time.Time, _ string) error {
			collected = append(collected, batch...)
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if pageCalls != 2 {
		t.Fatalf("pageCalls = %d; want 2", pageCalls)
	}
	if sawCursor != "OFFSET-AAAA" {
		t.Fatalf("page 2 next_offset = %q; want OFFSET-AAAA (cursor not propagated, events at same ms boundary can be lost)", sawCursor)
	}
	if len(collected) != 2 {
		t.Fatalf("collected %d; want 2 (both pages mapped)", len(collected))
	}
}

func TestFetchAccessAuditLogs_NotAvailable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(server.Close)
	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
	c.nowFn = func() time.Time { return time.Date(2024, 7, 1, 0, 0, 0, 0, time.UTC) }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Date(2024, 7, 1, 0, 0, 0, 0, time.UTC)},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err != access.ErrAuditNotAvailable {
		t.Fatalf("err = %v; want ErrAuditNotAvailable", err)
	}
}

func TestFetchAccessAuditLogs_ProviderError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
	c.nowFn = func() time.Time { return time.Date(2024, 7, 1, 0, 0, 0, 0, time.UTC) }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(), nil,
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err == nil {
		t.Fatal("expected provider error")
	}
	if err == access.ErrAuditNotAvailable {
		t.Fatalf("err = ErrAuditNotAvailable; want generic error")
	}
}
