package monday

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func TestFetchAccessAuditLogs_PaginatesAndMaps(t *testing.T) {
	call := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		if r.Header.Get("Authorization") == "" {
			t.Errorf("Authorization missing")
		}
		body, _ := io.ReadAll(r.Body)
		var payload graphQLRequest
		_ = json.Unmarshal(body, &payload)
		if !strings.Contains(payload.Query, "audit_log") {
			t.Errorf("query = %q", payload.Query)
		}
		switch call {
		case 0:
			if !strings.Contains(payload.Query, "page: 1") {
				t.Errorf("page1 query = %q", payload.Query)
			}
			call++
			// Emit `limit` rows to force a page-2 fetch.
			rows := make([]map[string]interface{}, 0, 100)
			rows = append(rows, map[string]interface{}{
				"id":         "1001",
				"event":      "user.invited",
				"timestamp":  "2024-01-01T10:00:00.123Z",
				"user_id":    "42",
				"user_email": "admin@example.com",
				"ip_address": "203.0.113.1",
			})
			for i := 1; i < 100; i++ {
				rows = append(rows, map[string]interface{}{
					"id":        strings.Repeat("9", 1) + "001",
					"event":     "noop",
					"timestamp": "2024-01-01T10:30:00Z",
				})
			}
			rows[0]["id"] = "1001"
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{"audit_log": rows},
			})
		case 1:
			if !strings.Contains(payload.Query, "page: 2") {
				t.Errorf("page2 query = %q", payload.Query)
			}
			call++
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"audit_log": []map[string]interface{}{
						{
							"id":        "1002",
							"event":     "board.shared",
							"timestamp": "2024-01-01T11:00:00Z",
							"user_id":   "43",
						},
					},
				},
			})
		default:
			t.Errorf("unexpected call %d", call)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	var collected []*access.AuditLogEntry
	var lastSince time.Time
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
		func(batch []*access.AuditLogEntry, nextSince time.Time, _ string) error {
			collected = append(collected, batch...)
			lastSince = nextSince
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) < 2 {
		t.Fatalf("len = %d, want >=2", len(collected))
	}
	if collected[0].EventType != "user.invited" || collected[0].ActorExternalID != "42" {
		t.Errorf("entry 0 = %+v", collected[0])
	}
	want := time.Date(2024, 1, 1, 11, 0, 0, 0, time.UTC)
	if !lastSince.Equal(want) {
		t.Errorf("lastSince = %s, want %s", lastSince, want)
	}
}

// TestFetchAccessAuditLogs_SkipsUnparseableTimestamp is a regression test for
// the missing zero-timestamp guard: a row whose timestamp is empty/garbage must
// be dropped (matching the sibling connectors) rather than flowing into the
// audit pipeline with a zero time.Time. The valid row in the same page must
// still be emitted.
func TestFetchAccessAuditLogs_SkipsUnparseableTimestamp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"audit_log": []map[string]interface{}{
					{
						"id":        "1001",
						"event":     "user.invited",
						"timestamp": "not-a-timestamp",
						"user_id":   "42",
					},
					{
						"id":        "1002",
						"event":     "board.shared",
						"timestamp": "2024-01-01T11:00:00Z",
						"user_id":   "43",
					},
				},
			},
		})
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	var collected []*access.AuditLogEntry
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
		func(batch []*access.AuditLogEntry, _ time.Time, _ string) error {
			collected = append(collected, batch...)
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) != 1 {
		t.Fatalf("len = %d; want 1 (bad-timestamp row dropped)", len(collected))
	}
	if collected[0].EventID != "1002" {
		t.Fatalf("kept %q; want 1002", collected[0].EventID)
	}
}

func TestFetchAccessAuditLogs_ProviderError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Now().Add(-time.Hour)},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestFetchAccessAuditLogs_NotAvailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"errors": []map[string]interface{}{
				{"message": "audit log requires Enterprise tier"},
			},
		})
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Now().Add(-time.Hour)},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if !errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v, want ErrAuditNotAvailable", err)
	}
}

// TestParseMondayTime_NormalizesToUTC is a regression test ensuring the RFC3339
// branches of parseMondayTime normalize to UTC like its numeric-epoch branches
// (and like every sibling connector's parser). Previously the RFC3339 paths
// returned the original offset, so a feed mixing RFC3339 strings and numeric
// epochs produced a batchMax cursor with mixed zones.
func TestParseMondayTime_NormalizesToUTC(t *testing.T) {
	cases := []string{
		"2024-01-01T11:00:00+08:00",     // RFC3339 with offset
		"2024-01-01T11:00:00.500+08:00", // RFC3339Nano with offset
	}
	for _, in := range cases {
		got := parseMondayTime(in)
		if got.IsZero() {
			t.Fatalf("parseMondayTime(%q) returned zero time", in)
		}
		if loc := got.Location(); loc != time.UTC {
			t.Errorf("parseMondayTime(%q) location = %v; want UTC", in, loc)
		}
		want, _ := time.Parse(time.RFC3339Nano, in)
		if !got.Equal(want) {
			t.Errorf("parseMondayTime(%q) = %v; want instant %v", in, got, want)
		}
	}
	// Numeric epoch path already normalizes; assert it stays UTC.
	if got := parseMondayTime("1704106800"); got.Location() != time.UTC {
		t.Errorf("parseMondayTime(epoch) location = %v; want UTC", got.Location())
	}
}
