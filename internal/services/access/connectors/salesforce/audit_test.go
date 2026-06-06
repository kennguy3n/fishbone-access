package salesforce

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
	call := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/services/data/v59.0/query") {
			t.Errorf("path = %s", r.URL.Path)
		}
		switch call {
		case 0:
			call++
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"done":           false,
				"totalSize":      2,
				"nextRecordsUrl": "/services/data/v59.0/query/01g000-2000",
				"records": []map[string]interface{}{
					{
						"attributes": map[string]interface{}{"type": "EventLogFile", "url": "/services/data/v59.0/sobjects/EventLogFile/0AT1"},
						"Id":         "0AT1",
						"EventType":  "Login",
						"LogDate":    "2024-01-01T10:00:00.000+0000",
					},
				},
			})
		case 1:
			call++
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"done":      true,
				"totalSize": 2,
				"records": []map[string]interface{}{
					{
						"attributes": map[string]interface{}{"type": "EventLogFile"},
						"Id":         "0AT2",
						"EventType":  "Logout",
						"LogDate":    "2024-01-01T11:00:00.000+0000",
					},
				},
			})
		}
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
	if len(collected) != 2 {
		t.Fatalf("len = %d", len(collected))
	}
	if collected[0].EventType != "Login" || collected[1].EventType != "Logout" {
		t.Errorf("event types = %s, %s", collected[0].EventType, collected[1].EventType)
	}
	// LogDate parsing must produce non-zero, wall-clock-correct
	// timestamps; otherwise cursor advancement silently stalls and
	// the worker re-fetches the same EventLogFile records forever.
	wantE1 := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)
	wantE2 := time.Date(2024, 1, 1, 11, 0, 0, 0, time.UTC)
	if !collected[0].Timestamp.Equal(wantE1) {
		t.Errorf("collected[0].Timestamp = %s, want %s (LogDate=%q)", collected[0].Timestamp, wantE1, "2024-01-01T10:00:00.000+0000")
	}
	if !collected[1].Timestamp.Equal(wantE2) {
		t.Errorf("collected[1].Timestamp = %s, want %s (LogDate=%q)", collected[1].Timestamp, wantE2, "2024-01-01T11:00:00.000+0000")
	}
}

// TestMapSalesforceEventLog_ParsesLogDateFormats covers every Salesforce
// REST timestamp shape we've seen in the wild. The canonical format is
// "2024-01-01T10:00:00.000+0000" — not RFC3339 (the offset has no colon
// and there are milliseconds in the middle) — which silently parsed to
// zero time before the multi-layout fallback was added.
func TestMapSalesforceEventLog_ParsesLogDateFormats(t *testing.T) {
	want := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name    string
		logDate string
	}{
		{"salesforce_canonical_+0000", "2024-01-01T10:00:00.000+0000"},
		{"salesforce_canonical_offset", "2024-01-01T05:00:00.000-0500"},
		{"rfc3339_z", "2024-01-01T10:00:00Z"},
		{"rfc3339_z_with_millis", "2024-01-01T10:00:00.000Z"},
		{"rfc3339_with_colon_offset", "2024-01-01T10:00:00.000+00:00"},
		{"compact_offset_no_millis", "2024-01-01T10:00:00+0000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entry := mapSalesforceEventLog(&sfEventLogRecord{
				ID:        "0AT1",
				EventType: "Login",
				LogDate:   tc.logDate,
			})
			if entry == nil {
				t.Fatalf("mapSalesforceEventLog returned nil")
			}
			if entry.Timestamp.IsZero() {
				t.Fatalf("Timestamp is zero (logDate=%q) — cursor would stall", tc.logDate)
			}
			if !entry.Timestamp.UTC().Equal(want) {
				t.Errorf("Timestamp = %s, want %s (logDate=%q)", entry.Timestamp.UTC(), want, tc.logDate)
			}
		})
	}
}

// TestMapSalesforceEventLog_EmptyOrInvalid documents the
// already-defensive empty-input behaviour and ensures it stays
// defensive (zero time, no panic) when fed garbage.
func TestMapSalesforceEventLog_EmptyOrInvalid(t *testing.T) {
	if e := mapSalesforceEventLog(&sfEventLogRecord{ID: "0AT1", LogDate: ""}); e == nil || !e.Timestamp.IsZero() {
		t.Errorf("empty LogDate: got %+v, want non-nil entry with zero Timestamp", e)
	}
	if e := mapSalesforceEventLog(&sfEventLogRecord{ID: "0AT1", LogDate: "not-a-timestamp"}); e == nil || !e.Timestamp.IsZero() {
		t.Errorf("garbage LogDate: got %+v, want non-nil entry with zero Timestamp", e)
	}
	if e := mapSalesforceEventLog(nil); e != nil {
		t.Errorf("nil record: got %+v, want nil", e)
	}
	if e := mapSalesforceEventLog(&sfEventLogRecord{ID: ""}); e != nil {
		t.Errorf("empty ID: got %+v, want nil", e)
	}
}

func TestFetchAccessAuditLogs_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
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
