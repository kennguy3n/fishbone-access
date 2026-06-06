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

// TestMapSalesforceEventLog_EmptyOrInvalid ensures records whose
// LogDate is empty or unparseable are filtered out (return nil) rather
// than emitted with a zero (0001-01-01) Timestamp. Every other audit
// mapper drops zero-timestamp entries; emitting them pollutes the audit
// pipeline and can corrupt cursor advancement.
func TestMapSalesforceEventLog_EmptyOrInvalid(t *testing.T) {
	if e := mapSalesforceEventLog(&sfEventLogRecord{ID: "0AT1", LogDate: ""}); e != nil {
		t.Errorf("empty LogDate: got %+v, want nil (zero timestamp must be filtered)", e)
	}
	if e := mapSalesforceEventLog(&sfEventLogRecord{ID: "0AT1", LogDate: "not-a-timestamp"}); e != nil {
		t.Errorf("garbage LogDate: got %+v, want nil (zero timestamp must be filtered)", e)
	}
	if e := mapSalesforceEventLog(nil); e != nil {
		t.Errorf("nil record: got %+v, want nil", e)
	}
	if e := mapSalesforceEventLog(&sfEventLogRecord{ID: ""}); e != nil {
		t.Errorf("empty ID: got %+v, want nil", e)
	}
}

// TestFetchAccessAuditLogs_Failure verifies that 401/403/404 (tenant
// edition lacks EventLogFile access) surface as access.ErrAuditNotAvailable
// so the audit worker soft-skips, matching every other AccessAuditor.
func TestFetchAccessAuditLogs_Failure(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(code)
		}))
		c := New()
		c.urlOverride = srv.URL
		c.httpClient = func() httpDoer { return srv.Client() }
		err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
			map[string]time.Time{access.DefaultAuditPartition: time.Now().Add(-time.Hour)},
			func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
		if err != access.ErrAuditNotAvailable {
			t.Errorf("status %d: err = %v; want ErrAuditNotAvailable", code, err)
		}
		srv.Close()
	}
}

// TestFetchAccessAuditLogs_ServerError verifies a 5xx remains a hard
// error (not soft-skipped).
func TestFetchAccessAuditLogs_ServerError(t *testing.T) {
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
	if err == nil || err == access.ErrAuditNotAvailable {
		t.Fatalf("err = %v; want generic hard error", err)
	}
}
