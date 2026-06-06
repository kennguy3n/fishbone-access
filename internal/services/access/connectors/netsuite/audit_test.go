package netsuite

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
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/record/v1/systemNote") {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if auth := r.Header.Get("Authorization"); !strings.HasPrefix(auth, "Bearer ") {
			t.Errorf("missing bearer auth: %q", auth)
		}
		calls++
		w.Header().Set("Content-Type", "application/json")
		offset := r.URL.Query().Get("offset")
		if offset == "0" || offset == "" {
			_ = json.NewEncoder(w).Encode(netsuiteSystemNotePage{
				HasMore: true,
				Items: []netsuiteSystemNote{
					{ID: "n1", Type: "Create", Date: "2024-02-01T10:00:00.000Z", Name: "admin@example.com", Record: "employee-7"},
				},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(netsuiteSystemNotePage{
			HasMore: false,
			Items: []netsuiteSystemNote{
				{ID: "n2", Type: "Edit", Date: "2024-02-01T11:00:00Z", Name: "alice@example.com", Record: "employee-8", Field: "department"},
			},
		})
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }

	var collected []*access.AuditLogEntry
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC)},
		func(batch []*access.AuditLogEntry, _ time.Time, _ string) error {
			collected = append(collected, batch...)
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if calls != 2 {
		t.Errorf("calls = %d; want 2", calls)
	}
	if len(collected) != 2 {
		t.Fatalf("collected %d; want 2", len(collected))
	}
	if collected[0].EventType != "Create" || collected[0].TargetExternalID != "employee-7" {
		t.Errorf("entry 0 = %+v", collected[0])
	}
	if collected[1].TargetType != "department" {
		t.Errorf("entry 1 TargetType = %q", collected[1].TargetType)
	}
}

func TestFetchAccessAuditLogs_NotAvailable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"type":"https://example/insufficient-permissions"}`))
	}))
	t.Cleanup(server.Close)
	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Now().Add(-time.Hour)},
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
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(), nil,
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err == nil {
		t.Fatal("expected provider error")
	}
	if err == access.ErrAuditNotAvailable {
		t.Fatalf("err = ErrAuditNotAvailable; want generic error")
	}
}

func TestMapNetSuiteSystemNote_DropsUnparseableTimestamp(t *testing.T) {
	// A non-empty but unparseable date must not produce a zero-timestamp entry.
	got := mapNetSuiteSystemNote(&netsuiteSystemNote{ID: "n1", Type: "Create", Date: "01/02/2024 10:00", Record: "employee-7"})
	if got != nil {
		t.Fatalf("expected nil for unparseable timestamp, got %+v", got)
	}
}

func TestMapNetSuiteSystemNote_DropsEmptyID(t *testing.T) {
	// A valid date but empty id must be dropped so EventID is never empty.
	got := mapNetSuiteSystemNote(&netsuiteSystemNote{ID: "   ", Type: "Create", Date: "2024-02-01T10:00:00Z", Record: "employee-7"})
	if got != nil {
		t.Fatalf("expected nil for empty event id, got %+v", got)
	}
}

func TestFetchAccessAuditLogs_NotAvailableOn404(t *testing.T) {
	// A 404 from the systemNote endpoint must soft-skip the tenant
	// (ErrAuditNotAvailable), consistent with every other audit connector.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"type":"https://example/not-found"}`))
	}))
	t.Cleanup(server.Close)
	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Now().Add(-time.Hour)},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err != access.ErrAuditNotAvailable {
		t.Fatalf("err = %v; want ErrAuditNotAvailable", err)
	}
}
