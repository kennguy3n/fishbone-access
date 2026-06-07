package paypal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func TestPayPalFetchAccessAuditLogs_Maps(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/oauth2/token":
			_, _ = w.Write([]byte(`{"access_token":"tok-123"}`))
		case "/v1/reporting/transactions":
			if r.Header.Get("Authorization") != "Bearer tok-123" {
				t.Errorf("auth header missing: %q", r.Header.Get("Authorization"))
			}
			_, _ = w.Write([]byte(`{"transaction_details":[{"transaction_info":{"transaction_id":"T1","transaction_event_code":"T0006","transaction_updated_date":"2024-08-01T12:00:00Z","transaction_status":"S"},"payer_info":{"account_id":"A1","email_address":"a@example.com"}}],"page":1,"total_pages":1}`))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var got []*access.AuditLogEntry
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
		func(batch []*access.AuditLogEntry, _ time.Time, _ string) error {
			got = batch
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(got) != 1 || got[0].EventID != "T1" {
		t.Fatalf("got = %#v", got)
	}
}

func TestPayPalFetchAccessAuditLogs_FirstRunBackfillWindow(t *testing.T) {
	// On the first run (zero since) PayPal must request the widest window the
	// Transaction Search API allows (31 days) rather than only 24h, otherwise
	// up to 30 days of history is silently lost. We assert the start_date is
	// ~31 days before end_date.
	var gotStart, gotEnd string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/oauth2/token":
			_, _ = w.Write([]byte(`{"access_token":"tok-123"}`))
		case "/v1/reporting/transactions":
			gotStart = r.URL.Query().Get("start_date")
			gotEnd = r.URL.Query().Get("end_date")
			_, _ = w.Write([]byte(`{"transaction_details":[],"page":1,"total_pages":1}`))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{}, // no cursor -> zero since
		func([]*access.AuditLogEntry, time.Time, string) error { return nil })
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	start, err := time.Parse(time.RFC3339, gotStart)
	if err != nil {
		t.Fatalf("parse start_date %q: %v", gotStart, err)
	}
	end, err := time.Parse(time.RFC3339, gotEnd)
	if err != nil {
		t.Fatalf("parse end_date %q: %v", gotEnd, err)
	}
	window := end.Sub(start)
	if window < paypalAuditBackfill-time.Minute || window > paypalAuditBackfill+time.Minute {
		t.Errorf("first-run window = %s; want ~%s (PayPal 31d max)", window, paypalAuditBackfill)
	}
}

func TestPayPalFetchAccessAuditLogs_NotAvailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/oauth2/token":
			_, _ = w.Write([]byte(`{"access_token":"tok-123"}`))
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
		func([]*access.AuditLogEntry, time.Time, string) error { return nil })
	if err != access.ErrAuditNotAvailable {
		t.Fatalf("err = %v; want ErrAuditNotAvailable", err)
	}
}

func TestPayPalFetchAccessAuditLogs_TransientFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/oauth2/token":
			_, _ = w.Write([]byte(`{"access_token":"tok-123"}`))
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
		func([]*access.AuditLogEntry, time.Time, string) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("err = %v", err)
	}
}
