package xero

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func xeroAuditConfig() map[string]interface{} {
	return map[string]interface{}{"tenant_id": "t-1"}
}
func xeroAuditSecrets() map[string]interface{} {
	return map[string]interface{}{"access_token": "tok"}
}

func TestXeroFetchAccessAuditLogs_Maps(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Xero-Tenant-Id") != "t-1" {
			t.Errorf("tenant header = %q", r.Header.Get("Xero-Tenant-Id"))
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"Journals": []map[string]interface{}{{
				"JournalID":      "j-1",
				"JournalNumber":  1001,
				"CreatedDateUTC": "2024-09-01T10:00:00Z",
				"SourceID":       "inv-9",
				"SourceType":     "ACCRECPAYMENT",
			}},
		})
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var collected []*access.AuditLogEntry
	err := c.FetchAccessAuditLogs(context.Background(), xeroAuditConfig(), xeroAuditSecrets(),
		map[string]time.Time{},
		func(batch []*access.AuditLogEntry, _ time.Time, _ string) error {
			collected = append(collected, batch...)
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) != 1 || collected[0].EventID != "j-1" {
		t.Fatalf("collected = %+v", collected)
	}
}

func TestXeroFetchAccessAuditLogs_NotAvailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), xeroAuditConfig(), xeroAuditSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if !errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v", err)
	}
}

func TestXeroFetchAccessAuditLogs_TransientFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), xeroAuditConfig(), xeroAuditSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("err = %v", err)
	}
}
