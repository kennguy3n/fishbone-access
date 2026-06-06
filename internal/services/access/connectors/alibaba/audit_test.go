package alibaba

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func alibabaAuditSecrets() map[string]interface{} {
	return map[string]interface{}{
		"access_key_id":     "AKID",
		"access_key_secret": "secret",
	}
}

func TestAlibabaFetchAccessAuditLogs_Maps(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("Action") != "LookupEvents" {
			t.Errorf("Action = %s", r.URL.Query().Get("Action"))
		}
		if r.URL.Query().Get("Signature") == "" {
			t.Errorf("missing Signature")
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"Events": []map[string]interface{}{
				{
					"eventId":         "evt-1",
					"eventName":       "CreateUser",
					"eventTime":       "2024-09-01T10:00:00Z",
					"eventSource":     "ram.aliyuncs.com",
					"serviceName":     "Ram",
					"sourceIpAddress": "203.0.113.1",
					"userIdentity":    map[string]string{"principalId": "12345", "userName": "admin"},
					"resourceName":    "user-1",
					"resourceType":    "ACS::RAM::User",
				},
			},
		})
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	c.timeOverride = func() time.Time { return time.Date(2024, 9, 1, 11, 0, 0, 0, time.UTC) }
	c.nonceOverride = func() string { return "nonce" }
	var collected []*access.AuditLogEntry
	err := c.FetchAccessAuditLogs(context.Background(), map[string]interface{}{}, alibabaAuditSecrets(),
		map[string]time.Time{},
		func(batch []*access.AuditLogEntry, _ time.Time, _ string) error {
			collected = append(collected, batch...)
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) != 1 || collected[0].IPAddress != "203.0.113.1" || collected[0].TargetType != "ACS::RAM::User" {
		t.Fatalf("collected = %+v", collected)
	}
}

func TestAlibabaFetchAccessAuditLogs_NotAvailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"Code":"AccessDenied"}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	c.timeOverride = func() time.Time { return time.Date(2024, 9, 1, 11, 0, 0, 0, time.UTC) }
	c.nonceOverride = func() string { return "nonce" }
	err := c.FetchAccessAuditLogs(context.Background(), map[string]interface{}{}, alibabaAuditSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if !errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v", err)
	}
}
