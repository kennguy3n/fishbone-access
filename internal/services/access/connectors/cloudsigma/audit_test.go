package cloudsigma

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

func csAuditConfig() map[string]interface{} {
	return map[string]interface{}{"region": "zrh"}
}
func csAuditSecrets() map[string]interface{} {
	return map[string]interface{}{"email": "admin@example.com", "password": "pw"}
}

func TestCloudSigmaFetchAccessAuditLogs_Maps(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/2.0/logs/" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Basic ") {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"objects": []map[string]interface{}{
				{
					"uuid":     "evt-1",
					"time":     "2024-09-01T10:00:00",
					"severity": "info",
					"message":  "Server created",
					"op_name":  "create_server",
					"user":     map[string]string{"uuid": "u-1", "email": "admin@example.com"},
				},
			},
			"meta": map[string]int{"limit": 100, "offset": 0, "total_count": 1},
		})
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var collected []*access.AuditLogEntry
	err := c.FetchAccessAuditLogs(context.Background(), csAuditConfig(), csAuditSecrets(),
		map[string]time.Time{},
		func(batch []*access.AuditLogEntry, _ time.Time, _ string) error {
			collected = append(collected, batch...)
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) != 1 || collected[0].Action != "create_server" || collected[0].ActorEmail != "admin@example.com" {
		t.Fatalf("collected = %+v", collected)
	}
}

func TestCloudSigmaFetchAccessAuditLogs_NotAvailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), csAuditConfig(), csAuditSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if !errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v", err)
	}
}
