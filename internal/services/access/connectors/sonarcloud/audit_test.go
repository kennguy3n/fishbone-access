package sonarcloud

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

func sonarcloudAuditConfig() map[string]interface{} {
	return map[string]interface{}{"organization": "acme"}
}
func sonarcloudAuditSecrets() map[string]interface{} {
	return map[string]interface{}{"token": "sonar-token"}
}

func TestSonarCloudFetchAccessAuditLogs_Maps(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/audit_logs/search" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.URL.Query().Get("organization") != "acme" {
			t.Errorf("org = %q", r.URL.Query().Get("organization"))
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"paging": map[string]interface{}{"pageIndex": 1, "pageSize": 100, "total": 1},
			"auditLogs": []map[string]interface{}{
				{
					"id":         "log-1",
					"category":   "USER",
					"action":     "user_added",
					"userLogin":  "admin",
					"date":       "2024-07-01T10:00:00+0000",
					"targetKey":  "newbie",
					"targetType": "USER",
				},
			},
		})
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var collected []*access.AuditLogEntry
	var nextSince time.Time
	err := c.FetchAccessAuditLogs(context.Background(), sonarcloudAuditConfig(), sonarcloudAuditSecrets(),
		map[string]time.Time{},
		func(batch []*access.AuditLogEntry, n time.Time, _ string) error {
			collected = append(collected, batch...)
			nextSince = n
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) != 1 || collected[0].Action != "user_added" {
		t.Fatalf("collected = %+v", collected)
	}
	if nextSince.IsZero() {
		t.Error("nextSince zero")
	}
}

func TestSonarCloudFetchAccessAuditLogs_NotAvailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), sonarcloudAuditConfig(), sonarcloudAuditSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if !errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v", err)
	}
}

func TestSonarCloudFetchAccessAuditLogs_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), sonarcloudAuditConfig(), sonarcloudAuditSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err == nil || errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v", err)
	}
}
