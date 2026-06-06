package vercel

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

func vercelAuditConfig() map[string]interface{} {
	return map[string]interface{}{"team_id": "team-1"}
}
func vercelAuditSecrets() map[string]interface{} {
	return map[string]interface{}{"api_token": "vercel-token"}
}

func TestVercelFetchAccessAuditLogs_Maps(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/v1/teams/team-1/audit-logs") {
			t.Errorf("path = %s", r.URL.Path)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"events": []map[string]interface{}{
				{
					"id":        "evt-1",
					"type":      "deployment.created",
					"action":    "create",
					"createdAt": int64(1725184800000),
					"principal": map[string]string{"id": "u-1", "email": "user@example.com"},
					"entity":    map[string]string{"id": "dep-1", "type": "deployment"},
				},
			},
			"pagination": map[string]interface{}{},
		})
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var collected []*access.AuditLogEntry
	var nextSince time.Time
	err := c.FetchAccessAuditLogs(context.Background(), vercelAuditConfig(), vercelAuditSecrets(),
		map[string]time.Time{},
		func(batch []*access.AuditLogEntry, n time.Time, _ string) error {
			collected = append(collected, batch...)
			nextSince = n
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) != 1 || collected[0].TargetType != "deployment" || collected[0].ActorEmail != "user@example.com" {
		t.Fatalf("collected = %+v", collected)
	}
	if nextSince.IsZero() {
		t.Errorf("nextSince zero")
	}
}

func TestVercelFetchAccessAuditLogs_NotAvailableNoTeam(t *testing.T) {
	c := New()
	err := c.FetchAccessAuditLogs(context.Background(), map[string]interface{}{}, vercelAuditSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if !errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v", err)
	}
}

func TestVercelFetchAccessAuditLogs_NotAvailableHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusPaymentRequired)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), vercelAuditConfig(), vercelAuditSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if !errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v", err)
	}
}
