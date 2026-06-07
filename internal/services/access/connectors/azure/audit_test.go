package azure

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

func TestFetchAccessAuditLogs_PaginatesAndMaps(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/Microsoft.Insights/eventtypes/management/values") {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.URL.Query().Get("$skiptoken") == "" {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{
						"eventDataId":    "evt-1",
						"eventTimestamp": "2024-01-01T10:00:00Z",
						"operationName":  map[string]interface{}{"value": "Microsoft.Authorization/roleAssignments/write", "localizedValue": "Create role assignment"},
						"status":         map[string]interface{}{"value": "Succeeded"},
						"caller":         "alice@corp.example",
						"resourceId":     "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa1",
						"resourceType":   map[string]interface{}{"value": "Microsoft.Storage/storageAccounts"},
						"category":       map[string]interface{}{"value": "Administrative"},
						"httpRequest":    map[string]interface{}{"clientIpAddress": "203.0.113.1"},
					},
				},
				"nextLink": server.URL + "/subscriptions/sub-1/providers/Microsoft.Insights/eventtypes/management/values?api-version=2015-04-01&$skiptoken=p2",
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"value": []map[string]interface{}{
				{
					"eventDataId":    "evt-2",
					"eventTimestamp": "2024-01-01T11:00:00Z",
					"operationName":  map[string]interface{}{"value": "Microsoft.Authorization/roleAssignments/delete"},
					"status":         map[string]interface{}{"value": "Failed"},
					"caller":         "bob@corp.example",
					"category":       map[string]interface{}{"value": "Administrative"},
				},
			},
		})
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "fake-token", nil }

	var collected []*access.AuditLogEntry
	err := c.FetchAccessAuditLogs(context.Background(),
		map[string]interface{}{"tenant_id": "tnt", "subscription_id": "sub-1"},
		validSecrets(),
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
	if collected[0].Outcome != "succeeded" {
		t.Errorf("entry 0 outcome = %q", collected[0].Outcome)
	}
	if collected[1].Outcome != "failed" {
		t.Errorf("entry 1 outcome = %q", collected[1].Outcome)
	}
	if collected[0].IPAddress != "203.0.113.1" {
		t.Errorf("entry 0 ip = %q", collected[0].IPAddress)
	}
}

// TestFetchAccessAuditLogs_SoftSkip verifies that the permission/availability
// statuses collapse to access.ErrAuditNotAvailable so the audit pipeline
// soft-skips the tenant instead of hard-failing the worker — matching every
// other AccessAuditor in this batch.
func TestFetchAccessAuditLogs_SoftSkip(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
		}))
		c := New()
		c.urlOverride = srv.URL
		c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "fake-token", nil }
		err := c.FetchAccessAuditLogs(context.Background(),
			map[string]interface{}{"tenant_id": "tnt", "subscription_id": "sub-1"},
			validSecrets(),
			map[string]time.Time{access.DefaultAuditPartition: time.Now().Add(-time.Hour)},
			func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
		srv.Close()
		if !errors.Is(err, access.ErrAuditNotAvailable) {
			t.Fatalf("status %d: err = %v, want ErrAuditNotAvailable", status, err)
		}
	}
}

// TestFetchAccessAuditLogs_HardFailure verifies that a genuine server error
// (500) still surfaces as a hard error rather than being soft-skipped.
func TestFetchAccessAuditLogs_HardFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "fake-token", nil }
	err := c.FetchAccessAuditLogs(context.Background(),
		map[string]interface{}{"tenant_id": "tnt", "subscription_id": "sub-1"},
		validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Now().Add(-time.Hour)},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err == nil || errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v, want non-nil hard error", err)
	}
}

// TestFetchAccessAuditLogs_RejectsOffHostPagination pins the assertSameARMHost
// guard on the activity-log pagination walk: an absolute nextLink pointing off
// the configured ARM host must be refused rather than followed, since the loop
// attaches the bearer token. Mirrors the doJSON same-host guard on the Graph
// sync paths and the GitHub/Sentry audit guards. The off-host server must never
// be contacted.
func TestFetchAccessAuditLogs_RejectsOffHostPagination(t *testing.T) {
	contacted := false
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contacted = true
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("bearer token leaked off-host: %q", got)
		}
		_, _ = w.Write([]byte(`{"value":[]}`))
	}))
	t.Cleanup(evil.Close)

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// First page is empty but points nextLink off-host.
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"value":    []map[string]interface{}{},
			"nextLink": evil.URL + "/subscriptions/sub-1/providers/Microsoft.Insights/eventtypes/management/values?api-version=2015-04-01&$skiptoken=p2",
		})
	}))
	t.Cleanup(api.Close)

	c := New()
	c.urlOverride = api.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "fake-token", nil }
	err := c.FetchAccessAuditLogs(context.Background(),
		map[string]interface{}{"tenant_id": "tnt", "subscription_id": "sub-1"},
		validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err == nil {
		t.Fatal("expected error for off-host audit pagination, got nil")
	}
	if !strings.Contains(err.Error(), "unexpected host") {
		t.Fatalf("error = %v; want host-mismatch refusal", err)
	}
	if contacted {
		t.Fatal("off-host server was contacted with the bearer token")
	}
}
