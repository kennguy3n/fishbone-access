package azure

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

func TestFetchAccessAuditLogs_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
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
	if err == nil {
		t.Fatal("expected error")
	}
}
