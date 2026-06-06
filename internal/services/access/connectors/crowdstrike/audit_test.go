package crowdstrike

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func TestFetchAccessAuditLogs_PaginatesAndMaps(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2/token":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "tok", "expires_in": 3600, "token_type": "bearer",
			})
		case "/user-management/queries/user-login-history/v1":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"resources": []string{"uuid-1"},
				"meta": map[string]interface{}{
					"pagination": map[string]interface{}{"offset": 0, "limit": 200, "total": 1},
				},
			})
		case "/user-management/entities/user-login-history/v1":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"resources": []map[string]interface{}{
					{
						"UUID": "uuid-1",
						"uid":  "alice@example.com",
						"user_logins": []map[string]interface{}{
							{"user_uuid": "uuid-1", "login_time": "2024-01-01T10:00:00Z", "success": true},
							{"user_uuid": "uuid-1", "login_time": "2024-01-01T11:00:00Z", "success": false},
						},
					},
				},
			})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }

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
	if collected[0].Outcome != "success" || collected[0].ActorEmail != "alice@example.com" {
		t.Errorf("entry 0 = %+v", collected[0])
	}
	if collected[1].Outcome != "failure" {
		t.Errorf("entry 1 outcome = %q; want failure", collected[1].Outcome)
	}
}

func TestFetchAccessAuditLogs_Forbidden_SoftSkip(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/token" {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "expires_in": 3600})
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errors":[{"code":403}]}`))
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
