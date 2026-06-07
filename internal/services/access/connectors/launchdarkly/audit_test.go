package launchdarkly

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

func ldAuditConfig() map[string]interface{} { return map[string]interface{}{} }
func ldAuditSecrets() map[string]interface{} {
	return map[string]interface{}{"api_key": "api-aaaa-bbbb"}
}

func TestLaunchDarklyFetchAccessAuditLogs_MapsAndPaginatesNewestFirst(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/api/v2/auditlog" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got == "" {
			t.Errorf("Authorization empty")
		}
		body := map[string]interface{}{}
		if calls == 1 {
			items := []map[string]interface{}{}
			for i := 0; i < 100; i++ {
				items = append(items, map[string]interface{}{
					"_id":              "evt-" + fmtInt(i),
					"kind":             "flag",
					"name":             "Updated flag",
					"date":             int64(1709251200000) + int64(i*1000),
					"member":           map[string]string{"_id": "m-1", "email": "a@example.com"},
					"target":           map[string]string{"kind": "flag", "name": "x", "key": "feature-x"},
					"titleVerb":        "updated",
					"shortDescription": "updated flag",
				})
			}
			body["items"] = items
		} else {
			body["items"] = []map[string]interface{}{
				{
					"_id":       "evt-final",
					"kind":      "member",
					"name":      "Removed member",
					"date":      int64(1709251200000),
					"member":    map[string]string{"_id": "m-2", "email": "b@example.com"},
					"target":    map[string]string{"kind": "member", "name": "Bob", "key": "bob"},
					"titleVerb": "removed",
				},
			}
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	var collected []*access.AuditLogEntry
	var nextSince time.Time
	err := c.FetchAccessAuditLogs(context.Background(), ldAuditConfig(), ldAuditSecrets(),
		map[string]time.Time{},
		func(batch []*access.AuditLogEntry, n time.Time, _ string) error {
			collected = append(collected, batch...)
			nextSince = n
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) != 101 {
		t.Fatalf("len = %d", len(collected))
	}
	// First yielded entry should be evt-final (oldest, from page 2 reversed).
	if collected[0].EventID != "evt-final" {
		t.Errorf("first = %s, want evt-final", collected[0].EventID)
	}
	// Largest timestamp = page 1 entry 99 at base + 99 seconds.
	want := time.UnixMilli(int64(1709251200000) + 99*1000).UTC()
	if !nextSince.Equal(want) {
		t.Errorf("nextSince = %s, want %s", nextSince, want)
	}
	if calls != 2 {
		t.Errorf("calls = %d", calls)
	}
}

func TestLaunchDarklyFetchAccessAuditLogs_NotAvailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), ldAuditConfig(), ldAuditSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if !errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v, want ErrAuditNotAvailable", err)
	}
}

func TestLaunchDarklyFetchAccessAuditLogs_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), ldAuditConfig(), ldAuditSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err == nil || errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v", err)
	}
}

func TestLaunchDarklyMapAuditEntry_DropsZeroDate(t *testing.T) {
	// A row with Date == 0 must be dropped — otherwise time.UnixMilli(0)
	// would emit a 1970-01-01 timestamp into the batch and poison the cursor.
	got := mapLaunchDarklyAuditEntry(&launchDarklyAuditEntry{
		ID:   "evt-zero",
		Kind: "flag",
		Name: "Created flag",
		Date: 0,
	})
	if got != nil {
		t.Fatalf("mapLaunchDarklyAuditEntry(Date=0) = %#v, want nil", got)
	}
}

func fmtInt(i int) string {
	if i == 0 {
		return "0"
	}
	out := ""
	for i > 0 {
		out = string(rune('0'+i%10)) + out
		i /= 10
	}
	return out
}
