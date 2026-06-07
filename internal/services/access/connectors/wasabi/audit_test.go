package wasabi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func wasabiAuditSecrets() map[string]interface{} {
	return map[string]interface{}{
		"access_key_id":     "AKID",
		"secret_access_key": "secret",
	}
}

func TestWasabiFetchAccessAuditLogs_Maps(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			t.Errorf("missing Authorization")
		}
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "Action=LookupEvents") {
			t.Errorf("body = %s", string(body))
		}
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<LookupEventsResponse>
<LookupEventsResult>
<Events>
<ResourceListEntry/>
<Event>
<EventId>evt-1</EventId>
<EventName>CreateUser</EventName>
<EventTime>2024-09-01T10:00:00Z</EventTime>
<Username>admin@example.com</Username>
<EventSource>iam.amazonaws.com</EventSource>
<Resources><ResourceListEntry><ResourceName>user-1</ResourceName><ResourceType>AWS::IAM::User</ResourceType></ResourceListEntry></Resources>
</Event>
</Events>
</LookupEventsResult>
</LookupEventsResponse>`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	c.timeOverride = func() time.Time { return time.Date(2024, 9, 1, 11, 0, 0, 0, time.UTC) }
	var collected []*access.AuditLogEntry
	err := c.FetchAccessAuditLogs(context.Background(), map[string]interface{}{}, wasabiAuditSecrets(),
		map[string]time.Time{},
		func(batch []*access.AuditLogEntry, _ time.Time, _ string) error {
			collected = append(collected, batch...)
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) != 1 || collected[0].TargetExternalID != "user-1" || collected[0].ActorExternalID != "admin@example.com" {
		t.Fatalf("collected = %+v", collected)
	}
}

func TestWasabiFetchAccessAuditLogs_NotAvailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>AccessDenied</Code></Error></ErrorResponse>`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	c.timeOverride = func() time.Time { return time.Date(2024, 9, 1, 11, 0, 0, 0, time.UTC) }
	err := c.FetchAccessAuditLogs(context.Background(), map[string]interface{}{}, wasabiAuditSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if !errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v", err)
	}
}
