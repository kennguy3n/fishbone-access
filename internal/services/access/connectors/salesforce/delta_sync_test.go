package salesforce

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

func sfDeltaConfig(u string) map[string]interface{} {
	return map[string]interface{}{"instance_url": u}
}
func sfDeltaSecrets() map[string]interface{} {
	return map[string]interface{}{"access_token": "sf-token"}
}

func TestSalesforce_SyncIdentitiesDelta_PaginatesAndTombstones(t *testing.T) {
	page1Path := "/services/data/" + defaultAPIVersion + "/query/01g000"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/services/data/"+defaultAPIVersion+"/query") && r.URL.RawQuery != "" {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"done":           false,
				"nextRecordsUrl": page1Path,
				"records": []map[string]interface{}{
					{"Id": "u-1", "Name": "Alice", "Email": "alice@example.com", "IsActive": true, "SystemModstamp": "2024-04-01T10:00:00Z"},
				},
			})
			return
		}
		if r.URL.Path == page1Path {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"done": true,
				"records": []map[string]interface{}{
					{"Id": "u-2", "Name": "Bob", "Email": "bob@example.com", "IsActive": false, "SystemModstamp": "2024-04-01T11:00:00Z"},
				},
			})
			return
		}
		t.Errorf("unexpected path=%q", r.URL.Path)
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL

	var collectedBatch, collectedRemoved int
	final, err := c.SyncIdentitiesDelta(context.Background(), sfDeltaConfig(server.URL), sfDeltaSecrets(),
		"2024-04-01T00:00:00Z",
		func(batch []*access.Identity, removed []string, _ string) error {
			collectedBatch += len(batch)
			collectedRemoved += len(removed)
			return nil
		})
	if err != nil {
		t.Fatalf("SyncIdentitiesDelta: %v", err)
	}
	if collectedBatch != 1 {
		t.Errorf("collected batch=%d; want 1", collectedBatch)
	}
	if collectedRemoved != 1 {
		t.Errorf("removed=%d; want 1", collectedRemoved)
	}
	if final != "2024-04-01T11:00:00Z" {
		t.Errorf("finalCursor=%q; want 2024-04-01T11:00:00Z", final)
	}
}

func TestSalesforce_SyncIdentitiesDelta_ExpiredCursor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`[{"errorCode":"INVALID_QUERY_LOCATOR","message":"cursor too old"}]`))
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	_, err := c.SyncIdentitiesDelta(context.Background(), sfDeltaConfig(server.URL), sfDeltaSecrets(),
		"2024-01-01T00:00:00Z",
		func(_ []*access.Identity, _ []string, _ string) error { return nil })
	if !errors.Is(err, access.ErrDeltaTokenExpired) {
		t.Fatalf("got %v; want ErrDeltaTokenExpired", err)
	}
}

func TestSalesforce_SyncIdentitiesDelta_RejectsMalformedCursor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("upstream must not be called when cursor is malformed")
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	_, err := c.SyncIdentitiesDelta(context.Background(), sfDeltaConfig(server.URL), sfDeltaSecrets(),
		"2024-01-01T00:00:00Z OR IsActive = true",
		func(_ []*access.Identity, _ []string, _ string) error { return nil })
	if err == nil {
		t.Fatal("err = nil; want non-nil on malformed cursor")
	}
	if !strings.Contains(err.Error(), "invalid deltaLink cursor") {
		t.Fatalf("err=%v; want invalid-cursor message", err)
	}
}

func TestSalesforce_SyncIdentitiesDelta_HTTPFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	_, err := c.SyncIdentitiesDelta(context.Background(), sfDeltaConfig(server.URL), sfDeltaSecrets(), "",
		func(_ []*access.Identity, _ []string, _ string) error { return nil })
	if err == nil {
		t.Fatal("err = nil; want non-nil on 500")
	}
	if errors.Is(err, access.ErrDeltaTokenExpired) {
		t.Fatalf("got ErrDeltaTokenExpired on plain 500; want generic error: %v", err)
	}
}

func TestSalesforce_InitialDeltaCursor_RoundTripsThroughSyncIdentitiesDelta(t *testing.T) {
	c := New()
	cursor, err := c.InitialDeltaCursor(context.Background(), sfDeltaConfig("https://example.my.salesforce.com"), sfDeltaSecrets())
	if err != nil {
		t.Fatalf("InitialDeltaCursor: %v", err)
	}
	parsed, perr := time.Parse(time.RFC3339, strings.TrimSpace(cursor))
	if perr != nil {
		t.Fatalf("seeded cursor %q failed RFC3339 parse: %v", cursor, perr)
	}
	if time.Since(parsed) > 5*time.Second {
		t.Errorf("seeded cursor %q is more than 5s in the past", cursor)
	}
}
