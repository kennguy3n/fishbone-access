package google_workspace

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func TestSyncIdentitiesDelta_PaginatesAndMapsUserEvents(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/activity/users/all/applications/admin") {
			t.Errorf("path = %s", r.URL.Path)
		}
		switch r.URL.Query().Get("pageToken") {
		case "":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"items": []map[string]interface{}{
					{
						"id": map[string]interface{}{
							"time":            "2024-04-01T10:00:00Z",
							"uniqueQualifier": "ev-1",
							"applicationName": "admin",
						},
						"actor": map[string]interface{}{"email": "admin@example.com", "profileId": "admin-1"},
						"events": []map[string]interface{}{
							{
								"name": "CREATE_USER",
								"parameters": []map[string]interface{}{
									{"name": "USER_ID", "value": "u-1"},
									{"name": "USER_EMAIL", "value": "alice@example.com"},
								},
							},
						},
					},
				},
				"nextPageToken": "p2",
			})
		case "p2":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"items": []map[string]interface{}{
					{
						"id": map[string]interface{}{
							"time":            "2024-04-01T11:00:00Z",
							"uniqueQualifier": "ev-2",
							"applicationName": "admin",
						},
						"actor": map[string]interface{}{"email": "admin@example.com", "profileId": "admin-1"},
						"events": []map[string]interface{}{
							{
								"name": "DELETE_USER",
								"parameters": []map[string]interface{}{
									{"name": "USER_ID", "value": "u-2"},
									{"name": "USER_EMAIL", "value": "bob@example.com"},
								},
							},
						},
					},
				},
			})
		default:
			t.Errorf("unexpected pageToken=%s", r.URL.Query().Get("pageToken"))
		}
	}))
	t.Cleanup(server.Close)

	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) (httpDoer, error) {
		return &fakeDirectoryClient{base: server.URL, c: server.Client()}, nil
	}

	var batchSize, removedCount int
	final, err := c.SyncIdentitiesDelta(context.Background(), validConfig(), validSecrets(t), "",
		func(batch []*access.Identity, removed []string, _ string) error {
			batchSize += len(batch)
			removedCount += len(removed)
			return nil
		})
	if err != nil {
		t.Fatalf("SyncIdentitiesDelta: %v", err)
	}
	if batchSize != 1 {
		t.Errorf("batch identities = %d; want 1", batchSize)
	}
	if removedCount != 1 {
		t.Errorf("removed = %d; want 1", removedCount)
	}
	if final == "" {
		t.Error("finalDeltaLink empty; want non-empty cursor for next sync")
	}
	if !strings.Contains(final, "startTime=") {
		t.Errorf("finalDeltaLink missing startTime: %q", final)
	}
}

func TestSyncIdentitiesDelta_410ReturnsErrDeltaTokenExpired(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusGone)
		_, _ = w.Write([]byte(`{"error":{"code":410,"message":"cursor gone"}}`))
	}))
	t.Cleanup(server.Close)

	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) (httpDoer, error) {
		return &fakeDirectoryClient{base: server.URL, c: server.Client()}, nil
	}
	_, err := c.SyncIdentitiesDelta(context.Background(), validConfig(), validSecrets(t),
		server.URL+"/admin/reports/v1/activity/users/all/applications/admin?startTime=stale",
		func(_ []*access.Identity, _ []string, _ string) error { return nil })
	if !errors.Is(err, access.ErrDeltaTokenExpired) {
		t.Fatalf("got %v; want ErrDeltaTokenExpired", err)
	}
}

func TestSyncIdentitiesDelta_400WithExpiredCursor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"code":400,"message":"startTime is too old","status":"INVALID_ARGUMENT"}}`))
	}))
	t.Cleanup(server.Close)

	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) (httpDoer, error) {
		return &fakeDirectoryClient{base: server.URL, c: server.Client()}, nil
	}
	_, err := c.SyncIdentitiesDelta(context.Background(), validConfig(), validSecrets(t),
		server.URL+"/admin/reports/v1/activity/users/all/applications/admin?startTime=stale",
		func(_ []*access.Identity, _ []string, _ string) error { return nil })
	if !errors.Is(err, access.ErrDeltaTokenExpired) {
		t.Fatalf("got %v; want ErrDeltaTokenExpired", err)
	}
}

// TestSyncIdentitiesDelta_IgnoresDeleteUserFailure locks in that the
// audit event DELETE_USER_FAILURE — emitted by the Admin SDK when an
// admin attempts to delete a user but the operation fails — does NOT
// feed the removed list. Otherwise the orchestrator would treat the
// still-extant user as deleted.
func TestSyncIdentitiesDelta_IgnoresDeleteUserFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"items": []map[string]interface{}{
				{
					"id": map[string]interface{}{
						"time":            "2024-04-01T12:00:00Z",
						"uniqueQualifier": "ev-3",
						"applicationName": "admin",
					},
					"actor": map[string]interface{}{"email": "admin@example.com", "profileId": "admin-1"},
					"events": []map[string]interface{}{
						{
							"name": "DELETE_USER_FAILURE",
							"parameters": []map[string]interface{}{
								{"name": "USER_ID", "value": "u-failed"},
								{"name": "USER_EMAIL", "value": "carol@example.com"},
							},
						},
					},
				},
			},
		})
	}))
	t.Cleanup(server.Close)

	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) (httpDoer, error) {
		return &fakeDirectoryClient{base: server.URL, c: server.Client()}, nil
	}
	var batchSize, removedCount int
	if _, err := c.SyncIdentitiesDelta(context.Background(), validConfig(), validSecrets(t), "",
		func(batch []*access.Identity, removed []string, _ string) error {
			batchSize += len(batch)
			removedCount += len(removed)
			return nil
		}); err != nil {
		t.Fatalf("SyncIdentitiesDelta: %v", err)
	}
	if removedCount != 0 {
		t.Errorf("removed = %d; want 0 (DELETE_USER_FAILURE is not a successful deletion)", removedCount)
	}
	if batchSize != 0 {
		t.Errorf("batch = %d; want 0 (failure event should not emit a created/updated identity)", batchSize)
	}
}

func TestSyncIdentitiesDelta_HTTPFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	t.Cleanup(server.Close)

	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) (httpDoer, error) {
		return &fakeDirectoryClient{base: server.URL, c: server.Client()}, nil
	}
	_, err := c.SyncIdentitiesDelta(context.Background(), validConfig(), validSecrets(t), "",
		func(_ []*access.Identity, _ []string, _ string) error { return nil })
	if err == nil {
		t.Fatal("err = nil; want non-nil on 500")
	}
	if errors.Is(err, access.ErrDeltaTokenExpired) {
		t.Fatalf("got ErrDeltaTokenExpired on plain 500; want generic error: %v", err)
	}
}

func TestGoogleWorkspace_InitialDeltaCursor_BuildsValidActivityURL(t *testing.T) {
	c := New()
	cursor, err := c.InitialDeltaCursor(context.Background(), validConfig(), validSecrets(t))
	if err != nil {
		t.Fatalf("InitialDeltaCursor: %v", err)
	}
	if !strings.HasPrefix(cursor, reportsBaseURL+"/activity/users/all/applications/admin?startTime=") {
		t.Fatalf("seeded cursor %q missing activity-URL prefix", cursor)
	}
	u, perr := url.Parse(cursor)
	if perr != nil {
		t.Fatalf("seeded cursor %q is not a valid URL: %v", cursor, perr)
	}
	startTime := u.Query().Get("startTime")
	parsed, terr := time.Parse(time.RFC3339, startTime)
	if terr != nil {
		t.Fatalf("startTime %q failed RFC3339 parse: %v", startTime, terr)
	}
	if time.Since(parsed) > 5*time.Second {
		t.Errorf("seeded startTime %q is more than 5s in the past", startTime)
	}
	if _, rerr := http.NewRequest(http.MethodGet, cursor, nil); rerr != nil {
		t.Errorf("http.NewRequest(seed) failed: %v", rerr)
	}
}
