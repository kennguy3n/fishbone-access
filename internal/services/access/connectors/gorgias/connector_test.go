package gorgias

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

type noNetworkRoundTripper struct{}

func (noNetworkRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return nil, errors.New("network call attempted")
}

func validConfig() map[string]interface{} { return map[string]interface{}{"account": "acme"} }
func validSecrets() map[string]interface{} {
	return map[string]interface{}{"email": "ops@acme.com", "api_key": "grgsAAAA1234bbbbCCCC"}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_RejectsMissing(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), map[string]interface{}{}, validSecrets()); err == nil {
		t.Error("missing account")
	}
	if err := c.Validate(context.Background(), validConfig(), map[string]interface{}{"email": "e@x.com"}); err == nil {
		t.Error("missing api_key")
	}
}

func TestValidate_RejectsInvalidAccount(t *testing.T) {
	c := New()
	for _, bad := range []string{"acme.example", "acme/x", "acme acme", "-acme", "acme-"} {
		if err := c.Validate(context.Background(), map[string]interface{}{"account": bad}, validSecrets()); err == nil {
			t.Errorf("expected error for account %q", bad)
		}
	}
}

func TestValidate_PureLocal(t *testing.T) {
	prev := http.DefaultTransport
	http.DefaultTransport = noNetworkRoundTripper{}
	t.Cleanup(func() { http.DefaultTransport = prev })
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestRegistryIntegration(t *testing.T) {
	if got, _ := access.GetAccessConnector(ProviderName); got == nil {
		t.Fatal("not registered")
	}
}

func TestSync_PaginatesUsers(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Basic ") {
			t.Errorf("expected Basic auth")
		}
		if r.Header.Get("X-Gorgias-Account") != "acme" {
			t.Errorf("X-Gorgias-Account = %q", r.Header.Get("X-Gorgias-Account"))
		}
		if r.URL.Path != "/api/users" {
			t.Errorf("path = %q", r.URL.Path)
		}
		page := r.URL.Query().Get("page")
		if calls == 1 && page != "1" {
			t.Errorf("page = %q", page)
		}
		if calls == 2 && page != "2" {
			t.Errorf("page = %q", page)
		}
		body := map[string]interface{}{"meta": map[string]interface{}{"next_page": 0}}
		if calls == 1 {
			items := make([]map[string]interface{}, 0, pageSize)
			for i := 0; i < pageSize; i++ {
				items = append(items, map[string]interface{}{"id": i + 1, "firstname": "U", "lastname": fmt.Sprintf("%d", i), "email": fmt.Sprintf("u%d@x.com", i), "active": true})
			}
			body["data"] = items
			body["meta"] = map[string]interface{}{"next_page": 2}
		} else {
			body["data"] = []map[string]interface{}{{"id": 999, "firstname": "Last", "lastname": "User", "email": "last@x.com", "active": false}}
		}
		b, _ := json.Marshal(body)
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var got []*access.Identity
	err := c.SyncIdentities(context.Background(), validConfig(), validSecrets(), "", func(b []*access.Identity, _ string) error {
		got = append(got, b...)
		return nil
	})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(got) != pageSize+1 || calls != 2 {
		t.Fatalf("got=%d calls=%d", len(got), calls)
	}
	if got[len(got)-1].Status != "inactive" {
		t.Errorf("status = %q", got[len(got)-1].Status)
	}
}

func TestConnect_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.Connect(context.Background(), validConfig(), validSecrets()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("Connect err = %v; want 401", err)
	}
}

// TestSync_CheckpointTracksLocalCursor verifies that the checkpoint emitted to
// the handler always corresponds to the page the loop will fetch next (i.e.
// page+1) — never the API's reported `meta.next_page` value, which can
// disagree and would otherwise cause page skipping on resume.
func TestSync_CheckpointTracksLocalCursor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		body := map[string]interface{}{}
		items := make([]map[string]interface{}, 0, pageSize)
		for i := 0; i < pageSize; i++ {
			items = append(items, map[string]interface{}{"id": i, "firstname": "U", "lastname": page, "email": fmt.Sprintf("u%s@x.com", page), "active": true})
		}
		body["data"] = items
		// Server reports a wildly out-of-band next_page on page 1 so we
		// can prove the connector ignores it for checkpoint emission.
		if page == "1" {
			body["meta"] = map[string]interface{}{"next_page": 99}
		} else {
			body["data"] = []map[string]interface{}{}
			body["meta"] = map[string]interface{}{"next_page": 0}
		}
		b, _ := json.Marshal(body)
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var seen []string
	err := c.SyncIdentities(context.Background(), validConfig(), validSecrets(), "", func(_ []*access.Identity, next string) error {
		seen = append(seen, next)
		return nil
	})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(seen) != 2 {
		t.Fatalf("emitted %d checkpoints, want 2: %v", len(seen), seen)
	}
	if seen[0] != "2" {
		t.Errorf("checkpoint after page 1 = %q, want %q (local cursor, not API next_page=99)", seen[0], "2")
	}
	if seen[1] != "" {
		t.Errorf("final checkpoint = %q, want empty", seen[1])
	}
}

// TestSync_ExternalIDReconcilesWithRevoke locks the fix for the
// identity-format mismatch: SyncIdentities must emit the email (the key
// RevokeAccess/ListEntitlements resolve against), NOT the numeric id.
// Emitting the numeric id silently broke revokes (the email lookup never
// matched, so RevokeAccess returned nil without issuing a DELETE).
func TestSync_ExternalIDReconcilesWithRevoke(t *testing.T) {
	const email = "ada@example.com"
	const userID = 42
	deleted := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/users":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []map[string]interface{}{{"id": userID, "email": email, "role": "agent", "active": true}},
				"meta": map[string]interface{}{"next_page": 0},
			})
		case r.Method == http.MethodDelete && r.URL.Path == fmt.Sprintf("/api/users/%d", userID):
			deleted = true
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	var synced []*access.Identity
	if err := c.SyncIdentities(context.Background(), validConfig(), validSecrets(), "", func(b []*access.Identity, _ string) error {
		synced = append(synced, b...)
		return nil
	}); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(synced) != 1 || synced[0].ExternalID != email {
		t.Fatalf("ExternalID = %q, want %q", synced[0].ExternalID, email)
	}
	// Feed the synced ExternalID straight back into RevokeAccess — it must
	// resolve the numeric id and issue the DELETE.
	if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(),
		access.AccessGrant{UserExternalID: synced[0].ExternalID, ResourceExternalID: "agent"}); err != nil {
		t.Fatalf("RevokeAccess: %v", err)
	}
	if !deleted {
		t.Fatal("RevokeAccess did not issue DELETE — synced ExternalID failed to reconcile")
	}
}

func TestGetCredentialsMetadata_RedactsToken(t *testing.T) {
	md, err := New().GetCredentialsMetadata(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	short, _ := md["key_short"].(string)
	if short == "" || strings.Contains(short, "AAAA1234") {
		t.Errorf("key_short = %q", short)
	}
}
