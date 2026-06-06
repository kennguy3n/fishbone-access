package slack

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// TestConnectorFlow_FullLifecycle walks the Slack connector through
// Validate → ProvisionAccess (conversations.invite) → ListEntitlements
// (users.conversations) → RevokeAccess (conversations.kick). Slack's
// 4xx error model is "200 OK with {"ok":false,"error":"..."}" so the
// mock keeps an `in` flag and returns ok=true/false accordingly.
func TestConnectorFlow_FullLifecycle(t *testing.T) {
	var in atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/conversations.invite"):
			if in.Load() {
				_, _ = w.Write([]byte(`{"ok":false,"error":"already_in_channel"}`))
				return
			}
			in.Store(true)
			_, _ = w.Write([]byte(`{"ok":true,"channel":{"id":"C123"}}`))
		case strings.HasSuffix(r.URL.Path, "/conversations.kick"):
			if !in.Load() {
				_, _ = w.Write([]byte(`{"ok":false,"error":"not_in_channel"}`))
				return
			}
			in.Store(false)
			_, _ = w.Write([]byte(`{"ok":true}`))
		case strings.Contains(r.URL.Path, "/users.conversations"):
			if in.Load() {
				_, _ = w.Write([]byte(`{"ok":true,"channels":[{"id":"C123","name":"general"}],"response_metadata":{"next_cursor":""}}`))
				return
			}
			_, _ = w.Write([]byte(`{"ok":true,"channels":[],"response_metadata":{"next_cursor":""}}`))
		default:
			_, _ = w.Write([]byte(`{"ok":true}`))
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	if err := c.Validate(context.Background(), nil, validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	grant := access.AccessGrant{UserExternalID: "U1", ResourceExternalID: "C123"}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), nil, validSecrets(), grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	ents, err := c.ListEntitlements(context.Background(), nil, validSecrets(), "U1")
	if err != nil {
		t.Fatalf("ListEntitlements after provision: %v", err)
	}
	if len(ents) == 0 {
		t.Fatalf("ListEntitlements after provision: got 0, want >=1")
	}
	for i := 0; i < 2; i++ {
		if err := c.RevokeAccess(context.Background(), nil, validSecrets(), grant); err != nil {
			t.Fatalf("RevokeAccess[%d]: %v", i, err)
		}
	}
	ents, _ = c.ListEntitlements(context.Background(), nil, validSecrets(), "U1")
	if len(ents) != 0 {
		t.Fatalf("ListEntitlements after revoke: got %d, want 0", len(ents))
	}
}

func TestConnectorFlow_ProvisionFailsOnInvalidChannel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":false,"error":"channel_not_found"}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(), nil, validSecrets(), access.AccessGrant{
		UserExternalID: "U1", ResourceExternalID: "C999",
	})
	if err == nil || !strings.Contains(err.Error(), "channel_not_found") {
		t.Fatalf("want channel_not_found error, got %v", err)
	}
}
