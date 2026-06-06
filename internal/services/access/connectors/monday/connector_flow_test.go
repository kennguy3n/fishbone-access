package monday

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// TestConnectorFlow_FullLifecycle drives the Monday.com connector through
// add_users_to_board → boards{subscribers} filter → delete_subscribers_from_board
// using a single httptest.Server that dispatches on the GraphQL request body.
func TestConnectorFlow_FullLifecycle(t *testing.T) {
	var inBoard atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		body := string(bodyBytes)
		switch {
		case strings.Contains(body, "add_users_to_board"):
			if inBoard.Load() {
				_, _ = w.Write([]byte(`{"errors":[{"message":"User is already a subscriber"}]}`))
				return
			}
			inBoard.Store(true)
			_, _ = w.Write([]byte(`{"data":{"add_users_to_board":[42]}}`))
		case strings.Contains(body, "delete_subscribers_from_board"):
			if !inBoard.Load() {
				_, _ = w.Write([]byte(`{"errors":[{"message":"User is not subscribed"}]}`))
				return
			}
			inBoard.Store(false)
			_, _ = w.Write([]byte(`{"data":{"delete_subscribers_from_board":[7]}}`))
		case strings.Contains(body, "boards("):
			if inBoard.Load() {
				_, _ = w.Write([]byte(`{"data":{"boards":[{"id":42,"name":"Marketing","subscribers":[{"id":7}]}]}}`))
				return
			}
			_, _ = w.Write([]byte(`{"data":{"boards":[]}}`))
		default:
			_, _ = w.Write([]byte(`{"data":{}}`))
		}
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)

	if err := c.Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	grant := access.AccessGrant{UserExternalID: "7", ResourceExternalID: "42", Role: "subscriber"}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	ents, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "7")
	if err != nil {
		t.Fatalf("ListEntitlements after provision: %v", err)
	}
	if len(ents) == 0 {
		t.Fatalf("got 0 entitlements after provision")
	}
	for i := 0; i < 2; i++ {
		if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
			t.Fatalf("RevokeAccess[%d]: %v", i, err)
		}
	}
	ents, _ = c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "7")
	if len(ents) != 0 {
		t.Fatalf("got %d entitlements after revoke; want 0", len(ents))
	}
}

func TestConnectorFlow_ProvisionFailsOnPermission(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"errors":[{"message":"Permission denied"}]}`))
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "7", ResourceExternalID: "42",
	})
	if err == nil || !strings.Contains(err.Error(), "Permission") {
		t.Fatalf("want permission error; got %v", err)
	}
}
