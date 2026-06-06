package lastpass

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// TestConnectorFlow_FullLifecycle exercises the LastPass connector lifecycle:
// batchchangegrp (provision/revoke) and getsfdata (list_entitlements). The
// LastPass API uses POST with a JSON body whose "cmd" field selects the
// operation, so the mock branches on cmd.
func TestConnectorFlow_FullLifecycle(t *testing.T) {
	var assigned bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		switch body["cmd"] {
		case "batchchangegrp":
			data, _ := body["data"].(map[string]interface{})
			switch data["op"] {
			case "add":
				assigned = true
				_, _ = w.Write([]byte(`{"status":"OK"}`))
			case "del":
				if !assigned {
					_, _ = w.Write([]byte(`{"status":"FAIL","errors":["User is not in the group"]}`))
					return
				}
				assigned = false
				_, _ = w.Write([]byte(`{"status":"OK"}`))
			}
		case "getsfdata":
			folders := []lastpassSharedFolder{}
			if assigned {
				folders = append(folders, lastpassSharedFolder{
					SharedFolderID:   "sf-Engineering",
					SharedFolderName: "Engineering",
					Users: []lastpassFolderMember{{
						Username: "alice@example.com", UserID: "uid1",
					}},
				})
			}
			_ = json.NewEncoder(w).Encode(lastpassSharedFolderDataResponse{Folders: folders})
		default:
			_, _ = w.Write([]byte(`{"status":"OK"}`))
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	if err := c.Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	grant := access.AccessGrant{UserExternalID: "alice@example.com", ResourceExternalID: "Engineering"}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}

	ents, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "alice@example.com")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(ents) == 0 {
		t.Fatalf("expected provisioned grant to appear, got 0")
	}

	for i := 0; i < 2; i++ {
		if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
			t.Fatalf("RevokeAccess[%d]: %v", i, err)
		}
	}

	ents, _ = c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "alice@example.com")
	if len(ents) != 0 {
		t.Fatalf("ListEntitlements after revoke: got %d, want 0", len(ents))
	}
}

func TestConnectorFlow_ConnectFailsWithBadCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"FAIL","errors":["unauthorized"]}`))
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	if err := c.Connect(context.Background(), validConfig(), validSecrets()); err == nil {
		t.Fatal("Connect with FAIL: expected error, got nil")
	}
}
