package namely

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func TestConnectorFlow_FullLifecycle(t *testing.T) {
	const userID = "prf-7"
	const resID = "grp-9"
	isMember := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("auth header missing: %q", r.Header.Get("Authorization"))
		}
		postPath := "/api/v1/profiles/" + userID + "/groups"
		deletePath := "/api/v1/profiles/" + userID + "/groups/" + resID
		switch {
		case r.Method == http.MethodPost && r.URL.Path == postPath:
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), resID) {
				t.Errorf("body missing resource id: %s", string(body))
			}
			if isMember {
				w.WriteHeader(http.StatusConflict)
				return
			}
			isMember = true
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodDelete && r.URL.Path == deletePath:
			if !isMember {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			isMember = false
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == postPath:
			groups := []map[string]interface{}{}
			if isMember {
				groups = append(groups, map[string]interface{}{"id": resID, "name": "Engineering"})
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"groups": groups})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := validConfig()
	secrets := validSecrets()
	grant := access.AccessGrant{UserExternalID: userID, ResourceExternalID: resID}

	if err := c.Validate(context.Background(), cfg, secrets); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	ents, err := c.ListEntitlements(context.Background(), cfg, secrets, userID)
	if err != nil {
		t.Fatalf("ListEntitlements after provision: %v", err)
	}
	if len(ents) != 1 || ents[0].ResourceExternalID != resID {
		t.Fatalf("ents = %#v", ents)
	}
	for i := 0; i < 2; i++ {
		if err := c.RevokeAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("RevokeAccess[%d]: %v", i, err)
		}
	}
	ents, err = c.ListEntitlements(context.Background(), cfg, secrets, userID)
	if err != nil {
		t.Fatalf("ListEntitlements after revoke: %v", err)
	}
	if len(ents) != 0 {
		t.Fatalf("expected empty, got %#v", ents)
	}
}

func TestConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		validConfig(),
		validSecrets(),
		access.AccessGrant{UserExternalID: "prf-7", ResourceExternalID: "grp-9"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}

func TestListEntitlements_SkipsNullID(t *testing.T) {
	// A JSON null id must be skipped, not rendered as the literal "<nil>".
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"groups":[{"id":null,"name":"Ghost"},{"id":"grp-7","name":"Real"}]}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	ents, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "user-1")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(ents) != 1 {
		t.Fatalf("ents = %#v; want exactly 1 (null id skipped)", ents)
	}
	if ents[0].ResourceExternalID != "grp-7" {
		t.Fatalf("ResourceExternalID = %q; want grp-7", ents[0].ResourceExternalID)
	}
}
