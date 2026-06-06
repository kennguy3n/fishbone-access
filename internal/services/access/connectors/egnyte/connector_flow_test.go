package egnyte

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func TestConnectorFlow_FullLifecycle(t *testing.T) {
	var member atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPatch && strings.HasSuffix(r.URL.Path, "/pubapi/v2/groups/GRP1"):
			body := make([]byte, 512)
			n, _ := r.Body.Read(body)
			isAdd := strings.Contains(string(body[:n]), `"add"`)
			isRemove := strings.Contains(string(body[:n]), `"remove"`)
			switch {
			case isAdd:
				if member.Load() {
					w.WriteHeader(http.StatusConflict)
					return
				}
				member.Store(true)
				_, _ = w.Write([]byte(`{}`))
			case isRemove:
				if !member.Load() {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				member.Store(false)
				_, _ = w.Write([]byte(`{}`))
			default:
				_, _ = w.Write([]byte(`{}`))
			}
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/pubapi/v2/groups"):
			if member.Load() {
				_, _ = w.Write([]byte(`{"startIndex":1,"itemsPerPage":1,"totalResults":1,"resources":[{"id":99,"displayName":"GRP1","members":[{"value":"10"}]}]}`))
				return
			}
			_, _ = w.Write([]byte(`{"startIndex":1,"itemsPerPage":0,"totalResults":0,"resources":[]}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/pubapi/v1/userinfo"):
			_, _ = w.Write([]byte(`{"username":"me"}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	if err := c.Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	grant := access.AccessGrant{UserExternalID: "10", ResourceExternalID: "GRP1"}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	ents, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "10")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(ents) == 0 {
		t.Fatalf("got 0 after provision")
	}
	for i := 0; i < 2; i++ {
		if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
			t.Fatalf("RevokeAccess[%d]: %v", i, err)
		}
	}
	ents, _ = c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "10")
	if len(ents) != 0 {
		t.Fatalf("got %d after revoke", len(ents))
	}
}

func TestConnectorFlow_ProvisionFailsOn403(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "10", ResourceExternalID: "GRP1",
	})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("want 403; got %v", err)
	}
}
