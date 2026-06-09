package workflow

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
)

// fakeResolver returns a fixed connector implementation for any id, so the
// provisioning service can drive a grant to completion without a real connector
// row or sealed secrets. It mirrors how the production DB resolver hands back a
// ResolvedConnector, but with an in-memory MockAccessConnector.
type fakeResolver struct{ impl access.AccessConnector }

func (r fakeResolver) Resolve(_ context.Context, _, _ uuid.UUID) (*lifecycle.ResolvedConnector, error) {
	return &lifecycle.ResolvedConnector{Provider: "mock", Impl: r.impl}, nil
}

// TestGrantAdapter_GrantRoleApprovesBeforeProvision is the regression test for
// the bug where grantAdapter.GrantRole created a request (StateRequested) and
// called Provision directly. Provision only accepts an approved request, so the
// requested → provisioning transition was rejected by the FSM and EVERY live
// grant_role / provision_connector step failed. The executor unit tests use a
// fakeGranter, so only this adapter-level integration test against the real
// lifecycle services exercises the requested → approved → provisioned path.
func TestGrantAdapter_GrantRoleApprovesBeforeProvision(t *testing.T) {
	db := execTestDB(t)
	ws := uuid.New()

	requests := lifecycle.NewAccessRequestService(db)
	mock := &access.MockAccessConnector{} // ProvisionAccess defaults to a no-op success
	prov := lifecycle.NewAccessProvisioningService(db, requests, fakeResolver{impl: mock})
	prov.SetRetryPolicy(1, func(int) time.Duration { return 0 })

	a := grantAdapter{requests: requests, prov: prov, ws: ws}
	ref, err := a.GrantRole(context.Background(), GrantInput{
		Subject:     Subject{ExternalID: "u1"},
		ConnectorID: uuid.New().String(),
		ResourceRef: "repo:acme/widgets",
		Role:        "maintainer",
	}, "admin")
	if err != nil {
		t.Fatalf("GrantRole returned an error (the requested→approved→provision path must succeed): %v", err)
	}
	if ref == "" {
		t.Fatal("GrantRole returned an empty grant reference")
	}
	if mock.ProvisionAccessCalls != 1 {
		t.Fatalf("connector ProvisionAccess called %d times, want 1", mock.ProvisionAccessCalls)
	}
}
