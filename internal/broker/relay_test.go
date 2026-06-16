package broker

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

// TestServeControlOwnershipLostDoesNotMarkOffline proves the takeover path is
// crisp: when a heartbeat reveals another replica took over the agent (it
// reconnected elsewhere), the losing replica drops its local tunnel WITHOUT
// touching shared state — it must not flip the agent to offline, must not append
// a misleading AgentOffline event to the immutable audit chain, and must not
// Release the directory row the new owner now holds.
func TestServeControlOwnershipLostDoesNotMarkOffline(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "acme")
	store := NewGormStore(db)
	dir := NewGormSessionDirectory(db, 0)

	agentID := uuid.New()
	now := time.Now()
	if err := db.Create(&models.TargetAgent{
		Base:            models.Base{ID: agentID},
		WorkspaceID:     ws,
		Name:            "agent-1",
		CertFingerprint: "fp-" + agentID.String(),
		CertSerial:      "serial-1",
		CertNotAfter:    now.Add(time.Hour),
		Status:          models.AgentStatusEnrolled,
	}).Error; err != nil {
		t.Fatalf("seed agent: %v", err)
	}

	relay := NewRelay(store, nil, WithCrossReplica(dir, nil, "node-a", "10.0.0.1:7444"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, cli := net.Pipe()
	defer cli.Close()
	ac := &agentConn{identity: AgentIdentity{AgentID: agentID, WorkspaceID: ws}}

	done := make(chan struct{})
	go func() {
		relay.serveControl(ctx, ac, srv)
		close(done)
	}()

	enc := json.NewEncoder(cli)
	// Register: relay A claims ownership (epoch 1).
	if err := enc.Encode(ControlMessage{Type: ControlTypeRegister, Register: &RegisterPayload{Platform: "linux", AgentVersion: "test"}}); err != nil {
		t.Fatalf("write register: %v", err)
	}
	waitOwner(t, dir, ws, agentID, "node-a")

	// Simulate the agent reconnecting to another replica that takes over: a new
	// Claim bumps the epoch, so A's next heartbeat Refresh CAS-fails.
	if _, err := dir.Claim(ctx, ws, agentID, "node-b", "10.0.0.2:7444"); err != nil {
		t.Fatalf("takeover claim: %v", err)
	}

	// Heartbeat on A now loses ownership and drops the (now stale) tunnel.
	if err := enc.Encode(ControlMessage{Type: ControlTypeHeartbeat}); err != nil {
		t.Fatalf("write heartbeat: %v", err)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("serveControl did not return after ownership loss")
	}

	if n := agentOfflineCount(t, db, ws); n != 0 {
		t.Fatalf("AgentOffline audit events = %d, want 0 (tunnel migrated, agent not offline)", n)
	}
	entry, _, err := dir.Lookup(ctx, ws, agentID)
	if err != nil || entry == nil || entry.NodeID != "node-b" {
		t.Fatalf("directory owner = %+v err=%v, want node-b retained (losing replica must not Release)", entry, err)
	}
	var row models.TargetAgent
	if err := db.First(&row, "id = ?", agentID).Error; err != nil {
		t.Fatalf("load agent: %v", err)
	}
	if row.Status == models.AgentStatusOffline {
		t.Fatalf("losing replica wrongly flipped the migrated agent to offline")
	}
}

// claimFailOnceDirectory wraps a SessionDirectory and fails the first Claim, to
// simulate a transient Postgres error at register so we can prove the heartbeat
// re-claims rather than leaving the agent forward-unreachable until reconnect.
type claimFailOnceDirectory struct {
	SessionDirectory
	mu     sync.Mutex
	failed bool
}

func (d *claimFailOnceDirectory) Claim(ctx context.Context, ws, agentID uuid.UUID, nodeID, forwardAddr string) (int64, error) {
	d.mu.Lock()
	first := !d.failed
	d.failed = true
	d.mu.Unlock()
	if first {
		return 0, errors.New("transient claim failure")
	}
	return d.SessionDirectory.Claim(ctx, ws, agentID, nodeID, forwardAddr)
}

// TestServeControlHeartbeatReclaimsAfterClaimFailure proves a transient Claim
// failure at register self-heals: the agent holds no epoch, so the next
// heartbeat re-claims ownership (rather than a Refresh that has nothing to
// update), making the agent forward-reachable without waiting for a reconnect.
func TestServeControlHeartbeatReclaimsAfterClaimFailure(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "acme")
	store := NewGormStore(db)
	dir := &claimFailOnceDirectory{SessionDirectory: NewGormSessionDirectory(db, 0)}

	agentID := uuid.New()
	now := time.Now()
	if err := db.Create(&models.TargetAgent{
		Base:            models.Base{ID: agentID},
		WorkspaceID:     ws,
		Name:            "agent-1",
		CertFingerprint: "fp-" + agentID.String(),
		CertSerial:      "serial-1",
		CertNotAfter:    now.Add(time.Hour),
		Status:          models.AgentStatusEnrolled,
	}).Error; err != nil {
		t.Fatalf("seed agent: %v", err)
	}

	relay := NewRelay(store, nil, WithCrossReplica(dir, nil, "node-a", "10.0.0.1:7444"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, cli := net.Pipe()
	defer cli.Close()
	ac := &agentConn{identity: AgentIdentity{AgentID: agentID, WorkspaceID: ws}}

	done := make(chan struct{})
	go func() {
		relay.serveControl(ctx, ac, srv)
		close(done)
	}()

	enc := json.NewEncoder(cli)
	// Register: the wrapped directory fails this Claim, so no owner row exists.
	if err := enc.Encode(ControlMessage{Type: ControlTypeRegister, Register: &RegisterPayload{Platform: "linux", AgentVersion: "test"}}); err != nil {
		t.Fatalf("write register: %v", err)
	}
	// The failed Claim left no directory entry: the agent is not yet reachable
	// via forwarding.
	if entry, _, _ := dir.Lookup(ctx, ws, agentID); entry != nil {
		t.Fatalf("expected no owner entry after failed claim, got %+v", entry)
	}

	// Heartbeat: with no epoch held, this must re-claim (not Refresh), so the
	// agent becomes forward-reachable.
	if err := enc.Encode(ControlMessage{Type: ControlTypeHeartbeat}); err != nil {
		t.Fatalf("write heartbeat: %v", err)
	}
	waitOwner(t, dir, ws, agentID, "node-a")

	cancel()
	<-done
}

// agentOfflineCount counts agent-offline audit events in a workspace.
func agentOfflineCount(t *testing.T, db *gorm.DB, ws uuid.UUID) int {
	t.Helper()
	var n int64
	if err := db.Model(&models.AuditEvent{}).
		Where("workspace_id = ? AND action = ?", ws, AuditActionAgentOffline).
		Count(&n).Error; err != nil {
		t.Fatalf("count audit events: %v", err)
	}
	return int(n)
}
