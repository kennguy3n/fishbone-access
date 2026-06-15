package gateway

import (
	"context"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
)

// TestGormSessionWorkspaceResolverResolvesSoftDeletedSession proves the resolver
// is UNSCOPED: a recording's per-workspace DEK must stay derivable even after the
// owning PAM session row is soft-deleted, otherwise the encrypted blob would
// become permanently unreadable for forensic replay/retention.
func TestGormSessionWorkspaceResolverResolvesSoftDeletedSession(t *testing.T) {
	t.Parallel()

	db, err := database.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := database.AutoMigrate(db); err != nil {
		t.Fatalf("auto-migrate: %v", err)
	}

	ws := &models.Workspace{Name: "acme", IAMCoreTenantID: "acme", Plan: "base"}
	if err := db.Create(ws).Error; err != nil {
		t.Fatalf("seed workspace: %v", err)
	}
	target := &models.PAMTarget{WorkspaceID: ws.ID, Name: "db1", Protocol: "postgres", Address: "10.0.0.1:5432"}
	if err := db.Create(target).Error; err != nil {
		t.Fatalf("seed target: %v", err)
	}
	session := &models.PAMSession{WorkspaceID: ws.ID, TargetID: target.ID, Subject: "alice", Protocol: "postgres", State: "closed"}
	if err := db.Create(session).Error; err != nil {
		t.Fatalf("seed session: %v", err)
	}

	r := NewGormSessionWorkspaceResolver(db)
	ctx := context.Background()

	got, err := r.WorkspaceForSession(ctx, session.ID.String())
	if err != nil {
		t.Fatalf("resolve before delete: %v", err)
	}
	if got != ws.ID.String() {
		t.Fatalf("workspace before delete = %q, want %q", got, ws.ID.String())
	}

	// Soft-delete the session: a default-scoped query would now miss it.
	if err := db.Delete(session).Error; err != nil {
		t.Fatalf("soft-delete session: %v", err)
	}

	got, err = r.WorkspaceForSession(ctx, session.ID.String())
	if err != nil {
		t.Fatalf("resolve after soft-delete: %v (the DEK binding would be lost, making the blob unreadable)", err)
	}
	if got != ws.ID.String() {
		t.Fatalf("workspace after soft-delete = %q, want %q", got, ws.ID.String())
	}
}
