// Command freshenagents emits the heartbeat a connected outbound agent would be
// sending right now, so the console renders online agents as Online rather than
// Stale when the screenshot harness runs.
//
// An agent's health is derived (internal/broker/directory.go): Online requires
// status=online AND a last_seen within HealthOfflineAfter (90s). The seed
// materialises the durable agent row, its issued-cert fields, and its
// self-reported reachable bindings — everything except the one thing a seed
// binary cannot hold: a live mTLS socket. last_seen IS that socket's heartbeat
// signal, so bumping it to now for already-online agents is a faithful stand-in
// for a connected agent, not a fabricated state. It is deliberately a no-op for
// offline/revoked agents, so their real health still shows through.
package main

import (
	"context"
	"flag"
	"os"
	"time"

	"github.com/kennguy3n/fishbone-access/blog/harness/harnesskit"
	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
)

func main() {
	dbURL := flag.String("db", os.Getenv("ACCESS_DATABASE_URL"), "Postgres URL (defaults to $ACCESS_DATABASE_URL)")
	flag.Parse()
	if *dbURL == "" {
		harnesskit.Fatalf("ACCESS_DATABASE_URL (or -db) is required")
	}

	db, err := database.Open(*dbURL)
	if err != nil {
		harnesskit.Fatalf("open database: %v", err)
	}

	now := time.Now().UTC()
	res := db.WithContext(context.Background()).
		Model(&models.TargetAgent{}).
		Where("status = ?", models.AgentStatusOnline).
		Update("last_seen_at", now)
	if res.Error != nil {
		harnesskit.Fatalf("freshen agent heartbeats: %v", res.Error)
	}
	harnesskit.Logf("OK   freshened %d online agent heartbeat(s) to %s", res.RowsAffected, now.Format(time.RFC3339))
}
