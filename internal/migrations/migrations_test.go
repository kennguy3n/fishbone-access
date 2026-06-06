package migrations

import (
	"strings"
	"testing"
)

func TestLoadOrdersAndParses(t *testing.T) {
	migs, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(migs) == 0 {
		t.Fatal("Load returned no migrations")
	}
	// Versions must be strictly increasing (lexical == apply order).
	for i := 1; i < len(migs); i++ {
		if migs[i-1].Version >= migs[i].Version {
			t.Fatalf("migrations not ordered: %s >= %s", migs[i-1].Version, migs[i].Version)
		}
	}
	first := migs[0]
	if first.Version != "0001" || first.Name != "init" {
		t.Errorf("first migration = %s_%s, want 0001_init", first.Version, first.Name)
	}
	// The init migration must create the ten core tables.
	for _, table := range []string{
		"workspaces", "teams", "team_members", "access_connectors", "access_jobs",
		"access_requests", "access_grants", "access_reviews", "policies", "audit_events",
	} {
		if !strings.Contains(first.SQL, "CREATE TABLE IF NOT EXISTS "+table) {
			t.Errorf("0001_init missing table %q", table)
		}
	}
}
