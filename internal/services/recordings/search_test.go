package recordings

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

// indexFixture seeds and indexes a session with the given facts, returning its id.
func indexFixture(t *testing.T, db *gorm.DB, svc *Service, ws, target uuid.UUID, subject, proto string, started time.Time, cmds ...string) uuid.UUID {
	t.Helper()
	end := started.Add(time.Minute)
	session := seedSession(t, db, ws, target, subject, proto, models.PAMSessionClosed, started, &end)
	for i, c := range cmds {
		seedCommand(t, db, ws, session, int64(i+1), c, models.PAMDecisionAllow, "")
	}
	if err := svc.IndexSession(context.Background(), ws, session); err != nil {
		t.Fatalf("index fixture: %v", err)
	}
	return session
}

func TestSearchFacetsAndFullText(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "acme")
	other := seedWorkspace(t, db, "globex")
	target := seedTarget(t, db, ws, "prod-db", "ssh")
	pgTarget := seedTarget(t, db, ws, "analytics", "postgres")
	otherTarget := seedTarget(t, db, other, "their-db", "ssh")
	svc := NewService(db)

	base := time.Now().Add(-24 * time.Hour).UTC()
	sshSession := indexFixture(t, db, svc, ws, target, "alice@acme.io", "ssh", base, "systemctl restart nginx", "tail -f /var/log/syslog")
	pgSession := indexFixture(t, db, svc, ws, pgTarget, "bob@acme.io", "postgres", base.Add(time.Hour), "SELECT * FROM customers", "DROP TABLE staging")
	// A different tenant's recording must never appear in acme's results.
	indexFixture(t, db, svc, other, otherTarget, "mallory@globex.io", "ssh", base, "systemctl restart nginx")

	t.Run("full text over commands", func(t *testing.T) {
		res, err := svc.Search(context.Background(), ws, SearchQuery{Text: "nginx"})
		if err != nil {
			t.Fatalf("search: %v", err)
		}
		if res.Total != 1 || len(res.Recordings) != 1 {
			t.Fatalf("total = %d (rows %d), want 1", res.Total, len(res.Recordings))
		}
		if res.Recordings[0].SessionID != sshSession {
			t.Errorf("got session %s, want %s", res.Recordings[0].SessionID, sshSession)
		}
	})

	t.Run("full text matches target name", func(t *testing.T) {
		// The target's (non-secret) display name is part of the FTS payload, so an
		// auditor can find a session by typing the target into the search box, not
		// only via the dedicated facet filter.
		res, err := svc.Search(context.Background(), ws, SearchQuery{Text: "prod-db"})
		if err != nil {
			t.Fatalf("search: %v", err)
		}
		if res.Total != 1 || res.Recordings[0].SessionID != sshSession {
			t.Fatalf("full-text target match total=%d, want the ssh session", res.Total)
		}
	})

	t.Run("full text matches sql statement", func(t *testing.T) {
		res, err := svc.Search(context.Background(), ws, SearchQuery{Text: "customers"})
		if err != nil {
			t.Fatalf("search: %v", err)
		}
		if res.Total != 1 || res.Recordings[0].SessionID != pgSession {
			t.Fatalf("want pg session for 'customers', got total=%d", res.Total)
		}
	})

	t.Run("protocol facet", func(t *testing.T) {
		res, err := svc.Search(context.Background(), ws, SearchQuery{Protocol: "postgres"})
		if err != nil {
			t.Fatalf("search: %v", err)
		}
		if res.Total != 1 || res.Recordings[0].Protocol != "postgres" {
			t.Fatalf("protocol facet total=%d", res.Total)
		}
	})

	t.Run("operator facet", func(t *testing.T) {
		res, err := svc.Search(context.Background(), ws, SearchQuery{Operator: "alice@acme.io"})
		if err != nil {
			t.Fatalf("search: %v", err)
		}
		if res.Total != 1 || res.Recordings[0].Operator != "alice@acme.io" {
			t.Fatalf("operator facet total=%d", res.Total)
		}
	})

	t.Run("target facet matches substring", func(t *testing.T) {
		res, err := svc.Search(context.Background(), ws, SearchQuery{Target: "prod-db"})
		if err != nil {
			t.Fatalf("search: %v", err)
		}
		if res.Total != 1 || res.Recordings[0].SessionID != sshSession {
			t.Fatalf("target facet total=%d, want the ssh session", res.Total)
		}
	})

	t.Run("target facet escapes LIKE wildcards", func(t *testing.T) {
		// "prod_db" must be matched literally: the underscore is a LIKE wildcard
		// that would otherwise match the dash in "prod-db". Escaping it means no
		// recording matches.
		res, err := svc.Search(context.Background(), ws, SearchQuery{Target: "prod_db"})
		if err != nil {
			t.Fatalf("search: %v", err)
		}
		if res.Total != 0 {
			t.Fatalf("target facet total=%d, want 0 (underscore must not act as a wildcard)", res.Total)
		}
	})

	t.Run("time range excludes earlier session", func(t *testing.T) {
		from := base.Add(30 * time.Minute)
		res, err := svc.Search(context.Background(), ws, SearchQuery{From: &from})
		if err != nil {
			t.Fatalf("search: %v", err)
		}
		if res.Total != 1 || res.Recordings[0].SessionID != pgSession {
			t.Fatalf("time range total=%d, want only pg session", res.Total)
		}
	})

	t.Run("empty query lists workspace newest first", func(t *testing.T) {
		res, err := svc.Search(context.Background(), ws, SearchQuery{})
		if err != nil {
			t.Fatalf("search: %v", err)
		}
		if res.Total != 2 {
			t.Fatalf("total = %d, want 2 (tenant isolation)", res.Total)
		}
		if res.Recordings[0].SessionID != pgSession {
			t.Errorf("newest-first ordering broken: first = %s", res.Recordings[0].SessionID)
		}
	})
}

func TestSearchPaginationTotal(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "acme")
	target := seedTarget(t, db, ws, "db", "ssh")
	svc := NewService(db)
	base := time.Now().Add(-10 * time.Hour).UTC()
	for i := 0; i < 5; i++ {
		indexFixture(t, db, svc, ws, target, "a@acme.io", "ssh", base.Add(time.Duration(i)*time.Hour), "ls")
	}
	res, err := svc.Search(context.Background(), ws, SearchQuery{Limit: 2, Offset: 0})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if res.Total != 5 {
		t.Errorf("total = %d, want 5", res.Total)
	}
	if len(res.Recordings) != 2 {
		t.Errorf("page size = %d, want 2", len(res.Recordings))
	}
}
