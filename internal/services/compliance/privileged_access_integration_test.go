//go:build integration

package compliance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/gateway"
	"github.com/kennguy3n/fishbone-access/internal/migrations"
	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
	"github.com/kennguy3n/fishbone-access/internal/services/access"
	"github.com/kennguy3n/fishbone-access/internal/services/pam"
)

// TestPrivilegedSessionEvidenceEndToEndPostgres is the WS3 success-criteria
// guard: it threads a *real* gateway recording (bytes captured, persisted, and
// SHA-256'd by the production IORecorder) through the production PAM control
// plane (mint → redeem → command → recording → close) and then proves the
// compliance layer surfaces it — CC6.7 / A.8.2 show non-zero, control-mapped
// evidence, and the evidence pack carries a recording reference whose integrity
// hash recomputes from the exact bytes in the replay store.
//
// It runs against Postgres (the dialect the audit chain ships on) and is the
// one test that demonstrates the four deliverables compose end to end rather
// than only in isolation.
func TestPrivilegedSessionEvidenceEndToEndPostgres(t *testing.T) {
	dsn := os.Getenv("ACCESS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("ACCESS_TEST_DATABASE_URL not set; skipping Postgres PAM-evidence scenario test")
	}
	ctx := context.Background()
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql db handle: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	if _, err := sqlDB.ExecContext(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	if _, err := migrations.Run(ctx, sqlDB); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	ws := &models.Workspace{Name: "tenant-pam", IAMCoreTenantID: "tenant-pam-" + uuid.NewString(), Plan: "base"}
	if err := db.Create(ws).Error; err != nil {
		t.Fatalf("seed workspace: %v", err)
	}

	// 1) Capture a real privileged-session recording through the gateway
	//    recorder and persist it, exactly as a live proxy teardown does.
	sessionKey := "scenario-" + uuid.NewString()
	store := gateway.NewMemoryReplayStore()
	rec := gateway.NewIORecorder(ctx, sessionKey, 0)
	rec.Record(gateway.DirInput, []byte("SELECT secret FROM vault;\n"))
	rec.Record(gateway.DirOutput, []byte("redacted\n"))
	if err := rec.Flush(ctx, store); err != nil {
		t.Fatalf("recorder flush: %v", err)
	}
	recording := rec.Recording()
	if !recording.Stored || recording.SHA256 == "" {
		t.Fatalf("expected a stored recording with a digest, got %+v", recording)
	}

	// 2) Drive the full privileged-session lifecycle through the production
	//    PAM services, anchoring the recording reference we just produced.
	enc, err := access.CredentialEncryptorFromKey(os.Getenv("ACCESS_CREDENTIAL_DEK"))
	if err != nil {
		t.Fatalf("encryptor: %v", err)
	}
	vault := pam.NewVault(db, enc, nil)
	broker := pam.NewBroker(db, vault, nil)
	sessions := pam.NewSessionManager(db, nil, nil)
	seeder := pam.NewSeeder(vault, broker, sessions)

	res, err := seeder.SeedPrivilegedSession(ctx, pam.SeedPrivilegedSessionInput{
		WorkspaceID: ws.ID,
		Subject:     "alice",
		Actor:       "admin",
		TargetName:  "prod-db",
		Protocol:    models.PAMProtocolSSH,
		Address:     "db.internal:22",
		Secret:      pam.Secret{Password: "pw"},
		Commands:    []string{"SELECT secret FROM vault;"},
		Recording: pam.RecordingRef{
			Key:       recording.Key,
			SHA256:    recording.SHA256,
			Bytes:     recording.Bytes,
			Truncated: recording.Truncated,
		},
	})
	if err != nil {
		t.Fatalf("SeedPrivilegedSession: %v", err)
	}
	if !res.Recorded || res.Commands != 1 {
		t.Fatalf("unexpected seed result: %+v", res)
	}

	svc := NewEvidenceService(db)

	// The seeded chain must verify (the events are real, chained audit rows).
	if v, err := svc.VerifyChain(ctx, ws.ID); err != nil || !v.OK {
		t.Fatalf("VerifyChain: ok=%v err=%v", v.OK, err)
	}

	// 3) CC6.7 / A.8.2 now show real, non-zero privileged-access evidence.
	cov, err := svc.PrivilegedAccessCoverage(ctx, ws.ID, nil, nil)
	if err != nil {
		t.Fatalf("PrivilegedAccessCoverage: %v", err)
	}
	if !cov.Monitored || cov.Sessions < 2 || cov.Commands < 1 || cov.Recordings < 1 {
		t.Fatalf("expected monitored privileged access with sessions/commands/recordings, got %+v", cov)
	}
	covered := map[string]bool{}
	for _, c := range cov.Controls {
		if c.Covered {
			covered[c.ID] = true
		}
	}
	for _, id := range []string{"CC6.7", "A.8.2"} {
		if !covered[id] {
			t.Fatalf("expected control %s covered after scenario", id)
		}
	}

	// 4) The evidence pack ties the CC6.7 record to a tamper-evident recording:
	//    the indexed digest must recompute from the exact persisted bytes.
	pw := NewPackWriter(db, svc)
	var buf bytes.Buffer
	if _, err := pw.WritePack(ctx, &buf, ExportOptions{WorkspaceID: ws.ID, Framework: FrameworkSOC2, GeneratedBy: "auditor"}); err != nil {
		t.Fatalf("WritePack: %v", err)
	}
	files := readZip(t, buf.Bytes())
	raw, ok := files["pam-recordings.jsonl"]
	if !ok {
		t.Fatalf("pack missing pam-recordings.jsonl (have %v)", keys(files))
	}
	var row recordingIndexRow
	if err := json.Unmarshal(bytes.TrimSpace(raw), &row); err != nil {
		t.Fatalf("recording row unmarshal: %v", err)
	}

	persisted, ok := store.Get(sessionKey)
	if !ok {
		t.Fatalf("replay bytes missing from store for %s", sessionKey)
	}
	sum := sha256.Sum256(persisted)
	wantHex := hex.EncodeToString(sum[:])
	if row.SHA256 != wantHex {
		t.Fatalf("pack recording digest %q != sha256 of persisted replay %q", row.SHA256, wantHex)
	}
	if row.SHA256 != recording.SHA256 {
		t.Fatalf("pack digest %q != recorder digest %q", row.SHA256, recording.SHA256)
	}
	if row.Bytes != int64(len(persisted)) {
		t.Fatalf("pack recording bytes %d != persisted len %d", row.Bytes, len(persisted))
	}
	if row.ChainHash == "" {
		t.Fatalf("recording index row missing anchoring chain hash")
	}
}
