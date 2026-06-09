package compliance

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

// readZip reads a zip archive from b into a name->bytes map.
func readZip(t *testing.T, b []byte) map[string][]byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}
	out := map[string][]byte{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open zip entry %s: %v", f.Name, err)
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("read zip entry %s: %v", f.Name, err)
		}
		out[f.Name] = data
	}
	return out
}

func countLines(b []byte) int {
	n := 0
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) != "" {
			n++
		}
	}
	return n
}

func TestWritePackContentsAndMapping(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	conn := seedConnector(t, db, ws, "fake")
	ctx := context.Background()

	// Seed evidence that credits SOC 2 controls + a campaign.
	appendEvent(t, db, ws, "policy.promoted", "p1")
	appendEvent(t, db, ws, "access_grant.created", "g1")
	seedGrant(t, db, ws, conn, "u1", "prod/db", "reader")

	cert := NewCertificationService(db, newFakeRevoker(db))
	if _, _, err := cert.StartCampaign(ctx, ws, CampaignInput{Name: "c"}, "auditor"); err != nil {
		t.Fatalf("start campaign: %v", err)
	}

	ev := NewEvidenceService(db)
	pw := NewPackWriter(db, ev)

	var buf bytes.Buffer
	manifest, err := pw.WritePack(ctx, &buf, ExportOptions{WorkspaceID: ws, Framework: FrameworkSOC2, GeneratedBy: "auditor"})
	if err != nil {
		t.Fatalf("WritePack: %v", err)
	}

	files := readZip(t, buf.Bytes())
	for _, want := range []string{"README.md", "evidence.jsonl", "access-grants.jsonl", "certification-campaigns.jsonl", "certification-items.jsonl", "policies.jsonl", "control-coverage.json", "chain-verification.json", "manifest.json"} {
		if _, ok := files[want]; !ok {
			t.Fatalf("pack missing %s (have %v)", want, keys(files))
		}
	}

	// evidence.jsonl row count matches the manifest + at least our 3 events
	// (2 appended + 1 campaign.started).
	evLines := countLines(files["evidence.jsonl"])
	if evLines != manifest.EvidenceTotal {
		t.Fatalf("evidence.jsonl lines %d != manifest total %d", evLines, manifest.EvidenceTotal)
	}
	if evLines < 3 {
		t.Fatalf("expected >=3 evidence rows, got %d", evLines)
	}

	// manifest parses and the content digest recomputes from the per-file digests.
	var parsed PackManifest
	if err := json.Unmarshal(files["manifest.json"], &parsed); err != nil {
		t.Fatalf("manifest unmarshal: %v", err)
	}
	if parsed.ContentSHA256 == "" || parsed.ContentSHA256 != contentDigest(parsed.Files) {
		t.Fatalf("content digest mismatch")
	}
	if parsed.ChainVerification.Status != chainStatusValid {
		t.Fatalf("expected valid chain in manifest, got %s", parsed.ChainVerification.Status)
	}

	// README documents the framework + at least one control id.
	readme := string(files["README.md"])
	if !strings.Contains(readme, string(FrameworkSOC2)) || !strings.Contains(readme, "CC6.1") {
		t.Fatalf("README missing framework/control mapping: %s", readme)
	}

	// Coverage in the pack credits CC6.1 (policy.promoted + access_grant.created).
	var cov FrameworkCoverage
	if err := json.Unmarshal(files["control-coverage.json"], &cov); err != nil {
		t.Fatalf("coverage unmarshal: %v", err)
	}
	covered := false
	for _, c := range cov.Controls {
		if c.ID == "CC6.1" && c.Covered {
			covered = true
		}
	}
	if !covered {
		t.Fatalf("expected CC6.1 covered in pack coverage")
	}
}

func TestWritePackUnknownFramework(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	pw := NewPackWriter(db, NewEvidenceService(db))
	var buf bytes.Buffer
	_, err := pw.WritePack(context.Background(), &buf, ExportOptions{WorkspaceID: ws, Framework: Framework("HIPAA")})
	if !errors.Is(err, ErrUnknownFramework) {
		t.Fatalf("expected ErrUnknownFramework, got %v", err)
	}
}

func TestWritePackCrossTenantExcludesOtherTenant(t *testing.T) {
	db := newTestDB(t)
	wsA := seedWorkspace(t, db, "tenant-a")
	wsB := seedWorkspace(t, db, "tenant-b")
	ctx := context.Background()

	appendEvent(t, db, wsA, "policy.promoted", "pa")
	appendEvent(t, db, wsB, "policy.promoted", "pb")
	connB := seedConnector(t, db, wsB, "fake")
	seedGrant(t, db, wsB, connB, "ub", "rb", "reader")

	pw := NewPackWriter(db, NewEvidenceService(db))
	var buf bytes.Buffer
	manifest, err := pw.WritePack(ctx, &buf, ExportOptions{WorkspaceID: wsA, Framework: FrameworkSOC2, GeneratedBy: "auditor"})
	if err != nil {
		t.Fatalf("WritePack: %v", err)
	}
	files := readZip(t, buf.Bytes())

	// Only ws A's single event; ws B's grant absent.
	if got := countLines(files["evidence.jsonl"]); got != manifest.EvidenceTotal || got != 1 {
		t.Fatalf("expected 1 evidence row for ws A, got %d (manifest %d)", got, manifest.EvidenceTotal)
	}
	if got := countLines(files["access-grants.jsonl"]); got != 0 {
		t.Fatalf("expected 0 grants for ws A, got %d", got)
	}
	// Defensive: ws B's target ref must not appear anywhere in the stream.
	if bytes.Contains(files["evidence.jsonl"], []byte("\"pb\"")) {
		t.Fatalf("cross-tenant evidence leak")
	}
}

func keys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
