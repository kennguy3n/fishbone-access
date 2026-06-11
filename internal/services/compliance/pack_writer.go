package compliance

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

// packSchemaVersion is the stable contract version of the evidence-pack layout.
// External compliance tooling keys off it; bump it only on a breaking change to
// the file set or record shapes.
//
//	1.0 — initial layout.
//	1.1 — adds pam-recordings.jsonl (privileged-session recording references).
//
// Adding a file is additive, but tooling that validates the pack against a
// closed file allowlist treats an unknown file as breaking, so the addition is
// versioned here.
const packSchemaVersion = "1.1"

// PackFileInfo describes one file in the archive: its name, a human comment, the
// number of JSONL rows (0 for non-JSONL files), and the SHA-256 of its bytes.
// The per-file digests are folded into the manifest's ContentSHA256 so the pack
// is integrity-checkable as a whole.
type PackFileInfo struct {
	Name    string `json:"name"`
	Comment string `json:"comment"`
	Rows    int    `json:"rows"`
	SHA256  string `json:"sha256"`
}

// PackManifest is the machine-readable index of an evidence pack. It is written
// last (it embeds every other file's digest) and pretty-printed for human
// inspection. ContentSHA256 is the digest over the sorted per-file digests; the
// same value is recorded in the compliance.export audit event, anchoring the
// pack in the workspace's tamper-evident hash chain — that anchoring, not a
// detached key, is what makes the export verifiable after the fact.
type PackManifest struct {
	SchemaVersion     string            `json:"schema_version"`
	WorkspaceID       uuid.UUID         `json:"workspace_id"`
	Framework         Framework         `json:"framework"`
	From              *time.Time        `json:"from,omitempty"`
	To                *time.Time        `json:"to,omitempty"`
	GeneratedAt       time.Time         `json:"generated_at"`
	GeneratedBy       string            `json:"generated_by"`
	EvidenceTotal     int               `json:"evidence_total"`
	Files             []PackFileInfo    `json:"files"`
	ContentSHA256     string            `json:"content_sha256"`
	ChainVerification ChainVerification `json:"chain_verification"`
	Coverage          FrameworkCoverage `json:"coverage"`
}

// ExportOptions is the fully-resolved, server-derived scope of one export. The
// handler builds it from the validated token + tenant context; nothing here
// comes from an untrusted request body except the framework and period.
type ExportOptions struct {
	WorkspaceID uuid.UUID
	Framework   Framework
	From        *time.Time
	To          *time.Time
	GeneratedBy string
}

// PackWriter assembles framework-mapped evidence packs. It composes the
// evidence service (chain projection + verification + coverage) with the shared
// DB pool for the supporting entity snapshots.
type PackWriter struct {
	db       *gorm.DB
	evidence *EvidenceService
}

// NewPackWriter wires the pack writer.
func NewPackWriter(db *gorm.DB, evidence *EvidenceService) *PackWriter {
	return &PackWriter{db: db, evidence: evidence}
}

// WritePack streams a framework-mapped evidence pack into w as a ZIP and returns
// the manifest (so the caller can record the content digest in the export audit
// event). The big evidence.jsonl and the entity snapshots are streamed row-by-
// row, so exporting a multi-year period holds only one row plus the ZIP buffer
// in memory — safe to run for any of the 5000 tenants without an OOM risk.
//
// Archive layout (stable; documented in docs/compliance/evidence-pack.md):
//
//   - README.md                       auditor-facing description + control map
//   - evidence.jsonl                  the audit-chain evidence stream (period)
//   - pam-recordings.jsonl            privileged-session recording references + hashes
//   - access-grants.jsonl             grants active at any point in the period
//   - certification-campaigns.jsonl   campaigns overlapping the period
//   - certification-items.jsonl       per-grant decisions for those campaigns
//   - policies.jsonl                  policies in force during the period
//   - control-coverage.json           per-control evidence coverage
//   - chain-verification.json         tamper-evidence verdict at export time
//   - manifest.json                   machine-readable index (written last)
func (pw *PackWriter) WritePack(ctx context.Context, w io.Writer, opts ExportOptions) (PackManifest, error) {
	if opts.WorkspaceID == uuid.Nil {
		return PackManifest{}, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	if Controls(opts.Framework) == nil {
		return PackManifest{}, fmt.Errorf("%w: %q", ErrUnknownFramework, opts.Framework)
	}

	verification, err := pw.evidence.VerifyChain(ctx, opts.WorkspaceID)
	if err != nil {
		return PackManifest{}, err
	}
	coverage, err := pw.evidence.Coverage(ctx, opts.WorkspaceID, opts.Framework, opts.From, opts.To)
	if err != nil {
		return PackManifest{}, err
	}

	manifest := PackManifest{
		SchemaVersion:     packSchemaVersion,
		WorkspaceID:       opts.WorkspaceID,
		Framework:         opts.Framework,
		From:              opts.From,
		To:                opts.To,
		GeneratedAt:       time.Now().UTC(),
		GeneratedBy:       opts.GeneratedBy,
		ChainVerification: verification,
		Coverage:          coverage,
	}

	zw := zip.NewWriter(w)

	// Data files first. Both the README's file inventory and the manifest's
	// content digest need every data file's PackFileInfo, so the README and the
	// manifest are assembled last — once the inventory below is complete. ZIP
	// imposes no entry ordering, so this is purely an assembly-order detail and
	// does not affect how an unzip tool presents the files.

	// evidence.jsonl — the chain-derived evidence stream for the period. The same
	// pass collects the privileged-recording references so the recordings index
	// below costs no additional chain scan.
	evInfo, evCount, recordings, err := pw.streamEvidence(ctx, zw, opts)
	if err != nil {
		return PackManifest{}, err
	}
	manifest.EvidenceTotal = evCount
	manifest.Files = append(manifest.Files, evInfo)

	// pam-recordings.jsonl — the privileged-session recording references (replay
	// key + integrity hash) for the period, so an auditor can tie CC6.7/A.8.2
	// evidence to tamper-evident recordings without parsing evidence.jsonl. It is
	// written from the references gathered during the evidence pass above.
	recInfo, err := pw.writeRecordings(zw, recordings)
	if err != nil {
		return PackManifest{}, err
	}
	manifest.Files = append(manifest.Files, recInfo)

	// Supporting entity snapshots.
	grantInfo, err := pw.streamGrants(ctx, zw, opts)
	if err != nil {
		return PackManifest{}, err
	}
	manifest.Files = append(manifest.Files, grantInfo)

	campInfo, itemInfo, err := pw.streamCampaigns(ctx, zw, opts)
	if err != nil {
		return PackManifest{}, err
	}
	manifest.Files = append(manifest.Files, campInfo, itemInfo)

	polInfo, err := pw.streamPolicies(ctx, zw, opts)
	if err != nil {
		return PackManifest{}, err
	}
	manifest.Files = append(manifest.Files, polInfo)

	covInfo, err := pw.writeJSON(zw, "control-coverage.json", "Per-control evidence coverage for the framework over the period.", &coverage)
	if err != nil {
		return PackManifest{}, err
	}
	manifest.Files = append(manifest.Files, covInfo)

	verInfo, err := pw.writeJSON(zw, "chain-verification.json", "Audit hash-chain tamper-evidence verdict computed at export time.", &verification)
	if err != nil {
		return PackManifest{}, err
	}
	manifest.Files = append(manifest.Files, verInfo)

	// README is rendered now that the data-file inventory is populated, so its
	// "## Files" section actually lists the data files (it described nothing
	// when it was written before the inventory existed).
	readmeInfo, err := pw.writeBytes(zw, "README.md", "Auditor-facing guide to this evidence pack.", []byte(renderReadme(&manifest)))
	if err != nil {
		return PackManifest{}, err
	}
	manifest.Files = append(manifest.Files, readmeInfo)

	// ContentSHA256 over the sorted per-file digests makes the pack integrity-
	// checkable as a whole and is the value anchored in the export audit event.
	// manifest.json is excluded by design — it carries this very digest, so
	// folding its own hash in would be circular.
	manifest.ContentSHA256 = contentDigest(manifest.Files)

	if _, err := pw.writeJSON(zw, "manifest.json", "Machine-readable index of this pack (written last).", &manifest); err != nil {
		return PackManifest{}, err
	}

	if err := zw.Close(); err != nil {
		return PackManifest{}, fmt.Errorf("compliance: close zip: %w", err)
	}
	return manifest, nil
}

// streamEvidence writes the period's evidence stream as JSONL, returning the
// file info, the row count, and the privileged-recording references seen in the
// same pass. Collecting the recordings here means the pack indexes them without
// a second scan of the chain: the references are sparse (one per privileged
// session), so buffering only those rows stays bounded well below the full
// evidence stream, which is streamed straight to the archive and never buffered.
func (pw *PackWriter) streamEvidence(ctx context.Context, zw *zip.Writer, opts ExportOptions) (PackFileInfo, int, []recordingIndexRow, error) {
	fw, err := zw.Create("evidence.jsonl")
	if err != nil {
		return PackFileInfo{}, 0, nil, fmt.Errorf("compliance: create evidence.jsonl: %w", err)
	}
	h := sha256.New()
	enc := json.NewEncoder(io.MultiWriter(fw, h))
	count := 0
	var recordings []recordingIndexRow
	if err := pw.evidence.streamPeriod(ctx, opts.WorkspaceID, opts.From, opts.To, func(rec EvidenceRecord) error {
		count++
		if rec.Kind == KindPrivilegedRecording {
			recordings = append(recordings, projectRecordingRow(rec))
		}
		return enc.Encode(rec)
	}); err != nil {
		return PackFileInfo{}, 0, nil, err
	}
	return PackFileInfo{
		Name:    "evidence.jsonl",
		Comment: "Every control-relevant audit-chain event in the period, projected to an evidence record. One JSON object per line, in chain order.",
		Rows:    count,
		SHA256:  hex.EncodeToString(h.Sum(nil)),
	}, count, recordings, nil
}

// recordingIndexRow is one line of pam-recordings.jsonl: a flattened, auditor-
// friendly view of a privileged-session recording reference lifted out of the
// chain. It pairs the replayable artifact (ReplayKey) with its integrity hash
// (SHA256) and the exact chain position (ChainSeq / ChainHash) that anchors it,
// so an auditor can (1) fetch replay.bin, (2) re-hash it and compare to SHA256,
// and (3) confirm that hash is itself pinned in the tamper-evident chain — the
// full CC6.7 / A.8.2 "recording is monitored and unaltered" argument in one row.
type recordingIndexRow struct {
	ChainSeq   int64     `json:"chain_seq"`
	OccurredAt time.Time `json:"occurred_at"`
	SessionID  string    `json:"session_id"`
	TargetRef  string    `json:"target_ref,omitempty"`
	Actor      string    `json:"actor"`
	ReplayKey  string    `json:"replay_key"`
	SHA256     string    `json:"sha256"`
	Bytes      int64     `json:"bytes"`
	Truncated  bool      `json:"truncated"`
	ChainHash  string    `json:"chain_hash"`
	// ParseError flags a row whose recording metadata could not be decoded, so
	// an auditor seeing empty reference fields (SessionID/ReplayKey/SHA256) knows
	// the blanks are a decode failure rather than a genuinely empty recording.
	// Omitted on the normal path so well-formed rows stay clean.
	ParseError bool `json:"parse_error,omitempty"`
}

// recordingMeta is the shape of a pam.session.recording event's metadata as
// written by pam.SessionManager.RecordRecording.
type recordingMeta struct {
	SessionID string `json:"session_id"`
	ReplayKey string `json:"replay_key"`
	SHA256    string `json:"sha256"`
	Bytes     int64  `json:"bytes"`
	Truncated bool   `json:"truncated"`
}

// projectRecordingRow flattens a KindPrivilegedRecording evidence record into a
// pam-recordings.jsonl row, decoding the recording metadata best-effort: a
// malformed metadata blob still yields a row (with whatever decoded) so the
// recording stays indexed rather than silently dropped, flagged with
// ParseError so the empty reference fields are self-explaining.
func projectRecordingRow(rec EvidenceRecord) recordingIndexRow {
	var md recordingMeta
	parseErr := false
	if len(rec.Metadata) > 0 {
		if err := json.Unmarshal(rec.Metadata, &md); err != nil {
			parseErr = true
		}
	}
	return recordingIndexRow{
		ChainSeq:   rec.ChainSeq,
		OccurredAt: rec.OccurredAt,
		SessionID:  md.SessionID,
		TargetRef:  rec.TargetRef,
		Actor:      rec.Actor,
		ReplayKey:  md.ReplayKey,
		SHA256:     md.SHA256,
		Bytes:      md.Bytes,
		Truncated:  md.Truncated,
		ChainHash:  rec.ChainHash,
		ParseError: parseErr,
	}
}

// writeRecordings writes pam-recordings.jsonl from the privileged-recording
// references gathered during the streamEvidence pass. It is a derived index, not
// a new source of truth — every row was reconstructed from a chain event, so it
// carries no integrity weight the chain does not already guarantee — but it
// spares an auditor from filtering evidence.jsonl by hand to tie CC6.7/A.8.2
// records to replayable recordings, and it adds no chain scan of its own.
func (pw *PackWriter) writeRecordings(zw *zip.Writer, rows []recordingIndexRow) (PackFileInfo, error) {
	fw, err := zw.Create("pam-recordings.jsonl")
	if err != nil {
		return PackFileInfo{}, fmt.Errorf("compliance: create pam-recordings.jsonl: %w", err)
	}
	h := sha256.New()
	enc := json.NewEncoder(io.MultiWriter(fw, h))
	for i := range rows {
		if err := enc.Encode(rows[i]); err != nil {
			return PackFileInfo{}, fmt.Errorf("compliance: encode recording row: %w", err)
		}
	}
	return PackFileInfo{
		Name:    "pam-recordings.jsonl",
		Comment: "Privileged-session recording references in the period: replay key + SHA-256 integrity hash + anchoring chain position. One JSON object per line, in chain order.",
		Rows:    len(rows),
		SHA256:  hex.EncodeToString(h.Sum(nil)),
	}, nil
}

// streamGrants writes grants that were active at any point during the period.
func (pw *PackWriter) streamGrants(ctx context.Context, zw *zip.Writer, opts ExportOptions) (PackFileInfo, error) {
	q := pw.db.WithContext(ctx).Model(&models.AccessGrant{}).Where("workspace_id = ?", opts.WorkspaceID)
	if opts.To != nil {
		q = q.Where("granted_at < ?", opts.To.UTC())
	}
	if opts.From != nil {
		q = q.Where("(revoked_at IS NULL OR revoked_at >= ?)", opts.From.UTC())
	}
	q = q.Order("granted_at asc, id asc")
	return pw.streamRows(zw, "access-grants.jsonl",
		"Every grant active at any point during the period (granted_at < to AND (revoked_at IS NULL OR revoked_at >= from)).",
		q, func() any { return &models.AccessGrant{} })
}

// streamCampaigns writes certification campaigns overlapping the period and the
// items belonging to them.
func (pw *PackWriter) streamCampaigns(ctx context.Context, zw *zip.Writer, opts ExportOptions) (PackFileInfo, PackFileInfo, error) {
	cq := pw.db.WithContext(ctx).Model(&models.CertificationCampaign{}).Where("workspace_id = ?", opts.WorkspaceID)
	if opts.To != nil {
		cq = cq.Where("created_at < ?", opts.To.UTC())
	}
	if opts.From != nil {
		cq = cq.Where("(closed_at IS NULL OR closed_at >= ?)", opts.From.UTC())
	}
	cq = cq.Order("created_at asc, id asc")
	campInfo, err := pw.streamRows(zw, "certification-campaigns.jsonl",
		"Certification campaigns whose lifecycle overlapped the period.",
		cq, func() any { return &models.CertificationCampaign{} })
	if err != nil {
		return PackFileInfo{}, PackFileInfo{}, err
	}

	// Items for campaigns overlapping the period (scoped by the same overlap via
	// a subquery so the export stays workspace- and period-bounded).
	sub := pw.db.WithContext(ctx).Model(&models.CertificationCampaign{}).Select("id").Where("workspace_id = ?", opts.WorkspaceID)
	if opts.To != nil {
		sub = sub.Where("created_at < ?", opts.To.UTC())
	}
	if opts.From != nil {
		sub = sub.Where("(closed_at IS NULL OR closed_at >= ?)", opts.From.UTC())
	}
	iq := pw.db.WithContext(ctx).Model(&models.CertificationItem{}).
		Where("workspace_id = ? AND campaign_id IN (?)", opts.WorkspaceID, sub).
		Order("campaign_id asc, created_at asc, id asc")
	itemInfo, err := pw.streamRows(zw, "certification-items.jsonl",
		"Per-grant certification decisions for the campaigns above. Sorted by (campaign_id, created_at).",
		iq, func() any { return &models.CertificationItem{} })
	if err != nil {
		return PackFileInfo{}, PackFileInfo{}, err
	}
	return campInfo, itemInfo, nil
}

// streamPolicies writes the policies that were in force at any point during the
// period, so an auditor sees the full access-control landscape for the window
// rather than only the policies that happened to change in it. Concretely, with
// a [from, to) period the filter keeps a policy when it was created before `to`
// AND (it is still live OR it was tombstoned within the period):
//
//   - created_at < to                 — existed by the end of the window
//   - updated_at >= from               — soft-deleted/edited inside the window
//     OR deleted_at IS NULL            — still live (kept regardless of when it
//     last changed; a years-old unchanged
//     live policy is still part of the
//     landscape and is included)
//
// Soft-deleted rows are included (Unscoped) so a tombstoned-in-period policy is
// not silently dropped from the evidence. The parentheses keep GORM's AND/OR
// precedence correct so workspace scope never leaks (locked by
// TestWritePackCrossTenantWithPeriodFilter).
func (pw *PackWriter) streamPolicies(ctx context.Context, zw *zip.Writer, opts ExportOptions) (PackFileInfo, error) {
	q := pw.db.WithContext(ctx).Unscoped().Model(&models.Policy{}).Where("workspace_id = ?", opts.WorkspaceID)
	if opts.To != nil {
		q = q.Where("created_at < ?", opts.To.UTC())
	}
	if opts.From != nil {
		q = q.Where("(updated_at >= ? OR deleted_at IS NULL)", opts.From.UTC())
	}
	q = q.Order("created_at asc, id asc")
	return pw.streamRows(zw, "policies.jsonl",
		"Every policy in force at any point during the period: all policies still live at export time (created before the period end) plus any soft-deleted within the period. Includes soft-deleted rows.",
		q, func() any { return &models.Policy{} })
}

// streamRows streams a query's rows into a JSONL zip entry, one object per line,
// hashing as it goes. fresh() returns a pointer to a zero value of the row type
// to scan into.
func (pw *PackWriter) streamRows(zw *zip.Writer, name, comment string, q *gorm.DB, fresh func() any) (PackFileInfo, error) {
	fw, err := zw.Create(name)
	if err != nil {
		return PackFileInfo{}, fmt.Errorf("compliance: create %s: %w", name, err)
	}
	h := sha256.New()
	enc := json.NewEncoder(io.MultiWriter(fw, h))

	rows, err := q.Rows()
	if err != nil {
		return PackFileInfo{}, fmt.Errorf("compliance: open %s cursor: %w", name, err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		dst := fresh()
		if err := pw.db.ScanRows(rows, dst); err != nil {
			return PackFileInfo{}, fmt.Errorf("compliance: scan %s row: %w", name, err)
		}
		if err := enc.Encode(dst); err != nil {
			return PackFileInfo{}, fmt.Errorf("compliance: encode %s row: %w", name, err)
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return PackFileInfo{}, fmt.Errorf("compliance: iterate %s rows: %w", name, err)
	}
	return PackFileInfo{Name: name, Comment: comment, Rows: count, SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}

func (pw *PackWriter) writeBytes(zw *zip.Writer, name, comment string, data []byte) (PackFileInfo, error) {
	fw, err := zw.Create(name)
	if err != nil {
		return PackFileInfo{}, fmt.Errorf("compliance: create %s: %w", name, err)
	}
	if _, err := fw.Write(data); err != nil {
		return PackFileInfo{}, fmt.Errorf("compliance: write %s: %w", name, err)
	}
	sum := sha256.Sum256(data)
	return PackFileInfo{Name: name, Comment: comment, SHA256: hex.EncodeToString(sum[:])}, nil
}

func (pw *PackWriter) writeJSON(zw *zip.Writer, name, comment string, v any) (PackFileInfo, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return PackFileInfo{}, fmt.Errorf("compliance: marshal %s: %w", name, err)
	}
	return pw.writeBytes(zw, name, comment, data)
}

// contentDigest folds the per-file digests into a single SHA-256 over the
// sorted "name=sha256" lines, so the manifest pins the whole pack's content
// regardless of file write order.
func contentDigest(files []PackFileInfo) string {
	lines := make([]string, 0, len(files))
	for _, f := range files {
		lines = append(lines, f.Name+"="+f.SHA256)
	}
	sort.Strings(lines)
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l)
		b.WriteString("\n")
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// renderReadme produces the auditor-facing README describing every file and the
// framework-control mapping. It must be called only after the data-file
// inventory (m.Files) is populated, otherwise the "## Files" section is empty.
// README.md and manifest.json are not in m.Files at call time (README is
// appended right after; manifest is excluded from the digest by design), so
// they are listed explicitly to keep the human inventory complete.
func renderReadme(m *PackManifest) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Compliance evidence pack — %s\n\n", m.Framework)
	fmt.Fprintf(&b, "Workspace: `%s`\n\n", m.WorkspaceID)
	period := "all time"
	if m.From != nil || m.To != nil {
		period = fmt.Sprintf("%s — %s", fmtTime(m.From), fmtTime(m.To))
	}
	fmt.Fprintf(&b, "Reporting period: %s\n\n", period)
	fmt.Fprintf(&b, "Generated: %s by `%s`\n\n", m.GeneratedAt.Format(time.RFC3339), m.GeneratedBy)

	b.WriteString("## Integrity\n\n")
	fmt.Fprintf(&b, "This pack is derived from the workspace's append-only audit hash chain. "+
		"At export time the chain verified as **%s** (length %d). "+
		"The pack content digest (`manifest.json` → `content_sha256`) is recorded in the "+
		"`compliance.export` event in that same chain, so this export is anchored in a "+
		"tamper-evident log rather than relying on a detached signature.\n\n",
		m.ChainVerification.Status, m.ChainVerification.Length)

	b.WriteString("## Files\n\n")
	for _, f := range m.Files {
		if f.Rows > 0 || strings.HasSuffix(f.Name, ".jsonl") {
			fmt.Fprintf(&b, "- `%s` (%d rows) — %s\n", f.Name, f.Rows, f.Comment)
		} else {
			fmt.Fprintf(&b, "- `%s` — %s\n", f.Name, f.Comment)
		}
	}
	// README.md and manifest.json are not in m.Files when this renders, so list
	// them explicitly to keep the human-facing inventory complete.
	b.WriteString("- `README.md` — this guide.\n")
	b.WriteString("- `manifest.json` — machine-readable index with per-file SHA-256 digests (written last).\n")
	b.WriteString("\n## Framework control mapping\n\n")
	fmt.Fprintf(&b, "Controls covered: %d of %d. Evidence records in period: %d.\n\n",
		m.Coverage.ControlsCovered, m.Coverage.ControlsTotal, m.Coverage.EvidenceTotal)
	for _, c := range m.Coverage.Controls {
		status := "NOT COVERED"
		if c.Covered {
			status = fmt.Sprintf("covered (%d evidence records)", c.EvidenceN)
		}
		fmt.Fprintf(&b, "- **%s** %s — %s\n", c.ID, c.Title, status)
	}
	b.WriteString("\nEach control is demonstrated by the evidence kinds listed in `control-coverage.json`. " +
		"Cross-reference the `kind` field in `evidence.jsonl` to inspect the underlying events.\n")
	return b.String()
}

func fmtTime(t *time.Time) string {
	if t == nil {
		return "—"
	}
	return t.UTC().Format(time.RFC3339)
}
