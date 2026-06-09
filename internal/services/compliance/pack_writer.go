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
const packSchemaVersion = "1.0"

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
//   - access-grants.jsonl             grants active at any point in the period
//   - certification-campaigns.jsonl   campaigns overlapping the period
//   - certification-items.jsonl       per-grant decisions for those campaigns
//   - policies.jsonl                  policies touched in the period
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

	// README first so a human unzipping sees it at the top.
	readmeInfo, err := pw.writeBytes(zw, "README.md", "Auditor-facing guide to this evidence pack.", []byte(renderReadme(&manifest)))
	if err != nil {
		return PackManifest{}, err
	}
	manifest.Files = append(manifest.Files, readmeInfo)

	// evidence.jsonl — the chain-derived evidence stream for the period.
	evInfo, evCount, err := pw.streamEvidence(ctx, zw, opts)
	if err != nil {
		return PackManifest{}, err
	}
	manifest.EvidenceTotal = evCount
	manifest.Files = append(manifest.Files, evInfo)

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

	// ContentSHA256 over the sorted per-file digests makes the pack integrity-
	// checkable as a whole and is the value anchored in the export audit event.
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
// file info and row count.
func (pw *PackWriter) streamEvidence(ctx context.Context, zw *zip.Writer, opts ExportOptions) (PackFileInfo, int, error) {
	fw, err := zw.Create("evidence.jsonl")
	if err != nil {
		return PackFileInfo{}, 0, fmt.Errorf("compliance: create evidence.jsonl: %w", err)
	}
	h := sha256.New()
	enc := json.NewEncoder(io.MultiWriter(fw, h))
	count := 0
	if err := pw.evidence.streamPeriod(ctx, opts.WorkspaceID, opts.From, opts.To, func(rec EvidenceRecord) error {
		count++
		return enc.Encode(rec)
	}); err != nil {
		return PackFileInfo{}, 0, err
	}
	return PackFileInfo{
		Name:    "evidence.jsonl",
		Comment: "Every control-relevant audit-chain event in the period, projected to an evidence record. One JSON object per line, in chain order.",
		Rows:    count,
		SHA256:  hex.EncodeToString(h.Sum(nil)),
	}, count, nil
}

// streamGrants writes grants that were active at any point during the period.
func (pw *PackWriter) streamGrants(ctx context.Context, zw *zip.Writer, opts ExportOptions) (PackFileInfo, error) {
	q := pw.db.WithContext(ctx).Model(&models.AccessGrant{}).Where("workspace_id = ?", opts.WorkspaceID)
	if opts.To != nil {
		q = q.Where("granted_at < ?", opts.To.UTC())
	}
	if opts.From != nil {
		q = q.Where("revoked_at IS NULL OR revoked_at >= ?", opts.From.UTC())
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
		cq = cq.Where("closed_at IS NULL OR closed_at >= ?", opts.From.UTC())
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
		sub = sub.Where("closed_at IS NULL OR closed_at >= ?", opts.From.UTC())
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

// streamPolicies writes policies created or updated during the period (includes
// soft-deleted rows so an auditor can reconstruct the policy graph).
func (pw *PackWriter) streamPolicies(ctx context.Context, zw *zip.Writer, opts ExportOptions) (PackFileInfo, error) {
	q := pw.db.WithContext(ctx).Unscoped().Model(&models.Policy{}).Where("workspace_id = ?", opts.WorkspaceID)
	if opts.To != nil {
		q = q.Where("created_at < ?", opts.To.UTC())
	}
	if opts.From != nil {
		q = q.Where("updated_at >= ? OR deleted_at IS NULL", opts.From.UTC())
	}
	q = q.Order("created_at asc, id asc")
	return pw.streamRows(zw, "policies.jsonl",
		"Policies created, edited, promoted, or tombstoned during the period. Includes soft-deleted rows.",
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
// framework-control mapping. Kept in sync with the file set written above.
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
