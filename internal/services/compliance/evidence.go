package compliance

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
)

// EvidenceRecord is one control-relevant event, projected from a row of the
// workspace audit hash chain (models.AuditEvent). It is NOT a separate stored
// record: the evidence stream re-labels the chain with a control Kind so the
// same tamper-evident row backs both the operational audit log and the
// compliance evidence stream. The chain linkage (PrevHash → ChainHash, ChainSeq)
// is carried through so an auditor can independently verify integrity.
type EvidenceRecord struct {
	ID          uuid.UUID      `json:"id"`
	WorkspaceID uuid.UUID      `json:"workspace_id"`
	ChainSeq    int64          `json:"chain_seq"`
	Kind        EvidenceKind   `json:"kind"`
	Action      string         `json:"action"`
	Actor       string         `json:"actor"`
	TargetRef   string         `json:"target_ref,omitempty"`
	Metadata    datatypes.JSON `json:"metadata,omitempty"`
	PrevHash    string         `json:"prev_hash,omitempty"`
	ChainHash   string         `json:"chain_hash"`
	OccurredAt  time.Time      `json:"occurred_at"`
}

func recordFrom(e *models.AuditEvent) EvidenceRecord {
	return EvidenceRecord{
		ID:          e.ID,
		WorkspaceID: e.WorkspaceID,
		ChainSeq:    e.ChainSeq,
		Kind:        classify(e.Action),
		Action:      e.Action,
		Actor:       e.Actor,
		TargetRef:   e.TargetRef,
		Metadata:    e.Metadata,
		PrevHash:    e.PrevHash,
		ChainHash:   e.ChainHash,
		OccurredAt:  e.CreatedAt.UTC(),
	}
}

// EvidenceFilter narrows the evidence stream. From/To bound the period
// (half-open [From, To)); Kinds restricts to specific control kinds;
// ControlledOnly drops the integrity-only KindOther rows; Limit caps the result
// for the dashboard timeline (0 = no cap). Newest flips the scan to descending
// chain order so a bounded read returns the most-recent N events (the dashboard
// timeline) rather than the oldest N; the default (false) preserves ascending
// chain order for callers that want the start of the chain.
type EvidenceFilter struct {
	From           *time.Time
	To             *time.Time
	Kinds          []EvidenceKind
	ControlledOnly bool
	Limit          int
	Newest         bool
}

// EvidenceService is the read surface over a workspace's evidence stream. It
// owns no tables: it queries audit_events (the hash chain the lifecycle/PAM/
// compliance services already append to) and projects rows into EvidenceRecords.
type EvidenceService struct {
	db *gorm.DB
}

// NewEvidenceService wires the service to the shared DB pool.
func NewEvidenceService(db *gorm.DB) *EvidenceService {
	return &EvidenceService{db: db}
}

// Stream returns the workspace's evidence in chain order, with the filter
// applied. By default the scan is ascending (oldest first); set f.Newest to
// scan descending so a bounded read (f.Limit) returns the most-recent N events
// — what the dashboard timeline wants — instead of the oldest N. Kind filtering
// is done in Go because Kind is derived from the Action string (a one-to-many
// prefix mapping) rather than stored, so it cannot be a SQL predicate without
// leaking the classification into the schema; the limit is therefore applied
// after the Go-side Kind filter so it caps matching records, not scanned rows.
// The time/order predicates ARE pushed to SQL so the row scan stays bounded.
func (s *EvidenceService) Stream(ctx context.Context, workspaceID uuid.UUID, f EvidenceFilter) ([]EvidenceRecord, error) {
	if workspaceID == uuid.Nil {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	kindSet := kindSet(f.Kinds)

	q := s.db.WithContext(ctx).
		Model(&models.AuditEvent{}).
		Where("workspace_id = ?", workspaceID)
	if f.From != nil {
		q = q.Where("created_at >= ?", f.From.UTC())
	}
	if f.To != nil {
		q = q.Where("created_at < ?", f.To.UTC())
	}
	if f.Newest {
		q = q.Order("chain_seq desc")
	} else {
		q = q.Order("chain_seq asc")
	}

	out := make([]EvidenceRecord, 0, 64)
	// Cursor through rows so a wide period never materialises the whole chain in
	// memory at once — important at 5000 tenants with long-lived workspaces.
	rows, err := q.Rows()
	if err != nil {
		return nil, fmt.Errorf("compliance: open evidence cursor: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var e models.AuditEvent
		if err := s.db.ScanRows(rows, &e); err != nil {
			return nil, fmt.Errorf("compliance: scan evidence row: %w", err)
		}
		rec := recordFrom(&e)
		if f.ControlledOnly && !isControlled(rec.Kind) {
			continue
		}
		if kindSet != nil {
			if _, ok := kindSet[rec.Kind]; !ok {
				continue
			}
		}
		out = append(out, rec)
		if f.Limit > 0 && len(out) >= f.Limit {
			break
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("compliance: iterate evidence rows: %w", err)
	}
	return out, nil
}

// streamPeriod invokes fn for every audit row in the workspace within the
// half-open period, in chain order, one row at a time. It is the memory-bounded
// primitive the pack writer streams through so an export of a multi-year period
// never holds more than one row plus the ZIP buffer in memory.
func (s *EvidenceService) streamPeriod(ctx context.Context, workspaceID uuid.UUID, from, to *time.Time, fn func(EvidenceRecord) error) error {
	q := s.db.WithContext(ctx).
		Model(&models.AuditEvent{}).
		Where("workspace_id = ?", workspaceID)
	if from != nil {
		q = q.Where("created_at >= ?", from.UTC())
	}
	if to != nil {
		q = q.Where("created_at < ?", to.UTC())
	}
	rows, err := q.Order("chain_seq asc").Rows()
	if err != nil {
		return fmt.Errorf("compliance: open evidence cursor: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var e models.AuditEvent
		if err := s.db.ScanRows(rows, &e); err != nil {
			return fmt.Errorf("compliance: scan evidence row: %w", err)
		}
		if err := fn(recordFrom(&e)); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("compliance: iterate evidence rows: %w", err)
	}
	return nil
}

// ChainVerification is the outcome of recomputing a workspace's audit hash
// chain. OK is true only when the chain is non-empty AND every row links to its
// predecessor AND every row's stored chain_hash recomputes from its contents.
type ChainVerification struct {
	WorkspaceID uuid.UUID `json:"workspace_id"`
	OK          bool      `json:"ok"`
	Length      int       `json:"length"`
	// Status is "valid", "empty", or "tampered".
	Status string `json:"status"`
	// BrokenAtSeq is the chain_seq of the first row that failed verification
	// (0 when OK or empty).
	BrokenAtSeq int64 `json:"broken_at_seq,omitempty"`
	// Reason describes the first failure (empty when OK).
	Reason string `json:"reason,omitempty"`
	// LegacyUnverified counts rows that predate the canonical (recomputable)
	// hash format (chain_hash_version 0). These are validated by chain linkage
	// only — their content cannot be cryptographically recomputed because the
	// pre-canonical pre-image folded a non-persisted nanosecond clock and raw
	// (pre-jsonb) metadata. A non-zero value is NOT a failure: it means the
	// chain spans a pre-verification baseline. Every row appended after the
	// canonical format shipped is fully recomputed, so this only ever counts
	// down as legacy rows age out.
	LegacyUnverified int `json:"legacy_unverified,omitempty"`
}

// legacyHashVersion is the chain_hash_version carried by rows appended before
// the canonical (recomputable) hash format shipped. Such rows are validated by
// linkage only — see ChainVerification.LegacyUnverified and the verify loop.
const legacyHashVersion = 0

const (
	chainStatusValid    = "valid"
	chainStatusEmpty    = "empty"
	chainStatusTampered = "tampered"
)

// VerifyChain walks the workspace's audit chain in sequence order and proves it
// is tamper-evident two ways at once:
//
//   - Linkage: each row's prev_hash must equal the previous row's chain_hash,
//     the first row's prev_hash must be empty, and chain_seq must be contiguous
//     (1..N with no gaps) — so an inserted, deleted, reordered, or truncated row
//     is detected.
//   - Recompute: each row's stored chain_hash must equal
//     SHA256(prev_hash || workspace || action || target || metadata || ts_micros),
//     the exact pre-image appendAudit folds — so an in-place edit of any hashed
//     field (action, target, metadata, timestamp) is detected even though the
//     row still links correctly.
//
// The recompute is dialect-stable because appendAudit truncates the timestamp
// to microseconds before both hashing and storing (see lifecycle/audit.go), so
// the verifier reproduces the same pre-image from the persisted created_at.
//
// Rows that predate the canonical hash format (chain_hash_version 0) are not
// recomputable from stored columns, so they are validated by linkage only and
// reported via LegacyUnverified rather than as false "tampered" verdicts — see
// the recompute branch below. Linkage and chain_seq contiguity are still
// enforced for those rows, so reordering/insertion/deletion is detected
// regardless of format.
func (s *EvidenceService) VerifyChain(ctx context.Context, workspaceID uuid.UUID) (ChainVerification, error) {
	if workspaceID == uuid.Nil {
		return ChainVerification{}, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	out := ChainVerification{WorkspaceID: workspaceID}

	// A full verify is the consistency scan anchored at the genesis (seq 0,
	// empty prev_hash): every row from the first is linkage-checked and
	// recomputed. VerifyChain and VerifyChainSince share one scanner so the two
	// can never drift in how they detect a gap, a broken link, or an edited row.
	scan, err := s.scanChainFrom(ctx, workspaceID, 0, "")
	if err != nil {
		return ChainVerification{}, err
	}
	out.Length = scan.scanned
	out.LegacyUnverified = scan.legacyUnverified
	if scan.broken {
		out.Status = chainStatusTampered
		out.BrokenAtSeq = scan.brokenAtSeq
		out.Reason = scan.reason
		return out, nil
	}
	if scan.scanned == 0 {
		out.Status = chainStatusEmpty
		return out, nil
	}
	out.OK = true
	out.Status = chainStatusValid
	return out, nil
}

// chainScan is the raw outcome of walking a (sub)range of a workspace chain in
// sequence order. It is the shared substrate VerifyChain and VerifyChainSince
// project into their respective public shapes.
type chainScan struct {
	scanned          int    // rows walked in this scan (the suffix when anchored)
	headSeq          int64  // chain_seq of the last good row (anchor seq when none scanned)
	headHash         string // chain_hash of the last good row (anchor hash when none scanned)
	legacyUnverified int
	broken           bool
	brokenAtSeq      int64
	reason           string
}

// scanChainFrom walks the workspace chain in ascending sequence order starting
// immediately AFTER anchorSeq, treating anchorHash as the chain_hash the first
// scanned row must link back to. (anchorSeq=0, anchorHash="") scans the whole
// chain from genesis — the full-verify case. A non-zero anchor scans only the
// suffix, so the cost is O(rows-after-anchor) rather than O(chain length): this
// is what lets a caller who already holds a trusted (seq, hash) baseline
// re-verify just the tail. Linkage (contiguous chain_seq + prev_hash match) and
// cryptographic recompute are applied identically to every scanned row, so the
// suffix scan is exactly as strict as a full scan over the same rows. It does
// NOT re-prove the prefix at or before the anchor — that soundness comes from
// the earlier full verify that produced the anchor (see VerifyChainSince).
func (s *EvidenceService) scanChainFrom(ctx context.Context, workspaceID uuid.UUID, anchorSeq int64, anchorHash string) (chainScan, error) {
	q := s.db.WithContext(ctx).
		Model(&models.AuditEvent{}).
		Where("workspace_id = ?", workspaceID)
	if anchorSeq > 0 {
		q = q.Where("chain_seq > ?", anchorSeq)
	}
	rows, err := q.Order("chain_seq asc").Rows()
	if err != nil {
		return chainScan{}, fmt.Errorf("compliance: open chain cursor: %w", err)
	}
	defer rows.Close()

	res := chainScan{headSeq: anchorSeq, headHash: anchorHash}
	prevHash := anchorHash
	expectedSeq := anchorSeq + 1
	for rows.Next() {
		var e models.AuditEvent
		if err := s.db.ScanRows(rows, &e); err != nil {
			return chainScan{}, fmt.Errorf("compliance: scan chain row: %w", err)
		}
		res.scanned++

		if e.ChainSeq != expectedSeq {
			res.broken = true
			res.brokenAtSeq = e.ChainSeq
			res.reason = fmt.Sprintf("chain_seq gap: expected %d, got %d", expectedSeq, e.ChainSeq)
			return res, nil
		}
		if e.PrevHash != prevHash {
			res.broken = true
			res.brokenAtSeq = e.ChainSeq
			res.reason = "prev_hash does not match prior row's chain_hash (linkage broken)"
			return res, nil
		}
		// Linkage (chain_seq contiguity + prev_hash) is format-independent and was
		// already enforced above for EVERY row, so an inserted, deleted, reordered
		// or truncated row is always detected regardless of hash version.
		// Cryptographic recompute, however, only applies to canonical rows: a
		// version-0 (pre-canonical) row folded the raw nanosecond clock and raw
		// metadata into its pre-image, neither of which survives in stored columns,
		// so recomputing it would falsely report "tampered" on chains that merely
		// predate the verifiable format. Such rows are accepted on linkage alone
		// and counted as legacy. This never masks tampering of canonical rows (they
		// are still fully recomputed) and never raises a false alarm on a legitimate
		// pre-verification baseline. When AuditHashVersion advances, this branch
		// must learn the per-version pre-image so older canonical rows keep
		// verifying under their own rule.
		if e.ChainHashVersion == legacyHashVersion {
			res.legacyUnverified++
		} else if want := recomputeChainHash(prevHash, &e); want != e.ChainHash {
			res.broken = true
			res.brokenAtSeq = e.ChainSeq
			res.reason = "chain_hash does not recompute from row contents (row edited)"
			return res, nil
		}

		prevHash = e.ChainHash
		res.headHash = e.ChainHash
		res.headSeq = e.ChainSeq
		expectedSeq++
	}
	if err := rows.Err(); err != nil {
		return chainScan{}, fmt.Errorf("compliance: iterate chain rows: %w", err)
	}
	return res, nil
}

// ChainConsistency is the outcome of an incremental ("since") verification: a
// proof that the rows appended after a previously-verified anchor extend the
// chain consistently, without re-walking the whole chain. It is the cheap
// re-verify a long-lived workspace dashboard runs on every load once it holds a
// trusted baseline, where a full VerifyChain is O(chain length).
type ChainConsistency struct {
	WorkspaceID uuid.UUID `json:"workspace_id"`
	OK          bool      `json:"ok"`
	// Status is "consistent" (suffix links cleanly onto the anchor), "tampered"
	// (a gap, broken link or edited row in the suffix), or "stale_anchor" (the
	// anchor seq is ahead of the chain head — the caller's baseline does not
	// belong to this chain).
	Status string `json:"status"`
	// FromSeq / FromHash echo the anchor the caller asserted.
	FromSeq  int64  `json:"from_seq"`
	FromHash string `json:"from_hash"`
	// HeadSeq / HeadHash are the chain head after the scan — the caller persists
	// these as its next anchor. When no new rows exist they equal the anchor.
	HeadSeq  int64  `json:"head_seq"`
	HeadHash string `json:"head_hash"`
	// Verified is the number of new rows checked in this scan (0 when the chain
	// has not grown since the anchor).
	Verified         int    `json:"verified"`
	LegacyUnverified int    `json:"legacy_unverified,omitempty"`
	BrokenAtSeq      int64  `json:"broken_at_seq,omitempty"`
	Reason           string `json:"reason,omitempty"`
}

const chainStatusConsistent = "consistent"
const chainStatusStaleAnchor = "stale_anchor"

// VerifyChainSince proves that the audit rows appended AFTER the anchor
// (anchorSeq, anchorHash) extend the workspace chain consistently — i.e. the
// first new row's prev_hash links to anchorHash, chain_seq stays contiguous,
// and every new canonical row recomputes. It scans only the suffix, so its cost
// is O(rows since the anchor) instead of O(chain length): a workspace with
// 200k evidence rows that has added 12 since the dashboard last verified pays
// for 12, not 200k. This is the standing-cost lever for the heaviest endpoint
// at 5,000-tenant scale.
//
// Soundness boundary, stated plainly: this is a CONSISTENCY proof of the
// suffix, not a fresh integrity proof of the whole chain. It assumes the anchor
// was produced by an earlier trusted full VerifyChain (the dashboard runs one
// full verify to establish the baseline, then cheap incremental verifies
// thereafter). It deliberately does not re-read or re-hash the prefix at or
// before anchorSeq, so it cannot by itself detect tampering of a row the anchor
// already covered — exactly what the periodic full sweep still exists to catch.
// A caller that needs the full guarantee calls VerifyChain.
func (s *EvidenceService) VerifyChainSince(ctx context.Context, workspaceID uuid.UUID, anchorSeq int64, anchorHash string) (ChainConsistency, error) {
	if workspaceID == uuid.Nil {
		return ChainConsistency{}, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	if anchorSeq < 0 {
		return ChainConsistency{}, fmt.Errorf("%w: from_seq must not be negative", ErrValidation)
	}
	if anchorSeq > 0 && anchorHash == "" {
		return ChainConsistency{}, fmt.Errorf("%w: from_hash is required when from_seq > 0", ErrValidation)
	}

	out := ChainConsistency{WorkspaceID: workspaceID, FromSeq: anchorSeq, FromHash: anchorHash}

	// Guard against an anchor that sits beyond the chain head: a contiguous-seq
	// chain has no rows after a stale or fabricated anchor, which would
	// otherwise masquerade as a clean "consistent, 0 new rows". Only treat
	// "0 rows after anchor" as consistent when the anchor IS the head.
	var headSeq int64
	if err := s.db.WithContext(ctx).
		Model(&models.AuditEvent{}).
		Where("workspace_id = ?", workspaceID).
		Select("COALESCE(MAX(chain_seq), 0)").
		Scan(&headSeq).Error; err != nil {
		return ChainConsistency{}, fmt.Errorf("compliance: read chain head: %w", err)
	}
	if anchorSeq > headSeq {
		out.Status = chainStatusStaleAnchor
		out.HeadSeq = headSeq
		out.Reason = fmt.Sprintf("anchor seq %d is ahead of chain head %d", anchorSeq, headSeq)
		return out, nil
	}

	scan, err := s.scanChainFrom(ctx, workspaceID, anchorSeq, anchorHash)
	if err != nil {
		return ChainConsistency{}, err
	}
	out.Verified = scan.scanned
	out.LegacyUnverified = scan.legacyUnverified
	out.HeadSeq = scan.headSeq
	out.HeadHash = scan.headHash
	if scan.broken {
		out.Status = chainStatusTampered
		out.BrokenAtSeq = scan.brokenAtSeq
		out.Reason = scan.reason
		return out, nil
	}
	out.OK = true
	out.Status = chainStatusConsistent
	return out, nil
}

// recomputeChainHash reproduces the appender's pre-image exactly by delegating
// to lifecycle.ComputeChainHash — the single source of truth shared with
// appendAudit — so the verifier can never drift from the writer. The stored
// metadata is re-canonicalized first because the audit_events.metadata jsonb
// column reorders keys and rewrites whitespace on read-back; canonicalizing
// reproduces the exact bytes that were folded into the hash at append time.
func recomputeChainHash(prevHash string, e *models.AuditEvent) string {
	return lifecycle.ComputeChainHash(
		prevHash, e.WorkspaceID, e.Action, e.TargetRef,
		lifecycle.CanonicalAuditMetadata(e.Metadata), e.CreatedAt,
	)
}

// ControlCoverage is one framework control and how much evidence demonstrates
// it in the reporting period.
type ControlCoverage struct {
	ID         string         `json:"id"`
	Title      string         `json:"title"`
	Covered    bool           `json:"covered"`
	EvidenceN  int            `json:"evidence_count"`
	ByKind     map[string]int `json:"by_kind,omitempty"`
	KindLabels []EvidenceKind `json:"kinds"`
}

// FrameworkCoverage summarises control coverage for a framework over a period.
type FrameworkCoverage struct {
	Framework       Framework         `json:"framework"`
	From            *time.Time        `json:"from,omitempty"`
	To              *time.Time        `json:"to,omitempty"`
	Controls        []ControlCoverage `json:"controls"`
	ControlsTotal   int               `json:"controls_total"`
	ControlsCovered int               `json:"controls_covered"`
	EvidenceTotal   int               `json:"evidence_total"`
}

// Coverage computes per-control evidence coverage for a framework over the
// period by counting stream records whose kind maps to each control. It is the
// data behind the "control coverage by framework" dashboard panel.
func (s *EvidenceService) Coverage(ctx context.Context, workspaceID uuid.UUID, framework Framework, from, to *time.Time) (FrameworkCoverage, error) {
	if workspaceID == uuid.Nil {
		return FrameworkCoverage{}, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	controls := Controls(framework)
	if controls == nil {
		return FrameworkCoverage{}, fmt.Errorf("%w: %q", ErrUnknownFramework, framework)
	}

	// Tally evidence by kind across the period in one streamed pass.
	byKind := map[EvidenceKind]int{}
	total := 0
	if err := s.streamPeriod(ctx, workspaceID, from, to, func(rec EvidenceRecord) error {
		if isControlled(rec.Kind) {
			byKind[rec.Kind]++
			total++
		}
		return nil
	}); err != nil {
		return FrameworkCoverage{}, err
	}

	cov := FrameworkCoverage{Framework: framework, From: from, To: to, EvidenceTotal: total}
	for _, c := range controls {
		cc := ControlCoverage{ID: c.ID, Title: c.Title, KindLabels: c.Kinds, ByKind: map[string]int{}}
		for _, k := range c.Kinds {
			if n := byKind[k]; n > 0 {
				cc.ByKind[string(k)] = n
				cc.EvidenceN += n
			}
		}
		cc.Covered = cc.EvidenceN > 0
		if len(cc.ByKind) == 0 {
			cc.ByKind = nil
		}
		cov.Controls = append(cov.Controls, cc)
		cov.ControlsTotal++
		if cc.Covered {
			cov.ControlsCovered++
		}
	}
	return cov, nil
}

// privilegedKinds are the evidence kinds that demonstrate privileged-access
// monitoring (the CC6.7 / A.8.2 control family): the session lifecycle, the
// per-command policy decisions, and the tamper-evident recording references.
var privilegedKinds = []EvidenceKind{KindPrivilegedSession, KindPrivilegedCommand, KindPrivilegedRecording}

var privilegedKindSet = func() map[EvidenceKind]struct{} {
	set := make(map[EvidenceKind]struct{}, len(privilegedKinds))
	for _, k := range privilegedKinds {
		set[k] = struct{}{}
	}
	return set
}()

// controlIsPrivileged reports whether a control is demonstrated by any
// privileged-access evidence kind, so PrivilegedAccessCoverage can gather the
// CC6.7 / A.8.2 / PCI-10.2 family across frameworks without hard-coding ids.
func controlIsPrivileged(c Control) bool {
	for _, k := range c.Kinds {
		if _, ok := privilegedKindSet[k]; ok {
			return true
		}
	}
	return false
}

// PrivilegedControlCoverage is a privileged-access control's coverage tagged
// with the framework it belongs to, so the console can render the cross-
// framework privileged-monitoring panel (CC6.7 / A.8.2 / PCI-10.2) in one view.
type PrivilegedControlCoverage struct {
	Framework Framework `json:"framework"`
	ControlCoverage
}

// PrivilegedAccessCoverage is the focused, cross-framework view of privileged-
// access monitoring over a period: the headline session/command/recording
// counts plus every control that privileged-access evidence demonstrates. It is
// the data behind the console's "privileged access is monitored" panel, which
// previously read zero because no PAM activity was projected into the chain as
// controlled evidence.
type PrivilegedAccessCoverage struct {
	From          *time.Time                  `json:"from,omitempty"`
	To            *time.Time                  `json:"to,omitempty"`
	Monitored     bool                        `json:"monitored"`
	Sessions      int                         `json:"sessions"`
	Commands      int                         `json:"commands"`
	Recordings    int                         `json:"recordings"`
	EvidenceTotal int                         `json:"evidence_total"`
	Controls      []PrivilegedControlCoverage `json:"controls"`
}

// PrivilegedAccessCoverage tallies privileged-access evidence over the period in
// one streamed pass and projects it onto the privileged-access control family
// across every framework. Monitored is true exactly when at least one
// privileged-access evidence record exists in the period, so a caller can show
// non-zero monitoring the moment a single PAM session is recorded.
func (s *EvidenceService) PrivilegedAccessCoverage(ctx context.Context, workspaceID uuid.UUID, from, to *time.Time) (PrivilegedAccessCoverage, error) {
	if workspaceID == uuid.Nil {
		return PrivilegedAccessCoverage{}, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}

	byKind := map[EvidenceKind]int{}
	if err := s.streamPeriod(ctx, workspaceID, from, to, func(rec EvidenceRecord) error {
		if _, ok := privilegedKindSet[rec.Kind]; ok {
			byKind[rec.Kind]++
		}
		return nil
	}); err != nil {
		return PrivilegedAccessCoverage{}, err
	}

	out := PrivilegedAccessCoverage{
		From:       from,
		To:         to,
		Sessions:   byKind[KindPrivilegedSession],
		Commands:   byKind[KindPrivilegedCommand],
		Recordings: byKind[KindPrivilegedRecording],
	}
	out.EvidenceTotal = out.Sessions + out.Commands + out.Recordings
	out.Monitored = out.EvidenceTotal > 0

	for _, fw := range Frameworks() {
		for _, c := range Controls(fw) {
			if !controlIsPrivileged(c) {
				continue
			}
			cc := ControlCoverage{ID: c.ID, Title: c.Title, KindLabels: c.Kinds, ByKind: map[string]int{}}
			for _, k := range c.Kinds {
				if n := byKind[k]; n > 0 {
					cc.ByKind[string(k)] = n
					cc.EvidenceN += n
				}
			}
			cc.Covered = cc.EvidenceN > 0
			if len(cc.ByKind) == 0 {
				cc.ByKind = nil
			}
			out.Controls = append(out.Controls, PrivilegedControlCoverage{Framework: fw, ControlCoverage: cc})
		}
	}
	return out, nil
}

func kindSet(kinds []EvidenceKind) map[EvidenceKind]struct{} {
	if len(kinds) == 0 {
		return nil
	}
	set := make(map[EvidenceKind]struct{}, len(kinds))
	for _, k := range kinds {
		set[k] = struct{}{}
	}
	return set
}
