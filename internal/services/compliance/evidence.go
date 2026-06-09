package compliance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
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
// for the dashboard timeline (0 = no cap).
type EvidenceFilter struct {
	From           *time.Time
	To             *time.Time
	Kinds          []EvidenceKind
	ControlledOnly bool
	Limit          int
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

// Stream returns the workspace's evidence in chain order (oldest first), with
// the filter applied. Kind filtering is done in Go because Kind is derived from
// the Action string (a one-to-many prefix mapping) rather than stored, so it
// cannot be a SQL predicate without leaking the classification into the schema.
// The time/limit predicates ARE pushed to SQL so the row scan stays bounded.
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
	q = q.Order("chain_seq asc")

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
}

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
func (s *EvidenceService) VerifyChain(ctx context.Context, workspaceID uuid.UUID) (ChainVerification, error) {
	if workspaceID == uuid.Nil {
		return ChainVerification{}, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	out := ChainVerification{WorkspaceID: workspaceID}

	rows, err := s.db.WithContext(ctx).
		Model(&models.AuditEvent{}).
		Where("workspace_id = ?", workspaceID).
		Order("chain_seq asc").
		Rows()
	if err != nil {
		return ChainVerification{}, fmt.Errorf("compliance: open chain cursor: %w", err)
	}
	defer rows.Close()

	prevHash := ""
	var expectedSeq int64 = 1
	n := 0
	for rows.Next() {
		var e models.AuditEvent
		if err := s.db.ScanRows(rows, &e); err != nil {
			return ChainVerification{}, fmt.Errorf("compliance: scan chain row: %w", err)
		}
		n++

		if e.ChainSeq != expectedSeq {
			out.Length = n
			out.Status = chainStatusTampered
			out.BrokenAtSeq = e.ChainSeq
			out.Reason = fmt.Sprintf("chain_seq gap: expected %d, got %d", expectedSeq, e.ChainSeq)
			return out, nil
		}
		if e.PrevHash != prevHash {
			out.Length = n
			out.Status = chainStatusTampered
			out.BrokenAtSeq = e.ChainSeq
			out.Reason = "prev_hash does not match prior row's chain_hash (linkage broken)"
			return out, nil
		}
		if want := recomputeChainHash(prevHash, &e); want != e.ChainHash {
			out.Length = n
			out.Status = chainStatusTampered
			out.BrokenAtSeq = e.ChainSeq
			out.Reason = "chain_hash does not recompute from row contents (row edited)"
			return out, nil
		}

		prevHash = e.ChainHash
		expectedSeq++
	}
	if err := rows.Err(); err != nil {
		return ChainVerification{}, fmt.Errorf("compliance: iterate chain rows: %w", err)
	}

	out.Length = n
	if n == 0 {
		out.Status = chainStatusEmpty
		return out, nil
	}
	out.OK = true
	out.Status = chainStatusValid
	return out, nil
}

// recomputeChainHash reproduces appendAudit's pre-image exactly:
// SHA256(prev_hash \n workspace \n action \n target \n metadata \n ts_micros).
// created_at is already UTC-microsecond (appendAudit truncates before storing),
// so UnixNano() here yields the same integer that was hashed at append time.
func recomputeChainHash(prevHash string, e *models.AuditEvent) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\n%s\n%s\n%s\n%s\n%d",
		prevHash, e.WorkspaceID, e.Action, e.TargetRef, string(e.Metadata),
		e.CreatedAt.UTC().Truncate(time.Microsecond).UnixNano())
	return hex.EncodeToString(h.Sum(nil))
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
