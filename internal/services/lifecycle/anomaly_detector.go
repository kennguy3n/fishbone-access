package lifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

// anomalyDetectorActor is the synthetic actor recorded on detector-emitted
// audit/evidence rows so they are attributable to the automated sweep rather
// than to a human.
const anomalyDetectorActor = "system:anomaly-detector"

// AnomalyDetector turns standing SoD violations among a workspace's live grants
// into dispositioned-anomaly EVIDENCE. It is the bridge between the SoD engine
// and the compliance evidence stream: for every newly-found toxic combination
// it records an AccessAnomaly (its own idempotent worklist) and appends two
// rows to the per-workspace audit hash chain — a detection and an automatic
// disposition — under the actions the compliance framework already maps to the
// SOC2 CC7.3 evidence kinds (orphan.detected → orphan_detected,
// orphan.disposition.* → orphan_disposition). CC7.3 ("Orphan / anomalous access
// detected and dispositioned") therefore shows real records as a side effect of
// the scheduled sweep, with no operator round-trip and without touching the
// compliance package.
//
// Auto-disposition ("flagged") is the NoOps-correct default: a 5,000-tenant
// fleet cannot rely on every dormant tenant triaging anomalies by hand, so the
// detector records the anomaly as flagged-for-review immediately; an operator
// can later acknowledge or resolve it. Idempotent via the anomaly fingerprint:
// a standing violation is detected and evidenced once, not on every sweep.
type AnomalyDetector struct {
	db  *gorm.DB
	sod *SodEngine
	now func() time.Time
}

// NewAnomalyDetector wires the detector to its SoD engine.
func NewAnomalyDetector(db *gorm.DB) *AnomalyDetector {
	return &AnomalyDetector{db: db, sod: NewSodEngine(db), now: time.Now}
}

// SetClock overrides the time source (tests).
func (d *AnomalyDetector) SetClock(now func() time.Time) {
	if now != nil {
		d.now = now
	}
}

// anomalyFingerprint is the stable idempotency key for a standing violation. It
// folds only (kind, subject, rule) — NOT the representative entitlement pair —
// because the detector emits at most one violation per (rule, subject) and the
// specific pair a wildcard rule reports can vary; keying on the pair would
// re-evidence the same standing violation when an unrelated grant shifts which
// pair is representative.
func anomalyFingerprint(kind, subject, ruleID string) string {
	sum := sha256.Sum256([]byte(kind + "\x00" + subject + "\x00" + ruleID))
	return hex.EncodeToString(sum[:])
}

// DetectAndRecord runs the standing SoD detector for one workspace and records +
// evidences every NEW toxic combination, returning the number of new anomalies
// recorded (0 when nothing new). Re-running it after the grants are unchanged is
// a no-op (every violation is already fingerprinted), so it is safe to call on
// every scheduler tick and from multiple replicas.
func (d *AnomalyDetector) DetectAndRecord(ctx context.Context, workspaceID uuid.UUID) (int, error) {
	violations, err := d.sod.DetectStandingViolations(ctx, workspaceID)
	if err != nil {
		return 0, err
	}
	if len(violations) == 0 {
		return 0, nil
	}

	recorded := 0
	err = d.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Serialize detectors in this workspace before the read-existing /
		// insert / append-evidence sequence so two concurrent sweeps (e.g. two
		// API replicas) cannot both pass the existence check and double-evidence
		// the same anomaly. The advisory lock is the same one appendAudit takes,
		// so this is also the lock-ordering anchor for the chain appends below.
		if err := lockWorkspace(ctx, tx, workspaceID); err != nil {
			return err
		}

		var existing []string
		if err := tx.Model(&models.AccessAnomaly{}).
			Where("workspace_id = ?", workspaceID).
			Pluck("fingerprint", &existing).Error; err != nil {
			return fmt.Errorf("lifecycle: load existing anomalies: %w", err)
		}
		seen := make(map[string]struct{}, len(existing))
		for _, fp := range existing {
			seen[fp] = struct{}{}
		}

		for i := range violations {
			v := violations[i]
			fp := anomalyFingerprint(models.AnomalyKindSodViolation, v.Subject, v.RuleID)
			if _, ok := seen[fp]; ok {
				continue // already detected and evidenced on a prior sweep
			}
			if err := d.recordOne(ctx, tx, workspaceID, v, fp); err != nil {
				return err
			}
			seen[fp] = struct{}{}
			recorded++
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return recorded, nil
}

// recordOne inserts the anomaly row and appends its detection + auto-disposition
// evidence to the workspace's audit hash chain, all within tx.
func (d *AnomalyDetector) recordOne(ctx context.Context, tx *gorm.DB, workspaceID uuid.UUID, v SodViolation, fingerprint string) error {
	now := d.now()
	ruleID := parseUUIDOrNil(v.RuleID)

	detail := map[string]any{
		"anomaly_kind": models.AnomalyKindSodViolation,
		"rule_id":      v.RuleID,
		"rule_name":    v.RuleName,
		"severity":     v.Severity,
		"subject":      v.Subject,
		"held":         v.Held,
		"conflicting":  v.Conflicting,
	}
	detailJSON, err := json.Marshal(detail)
	if err != nil {
		return fmt.Errorf("lifecycle: marshal anomaly detail: %w", err)
	}

	anomaly := &models.AccessAnomaly{
		WorkspaceID: workspaceID,
		Kind:        models.AnomalyKindSodViolation,
		Subject:     v.Subject,
		RuleID:      ruleID,
		Severity:    v.Severity,
		Detail:      datatypes.JSON(detailJSON),
		Disposition: models.AnomalyDispositionFlagged,
		DetectedAt:  now,
		Fingerprint: fingerprint,
	}
	anomaly.CreatedAt = now
	anomaly.UpdatedAt = now
	if err := tx.Create(anomaly).Error; err != nil {
		return fmt.Errorf("lifecycle: insert anomaly: %w", err)
	}

	// Detection evidence → KindOrphanDetected (CC7.3). The action string is the
	// one the compliance framework's classifier maps to the orphan/anomalous
	// detection kind; we reuse it deliberately so anomalous-access evidence
	// flows through the existing path without touching the compliance package.
	detMeta := map[string]any{
		"anomaly_kind": models.AnomalyKindSodViolation,
		"anomaly_id":   anomaly.ID.String(),
		"rule_id":      v.RuleID,
		"rule_name":    v.RuleName,
		"severity":     v.Severity,
		"subject":      v.Subject,
		"held":         v.Held,
		"conflicting":  v.Conflicting,
	}
	if err := d.appendEvidence(ctx, tx, now, workspaceID, "orphan.detected", anomaly.ID.String(), detMeta); err != nil {
		return err
	}

	// Auto-disposition evidence → KindOrphanDisposition (CC7.3). hasPrefix
	// "orphan.disposition." is what the classifier matches, so the ".flagged"
	// suffix records the automatic triage while still mapping to the disposition
	// evidence kind.
	dispMeta := map[string]any{
		"anomaly_kind": models.AnomalyKindSodViolation,
		"anomaly_id":   anomaly.ID.String(),
		"disposition":  models.AnomalyDispositionFlagged,
		"automated":    true,
		"severity":     v.Severity,
		"subject":      v.Subject,
	}
	return d.appendEvidence(ctx, tx, now, workspaceID, "orphan.disposition.flagged", anomaly.ID.String(), dispMeta)
}

// appendEvidence marshals meta and appends one evidence row to the workspace's
// audit hash chain via the shared appender.
func (d *AnomalyDetector) appendEvidence(ctx context.Context, tx *gorm.DB, now time.Time, workspaceID uuid.UUID, action, targetRef string, meta map[string]any) error {
	b, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("lifecycle: marshal evidence metadata: %w", err)
	}
	return appendAudit(ctx, tx, now, auditEntry{
		WorkspaceID: workspaceID,
		Actor:       anomalyDetectorActor,
		Action:      action,
		TargetRef:   targetRef,
		Metadata:    datatypes.JSON(b),
	})
}

// ListAnomalies returns the workspace's recorded access anomalies, newest first.
func (d *AnomalyDetector) ListAnomalies(ctx context.Context, workspaceID uuid.UUID) ([]models.AccessAnomaly, error) {
	var out []models.AccessAnomaly
	if err := d.db.WithContext(ctx).
		Where("workspace_id = ?", workspaceID).
		Order("detected_at desc").
		Find(&out).Error; err != nil {
		return nil, fmt.Errorf("lifecycle: list anomalies: %w", err)
	}
	return out, nil
}

// parseUUIDOrNil parses s as a UUID, returning nil on any failure (an empty or
// malformed rule id is recorded as a NULL foreign key rather than failing the
// whole detection).
func parseUUIDOrNil(s string) *uuid.UUID {
	id, err := uuid.Parse(s)
	if err != nil {
		return nil
	}
	return &id
}
