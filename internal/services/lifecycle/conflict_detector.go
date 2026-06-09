package lifecycle

import (
	"context"
	"fmt"
	"sort"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

// PolicyConflict describes an overlap between the simulated policy and an
// existing active policy. Kind is "grant_vs_deny" (the simulated policy and a
// live policy disagree on the same pair — the security-relevant case) or
// "redundant" (same action already covered by a live policy).
type PolicyConflict struct {
	Kind             string `json:"kind"`
	OtherPolicyID    string `json:"other_policy_id"`
	OtherPolicyName  string `json:"other_policy_name"`
	OtherPolicyState string `json:"other_policy_state"`
	Subject          string `json:"subject"`
	Resource         string `json:"resource"`
}

// Conflict kinds.
const (
	ConflictGrantVsDeny = "grant_vs_deny"
	ConflictRedundant   = "redundant"
)

// ConflictDetector compares a candidate policy definition against the
// workspace's other active policies and reports overlapping (subject, resource)
// pairs. It is read-only and workspace-scoped.
type ConflictDetector struct {
	db *gorm.DB
}

// NewConflictDetector returns a detector backed by db.
func NewConflictDetector(db *gorm.DB) *ConflictDetector {
	return &ConflictDetector{db: db}
}

// DetectConflicts walks the workspace's active policies (excluding excludeID,
// the policy being simulated) and returns every (subject, resource) overlap
// with def. A grant-vs-deny disagreement is always reported; a same-action
// overlap is reported as redundant. Output is deterministic (sorted).
func (d *ConflictDetector) DetectConflicts(ctx context.Context, workspaceID, excludeID uuid.UUID, def PolicyDefinition) ([]PolicyConflict, error) {
	return d.detectConflicts(ctx, d.db, workspaceID, excludeID, def)
}

// DetectConflictsTx is DetectConflicts scoped to an existing transaction, so the
// active-policy scan reads the same snapshot as a row that has already been
// locked FOR UPDATE in tx. Promote uses this to re-scan conflicts against the
// locked draft definition without a TOCTOU window.
func (d *ConflictDetector) DetectConflictsTx(ctx context.Context, tx *gorm.DB, workspaceID, excludeID uuid.UUID, def PolicyDefinition) ([]PolicyConflict, error) {
	return d.detectConflicts(ctx, tx, workspaceID, excludeID, def)
}

func (d *ConflictDetector) detectConflicts(ctx context.Context, db *gorm.DB, workspaceID, excludeID uuid.UUID, def PolicyDefinition) ([]PolicyConflict, error) {
	if workspaceID == uuid.Nil {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}

	var policies []models.Policy
	if err := db.WithContext(ctx).
		Where("workspace_id = ? AND state = ? AND id <> ?", workspaceID, PolicyStateActive, excludeID).
		Find(&policies).Error; err != nil {
		return nil, fmt.Errorf("lifecycle: load policies for conflict scan: %w", err)
	}

	subjectSet := make(map[string]struct{}, len(def.Subjects))
	for _, s := range def.Subjects {
		subjectSet[s] = struct{}{}
	}
	resourceSet := make(map[string]struct{}, len(def.Resources))
	defWildcard := false
	for _, r := range def.Resources {
		resourceSet[r] = struct{}{}
		if r == "*" {
			defWildcard = true
		}
	}

	var out []PolicyConflict
	for i := range policies {
		other, err := ParsePolicyDefinition(policies[i].Definition)
		if err != nil {
			// A malformed live policy is skipped rather than failing the whole
			// simulation; it cannot have been promoted through Simulate anyway.
			continue
		}
		kind := ConflictRedundant
		if other.Action != def.Action {
			kind = ConflictGrantVsDeny
		}
		for _, subj := range other.Subjects {
			if _, ok := subjectSet[subj]; !ok {
				continue
			}
			for _, res := range other.Resources {
				_, resMatch := resourceSet[res]
				if !resMatch && !defWildcard && res != "*" {
					continue
				}
				out = append(out, PolicyConflict{
					Kind:             kind,
					OtherPolicyID:    policies[i].ID.String(),
					OtherPolicyName:  policies[i].Name,
					OtherPolicyState: policies[i].State,
					Subject:          subj,
					Resource:         res,
				})
			}
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].OtherPolicyID != out[j].OtherPolicyID {
			return out[i].OtherPolicyID < out[j].OtherPolicyID
		}
		if out[i].Subject != out[j].Subject {
			return out[i].Subject < out[j].Subject
		}
		return out[i].Resource < out[j].Resource
	})
	return out, nil
}
