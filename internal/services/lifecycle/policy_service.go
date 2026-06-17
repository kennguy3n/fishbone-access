package lifecycle

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/aiclient"
)

// SimulationResult is the combined output of a policy simulation: the impact
// report plus any conflicts with live policies. It is returned by Simulate and
// (the impact half) cached on the draft.
type SimulationResult struct {
	Impact    ImpactReport     `json:"impact"`
	Conflicts []PolicyConflict `json:"conflicts"`
}

// PolicyService owns the policies table and the draft → simulate → promote
// lifecycle. Drafts never touch the data plane: only Promote flips a policy to
// PolicyStateActive, and only active policies are read by impact/conflict scans
// and by the enforcement path.
type PolicyService struct {
	db       *gorm.DB
	impact   *ImpactResolver
	conflict *ConflictDetector
	sod      *SodEngine
	ai       *aiclient.AIClient
	now      func() time.Time
}

// NewPolicyService wires the policy service to its resolvers.
func NewPolicyService(db *gorm.DB) *PolicyService {
	return &PolicyService{
		db:       db,
		impact:   NewImpactResolver(db),
		conflict: NewConflictDetector(db),
		sod:      NewSodEngine(db),
		now:      time.Now,
	}
}

// SetClock overrides the time source (tests).
func (s *PolicyService) SetClock(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

// SetRecommender attaches the AI client used by Recommend. It is optional: with
// no client (or an unconfigured one) Recommend returns an empty advisory rather
// than failing, so policy authoring never depends on the agent being reachable.
func (s *PolicyService) SetRecommender(ai *aiclient.AIClient) {
	s.ai = ai
}

// PolicyRecommendationInput is the contract for Recommend: the resource a policy
// would govern, the roles in scope, and free-text context describing intent.
type PolicyRecommendationInput struct {
	Resource string
	Roles    []string
	Context  string
}

// Recommend consults the policy_recommendation skill for a human-readable
// rationale to guide an operator drafting a policy. It is advisory and
// fail-open: with no configured agent it returns an empty string (callers treat
// an empty recommendation as "no AI guidance available"), and an agent outage is
// logged inside the aiclient fallback rather than surfaced as an error.
func (s *PolicyService) Recommend(ctx context.Context, workspaceID uuid.UUID, in PolicyRecommendationInput) string {
	if s.ai == nil || !s.ai.Configured() {
		return ""
	}
	resource := strings.TrimSpace(in.Resource)
	context := strings.TrimSpace(in.Context)
	// No signal at all (empty body): there is nothing for the model to reason
	// about, so skip the round-trip and return "no guidance" rather than spend an
	// agent call on an empty payload. Partial input (any one of the three) is
	// still forwarded — an operator can ask with as little context as they have.
	if resource == "" && context == "" && len(in.Roles) == 0 {
		return ""
	}
	return aiclient.RecommendPolicyWithFallback(ctx, s.ai, s.resolveAITier(ctx, workspaceID), aiclient.PolicyRecommendationInput{
		WorkspaceID: workspaceID.String(),
		Resource:    resource,
		Roles:       in.Roles,
		Context:     context,
	})
}

// resolveAITier maps the workspace's plan to the AI tier the agent uses to pick
// a model, failing safe to "deterministic" on a missing/unknown workspace.
func (s *PolicyService) resolveAITier(ctx context.Context, workspaceID uuid.UUID) string {
	var ws models.Workspace
	if err := s.db.WithContext(ctx).Select("plan").Where("id = ?", workspaceID).Take(&ws).Error; err != nil {
		return "deterministic"
	}
	switch strings.TrimSpace(strings.ToLower(ws.Plan)) {
	case "pro":
		return "local_4b"
	case "ultimate":
		return "local_8b"
	default:
		return "deterministic"
	}
}

// CreatePolicyInput is the contract for CreatePolicy.
type CreatePolicyInput struct {
	WorkspaceID uuid.UUID
	Name        string
	Definition  json.RawMessage
	Actor       string
}

// Transaction runs fn inside a database transaction bound to this service's
// connection. It lets sibling services (e.g. policy packs) compose several
// *Tx operations into a single atomic unit so a mid-batch failure rolls the
// whole batch back.
func (s *PolicyService) Transaction(ctx context.Context, fn func(tx *gorm.DB) error) error {
	return s.db.WithContext(ctx).Transaction(fn)
}

// CreatePolicy validates the definition and persists a new draft policy
// (version 1, StateDraft) in its own transaction. The definition must parse so
// a malformed policy can never enter the system. Use CreatePolicyTx to enroll
// the insert in a caller-provided transaction.
func (s *PolicyService) CreatePolicy(ctx context.Context, in CreatePolicyInput) (*models.Policy, error) {
	var pol *models.Policy
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var err error
		pol, err = s.CreatePolicyTx(ctx, tx, in)
		return err
	})
	if err != nil {
		return nil, err
	}
	return pol, nil
}

// CreatePolicyTx validates and inserts a draft policy (version 1, StateDraft)
// within the provided transaction, appending the policy.created audit row to
// the same tx. Callers that materialize several drafts at once (e.g. applying a
// policy pack) run this inside one Transaction so the whole set is atomic.
func (s *PolicyService) CreatePolicyTx(ctx context.Context, tx *gorm.DB, in CreatePolicyInput) (*models.Policy, error) {
	if in.WorkspaceID == uuid.Nil {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	if in.Name == "" {
		return nil, fmt.Errorf("%w: policy name is required", ErrValidation)
	}
	if _, err := ParsePolicyDefinition(in.Definition); err != nil {
		return nil, err
	}

	now := s.now()
	pol := &models.Policy{
		WorkspaceID: in.WorkspaceID,
		Name:        in.Name,
		State:       PolicyStateDraft,
		Version:     1,
		Definition:  datatypes.JSON(in.Definition),
	}
	pol.CreatedAt = now
	pol.UpdatedAt = now

	if err := tx.Create(pol).Error; err != nil {
		return nil, fmt.Errorf("lifecycle: insert policy: %w", err)
	}
	if err := appendAudit(ctx, tx, now, auditEntry{
		WorkspaceID: in.WorkspaceID,
		Actor:       in.Actor,
		Action:      "policy.created",
		TargetRef:   pol.ID.String(),
	}); err != nil {
		return nil, err
	}
	return pol, nil
}

// GetPolicy loads one policy scoped to the workspace.
func (s *PolicyService) GetPolicy(ctx context.Context, workspaceID, policyID uuid.UUID) (*models.Policy, error) {
	var pol models.Policy
	err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND id = ?", workspaceID, policyID).
		Take(&pol).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrPolicyNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("lifecycle: load policy: %w", err)
	}
	return &pol, nil
}

// ListPolicies returns the workspace's policies, newest first.
func (s *PolicyService) ListPolicies(ctx context.Context, workspaceID uuid.UUID) ([]models.Policy, error) {
	var out []models.Policy
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ?", workspaceID).
		Order("created_at desc").
		Find(&out).Error; err != nil {
		return nil, fmt.Errorf("lifecycle: list policies: %w", err)
	}
	return out, nil
}

// UpdateDraft replaces a draft policy's definition (and optionally its name).
// Only drafts are editable; an active or archived policy must be superseded by
// a new draft, so editing one returns ErrPolicyNotEditable.
func (s *PolicyService) UpdateDraft(ctx context.Context, workspaceID, policyID uuid.UUID, name string, def json.RawMessage, actor string) (*models.Policy, error) {
	if _, err := ParsePolicyDefinition(def); err != nil {
		return nil, err
	}
	now := s.now()
	var pol *models.Policy
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Take the per-workspace advisory lock before the row lock so this orders
		// consistently with Promote (advisory -> row). Without it, Promote
		// (advisory then row) and this method (row then advisory, via appendAudit)
		// would acquire the two locks in opposite orders and could deadlock on a
		// concurrent operation against the same policy. The lock is reentrant, so
		// the later appendAudit re-acquire is a no-op.
		if err := lockWorkspace(ctx, tx, workspaceID); err != nil {
			return err
		}
		loaded, err := loadPolicyTx(ctx, tx, workspaceID, policyID)
		if err != nil {
			return err
		}
		if loaded.State != PolicyStateDraft {
			return fmt.Errorf("%w: only draft policies can be edited (state=%s)", ErrPolicyNotEditable, loaded.State)
		}
		updates := map[string]any{
			"definition":   datatypes.JSON(def),
			"draft_impact": nil, // invalidate stale simulation
			"updated_at":   now,
		}
		if name != "" {
			updates["name"] = name
		}
		if err := tx.Model(&models.Policy{}).
			Where("workspace_id = ? AND id = ?", workspaceID, policyID).
			Updates(updates).Error; err != nil {
			return fmt.Errorf("lifecycle: update draft policy: %w", err)
		}
		loaded.Definition = datatypes.JSON(def)
		loaded.DraftImpact = nil
		loaded.UpdatedAt = now
		if name != "" {
			loaded.Name = name
		}
		pol = loaded
		return appendAudit(ctx, tx, now, auditEntry{
			WorkspaceID: workspaceID,
			Actor:       actor,
			Action:      "policy.draft_updated",
			TargetRef:   policyID.String(),
		})
	})
	if err != nil {
		return nil, err
	}
	return pol, nil
}

// Simulate runs the ImpactResolver + ConflictDetector against the policy's
// current definition WITHOUT changing live authorization. For a draft it caches
// the impact report on DraftImpact. It never mutates the data plane, so it is
// safe to call on any policy at any time.
func (s *PolicyService) Simulate(ctx context.Context, workspaceID, policyID uuid.UUID) (SimulationResult, error) {
	pol, err := s.GetPolicy(ctx, workspaceID, policyID)
	if err != nil {
		return SimulationResult{}, err
	}
	def, err := ParsePolicyDefinition(pol.Definition)
	if err != nil {
		return SimulationResult{}, err
	}
	impact, err := s.impact.ResolveImpact(ctx, workspaceID, def)
	if err != nil {
		return SimulationResult{}, err
	}
	conflicts, err := s.conflict.DetectConflicts(ctx, workspaceID, policyID, def)
	if err != nil {
		return SimulationResult{}, err
	}
	// Enrich the impact with the Separation-of-Duties what-if: the toxic
	// combinations this change would introduce, plus the catastrophic-change
	// verdict derived from them and the blast radius. This is cached on the
	// draft so the operator sees the same warnings at simulate and promote time.
	sodViolations, err := s.sod.EvaluatePolicyTx(ctx, s.db, workspaceID, def)
	if err != nil {
		return SimulationResult{}, err
	}
	impact.SoDViolations = sodViolations
	assessCatastrophic(&impact, def)

	result := SimulationResult{Impact: impact, Conflicts: conflicts}

	if pol.State == PolicyStateDraft {
		b, err := json.Marshal(impact)
		if err != nil {
			return SimulationResult{}, fmt.Errorf("lifecycle: marshal draft impact: %w", err)
		}
		now := s.now()
		// Persist the impact under the row lock, but only if the definition we
		// simulated is still the current one. Without the guard, a concurrent
		// UpdateDraft (which locks the row and clears DraftImpact on edit) could
		// commit between our read above and this write, and we would overwrite
		// its nil clear with impact computed from the now-stale definition —
		// falsely marking a since-edited draft as "simulated" and letting it
		// pass Promote's simulate-before-rollout gate.
		//
		// Lock-ordering invariant: this transaction takes only the row lock and
		// never the per-workspace advisory lock (it does not appendAudit), so it
		// cannot form a cycle with Promote/Archive/UpdateDraft, which take the
		// advisory lock before the row lock. If you ever add an appendAudit (or
		// any other lockWorkspace caller) inside this transaction, you MUST take
		// lockWorkspace at the top first — otherwise this becomes row→advisory
		// while Promote is advisory→row, reintroducing the AB/BA deadlock.
		err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			loaded, err := loadPolicyTx(ctx, tx, workspaceID, policyID)
			if err != nil {
				return err
			}
			if loaded.State != PolicyStateDraft || !bytes.Equal([]byte(loaded.Definition), []byte(pol.Definition)) {
				return nil // edited or no longer a draft since we simulated; leave the cache as-is
			}
			return tx.Model(&models.Policy{}).
				Where("workspace_id = ? AND id = ?", workspaceID, policyID).
				Updates(map[string]any{"draft_impact": datatypes.JSON(b), "updated_at": now}).Error
		})
		if err != nil {
			return SimulationResult{}, fmt.Errorf("lifecycle: cache draft impact: %w", err)
		}
	}
	return result, nil
}

// SimulateDefinition runs the same read-only what-if as Simulate against an
// ad-hoc policy definition that is NOT persisted — the engine behind a bulk
// role-change preview. It surfaces the blast radius, grant-vs-deny conflicts,
// SoD violations, and the catastrophic-change verdict so an operator can see the
// consequences of a sweeping change before applying it, without first creating a
// draft. It never mutates the data plane and caches nothing.
func (s *PolicyService) SimulateDefinition(ctx context.Context, workspaceID uuid.UUID, def PolicyDefinition) (SimulationResult, error) {
	if workspaceID == uuid.Nil {
		return SimulationResult{}, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	impact, err := s.impact.ResolveImpact(ctx, workspaceID, def)
	if err != nil {
		return SimulationResult{}, err
	}
	// excludeID is uuid.Nil: an ad-hoc definition is not a stored policy, so no
	// policy is excluded from the conflict scan.
	conflicts, err := s.conflict.DetectConflicts(ctx, workspaceID, uuid.Nil, def)
	if err != nil {
		return SimulationResult{}, err
	}
	sodViolations, err := s.sod.EvaluatePolicyTx(ctx, s.db, workspaceID, def)
	if err != nil {
		return SimulationResult{}, err
	}
	impact.SoDViolations = sodViolations
	assessCatastrophic(&impact, def)
	return SimulationResult{Impact: impact, Conflicts: conflicts}, nil
}

// PromoteOptions carries optional promotion controls. Force overrides the
// grant-vs-deny conflict block AND the SoD catastrophic-change block (the
// simulation requirement itself is never waivable); Reason is the audited
// justification recorded on the override.
type PromoteOptions struct {
	Force  bool
	Reason string
}

// PromoteSodError is returned when promotion is blocked because the candidate
// policy would INTRODUCE one or more high/critical Separation-of-Duties toxic
// combinations (a catastrophic change). It carries the offending violations so
// the caller can surface them, and satisfies errors.Is(err, ErrPolicyHasSodViolations).
type PromoteSodError struct {
	Violations []SodViolation
}

func (e *PromoteSodError) Error() string {
	return fmt.Sprintf("%v: %d high/critical SoD violation(s) block promotion", ErrPolicyHasSodViolations, len(e.Violations))
}

// Is lets callers match this typed error against the ErrPolicyHasSodViolations
// sentinel (e.g. the REST layer's status mapping).
func (e *PromoteSodError) Is(target error) bool {
	return target == ErrPolicyHasSodViolations
}

// Unwrap exposes the sentinel so errors.Is also works through wrapping.
func (e *PromoteSodError) Unwrap() error { return ErrPolicyHasSodViolations }

// blockingViolations filters an SoD violation set down to the introduced,
// high/critical violations that hard-block a promotion.
func blockingViolations(in []SodViolation) []SodViolation {
	var out []SodViolation
	for _, v := range in {
		if v.Introduced && sodBlockingSeverity(v.Severity) {
			out = append(out, v)
		}
	}
	return out
}

// PromoteConflictError is returned when promotion is blocked by unresolved
// grant-vs-deny conflicts. It carries the offending conflicts so the caller can
// surface them, and satisfies errors.Is(err, ErrPolicyHasConflicts).
type PromoteConflictError struct {
	Conflicts []PolicyConflict
}

func (e *PromoteConflictError) Error() string {
	return fmt.Sprintf("%v: %d unresolved grant-vs-deny conflict(s) block promotion", ErrPolicyHasConflicts, len(e.Conflicts))
}

// Is lets callers match this typed error against the ErrPolicyHasConflicts
// sentinel (e.g. the REST layer's status mapping).
func (e *PromoteConflictError) Is(target error) bool {
	return target == ErrPolicyHasConflicts
}

// Unwrap exposes the sentinel so errors.Is also works through wrapping.
func (e *PromoteConflictError) Unwrap() error { return ErrPolicyHasConflicts }

// hardConflicts filters a conflict set down to the security-relevant
// grant-vs-deny disagreements (redundant overlaps are informational and never
// block promotion).
func hardConflicts(in []PolicyConflict) []PolicyConflict {
	var out []PolicyConflict
	for _, c := range in {
		if c.Kind == ConflictGrantVsDeny {
			out = append(out, c)
		}
	}
	return out
}

// Promote flips a draft policy to active and stamps PromotedAt. It is
// idempotent: promoting an already-active policy is a no-op that returns the
// policy unchanged (so a retried promotion does not bump the version or restamp
// the timestamp). An archived policy cannot be promoted.
//
// Promotion enforces test-before-rollout for drafts: the draft must have been
// simulated since its last edit (a non-empty DraftImpact, which UpdateDraft
// clears on every edit, proves this), and it must not have unresolved
// grant-vs-deny conflicts with live policies. Conflicts are re-scanned at
// promote time so a conflict introduced by another policy promoted after this
// draft was simulated is still caught. A reviewed conflict can be overridden
// with opts.Force, which records the reason in the audit chain.
func (s *PolicyService) Promote(ctx context.Context, workspaceID, policyID uuid.UUID, actor string, opts PromoteOptions) (*models.Policy, error) {
	now := s.now()
	var pol *models.Policy
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Serialize all promotions in this workspace before doing anything else.
		// The row-level FOR UPDATE below only guards this one draft; it does NOT
		// stop a *different* draft from promoting concurrently. Two conflicting
		// drafts (a grant and a deny on the same pair) would each FOR UPDATE
		// their own row, and each conflict re-scan would see the other as still
		// a draft — so both could go active and silently defeat conflict
		// detection. Taking the per-workspace advisory lock here forces
		// promotions to run one at a time, so the second promotion's re-scan
		// runs only after the first has committed and observes it as ACTIVE.
		if err := lockWorkspace(ctx, tx, workspaceID); err != nil {
			return err
		}
		// loadPolicyTx locks the row FOR UPDATE, which serializes with
		// UpdateDraft (it locks the same row before clearing DraftImpact). All
		// test-before-rollout checks below therefore run against the committed,
		// locked state — there is no TOCTOU window where a concurrent edit could
		// clear DraftImpact or change the definition after we've checked it.
		loaded, err := loadPolicyTx(ctx, tx, workspaceID, policyID)
		if err != nil {
			return err
		}
		switch loaded.State {
		case PolicyStateActive:
			pol = loaded // idempotent: already promoted
			return nil
		case PolicyStateArchived:
			return fmt.Errorf("%w: archived policy %s", ErrPolicyNotPromotable, policyID)
		}

		// Draft: enforce simulate-before-rollout against the locked row.
		overrideMeta := datatypes.JSON(nil)
		if len(loaded.DraftImpact) == 0 {
			return fmt.Errorf("%w: draft %s", ErrPolicyNotSimulated, policyID)
		}
		def, err := ParsePolicyDefinition(loaded.Definition)
		if err != nil {
			return err
		}
		// Re-scan conflicts at promote time (within the tx, against the locked
		// definition) so a conflict introduced after this draft was simulated is
		// still caught.
		conflicts, err := s.conflict.DetectConflictsTx(ctx, tx, workspaceID, policyID, def)
		if err != nil {
			return err
		}
		hard := hardConflicts(conflicts)
		if len(hard) > 0 && !opts.Force {
			// Block on conflicts first so the operator's existing remediation
			// flow (review conflicts → re-simulate → force) is unchanged.
			return &PromoteConflictError{Conflicts: hard}
		}

		// Re-run the SoD what-if against the locked snapshot too, so a toxic
		// combination introduced by grants added after this draft was simulated
		// is still caught at rollout. A high/critical introduced violation is a
		// catastrophic change that blocks promotion unless force-overridden.
		sodViolations, err := s.sod.EvaluatePolicyTx(ctx, tx, workspaceID, def)
		if err != nil {
			return err
		}
		blockingSod := blockingViolations(sodViolations)
		if len(blockingSod) > 0 && !opts.Force {
			return &PromoteSodError{Violations: blockingSod}
		}

		// Either block may have been force-overridden. An override is a
		// security-relevant action, so it must carry an audited justification —
		// an empty reason is rejected rather than recorded as a blank audit
		// entry — and the offending counts are recorded for the audit trail.
		if len(hard) > 0 || len(blockingSod) > 0 {
			if strings.TrimSpace(opts.Reason) == "" {
				return fmt.Errorf("%w: a reason is required to override a blocked promotion (conflicts or SoD violations)", ErrValidation)
			}
			meta := map[string]any{
				"override": true,
				"reason":   opts.Reason,
			}
			if len(hard) > 0 {
				meta["overridden_conflicts"] = len(hard)
			}
			if len(blockingSod) > 0 {
				meta["overridden_sod_violations"] = len(blockingSod)
			}
			b, err := json.Marshal(meta)
			if err != nil {
				return fmt.Errorf("lifecycle: marshal override metadata: %w", err)
			}
			overrideMeta = datatypes.JSON(b)
		}

		if err := tx.Model(&models.Policy{}).
			Where("workspace_id = ? AND id = ?", workspaceID, policyID).
			Updates(map[string]any{
				"state":       PolicyStateActive,
				"promoted_at": now,
				"updated_at":  now,
				// Clear the draft-only simulation cache: it described the draft
				// and is meaningless (and misleading in API responses) once the
				// policy is active.
				"draft_impact": gorm.Expr("NULL"),
			}).Error; err != nil {
			return fmt.Errorf("lifecycle: promote policy: %w", err)
		}
		loaded.State = PolicyStateActive
		loaded.PromotedAt = &now
		loaded.UpdatedAt = now
		loaded.DraftImpact = nil
		pol = loaded
		action := "policy.promoted"
		if overrideMeta != nil {
			action = "policy.promoted_with_override"
		}
		return appendAudit(ctx, tx, now, auditEntry{
			WorkspaceID: workspaceID,
			Actor:       actor,
			Action:      action,
			TargetRef:   policyID.String(),
			Metadata:    overrideMeta,
		})
	})
	if err != nil {
		return nil, err
	}
	return pol, nil
}

// Archive flips an active or draft policy to archived (removing it from the
// live authorization set). Idempotent on an already-archived policy.
func (s *PolicyService) Archive(ctx context.Context, workspaceID, policyID uuid.UUID, actor string) (*models.Policy, error) {
	now := s.now()
	var pol *models.Policy
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Take the per-workspace advisory lock before the row lock so this orders
		// consistently with Promote (advisory -> row) and cannot deadlock against
		// it. The lock is reentrant, so the later appendAudit re-acquire is a no-op.
		if err := lockWorkspace(ctx, tx, workspaceID); err != nil {
			return err
		}
		loaded, err := loadPolicyTx(ctx, tx, workspaceID, policyID)
		if err != nil {
			return err
		}
		if loaded.State == PolicyStateArchived {
			pol = loaded
			return nil
		}
		if err := tx.Model(&models.Policy{}).
			Where("workspace_id = ? AND id = ?", workspaceID, policyID).
			Updates(map[string]any{"state": PolicyStateArchived, "updated_at": now}).Error; err != nil {
			return fmt.Errorf("lifecycle: archive policy: %w", err)
		}
		loaded.State = PolicyStateArchived
		loaded.UpdatedAt = now
		pol = loaded
		return appendAudit(ctx, tx, now, auditEntry{
			WorkspaceID: workspaceID,
			Actor:       actor,
			Action:      "policy.archived",
			TargetRef:   policyID.String(),
		})
	})
	if err != nil {
		return nil, err
	}
	return pol, nil
}

// loadPolicyTx loads a policy for update inside a transaction, workspace-scoped.
// It takes a row-level write lock (FOR UPDATE on Postgres) so concurrent
// Promote/Archive/UpdateDraft transactions serialize on the row rather than
// both reading the same state and each emitting a duplicate audit event.
func loadPolicyTx(ctx context.Context, tx *gorm.DB, workspaceID, policyID uuid.UUID) (*models.Policy, error) {
	var pol models.Policy
	err := forUpdate(tx.WithContext(ctx)).
		Where("workspace_id = ? AND id = ?", workspaceID, policyID).
		Take(&pol).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrPolicyNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("lifecycle: load policy for update: %w", err)
	}
	return &pol, nil
}
