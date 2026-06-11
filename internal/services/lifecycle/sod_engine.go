package lifecycle

import (
	"context"
	"fmt"
	"sort"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

// SodEngine evaluates Separation-of-Duties toxic-combination rules. It answers
// two questions, read-only and workspace-scoped:
//
//   - What-if (simulation/promote): would granting a candidate policy give some
//     subject a toxic combination they do not already have? (EvaluatePolicyTx)
//   - Standing (scheduled detector): which subjects ALREADY hold a toxic
//     combination among their live grants? (DetectStandingViolations)
//
// A rule pairs two entitlement selectors; an entitlement is an (resource, role)
// pair drawn from a subject's live access_grants (plus, in a what-if, the pairs
// the candidate policy would add). A subject violates a rule when their
// effective entitlements contain two DISTINCT entitlements, one matching each
// selector. This is cross-entitlement governance, deliberately NOT the pairwise
// grant-vs-deny overlap the ConflictDetector handles.
type SodEngine struct {
	db *gorm.DB
}

// NewSodEngine returns an engine backed by db.
func NewSodEngine(db *gorm.DB) *SodEngine {
	return &SodEngine{db: db}
}

// SodEntitlement is one (resource, role) entitlement referenced by a violation.
type SodEntitlement struct {
	Resource string `json:"resource"`
	Role     string `json:"role"`
}

// SodViolation is one detected toxic combination for a subject under a rule.
// Held matches the rule's selector A and Conflicting matches selector B.
// Introduced is true when the candidate policy in a what-if is what creates the
// combination (i.e. the subject did not already hold both sides) — those are the
// violations the promote guardrail blocks on. For the standing detector every
// violation has Introduced=false (the subject already holds both sides).
type SodViolation struct {
	RuleID      string         `json:"rule_id"`
	RuleName    string         `json:"rule_name"`
	Severity    string         `json:"severity"`
	Subject     string         `json:"subject"`
	Held        SodEntitlement `json:"held"`
	Conflicting SodEntitlement `json:"conflicting"`
	Introduced  bool           `json:"introduced"`
}

// sodBlockingSeverity reports whether a severity blocks a promotion (high or
// critical) absent a force override, versus merely being flagged for review.
func sodBlockingSeverity(severity string) bool {
	return severity == models.SodSeverityHigh || severity == models.SodSeverityCritical
}

// HasBlockingViolation reports whether any violation in vs is of blocking
// severity (high/critical) AND introduced by the candidate — the predicate the
// promote guardrail uses to decide whether a change is catastrophic.
func HasBlockingViolation(vs []SodViolation) bool {
	for _, v := range vs {
		if v.Introduced && sodBlockingSeverity(v.Severity) {
			return true
		}
	}
	return false
}

// wildcard reports whether a selector/entitlement segment matches anything.
func sodWildcard(s string) bool { return s == "" || s == "*" }

// sodSegMatch matches one selector segment against one entitlement segment,
// honoring wildcards on either side: a wildcard grant (resource "*") is access
// to every resource, so it matches a specific selector resource and vice versa.
func sodSegMatch(sel, val string) bool {
	return sodWildcard(sel) || sodWildcard(val) || sel == val
}

// loadEnabledRules returns the workspace's enabled SoD rules from db (which may
// be a transaction so a promote re-scan reads the locked snapshot).
func (e *SodEngine) loadEnabledRules(ctx context.Context, db *gorm.DB, workspaceID uuid.UUID) ([]models.SodRule, error) {
	var rules []models.SodRule
	if err := db.WithContext(ctx).
		Where("workspace_id = ? AND enabled = ?", workspaceID, true).
		Find(&rules).Error; err != nil {
		return nil, fmt.Errorf("lifecycle: load sod rules: %w", err)
	}
	return rules, nil
}

// matchesSelector reports whether ent satisfies selector (resourceSel, roleSel).
func matchesSelector(resourceSel, roleSel string, ent SodEntitlement) bool {
	return sodSegMatch(resourceSel, ent.Resource) && sodSegMatch(roleSel, ent.Role)
}

// rulePair finds a distinct (a, b) entitlement pair in ents satisfying a rule's
// two selectors, preferring a pair that uses an entitlement NOT in the exclude
// set (so a what-if reports the entitlement the change actually adds rather than
// a pre-existing one). It returns ok=false when no distinct satisfying pair
// exists. ents is assumed sorted, so the chosen pair is deterministic.
func rulePair(rule models.SodRule, ents []SodEntitlement, exclude map[SodEntitlement]struct{}) (a, b SodEntitlement, ok bool) {
	var aMatch, bMatch []SodEntitlement
	for _, ent := range ents {
		if matchesSelector(rule.ResourceA, rule.RoleA, ent) {
			aMatch = append(aMatch, ent)
		}
		if matchesSelector(rule.ResourceB, rule.RoleB, ent) {
			bMatch = append(bMatch, ent)
		}
	}
	isNew := func(ent SodEntitlement) bool {
		if exclude == nil {
			return false
		}
		_, inExclude := exclude[ent]
		return !inExclude
	}
	for _, ea := range aMatch {
		for _, eb := range bMatch {
			if ea == eb {
				continue // a single entitlement cannot satisfy a two-sided rule
			}
			if !ok {
				a, b, ok = ea, eb, true
			}
			if isNew(ea) || isNew(eb) {
				return ea, eb, true // prefer a pair touching a newly-added entitlement
			}
		}
	}
	return a, b, ok
}

// ruleSatisfiable reports whether ents contains a distinct pair satisfying the
// rule's two selectors.
func ruleSatisfiable(rule models.SodRule, ents []SodEntitlement) bool {
	_, _, ok := rulePair(rule, ents, nil)
	return ok
}

// evaluateSubject finds the toxic combinations a single subject's effective
// entitlement set violates. existing is the subject's entitlements WITHOUT the
// what-if candidate (equal to effective for the standing detector). A rule is
// reported when the effective set satisfies it, and marked Introduced when the
// existing-only set did NOT already satisfy it — so a what-if blocks only the
// toxic combinations the change actually creates, never a pre-existing one. At
// most one representative violation is returned per rule.
func evaluateSubject(rules []models.SodRule, subject string, existing, effective []SodEntitlement) []SodViolation {
	// Sort the effective set so the representative (Held, Conflicting) pair a
	// violation reports is stable across runs regardless of grant row order —
	// the standing detector's fingerprint and tests depend on determinism.
	sort.Slice(effective, func(i, j int) bool {
		if effective[i].Resource != effective[j].Resource {
			return effective[i].Resource < effective[j].Resource
		}
		return effective[i].Role < effective[j].Role
	})
	existingSet := make(map[SodEntitlement]struct{}, len(existing))
	for _, e := range existing {
		existingSet[e] = struct{}{}
	}

	var out []SodViolation
	for i := range rules {
		rule := rules[i]
		held, conflicting, ok := rulePair(rule, effective, existingSet)
		if !ok {
			continue // rule not satisfied by the effective set
		}
		// Introduced iff the change is what creates the combination: the
		// existing-only entitlements did not already satisfy this rule.
		introduced := !ruleSatisfiable(rule, existing)
		out = append(out, SodViolation{
			RuleID:      rule.ID.String(),
			RuleName:    rule.Name,
			Severity:    rule.Severity,
			Subject:     subject,
			Held:        held,
			Conflicting: conflicting,
			Introduced:  introduced,
		})
	}
	return out
}

// dedupeEntitlements removes duplicate (resource, role) pairs, preserving order.
func dedupeEntitlements(in []SodEntitlement) []SodEntitlement {
	seen := make(map[SodEntitlement]struct{}, len(in))
	out := in[:0:0]
	for _, e := range in {
		if _, ok := seen[e]; ok {
			continue
		}
		seen[e] = struct{}{}
		out = append(out, e)
	}
	return out
}

// candidateEntitlements expands a grant policy definition into the entitlements
// it would add per subject: one (resource, def.Role) per resource. A deny policy
// only removes access, so it can never create a toxic combination — it yields no
// candidate entitlements.
func candidateEntitlements(def PolicyDefinition) []SodEntitlement {
	if def.Action != PolicyActionGrant {
		return nil
	}
	ents := make([]SodEntitlement, 0, len(def.Resources))
	for _, res := range def.Resources {
		ents = append(ents, SodEntitlement{Resource: res, Role: def.Role})
	}
	return dedupeEntitlements(ents)
}

// EvaluatePolicyTx runs the SoD what-if for a candidate policy against the
// workspace's live grants using db (which may be a transaction so a promote
// re-scan reads the same locked snapshot as its conflict re-scan). It returns
// only the violations the candidate would INTRODUCE — toxic combinations a
// subject does not already hold — so a pre-existing violation unrelated to this
// change does not block it. Output is deterministic (sorted).
func (e *SodEngine) EvaluatePolicyTx(ctx context.Context, db *gorm.DB, workspaceID uuid.UUID, def PolicyDefinition) ([]SodViolation, error) {
	if workspaceID == uuid.Nil {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	candidate := candidateEntitlements(def)
	if len(candidate) == 0 || len(def.Subjects) == 0 {
		return nil, nil // deny policy, or nothing to grant: no new combinations
	}
	rules, err := e.loadEnabledRules(ctx, db, workspaceID)
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, nil
	}

	existing, err := e.grantsBySubject(ctx, db, workspaceID, def.Subjects)
	if err != nil {
		return nil, err
	}

	var out []SodViolation
	for _, subject := range def.Subjects {
		existingEnts := dedupeEntitlements(existing[subject])
		effective := dedupeEntitlements(append(append([]SodEntitlement(nil), existingEnts...), candidate...))
		for _, v := range evaluateSubject(rules, subject, existingEnts, effective) {
			if v.Introduced {
				out = append(out, v)
			}
		}
	}
	sortViolations(out)
	return out, nil
}

// DetectStandingViolations evaluates the workspace's LIVE grants against its SoD
// rules and returns every standing toxic combination (the scheduled detector's
// input). Unlike the what-if there is no candidate, so all entitlements are
// existing and every returned violation has Introduced=false.
func (e *SodEngine) DetectStandingViolations(ctx context.Context, workspaceID uuid.UUID) ([]SodViolation, error) {
	if workspaceID == uuid.Nil {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	rules, err := e.loadEnabledRules(ctx, e.db, workspaceID)
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, nil
	}

	bySubject, err := e.allGrantsBySubject(ctx, workspaceID)
	if err != nil {
		return nil, err
	}

	subjects := make([]string, 0, len(bySubject))
	for s := range bySubject {
		subjects = append(subjects, s)
	}
	sort.Strings(subjects)

	var out []SodViolation
	for _, subject := range subjects {
		effective := dedupeEntitlements(bySubject[subject])
		// existing == effective: the standing detector has no candidate, so
		// every reported violation is pre-existing (Introduced=false).
		out = append(out, evaluateSubject(rules, subject, effective, effective)...)
	}
	sortViolations(out)
	return out, nil
}

// grantsBySubject loads the live entitlements of the named subjects, indexed by
// subject. Used by the what-if (only the policy's subjects matter).
func (e *SodEngine) grantsBySubject(ctx context.Context, db *gorm.DB, workspaceID uuid.UUID, subjects []string) (map[string][]SodEntitlement, error) {
	out := make(map[string][]SodEntitlement, len(subjects))
	if len(subjects) == 0 {
		return out, nil
	}
	var grants []models.AccessGrant
	if err := db.WithContext(ctx).
		Where("workspace_id = ? AND state = ? AND revoked_at IS NULL AND iam_core_user_id IN ?", workspaceID, GrantStateActive, subjects).
		Find(&grants).Error; err != nil {
		return nil, fmt.Errorf("lifecycle: load grants for sod eval: %w", err)
	}
	for i := range grants {
		out[grants[i].IAMCoreUserID] = append(out[grants[i].IAMCoreUserID], SodEntitlement{
			Resource: grants[i].ResourceRef,
			Role:     grants[i].Role,
		})
	}
	return out, nil
}

// allGrantsBySubject loads every live entitlement in the workspace, indexed by
// subject. Used by the standing detector (every subject matters).
func (e *SodEngine) allGrantsBySubject(ctx context.Context, workspaceID uuid.UUID) (map[string][]SodEntitlement, error) {
	var grants []models.AccessGrant
	if err := e.db.WithContext(ctx).
		Where("workspace_id = ? AND state = ? AND revoked_at IS NULL", workspaceID, GrantStateActive).
		Find(&grants).Error; err != nil {
		return nil, fmt.Errorf("lifecycle: load grants for sod detection: %w", err)
	}
	out := make(map[string][]SodEntitlement)
	for i := range grants {
		out[grants[i].IAMCoreUserID] = append(out[grants[i].IAMCoreUserID], SodEntitlement{
			Resource: grants[i].ResourceRef,
			Role:     grants[i].Role,
		})
	}
	return out, nil
}

// sortViolations orders violations deterministically by (subject, rule, held,
// conflicting) so API responses and cached impact reports are stable.
func sortViolations(vs []SodViolation) {
	sort.Slice(vs, func(i, j int) bool {
		if vs[i].Subject != vs[j].Subject {
			return vs[i].Subject < vs[j].Subject
		}
		if vs[i].RuleID != vs[j].RuleID {
			return vs[i].RuleID < vs[j].RuleID
		}
		if vs[i].Held != vs[j].Held {
			if vs[i].Held.Resource != vs[j].Held.Resource {
				return vs[i].Held.Resource < vs[j].Held.Resource
			}
			return vs[i].Held.Role < vs[j].Held.Role
		}
		if vs[i].Conflicting.Resource != vs[j].Conflicting.Resource {
			return vs[i].Conflicting.Resource < vs[j].Conflicting.Resource
		}
		return vs[i].Conflicting.Role < vs[j].Conflicting.Role
	})
}
