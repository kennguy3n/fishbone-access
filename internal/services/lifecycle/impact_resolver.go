package lifecycle

import (
	"context"
	"fmt"
	"sort"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

// ImpactReport is the result of simulating a policy against the current state
// of a workspace. It is cached on models.Policy.DraftImpact while the policy is
// still a draft and returned to the caller from PolicyService.Simulate.
//
// It is purely informational: simulation never mutates the data plane.
type ImpactReport struct {
	Action        string `json:"action"`
	SubjectCount  int    `json:"subject_count"`
	ResourceCount int    `json:"resource_count"`
	// PairCount counts only the enumerable (subject, concrete-resource) pairs,
	// so the invariant PairCount == NewGrantPairs + RedundantPairs always holds
	// for a grant policy. A "*" resource cannot be expanded into concrete pairs;
	// when present WildcardResource is true and the wildcard is excluded from
	// PairCount (it is surfaced via WildcardResource instead of being silently
	// dropped from an otherwise-inconsistent total).
	PairCount         int      `json:"pair_count"`
	NewGrantPairs     int      `json:"new_grant_pairs"`
	RedundantPairs    int      `json:"redundant_pairs"`
	WildcardResource  bool     `json:"wildcard_resource"`
	AffectedGrants    int      `json:"affected_grants"`
	AffectedSubjects  []string `json:"affected_subjects"`
	AffectedResources []string `json:"affected_resources"`

	// SoDViolations are the Separation-of-Duties toxic combinations this change
	// would INTRODUCE (a subject gaining two entitlements that must stay
	// segregated). Populated by the simulate/promote what-if; empty when there
	// are no SoD rules or the change introduces none.
	SoDViolations []SodViolation `json:"sod_violations,omitempty"`
	// Catastrophic flags a change the operator should not apply blind: it
	// introduces a high/critical SoD violation, or has an unbounded/very large
	// blast radius. CatastrophicReasons lists the human-readable triggers. A
	// high/critical SoD violation also hard-blocks promotion (override with an
	// audited reason); blast-radius reasons are warnings, not blocks.
	Catastrophic        bool     `json:"catastrophic"`
	CatastrophicReasons []string `json:"catastrophic_reasons,omitempty"`
}

// Catastrophic-change blast-radius thresholds. A change at or above these is
// flagged (not hard-blocked) so a 5,000-tenant operator cannot apply a sweeping
// grant/teardown without the simulation loudly warning first. They are
// deliberately generous: routine changes never trip them, only genuinely
// large-footprint ones do.
const (
	catastrophicNewGrantPairs  = 100
	catastrophicAffectedGrants = 100
)

// assessCatastrophic fills the SoD-driven and blast-radius-driven catastrophic
// flags on report from its already-computed counts and SoDViolations. It is the
// single place the "catastrophic change" verdict is decided so Simulate, the
// ad-hoc what-if, and Promote all agree.
func assessCatastrophic(report *ImpactReport, def PolicyDefinition) {
	var reasons []string
	if HasBlockingViolation(report.SoDViolations) {
		reasons = append(reasons, "introduces high/critical separation-of-duties toxic combination(s)")
	}
	switch def.Action {
	case PolicyActionGrant:
		if report.WildcardResource {
			reasons = append(reasons, "grants a wildcard ('*') resource — unbounded blast radius")
		}
		if report.NewGrantPairs >= catastrophicNewGrantPairs {
			reasons = append(reasons, fmt.Sprintf("provisions %d new entitlement pairs (>= %d)", report.NewGrantPairs, catastrophicNewGrantPairs))
		}
	case PolicyActionDeny:
		if report.AffectedGrants >= catastrophicAffectedGrants {
			reasons = append(reasons, fmt.Sprintf("tears down %d live grants (>= %d)", report.AffectedGrants, catastrophicAffectedGrants))
		}
	}
	report.CatastrophicReasons = reasons
	report.Catastrophic = len(reasons) > 0
}

// ImpactResolver computes the blast radius of a policy definition by walking
// the workspace's live access_grants. It is read-only and workspace-scoped.
type ImpactResolver struct {
	db *gorm.DB
}

// NewImpactResolver returns a resolver backed by db.
func NewImpactResolver(db *gorm.DB) *ImpactResolver {
	return &ImpactResolver{db: db}
}

// ResolveImpact projects def onto workspace's current grants. For a grant
// policy it reports how many (subject, resource) pairs already have a live
// grant (redundant) versus how many would be newly provisioned; for a deny
// policy it reports how many live grants the policy would tear down.
func (r *ImpactResolver) ResolveImpact(ctx context.Context, workspaceID uuid.UUID, def PolicyDefinition) (ImpactReport, error) {
	if workspaceID == uuid.Nil {
		return ImpactReport{}, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}

	var grants []models.AccessGrant
	if err := r.db.WithContext(ctx).
		Where("workspace_id = ? AND state = ? AND revoked_at IS NULL", workspaceID, "active").
		Find(&grants).Error; err != nil {
		return ImpactReport{}, fmt.Errorf("lifecycle: load grants for impact: %w", err)
	}

	// Index live grants by (subject, resource) for O(1) overlap checks.
	type pair struct{ subject, resource string }
	live := make(map[pair]struct{}, len(grants))
	for i := range grants {
		live[pair{grants[i].IAMCoreUserID, grants[i].ResourceRef}] = struct{}{}
	}

	resourceWildcard := false
	concreteResources := 0
	for _, res := range def.Resources {
		if res == "*" {
			resourceWildcard = true
			continue
		}
		concreteResources++
	}

	report := ImpactReport{
		Action:        def.Action,
		SubjectCount:  len(def.Subjects),
		ResourceCount: len(def.Resources),
		// Only concrete resources are enumerable into pairs; a "*" is reported
		// via WildcardResource rather than counted, keeping PairCount consistent
		// with NewGrantPairs + RedundantPairs.
		PairCount:         len(def.Subjects) * concreteResources,
		WildcardResource:  resourceWildcard,
		AffectedSubjects:  append([]string(nil), def.Subjects...),
		AffectedResources: append([]string(nil), def.Resources...),
	}

	affectedGrantIDs := make(map[uuid.UUID]struct{})
	subjectSet := make(map[string]struct{}, len(def.Subjects))
	for _, s := range def.Subjects {
		subjectSet[s] = struct{}{}
	}

	switch def.Action {
	case PolicyActionGrant:
		for _, subj := range def.Subjects {
			for _, res := range def.Resources {
				if res == "*" {
					continue
				}
				if _, ok := live[pair{subj, res}]; ok {
					report.RedundantPairs++
				} else {
					report.NewGrantPairs++
				}
			}
		}
	case PolicyActionDeny:
		// A deny policy affects every live grant whose subject is in the set
		// and whose resource matches (or "*").
		for i := range grants {
			if _, ok := subjectSet[grants[i].IAMCoreUserID]; !ok {
				continue
			}
			if resourceWildcard {
				affectedGrantIDs[grants[i].ID] = struct{}{}
				continue
			}
			// We are iterating the live grants directly, so each grant's
			// (subject, resource) is necessarily present in the live index; the
			// only thing left to decide is whether the deny set names this
			// grant's resource explicitly.
			for _, res := range def.Resources {
				if res == grants[i].ResourceRef {
					affectedGrantIDs[grants[i].ID] = struct{}{}
					break
				}
			}
		}
	}
	report.AffectedGrants = len(affectedGrantIDs)

	sort.Strings(report.AffectedSubjects)
	sort.Strings(report.AffectedResources)
	return report, nil
}
