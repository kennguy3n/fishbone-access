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
			if _, ok := live[pair{grants[i].IAMCoreUserID, grants[i].ResourceRef}]; ok {
				for _, res := range def.Resources {
					if res == grants[i].ResourceRef {
						affectedGrantIDs[grants[i].ID] = struct{}{}
						break
					}
				}
			}
		}
	}
	report.AffectedGrants = len(affectedGrantIDs)

	sort.Strings(report.AffectedSubjects)
	sort.Strings(report.AffectedResources)
	return report, nil
}
