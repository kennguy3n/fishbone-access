package lifecycle

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Policy lifecycle states. A policy is born "draft", may be promoted to
// "active" (the only state the data plane reads), and may later be "archived".
// Drafts and archived policies never affect live authorization decisions.
const (
	PolicyStateDraft    = "draft"
	PolicyStateActive   = "active"
	PolicyStateArchived = "archived"
)

// Policy actions. A policy either grants or denies the (subjects × resources)
// product. Deny wins during conflict detection.
const (
	PolicyActionGrant = "grant"
	PolicyActionDeny  = "deny"
)

// PolicyDefinition is the decoded form of models.Policy.Definition. It is a
// deliberately small, declarative rule: the cartesian product of Subjects and
// Resources is the set of (subject, resource) pairs the policy acts on.
//
// Subjects are iam-core user ids (or "team:<id>" refs); Resources are connector
// resource refs (or "*" for all resources the policy's connector exposes). Role
// is the entitlement role granted (ignored for deny policies).
type PolicyDefinition struct {
	Action    string   `json:"action"`
	Subjects  []string `json:"subjects"`
	Resources []string `json:"resources"`
	Role      string   `json:"role,omitempty"`
}

// ParsePolicyDefinition decodes and validates raw policy JSON. It rejects an
// unknown action, an empty subject set, or an empty resource set so a
// malformed draft can never be simulated or promoted.
func ParsePolicyDefinition(raw []byte) (PolicyDefinition, error) {
	var def PolicyDefinition
	if len(raw) == 0 {
		return def, fmt.Errorf("%w: policy definition is empty", ErrValidation)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&def); err != nil {
		return def, fmt.Errorf("%w: policy definition: %v", ErrValidation, err)
	}
	def.Action = strings.ToLower(strings.TrimSpace(def.Action))
	switch def.Action {
	case PolicyActionGrant, PolicyActionDeny:
	default:
		return def, fmt.Errorf("%w: policy action must be %q or %q, got %q", ErrValidation, PolicyActionGrant, PolicyActionDeny, def.Action)
	}
	def.Subjects = normalizeSet(def.Subjects)
	def.Resources = normalizeSet(def.Resources)
	if len(def.Subjects) == 0 {
		return def, fmt.Errorf("%w: policy must list at least one subject", ErrValidation)
	}
	if len(def.Resources) == 0 {
		return def, fmt.Errorf("%w: policy must list at least one resource", ErrValidation)
	}
	return def, nil
}

// normalizeSet trims, drops empties, de-duplicates, and sorts a string set so
// downstream impact/conflict output is deterministic.
func normalizeSet(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
