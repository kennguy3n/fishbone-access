// Package packs provides curated "policy packs": ready-made bundles of ZTNA
// access-policy templates keyed by jurisdiction, industry, and compliance
// framework. They give an SME a sane starting point ("who can reach what")
// instead of a blank editor.
//
// A pack never enforces anything on its own. Applying a pack materializes its
// templates as DRAFT policies in the tenant's workspace via the normal
// lifecycle.PolicyService — so every materialized rule still has to be
// simulated and promoted (the test-before-rollout guarantee #37 enforces)
// before it touches the data plane. The template's subjects/resources are
// smart defaults the operator adapts to their own identities and systems.
package packs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
)

// Sentinel errors surfaced to the handler layer.
var (
	ErrPackNotFound      = errors.New("packs: pack not found")
	ErrNoTemplates       = errors.New("packs: pack has no templates to apply")
	ErrTemplateNotInPack = errors.New("packs: requested template is not part of this pack")
)

// Template is a smart-default access rule a pack can materialize as a DRAFT
// policy. Subjects and Resources are recommended starting points (group/role
// refs and system refs) that the operator adapts before simulating.
type Template struct {
	Key       string   `json:"key"`
	Name      string   `json:"name"`
	Summary   string   `json:"summary"`
	Action    string   `json:"action"` // "grant" or "deny"
	Subjects  []string `json:"subjects"`
	Resources []string `json:"resources"`
	Role      string   `json:"role,omitempty"`
	Control   string   `json:"control"` // mapped compliance control reference
}

// definition renders the template into the lifecycle PolicyDefinition JSON the
// PolicyService validates and stores.
func (t Template) definition() (json.RawMessage, error) {
	def := lifecycle.PolicyDefinition{
		Action:    t.Action,
		Subjects:  t.Subjects,
		Resources: t.Resources,
		Role:      t.Role,
	}
	raw, err := json.Marshal(def)
	if err != nil {
		return nil, fmt.Errorf("packs: marshal template %q: %w", t.Key, err)
	}
	return raw, nil
}

// Pack is a curated bundle of access-policy templates. Tier 1 packs are global
// compliance frameworks; tier 2 covers South-East Asia; tier 3 the remaining
// target regions (GCC, AU, UK, US, CH, DE, FR, LATAM).
type Pack struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Authority   string     `json:"authority"`
	Description string     `json:"description"`
	Tier        int        `json:"tier"`
	Regions     []string   `json:"regions"`
	Industries  []string   `json:"industries"`
	Frameworks  []string   `json:"frameworks"`
	Templates   []Template `json:"templates"`
}

// template returns the template with the given key, if present.
func (p Pack) template(key string) (Template, bool) {
	for _, t := range p.Templates {
		if t.Key == key {
			return t, true
		}
	}
	return Template{}, false
}

// Filter narrows the catalog. A zero-value field matches everything; set
// fields are matched case-insensitively against a pack's region/industry/
// framework/tier sets. Industry matching also accepts packs tagged "any".
type Filter struct {
	Region    string
	Industry  string
	Framework string
	Tier      int
}

func contains(set []string, want string) bool {
	want = strings.TrimSpace(want)
	for _, v := range set {
		if strings.EqualFold(v, want) {
			return true
		}
	}
	return false
}

func (f Filter) matches(p Pack) bool {
	if f.Tier != 0 && p.Tier != f.Tier {
		return false
	}
	if f.Region != "" && !contains(p.Regions, f.Region) {
		return false
	}
	if f.Framework != "" && !contains(p.Frameworks, f.Framework) {
		return false
	}
	if f.Industry != "" && !contains(p.Industries, f.Industry) && !contains(p.Industries, "any") {
		return false
	}
	return true
}

// ListPacks returns catalog packs matching the filter, ordered by tier then
// name for a stable gallery.
func ListPacks(f Filter) []Pack {
	out := make([]Pack, 0)
	for _, p := range Catalog() {
		if f.matches(p) {
			out = append(out, p)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Tier != out[j].Tier {
			return out[i].Tier < out[j].Tier
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// FindPack returns a single pack by id.
func FindPack(id string) (Pack, bool) {
	for _, p := range Catalog() {
		if p.ID == id {
			return p, true
		}
	}
	return Pack{}, false
}

// ApplyService materializes pack templates as draft policies. It depends only
// on the lifecycle PolicyService so applied policies follow the exact same
// draft -> simulate -> promote path as hand-authored ones.
type ApplyService struct {
	policies *lifecycle.PolicyService
}

// NewApplyService wires the apply service to the lifecycle policy service.
func NewApplyService(policies *lifecycle.PolicyService) *ApplyService {
	return &ApplyService{policies: policies}
}

// AppliedPolicy pairs a materialized draft with the template it came from.
type AppliedPolicy struct {
	TemplateKey string         `json:"template_key"`
	Policy      *models.Policy `json:"policy"`
}

// Apply creates one draft policy per selected template. When templateKeys is
// empty every template in the pack is applied. The created policies are drafts
// (StateDraft) — nothing is enforced until each is simulated and promoted.
func (a *ApplyService) Apply(ctx context.Context, workspaceID uuid.UUID, packID string, templateKeys []string, actor string) ([]AppliedPolicy, error) {
	pack, ok := FindPack(packID)
	if !ok {
		return nil, ErrPackNotFound
	}
	if len(pack.Templates) == 0 {
		return nil, ErrNoTemplates
	}

	selected := pack.Templates
	if len(templateKeys) > 0 {
		selected = make([]Template, 0, len(templateKeys))
		for _, key := range templateKeys {
			t, ok := pack.template(key)
			if !ok {
				return nil, fmt.Errorf("%w: %q", ErrTemplateNotInPack, key)
			}
			selected = append(selected, t)
		}
	}

	// Materialize every selected template in a single transaction so applying a
	// pack is all-or-nothing: a mid-loop failure rolls back the drafts already
	// created instead of leaving orphaned ones the caller can't see (and would
	// duplicate on retry).
	//
	// Apply is idempotent: a template whose policy already exists in the
	// workspace (matched by name, ignoring archived/superseded rows) is NOT
	// materialised again — the existing policy is returned instead. Without this
	// guard, re-applying a pack (a routine operation: re-running a seed, an
	// operator clicking "Apply" twice, a pack refreshed upstream) would create a
	// duplicate draft per template every time, silently multiplying a tenant's
	// policy set. The lookup is workspace-scoped, so cross-tenant isolation is
	// preserved.
	out := make([]AppliedPolicy, 0, len(selected))
	err := a.policies.Transaction(ctx, func(tx *gorm.DB) error {
		out = out[:0]

		existing := map[string]*models.Policy{}
		var rows []*models.Policy
		if err := tx.WithContext(ctx).
			Where("workspace_id = ? AND state <> ?", workspaceID, lifecycle.PolicyStateArchived).
			Find(&rows).Error; err != nil {
			return fmt.Errorf("packs: load existing policies: %w", err)
		}
		for _, r := range rows {
			// First occurrence wins; a workspace should not hold two live
			// policies with one name, but if it somehow does we keep the
			// earliest so the skip decision is deterministic.
			if _, seen := existing[r.Name]; !seen {
				existing[r.Name] = r
			}
		}

		for _, t := range selected {
			if pol, ok := existing[t.Name]; ok {
				out = append(out, AppliedPolicy{TemplateKey: t.Key, Policy: pol})
				continue
			}
			def, err := t.definition()
			if err != nil {
				return err
			}
			pol, err := a.policies.CreatePolicyTx(ctx, tx, lifecycle.CreatePolicyInput{
				WorkspaceID: workspaceID,
				Name:        t.Name,
				Definition:  def,
				Actor:       actor,
			})
			if err != nil {
				return err
			}
			// Guard against a pack that lists the same Name in two templates:
			// the second occurrence now resolves to the row we just created
			// rather than inserting a duplicate.
			existing[t.Name] = pol
			out = append(out, AppliedPolicy{TemplateKey: t.Key, Policy: pol})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
