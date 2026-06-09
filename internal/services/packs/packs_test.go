package packs

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"gorm.io/gorm"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
)

// --- catalog (no DB) ---

func TestCatalogIntegrity(t *testing.T) {
	seenPack := map[string]bool{}
	for _, p := range Catalog() {
		if p.ID == "" || p.Name == "" {
			t.Fatalf("pack with empty id/name: %+v", p)
		}
		if seenPack[p.ID] {
			t.Fatalf("duplicate pack id %q", p.ID)
		}
		seenPack[p.ID] = true
		if p.Tier < 1 || p.Tier > 3 {
			t.Fatalf("pack %q has out-of-range tier %d", p.ID, p.Tier)
		}
		if len(p.Templates) == 0 {
			t.Fatalf("pack %q has no templates", p.ID)
		}
		seenTmpl := map[string]bool{}
		for _, tm := range p.Templates {
			if tm.Key == "" || tm.Name == "" {
				t.Fatalf("pack %q has template with empty key/name", p.ID)
			}
			if seenTmpl[tm.Key] {
				t.Fatalf("pack %q has duplicate template key %q", p.ID, tm.Key)
			}
			seenTmpl[tm.Key] = true
			if tm.Action != "grant" && tm.Action != "deny" {
				t.Fatalf("pack %q template %q has bad action %q", p.ID, tm.Key, tm.Action)
			}
			if len(tm.Subjects) == 0 || len(tm.Resources) == 0 {
				t.Fatalf("pack %q template %q missing subjects/resources", p.ID, tm.Key)
			}
			// Every template must render to a definition the lifecycle layer
			// accepts, otherwise Apply would 500 at materialization time.
			raw, err := tm.definition()
			if err != nil {
				t.Fatalf("definition(%q/%q): %v", p.ID, tm.Key, err)
			}
			if _, err := lifecycle.ParsePolicyDefinition(raw); err != nil {
				t.Fatalf("pack %q template %q invalid definition: %v", p.ID, tm.Key, err)
			}
		}
	}
	if !seenPack["pci-dss-v4"] || !seenPack["vn-pdpd-decree13"] || !seenPack["br-lgpd"] {
		t.Fatalf("expected tier1/tier2/tier3 anchor packs present")
	}
}

func TestListPacksFilterAndSort(t *testing.T) {
	all := ListPacks(Filter{})
	if len(all) < 15 {
		t.Fatalf("expected a populated catalog, got %d", len(all))
	}
	// Sorted by tier asc, then name.
	for i := 1; i < len(all); i++ {
		if all[i-1].Tier > all[i].Tier {
			t.Fatalf("catalog not sorted by tier at %d", i)
		}
	}

	// Tier filter.
	for _, p := range ListPacks(Filter{Tier: 1}) {
		if p.Tier != 1 {
			t.Fatalf("tier filter leaked tier %d", p.Tier)
		}
	}

	// Region filter is case-insensitive.
	vn := ListPacks(Filter{Region: "VN"})
	if len(vn) != 1 || vn[0].ID != "vn-pdpd-decree13" {
		t.Fatalf("expected only the Vietnam pack for region=VN, got %+v", vn)
	}

	// Framework filter.
	pci := ListPacks(Filter{Framework: "PCI-DSS"})
	if len(pci) != 1 || pci[0].ID != "pci-dss-v4" {
		t.Fatalf("expected only the PCI pack for framework=PCI-DSS, got %+v", pci)
	}

	// Industry filter matches explicit industries AND "any"-tagged packs.
	hc := ListPacks(Filter{Industry: "healthcare"})
	var sawHIPAA, sawAny bool
	for _, p := range hc {
		if p.ID == "hipaa-security-rule" {
			sawHIPAA = true
		}
		if contains(p.Industries, "any") {
			sawAny = true
		}
	}
	if !sawHIPAA || !sawAny {
		t.Fatalf("industry filter should include healthcare-specific and any-tagged packs: %+v", hc)
	}

	// No match.
	if got := ListPacks(Filter{Region: "antarctica"}); len(got) != 0 {
		t.Fatalf("expected no packs for unknown region, got %d", len(got))
	}
}

func TestFindPack(t *testing.T) {
	if _, ok := FindPack("does-not-exist"); ok {
		t.Fatal("expected miss for unknown id")
	}
	p, ok := FindPack("soc2-logical-access")
	if !ok || p.Name == "" {
		t.Fatalf("expected to find soc2 pack, got ok=%v", ok)
	}
}

// --- apply (sqlite-backed, real PolicyService) ---

func newApplyService(t *testing.T) (*ApplyService, *lifecycle.PolicyService, *gorm.DB, uuid.UUID) {
	t.Helper()
	db, err := database.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := database.AutoMigrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	ws := &models.Workspace{Name: "tenant-a", IAMCoreTenantID: "tenant-a", Plan: "base"}
	if err := db.Create(ws).Error; err != nil {
		t.Fatalf("seed workspace: %v", err)
	}
	policies := lifecycle.NewPolicyService(db)
	return NewApplyService(policies), policies, db, ws.ID
}

func TestApplyMaterializesDrafts(t *testing.T) {
	svc, policies, _, ws := newApplyService(t)
	ctx := context.Background()

	applied, err := svc.Apply(ctx, ws, "pci-dss-v4", nil, "admin@corp")
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	pack, _ := FindPack("pci-dss-v4")
	if len(applied) != len(pack.Templates) {
		t.Fatalf("expected %d drafts, got %d", len(pack.Templates), len(applied))
	}
	for _, a := range applied {
		if a.Policy == nil {
			t.Fatalf("applied %q has nil policy", a.TemplateKey)
		}
		// Critical guarantee: pack output is a DRAFT, never enforced.
		if a.Policy.State != lifecycle.PolicyStateDraft {
			t.Fatalf("expected draft, got state %q", a.Policy.State)
		}
		// And the materialized definition round-trips to the template's intent.
		var def lifecycle.PolicyDefinition
		if err := json.Unmarshal(a.Policy.Definition, &def); err != nil {
			t.Fatalf("unmarshal def: %v", err)
		}
		tmpl, ok := pack.template(a.TemplateKey)
		if !ok {
			t.Fatalf("applied unknown template key %q", a.TemplateKey)
		}
		if def.Action != tmpl.Action {
			t.Fatalf("template %q action %q != draft action %q", tmpl.Key, tmpl.Action, def.Action)
		}
	}

	// The drafts are real, persisted, listable policies (same path the editor
	// loads), so they can subsequently be simulated and promoted.
	rows, err := policies.ListPolicies(ctx, ws)
	if err != nil {
		t.Fatalf("ListPolicies: %v", err)
	}
	if len(rows) != len(pack.Templates) {
		t.Fatalf("expected %d persisted policies, got %d", len(pack.Templates), len(rows))
	}
}

func TestApplySelectedTemplatesOnly(t *testing.T) {
	svc, _, _, ws := newApplyService(t)
	ctx := context.Background()

	applied, err := svc.Apply(ctx, ws, "pci-dss-v4", []string{"cde-deny-contractors"}, "admin@corp")
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(applied) != 1 || applied[0].TemplateKey != "cde-deny-contractors" {
		t.Fatalf("expected only the selected template, got %+v", applied)
	}
}

func TestApplyErrors(t *testing.T) {
	svc, _, _, ws := newApplyService(t)
	ctx := context.Background()

	if _, err := svc.Apply(ctx, ws, "no-such-pack", nil, "a"); !errors.Is(err, ErrPackNotFound) {
		t.Fatalf("expected ErrPackNotFound, got %v", err)
	}
	if _, err := svc.Apply(ctx, ws, "pci-dss-v4", []string{"ghost-template"}, "a"); !errors.Is(err, ErrTemplateNotInPack) {
		t.Fatalf("expected ErrTemplateNotInPack, got %v", err)
	}
}

func TestApplyIsolatedPerWorkspace(t *testing.T) {
	svc, policies, db, wsA := newApplyService(t)
	ctx := context.Background()
	wsB := &models.Workspace{Name: "tenant-b", IAMCoreTenantID: "tenant-b", Plan: "base"}
	if err := db.Create(wsB).Error; err != nil {
		t.Fatalf("seed ws-b: %v", err)
	}

	if _, err := svc.Apply(ctx, wsA, "soc2-logical-access", nil, "a"); err != nil {
		t.Fatalf("apply to A: %v", err)
	}
	// Workspace B sees none of A's materialized drafts.
	rowsB, err := policies.ListPolicies(ctx, wsB.ID)
	if err != nil {
		t.Fatalf("list B: %v", err)
	}
	if len(rowsB) != 0 {
		t.Fatalf("expected workspace B isolated, saw %d policies", len(rowsB))
	}
}
