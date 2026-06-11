package tenancy

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestTierBudgetDefaultsAndUnknownFallback(t *testing.T) {
	if b := TierBudget(TierEnterprise); b.MaxConcurrentSyncs != 8 {
		t.Errorf("enterprise MaxConcurrentSyncs = %d, want 8", b.MaxConcurrentSyncs)
	}
	// Unknown / empty / mixed-case all fall back to the most-constrained trial.
	for _, in := range []string{"", "gold", "  TRIAL  "} {
		got := TierBudget(in)
		if in == "  TRIAL  " {
			if got.Tier != TierTrial {
				t.Errorf("TierBudget(%q).Tier = %q, want trial", in, got.Tier)
			}
			continue
		}
		if got.Tier != TierTrial || got.MaxConcurrentSyncs != 1 {
			t.Errorf("TierBudget(%q) = %+v, want trial defaults", in, got)
		}
	}
}

func TestIsKnownTier(t *testing.T) {
	for _, in := range []string{TierTrial, TierBase, TierPro, TierEnterprise, "  PRO  "} {
		if !IsKnownTier(in) {
			t.Errorf("IsKnownTier(%q) = false, want true", in)
		}
	}
	for _, in := range []string{"", "gold", "platinum", "tria"} {
		if IsKnownTier(in) {
			t.Errorf("IsKnownTier(%q) = true, want false", in)
		}
	}
}

func TestResolveBudgetOverrides(t *testing.T) {
	// Pro tier with a single concurrency override; the other fields inherit.
	row := TenantResourceBudget{Tier: TierPro, MaxConcurrentSyncs: 16}
	b := resolveBudget(row)
	if b.MaxConcurrentSyncs != 16 {
		t.Errorf("override MaxConcurrentSyncs = %d, want 16", b.MaxConcurrentSyncs)
	}
	if b.MaxPeriodicJobsPerHour != 60 {
		t.Errorf("inherited MaxPeriodicJobsPerHour = %d, want 60 (pro default)", b.MaxPeriodicJobsPerHour)
	}
	if b.FairShareWeight != 4 {
		t.Errorf("inherited FairShareWeight = %d, want 4 (pro default)", b.FairShareWeight)
	}
}

func TestBudgetForUsesDefaultThenOverride(t *testing.T) {
	db := newTestDB(t)
	store := NewStore(db)
	ctx := context.Background()
	ws := uuid.New()

	// No row → default tier's budget.
	b, err := store.BudgetFor(ctx, ws, TierBase)
	if err != nil {
		t.Fatalf("BudgetFor: %v", err)
	}
	if b.Tier != TierBase || b.MaxConcurrentSyncs != 2 {
		t.Errorf("default = %+v, want base defaults", b)
	}

	// Explicit override row wins and normalizes the tier.
	if err := store.SetBudget(ctx, TenantResourceBudget{
		WorkspaceID:        ws,
		Tier:               "PRO",
		MaxConcurrentSyncs: 5,
	}); err != nil {
		t.Fatalf("SetBudget: %v", err)
	}
	b, err = store.BudgetFor(ctx, ws, TierBase)
	if err != nil {
		t.Fatalf("BudgetFor(2): %v", err)
	}
	if b.Tier != TierPro || b.MaxConcurrentSyncs != 5 || b.MaxPeriodicJobsPerHour != 60 {
		t.Errorf("override = %+v, want pro tier w/ 5 concurrent", b)
	}
}

func TestSetBudgetRejectsNilWorkspace(t *testing.T) {
	db := newTestDB(t)
	if err := NewStore(db).SetBudget(context.Background(), TenantResourceBudget{}); err == nil {
		t.Fatal("expected error for nil workspace id")
	}
}
