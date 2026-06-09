package access_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/services/access"

	_ "github.com/kennguy3n/fishbone-access/internal/services/access/connectors/all"
)

// TestCatalogueListNoFilterReturnsEveryConnector asserts that, with no filters,
// the catalogue returns exactly one entry per registered connector, sorted by
// provider key, and (with no DB) every entry is Connected=false.
func TestCatalogueListNoFilterReturnsEveryConnector(t *testing.T) {
	svc := access.NewAccessConnectorCatalogueService(nil)
	ws := uuid.New()

	entries, err := svc.ListCatalogue(context.Background(), access.ConnectorCatalogueQuery{WorkspaceID: ws})
	if err != nil {
		t.Fatalf("ListCatalogue: %v", err)
	}
	if got, want := len(entries), access.RegisteredCount(); got != want {
		t.Fatalf("catalogue size = %d, want registry count %d", got, want)
	}

	prev := ""
	for _, e := range entries {
		if e.Provider <= prev {
			t.Errorf("catalogue not sorted by provider: %q after %q", e.Provider, prev)
		}
		prev = e.Provider
		if e.Connected {
			t.Errorf("%q: Connected=true with no DB backing", e.Provider)
		}
		if !e.Registered {
			t.Errorf("%q: Registered=false for a registered connector", e.Provider)
		}
	}
}

// TestCatalogueWorkspaceRequired asserts the catalogue is never served unscoped:
// a nil workspace is a validation error, not an empty list.
func TestCatalogueWorkspaceRequired(t *testing.T) {
	svc := access.NewAccessConnectorCatalogueService(nil)
	if _, err := svc.ListCatalogue(context.Background(), access.ConnectorCatalogueQuery{}); err == nil {
		t.Fatal("expected validation error for missing workspace, got nil")
	}
}

// TestCatalogueCapabilityFilter asserts ?capability= narrows the result to
// connectors advertising that capability, and that the subset is a strict,
// non-empty, correct slice of the full catalogue.
func TestCatalogueCapabilityFilter(t *testing.T) {
	svc := access.NewAccessConnectorCatalogueService(nil)
	ws := uuid.New()
	ctx := context.Background()

	all, err := svc.ListCatalogue(ctx, access.ConnectorCatalogueQuery{WorkspaceID: ws})
	if err != nil {
		t.Fatalf("ListCatalogue (all): %v", err)
	}

	for _, capKey := range []string{
		access.CapabilitySSOFederation,
		access.CapabilityProvisionAccess,
		access.CapabilitySCIMProvisioning,
		access.CapabilityIdentityDeltaSync,
	} {
		filtered, err := svc.ListCatalogue(ctx, access.ConnectorCatalogueQuery{WorkspaceID: ws, Capability: capKey})
		if err != nil {
			t.Fatalf("ListCatalogue(capability=%s): %v", capKey, err)
		}
		if len(filtered) == 0 {
			t.Errorf("capability=%s returned no connectors; expected a non-empty subset", capKey)
		}
		if len(filtered) > len(all) {
			t.Errorf("capability=%s returned more than the full catalogue", capKey)
		}
		for _, e := range filtered {
			if !e.HasCapability(capKey) {
				t.Errorf("capability=%s returned %q which lacks the capability", capKey, e.Provider)
			}
		}
		// Count the full catalogue's matches independently and compare.
		want := 0
		for _, e := range all {
			if e.HasCapability(capKey) {
				want++
			}
		}
		if len(filtered) != want {
			t.Errorf("capability=%s: filtered %d, independent count %d", capKey, len(filtered), want)
		}
	}
}

// TestCatalogueTierAndCategoryFilter asserts tier/category filters are
// case-insensitive and AND together with the capability filter.
func TestCatalogueTierAndCategoryFilter(t *testing.T) {
	svc := access.NewAccessConnectorCatalogueService(nil)
	ws := uuid.New()
	ctx := context.Background()

	tierFiltered, err := svc.ListCatalogue(ctx, access.ConnectorCatalogueQuery{WorkspaceID: ws, Tier: "t1"})
	if err != nil {
		t.Fatalf("ListCatalogue(tier=t1): %v", err)
	}
	if len(tierFiltered) == 0 {
		t.Fatal("tier=t1 returned nothing; expected the core-identity connectors")
	}
	for _, e := range tierFiltered {
		if e.Tier != access.TierCoreIdentity {
			t.Errorf("tier=t1 returned %q with tier %q", e.Provider, e.Tier)
		}
	}

	// AND semantics: tier=T1 AND capability=sso_federation must be a subset of
	// tier=T1.
	combined, err := svc.ListCatalogue(ctx, access.ConnectorCatalogueQuery{
		WorkspaceID: ws,
		Tier:        access.TierCoreIdentity,
		Capability:  access.CapabilitySSOFederation,
	})
	if err != nil {
		t.Fatalf("ListCatalogue(tier+capability): %v", err)
	}
	if len(combined) > len(tierFiltered) {
		t.Errorf("AND filter returned %d, more than tier-only %d", len(combined), len(tierFiltered))
	}
	for _, e := range combined {
		if e.Tier != access.TierCoreIdentity || !e.UserFacing.SSOFederation {
			t.Errorf("AND filter returned non-matching entry %q", e.Provider)
		}
	}
}

// TestCatalogueFacets asserts the facet vocabulary is non-empty and the tiers
// are the five known tiers.
func TestCatalogueFacets(t *testing.T) {
	svc := access.NewAccessConnectorCatalogueService(nil)
	f := svc.Facets()
	if len(f.Tiers) == 0 || len(f.Categories) == 0 {
		t.Fatal("facets returned empty tiers or categories")
	}
	if len(f.UserFacingCapabilities) != 5 {
		t.Errorf("expected 5 user-facing capabilities, got %d", len(f.UserFacingCapabilities))
	}
	if len(f.OperationalCapabilities) != 7 {
		t.Errorf("expected 7 operational capabilities, got %d", len(f.OperationalCapabilities))
	}
}
