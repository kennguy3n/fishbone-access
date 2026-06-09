// These tests live in the access_test package (not the access package itself)
// so they can blank-import every connector to populate the process-global
// registry without creating an import cycle (connectors/all imports access).
package access_test

import (
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"

	// Blank-import the aggregate connector package so the registry is fully
	// populated (all providers) before the completeness assertions run.
	_ "github.com/kennguy3n/fishbone-access/internal/services/access/connectors/all"
)

// TestCapabilityDescriptorCompleteness is the anti-drift guard for the
// capability matrix: every connector registered in the process MUST have a
// curated catalog descriptor, and every curated descriptor MUST resolve to a
// registered connector. A connector added (or removed) without updating the
// curated catalog fails this test, which is exactly the drift the matrix is
// designed to prevent.
func TestCapabilityDescriptorCompleteness(t *testing.T) {
	registered := access.ListRegisteredProviders()
	if len(registered) == 0 {
		t.Fatal("registry is empty; the connectors/all blank-import did not run")
	}

	// Every registered provider has a descriptor.
	for _, p := range registered {
		if _, ok := access.CapabilityDescriptorFor(p); !ok {
			t.Errorf("registered connector %q has no curated capability descriptor", p)
		}
	}

	// Every curated descriptor resolves to a registered connector (no orphan
	// rows pointing at a provider that was renamed or dropped).
	registeredSet := make(map[string]struct{}, len(registered))
	for _, p := range registered {
		registeredSet[p] = struct{}{}
	}
	descriptors := access.ListCapabilityDescriptors()
	for _, d := range descriptors {
		if _, ok := registeredSet[d.Provider]; !ok {
			t.Errorf("curated descriptor %q does not match any registered connector", d.Provider)
		}
	}

	// The descriptor count equals the registry count exactly.
	if got, want := len(descriptors), access.RegisteredCount(); got != want {
		t.Errorf("curated descriptor count = %d, registry count = %d; they must match", got, want)
	}
}

// TestCapabilityDescriptorOperationalFlagsMatchTypeAssertion pins the derived
// operational capability flags to the live type assertions, so the descriptor
// can never advertise (or hide) an optional interface the connector does not
// actually implement.
func TestCapabilityDescriptorOperationalFlagsMatchTypeAssertion(t *testing.T) {
	for _, p := range access.ListRegisteredProviders() {
		conn, err := access.GetAccessConnector(p)
		if err != nil {
			t.Fatalf("GetAccessConnector(%q): %v", p, err)
		}
		d, ok := access.CapabilityDescriptorFor(p)
		if !ok {
			t.Fatalf("no descriptor for registered connector %q", p)
		}
		if !d.Registered {
			t.Errorf("%q: descriptor.Registered = false for a registered connector", p)
		}

		assert := func(name string, want bool, got bool) {
			if want != got {
				t.Errorf("%q: operational capability %q = %v, type-assertion says %v", p, name, got, want)
			}
		}
		_, groupSync := conn.(access.GroupSyncer)
		_, deltaSync := conn.(access.IdentityDeltaSyncer)
		_, auditor := conn.(access.AccessAuditor)
		_, scim := conn.(access.SCIMProvisioner)
		_, revoker := conn.(access.SessionRevoker)
		_, ssoCheck := conn.(access.SSOEnforcementChecker)
		_, renewer := conn.(access.CredentialRenewer)

		assert(access.CapabilityGroupSync, groupSync, d.Operational.GroupSync)
		assert(access.CapabilityIdentityDeltaSync, deltaSync, d.Operational.IdentityDeltaSync)
		assert(access.CapabilityAccessAuditOperations, auditor, d.Operational.AccessAuditStream)
		assert(access.CapabilitySCIMProvisioning, scim, d.Operational.SCIMProvisioning)
		assert(access.CapabilitySessionRevoke, revoker, d.Operational.SessionRevoke)
		assert(access.CapabilitySSOEnforcementCheck, ssoCheck, d.Operational.SSOEnforcementCheck)
		assert(access.CapabilityCredentialRenewal, renewer, d.Operational.CredentialRenewal)
	}
}

// TestCapabilityDescriptorTiersAreValid asserts every curated row carries one of
// the five known tiers and a non-empty display name / category, so the gallery
// never renders a blank tile.
func TestCapabilityDescriptorTiersAreValid(t *testing.T) {
	validTier := map[string]bool{
		access.TierCoreIdentity:        true,
		access.TierCloudInfrastructure: true,
		access.TierBusinessSaaS:        true,
		access.TierHRFinanceLegal:      true,
		access.TierVerticalNiche:       true,
	}
	for _, d := range access.ListCapabilityDescriptors() {
		if !validTier[d.Tier] {
			t.Errorf("%q: invalid tier %q", d.Provider, d.Tier)
		}
		if d.DisplayName == "" {
			t.Errorf("%q: empty display name", d.Provider)
		}
		if d.Category == "" {
			t.Errorf("%q: empty category", d.Provider)
		}
	}
}
