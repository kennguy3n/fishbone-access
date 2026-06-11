// Package access_test — registry-count guard tests.
//
// These tests live in an _test package (not the access package
// itself) so they can blank-import every connector to populate the
// process-global registry. The point of these tests is to fail the
// build the moment a connector is added or removed without the
// matching docs update, so the assertion is on exact counts.
//
// The expected counts here MUST stay in sync with:
//
//   - README.md (connector count, optional-interface counts)
//   - docs/architecture.md §12 (Where things run) + §13
//   - docs/connectors.md §2 capability status
package access_test

import (
	"os"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"

	// Blank-import the consolidated connectors/all package so the
	// orphan-directory guard sees every provider registered. Adding
	// a connector means adding one line to connectors/all/all.go.
	_ "github.com/kennguy3n/fishbone-access/internal/services/access/connectors/all"
)

// expectedConnectorCount is the canonical number of providers
// registered via init(). A future PR that adds or removes a
// connector MUST update this number AND the matching docs.
const expectedConnectorCount = 201

// expectedSessionRevokerCount is the canonical number of
// AccessConnector implementations that also satisfy SessionRevoker.
// docs/architecture.md §8 (kill-switch) calls this the Tier 1 set
// for the leaver flow.
const expectedSessionRevokerCount = 29

// expectedSSOEnforcementCheckerCount is the canonical number of
// AccessConnector implementations that also satisfy
// SSOEnforcementChecker. docs/architecture.md §13 (SSO-only
// enforcement verification) uses this set for the orphan
// reconciler's daily SSO-regression scan. The count grows when a
// connector adds a CheckSSOEnforcement implementation; the matching
// docs MUST be updated in the same PR. Group B T13/T14 bumped this
// to 14 by adding Dropbox + Zoom — keep this number aligned with
// README.md's connector list and the §2 entry in docs/connectors.md.
const expectedSSOEnforcementCheckerCount = 21

// TestRegistry_ExactConnectorCount fails when the connector count
// drifts from expectedConnectorCount. It is intentionally an
// equality check (not >=) so adding a connector forces a deliberate
// doc + count update.
func TestRegistry_ExactConnectorCount(t *testing.T) {
	got := len(access.ListRegisteredProviders())
	if got != expectedConnectorCount {
		t.Fatalf("ListRegisteredProviders() count = %d; want %d (update docs/architecture.md + docs/connectors.md + README.md)", got, expectedConnectorCount)
	}
}

// TestRegistry_SessionRevokerCount fails when the count of
// connectors implementing the SessionRevoker optional interface
// drifts. The expected value reflects the set of connectors
// that participate in the leaver-flow kill-switch.
func TestRegistry_SessionRevokerCount(t *testing.T) {
	providers := access.ListRegisteredProviders()
	got := 0
	for _, p := range providers {
		c, err := access.GetAccessConnector(p)
		if err != nil || c == nil {
			continue
		}
		if _, ok := c.(access.SessionRevoker); ok {
			got++
		}
	}
	if got != expectedSessionRevokerCount {
		t.Fatalf("SessionRevoker implementations = %d; want %d (update docs + README.md count)", got, expectedSessionRevokerCount)
	}
}

// TestRegistry_SSOEnforcementCheckerCount fails when the count of
// connectors implementing the SSOEnforcementChecker optional
// interface drifts. The expected value reflects the set of
// connectors that the orphan-reconciler / connector-setup SSO
// regression scan walks.
func TestRegistry_SSOEnforcementCheckerCount(t *testing.T) {
	providers := access.ListRegisteredProviders()
	got := 0
	for _, p := range providers {
		c, err := access.GetAccessConnector(p)
		if err != nil || c == nil {
			continue
		}
		if _, ok := c.(access.SSOEnforcementChecker); ok {
			got++
		}
	}
	if got != expectedSSOEnforcementCheckerCount {
		t.Fatalf("SSOEnforcementChecker implementations = %d; want %d (update docs + README.md count)", got, expectedSSOEnforcementCheckerCount)
	}
}

// TestRegistry_NoOrphanDirectories asserts every directory under
// internal/services/access/connectors/ maps to a registered
// provider. The check protects against the failure mode where a
// connector package is added but its blank-import is missed from
// cmd/<binary>/main.go (or this test file), which silently drops
// the provider out of the registry without tripping
// TestRegistry_ExactConnectorCount (the count check only verifies
// 200 — not that the 200 are the expected 200).
//
// The mapping from directory name to provider name is the
// directory's ProviderName constant; nearly every package uses the
// same string for the directory and the registry key, but we still
// resolve via the directory's ProviderName-vs-registry lookup so
// renames don't quietly slip through.
func TestRegistry_NoOrphanDirectories(t *testing.T) {
	// directoryToProvider captures every directory whose
	// ProviderName constant differs from the directory name.
	// Production registers connectors by their ProviderName, so
	// the registry guard MUST translate via this map rather than
	// assume directory == provider. Add an entry here whenever a
	// new connector picks a divergent registry key.
	directoryToProvider := map[string]string{
		"duo": "duo_security",
	}
	// nonConnectorDirs lists subdirectories under connectors/ that
	// are NOT individual provider packages and must be excluded
	// from the orphan-directory + count guards. The canonical
	// example is connectors/all/, which is a meta-package whose
	// only job is to blank-import every provider so the cmd
	// binaries (and this test file) can replace the duplicated
	// 200-line import lists with a single line. Add an entry here
	// whenever a future helper package lands under connectors/.
	nonConnectorDirs := map[string]struct{}{
		"all": {},
		// connutil holds shared HTTP helpers (e.g. the bounded,
		// fail-closed body reader) imported by the provider packages;
		// it is not itself a connector.
		"connutil": {},
	}
	const connectorsDir = "connectors"
	entries, err := os.ReadDir(connectorsDir)
	if err != nil {
		t.Fatalf("read connectors dir: %v", err)
	}
	registered := make(map[string]struct{}, expectedConnectorCount)
	for _, p := range access.ListRegisteredProviders() {
		registered[p] = struct{}{}
	}
	dirs := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, skip := nonConnectorDirs[e.Name()]; skip {
			continue
		}
		dirs++
		provider := e.Name()
		if alt, ok := directoryToProvider[provider]; ok {
			provider = alt
		}
		if _, ok := registered[provider]; !ok {
			t.Errorf("connectors/%s/ has no matching registry entry (forgot the blank-import in connectors/all/all.go? or add to directoryToProvider above)", e.Name())
		}
	}
	if dirs != expectedConnectorCount {
		t.Errorf("connectors/ directory count = %d; want %d (mismatch with expectedConnectorCount)", dirs, expectedConnectorCount)
	}
}

// expectedSCIMProvisionerCount is the canonical number of
// AccessConnector implementations that also satisfy
// SCIMProvisioner. Bumping this requires landing the matching
// scim.go + scim_test.go inside the connector package AND
// refreshing docs/connectors.md §3 + README.md in the same PR.
const expectedSCIMProvisionerCount = 33

// expectedGroupSyncerCount is the canonical number of
// AccessConnector implementations that also satisfy GroupSyncer.
// Bumping this requires landing the matching groups.go +
// groups_test.go inside the connector package AND refreshing
// docs/connectors.md §4 + README.md in the same PR.
const expectedGroupSyncerCount = 28

// expectedIdentityDeltaSyncerCount is the canonical number of
// AccessConnector implementations that also satisfy
// IdentityDeltaSyncer (delta-sync hardening per docs/connectors.md
// §4). The actual count at HEAD is 13 — bumped by the gitlab,
// aws, jira, zendesk, and bamboohr connectors adding
// SyncIdentitiesDelta via audit / CloudTrail / Atlassian Admin
// events / audit_logs / /v1/employees/changed.
const expectedIdentityDeltaSyncerCount = 13

// expectedAccessAuditorCount is the canonical number of
// AccessConnector implementations that also satisfy AccessAuditor.
// docs/connectors.md §3 reports "audit logs across 198 (2 n/a)"; the
// actual count at HEAD is 198, matching the docs.
const expectedAccessAuditorCount = 198

// TestRegistry_SCIMProvisionerCount fails when the count of
// connectors implementing SCIMProvisioner drifts. Bumping this
// count requires updating the README + docs/connectors.md §3 in the
// same PR.
func TestRegistry_SCIMProvisionerCount(t *testing.T) {
	got := countImpls[access.SCIMProvisioner]()
	if got != expectedSCIMProvisionerCount {
		t.Fatalf("SCIMProvisioner implementations = %d; want %d (update docs/connectors.md §3 + README.md)", got, expectedSCIMProvisionerCount)
	}
}

// TestRegistry_GroupSyncerCount fails when the count of connectors
// implementing GroupSyncer drifts.
func TestRegistry_GroupSyncerCount(t *testing.T) {
	got := countImpls[access.GroupSyncer]()
	if got != expectedGroupSyncerCount {
		t.Fatalf("GroupSyncer implementations = %d; want %d (update docs/connectors.md §4)", got, expectedGroupSyncerCount)
	}
}

// TestRegistry_IdentityDeltaSyncerCount fails when the count of
// connectors implementing IdentityDeltaSyncer drifts.
func TestRegistry_IdentityDeltaSyncerCount(t *testing.T) {
	got := countImpls[access.IdentityDeltaSyncer]()
	if got != expectedIdentityDeltaSyncerCount {
		t.Fatalf("IdentityDeltaSyncer implementations = %d; want %d (update docs/connectors.md §4)", got, expectedIdentityDeltaSyncerCount)
	}
}

// TestRegistry_AccessAuditorCount fails when the count of
// connectors implementing AccessAuditor drifts.
func TestRegistry_AccessAuditorCount(t *testing.T) {
	got := countImpls[access.AccessAuditor]()
	if got != expectedAccessAuditorCount {
		t.Fatalf("AccessAuditor implementations = %d; want %d (update docs/connectors.md §3 + README.md)", got, expectedAccessAuditorCount)
	}
}

// countImpls returns the number of registered AccessConnectors
// whose concrete type satisfies the optional interface T. The
// generic shape keeps the per-interface tests above to a single
// line each so adding a new optional interface boils down to a
// new const + a new TestRegistry_<...>Count test.
func countImpls[T any]() int {
	n := 0
	for _, p := range access.ListRegisteredProviders() {
		c, err := access.GetAccessConnector(p)
		if err != nil || c == nil {
			continue
		}
		if _, ok := any(c).(T); ok {
			n++
		}
	}
	return n
}
