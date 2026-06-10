// Package manual implements the access.AccessConnector contract for a
// manually-fulfilled access target: a system the platform governs but does not
// integrate with over an API (a legacy on-prem app, a physical-access system, a
// vendor portal with no automation surface, a spreadsheet-managed entitlement).
//
// This is a first-class capability, not a stub. Real SME tenants always have a
// tail of systems with no programmatic API, yet those systems still need the
// same governance guarantees as the automated fleet: a request that flows
// through policy + RBAC + step-up MFA, an approval, a recorded grant with an
// expiry, inclusion in access reviews and certification campaigns, and a
// revocation that lands on the audit chain. The manual connector provides
// exactly that. Provisioning and revocation are recorded by the control plane
// (the grant lifecycle, the evidence chain) while the physical fulfilment is
// performed out-of-band by an operator — so ProvisionAccess / RevokeAccess
// succeed locally without any network call.
//
// Scope:
//
//   - Validate (pure-local), Connect (always reachable — nothing to probe),
//     VerifyPermissions (everything it offers is local, so nothing is missing).
//   - ProvisionAccess / RevokeAccess: local, idempotent, no network. The grant
//     is materialised and audited by the lifecycle service; the operator
//     fulfils the physical change out-of-band.
//   - ListEntitlements: empty (the platform's own grant store is the system of
//     record for a manual target, so there is no provider to query).
//   - CountIdentities / SyncIdentities: no enumeration. SyncIdentities invokes
//     the handler once with a non-nil empty batch and a terminal cursor, the
//     same "configured but nothing to enumerate" contract the interface
//     documents — so the orphan reconciler treats a manual connector as a
//     no-op rather than tombstoning the grants it cannot see.
//   - GetSSOMetadata: (nil, nil) — a manual target does not federate SSO.
//   - GetCredentialsMetadata: a static descriptor (no secret is stored).
package manual

import (
	"context"
	"fmt"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// ProviderName is the registry key for the manual connector.
const ProviderName = "manual"

// ManualAccessConnector implements access.AccessConnector for a
// manually-fulfilled target.
type ManualAccessConnector struct{}

// New returns a fresh connector instance.
func New() *ManualAccessConnector { return &ManualAccessConnector{} }

// ---------- Validate / Connect / VerifyPermissions ----------

// Validate checks the (entirely optional) configuration is well-formed and
// performs no network I/O. A manual target carries no secrets, so a non-empty
// secrets map is the only validation failure — it almost always signals a
// misconfigured connector (secrets pasted into the wrong provider).
func (c *ManualAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
	if _, err := decodeConfig(configRaw); err != nil {
		return err
	}
	if len(secretsRaw) > 0 {
		return fmt.Errorf("%w: manual: a manually-fulfilled target stores no secrets", access.ErrValidation)
	}
	return nil
}

// Connect is a no-op success: a manual target has no endpoint or credentials to
// probe, and is by definition always "reachable" (fulfilment is human).
func (c *ManualAccessConnector) Connect(_ context.Context, configRaw, _ map[string]interface{}) error {
	_, err := decodeConfig(configRaw)
	return err
}

// VerifyPermissions reports no missing capabilities: everything the manual
// connector offers (provision, revoke) is performed locally and cannot be
// "unauthorized" at a provider. Capabilities it structurally lacks (identity
// sync, SSO federation) are surfaced through the catalogue descriptor, not as
// a per-connector permission gap.
func (c *ManualAccessConnector) VerifyPermissions(_ context.Context, _, _ map[string]interface{}, _ []string) ([]string, error) {
	return nil, nil
}

// ---------- enumeration ----------

// CountIdentities returns 0: the control plane's own grant store is the system
// of record for a manual target, so there is nothing to enumerate from a
// provider.
func (c *ManualAccessConnector) CountIdentities(_ context.Context, _, _ map[string]interface{}) (int, error) {
	return 0, nil
}

// SyncIdentities performs no enumeration. It invokes handler once with a
// non-nil empty batch and a terminal ("") cursor, honouring the interface's
// empty-batch contract so downstream JSON consumers see [] not null, and so the
// orphan reconciler treats a manual connector as "nothing to compare" rather
// than tombstoning every recorded grant.
func (c *ManualAccessConnector) SyncIdentities(
	_ context.Context,
	_, _ map[string]interface{},
	_ string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	return handler([]*access.Identity{}, "")
}

// ---------- provisioning ----------

// ProvisionAccess records that access should be fulfilled on the manual target.
// It is a local, idempotent success: the lifecycle service materialises and
// audits the grant, and an operator performs the physical change out-of-band.
// The (user, resource) pair is still validated so a malformed grant fails fast
// rather than recording an un-actionable entry.
func (c *ManualAccessConnector) ProvisionAccess(_ context.Context, _, _ map[string]interface{}, grant access.AccessGrant) error {
	return validateGrantPair(grant)
}

// RevokeAccess records that access should be removed on the manual target.
// Local, idempotent success, mirroring ProvisionAccess.
func (c *ManualAccessConnector) RevokeAccess(_ context.Context, _, _ map[string]interface{}, grant access.AccessGrant) error {
	return validateGrantPair(grant)
}

// ListEntitlements returns an empty set: for a manual target the platform's own
// grant store is the system of record, so there is no external entitlement
// surface to read back.
func (c *ManualAccessConnector) ListEntitlements(_ context.Context, _, _ map[string]interface{}, _ string) ([]access.Entitlement, error) {
	return []access.Entitlement{}, nil
}

// ---------- SSO / credentials metadata ----------

// GetSSOMetadata returns (nil, nil): a manual target does not federate SSO.
func (c *ManualAccessConnector) GetSSOMetadata(_ context.Context, _, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return nil, nil
}

// GetCredentialsMetadata returns a static descriptor. A manual target stores no
// secret, so there is no expiry, scope, or fingerprint to report — the auth
// type is reported as "manual" so the expiry-alert and renewal crons skip it.
func (c *ManualAccessConnector) GetCredentialsMetadata(_ context.Context, _, _ map[string]interface{}) (map[string]interface{}, error) {
	return map[string]interface{}{"auth_type": "manual"}, nil
}

// validateGrantPair enforces the idempotency key the interface contract
// requires: a grant with no user or no resource is un-actionable.
func validateGrantPair(grant access.AccessGrant) error {
	if grant.UserExternalID == "" {
		return fmt.Errorf("%w: manual: grant.UserExternalID is required", access.ErrValidation)
	}
	if grant.ResourceExternalID == "" {
		return fmt.Errorf("%w: manual: grant.ResourceExternalID is required", access.ErrValidation)
	}
	return nil
}
