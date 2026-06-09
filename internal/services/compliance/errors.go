// Package compliance turns the access control plane's normal operation into
// audit-grade compliance evidence and runs full certification campaigns.
//
// Two ideas drive the package:
//
//   - Evidence as a side effect. The compliance evidence stream is NOT a new,
//     separately-forgeable log. It is a typed projection over the existing
//     per-workspace audit hash chain (lifecycle.appendAudit → models.AuditEvent):
//     every control-relevant action (access granted/revoked, policy promoted,
//     review/certification completed, leaver kill-switch fired, privileged
//     command, evidence exported) is already linked into the SHA-256 chain, so
//     evidence inherits the chain's tamper-evidence instead of duplicating it.
//
//   - Certification campaigns are the full expansion of the 1C access-review
//     primitive: scoped (resource / role / connector), reviewer-assigned,
//     due-dated reviews whose per-grant decisions are STAGED and only applied
//     (grants torn down) at close — so the destructive effect can be previewed
//     first, mirroring the policy promote simulate-before-promote gate.
//
// Everything is workspace-scoped and fail-closed: a missing workspace id, an
// unknown campaign, or a revoke with no wired revoker is rejected, never
// silently widened.
package compliance

import "errors"

// Sentinel errors surfaced to the handler layer, which maps them to HTTP status
// codes. They are wrapped with fmt.Errorf("...: %w", err) at the raise site so
// callers errors.Is them without depending on message formats.
var (
	// ErrValidation is returned when service input is missing a required field
	// or is otherwise malformed.
	ErrValidation = errors.New("compliance: validation failed")

	// ErrCampaignNotFound is returned when a campaign id matches no row in the
	// caller's workspace.
	ErrCampaignNotFound = errors.New("compliance: certification campaign not found")

	// ErrItemNotFound is returned when a campaign exists but the referenced item
	// id matches no row in it.
	ErrItemNotFound = errors.New("compliance: certification item not found")

	// ErrCampaignClosed is returned when a decision is submitted against a
	// closed campaign.
	ErrCampaignClosed = errors.New("compliance: certification campaign is closed")

	// ErrItemDecided is returned when a decision flips an item that already
	// carries a different terminal decision (certify/revoke). Re-submitting the
	// same decision is idempotent and allowed.
	ErrItemDecided = errors.New("compliance: certification item already decided")

	// ErrNoRevoker is returned when a campaign with staged revoke decisions is
	// closed but no grant revoker is wired — fail closed rather than mark a
	// grant "revoked" we cannot actually tear down.
	ErrNoRevoker = errors.New("compliance: certification service has no grant revoker wired")

	// ErrUnknownFramework is returned when an export requests a framework that
	// is not in the catalog.
	ErrUnknownFramework = errors.New("compliance: unknown framework")
)
