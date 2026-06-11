package lifecycle

import "errors"

// Shared sentinel errors for the lifecycle services. They are wrapped with
// fmt.Errorf("...: %w", err) at the raise site so callers errors.Is them
// without depending on message formats, and the REST layer maps them to HTTP
// status codes (ErrValidation/ErrInvalidStateTransition → 400/409,
// Err*NotFound → 404).
var (
	// ErrValidation is returned when service input is missing a required
	// field or is otherwise malformed.
	ErrValidation = errors.New("lifecycle: validation failed")

	// ErrRequestNotFound is returned when an access-request id matches no row
	// in the caller's workspace.
	ErrRequestNotFound = errors.New("lifecycle: access request not found")

	// ErrPolicyNotFound is returned when a policy id matches no row in the
	// caller's workspace.
	ErrPolicyNotFound = errors.New("lifecycle: policy not found")

	// ErrReviewNotFound is returned when a review id matches no row in the
	// caller's workspace.
	ErrReviewNotFound = errors.New("lifecycle: access review not found")

	// ErrReviewItemNotFound is returned when a review exists but the referenced
	// item id matches no row in it. Distinct from ErrReviewNotFound so a client
	// gets an accurate message (the review is fine; the item is the problem)
	// rather than a misleading "access review not found". Both still map to 404.
	ErrReviewItemNotFound = errors.New("lifecycle: access review item not found")

	// ErrReviewClosed is returned when a decision is submitted against a
	// completed campaign.
	ErrReviewClosed = errors.New("lifecycle: access review is closed")

	// ErrReviewItemDecided is returned when a decision is submitted against a
	// review item that already carries a terminal decision (certify/revoke).
	// Re-deciding is rejected so a destructive revoke can never be silently
	// flipped back to certify (or vice versa); an escalated item may still be
	// resolved.
	ErrReviewItemDecided = errors.New("lifecycle: review item already decided")

	// ErrGrantNotFound is returned when a grant id matches no live row.
	ErrGrantNotFound = errors.New("lifecycle: access grant not found")

	// ErrOrphanNotFound is returned when an orphan-account id matches no row
	// in the caller's workspace.
	ErrOrphanNotFound = errors.New("lifecycle: orphan account not found")

	// ErrConnectorNotConfigured is returned when a request/grant references a
	// connector that is not registered in the access factory, or when the
	// request carries no connector id at all.
	ErrConnectorNotConfigured = errors.New("lifecycle: connector not configured")

	// ErrPolicyNotPromotable is returned when Promote is called on a policy in
	// a state that cannot be promoted (e.g. archived).
	ErrPolicyNotPromotable = errors.New("lifecycle: policy cannot be promoted")

	// ErrPolicyNotEditable is returned when UpdateDraft is called on a policy
	// that is not a draft (an active or archived policy must be superseded by a
	// new draft, not edited in place).
	ErrPolicyNotEditable = errors.New("lifecycle: policy is not editable")

	// ErrPolicyNotSimulated is returned when Promote is called on a draft that
	// has not been simulated since its last edit. Access policies must be
	// tested (simulated) and verified before they can be rolled out, so a draft
	// with no cached impact report cannot be promoted.
	ErrPolicyNotSimulated = errors.New("lifecycle: policy must be simulated before promotion")

	// ErrPolicyHasConflicts is returned when Promote is called on a draft that
	// still has unresolved grant-vs-deny conflicts with live policies. The
	// caller can override with an audited reason once the conflict is reviewed.
	ErrPolicyHasConflicts = errors.New("lifecycle: policy has unresolved conflicts")

	// ErrPolicyHasSodViolations is returned when Promote is blocked because the
	// candidate policy would introduce a high/critical Separation-of-Duties
	// toxic combination ("catastrophic change"). Overridable with an audited
	// reason once the violation is reviewed, exactly like a grant-vs-deny block.
	ErrPolicyHasSodViolations = errors.New("lifecycle: policy introduces separation-of-duties violations")

	// ErrSodRuleNotFound is returned when a SoD rule id matches no row in the
	// caller's workspace.
	ErrSodRuleNotFound = errors.New("lifecycle: sod rule not found")

	// ErrContractorGrantNotFound is returned when a contractor-grant id matches
	// no row in the caller's workspace.
	ErrContractorGrantNotFound = errors.New("lifecycle: contractor grant not found")

	// ErrContractorState is returned when a contractor-grant operation is
	// invalid for the grant's current state (e.g. approving an already-active
	// grant, or extending a revoked one).
	ErrContractorState = errors.New("lifecycle: invalid contractor grant state for this operation")
)
