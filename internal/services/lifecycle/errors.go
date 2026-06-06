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

	// ErrReviewNotFound is returned when a review id (or review item) matches
	// no row in the caller's workspace.
	ErrReviewNotFound = errors.New("lifecycle: access review not found")

	// ErrReviewClosed is returned when a decision is submitted against a
	// completed campaign.
	ErrReviewClosed = errors.New("lifecycle: access review is closed")

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
)
