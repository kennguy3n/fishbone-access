package workflow

import "errors"

// Sentinel errors for the workflow service. They are wrapped with
// fmt.Errorf("...: %w", err) at the raise site so callers errors.Is them
// without depending on message formats, and the REST layer maps them to HTTP
// status codes (ErrValidation → 400, ErrNotFound → 404,
// ErrNotEditable/ErrNotSimulated/ErrNotPublishable → 409).
var (
	// ErrValidation is returned when input is missing a required field or the
	// workflow document is malformed.
	ErrValidation = errors.New("workflow: validation failed")

	// ErrNotFound is returned when a workflow id matches no row in the caller's
	// workspace.
	ErrNotFound = errors.New("workflow: not found")

	// ErrNotEditable is returned when UpdateDraft is called on a workflow that
	// is not a draft. A published workflow must be superseded by a new draft
	// version, not edited in place, so a live automation never changes
	// underneath running executions.
	ErrNotEditable = errors.New("workflow: not editable")

	// ErrNotSimulated is returned when Publish is called on a draft that has
	// not been dry-run since its last edit. Publishing is gated on a successful
	// simulate (test-before-publish), so a draft with no cached simulation
	// cannot be published.
	ErrNotSimulated = errors.New("workflow: must be simulated before publish")

	// ErrNotPublishable is returned when Publish/Archive is called on a
	// workflow in a state that cannot make that transition (e.g. publishing an
	// already-archived workflow).
	ErrNotPublishable = errors.New("workflow: cannot be published")

	// ErrSimulationFailed is returned when Publish is gated on a dry-run whose
	// cached result reported a failure: a workflow that does not simulate
	// cleanly must not be published.
	ErrSimulationFailed = errors.New("workflow: last simulation reported failures")

	// ErrSimulationNotMatched is returned when Publish is gated on a dry-run
	// whose sample identity did not match the workflow's conditions. A
	// non-matching simulation only proves the conditions filtered the sample
	// out; it never exercises the steps, so it cannot satisfy the
	// test-before-publish guardrail. The admin must simulate a sample that
	// matches the conditions (a workflow with no conditions matches everyone).
	ErrSimulationNotMatched = errors.New("workflow: last simulation did not match the workflow conditions")

	// ErrNotRunnable is returned when a live run is requested for a workflow
	// that is not published. Only a published workflow executes (a draft is
	// dry-run only); this is fail-closed so an unreviewed draft can never
	// effect real changes.
	ErrNotRunnable = errors.New("workflow: only a published workflow can run")
)
