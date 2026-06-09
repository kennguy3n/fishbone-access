// Package lifecycle implements Session 1C of ShieldNet Access: the access
// request state machine, the request / workflow / policy / provisioning /
// review / JML services, the six-layer leaver kill switch, orphan-account
// reconciliation, and the grant-expiry enforcer.
//
// The package depends only on the AccessConnector interface contract from
// internal/services/access (never on the concrete 1B connector packages) so
// the two sessions coordinate through interfaces, and on internal/models for
// persistence. Every tenant-scoped query is filtered by workspace_id; callers
// reach these services through the tenant-scoped, RequireTenant-guarded REST
// routes in internal/handlers.
package lifecycle

import (
	"errors"
	"fmt"
)

// RequestState is a typed alias for the values stored in
// models.AccessRequest.State. It is an alias (not a defined type) so values
// round-trip through GORM and JSON without translation and so switch
// statements over it are not subject to exhaustiveness linting.
type RequestState = string

// Access-request lifecycle states. Kept as string constants local to this
// package so the FSM has no dependency on the models package (the column is a
// plain TEXT default of "requested").
const (
	StateRequested       RequestState = "requested"
	StateAIReviewed      RequestState = "ai_reviewed"
	StateApproved        RequestState = "approved"
	StateDenied          RequestState = "denied"
	StateCancelled       RequestState = "cancelled"
	StateProvisioning    RequestState = "provisioning"
	StateProvisioned     RequestState = "provisioned"
	StateProvisionFailed RequestState = "provision_failed"
	StateActive          RequestState = "active"
	StateRevoked         RequestState = "revoked"
	StateExpired         RequestState = "expired"
)

// ErrInvalidStateTransition is returned by Transition when a (from, to) pair is
// not in the allow-list. Callers wrap it with fmt.Errorf("...: %w", err) and
// surface it as a 4xx validation error; errors.Is reaches the sentinel.
var ErrInvalidStateTransition = errors.New("lifecycle: invalid request state transition")

// allowedTransitions is the single source of truth for the request lifecycle.
// Keys are "from" states; values are the set of legal "to" states.
//
//	requested        → ai_reviewed | approved | denied | cancelled
//	ai_reviewed      → approved | denied | cancelled
//	approved         → provisioning | cancelled
//	provisioning     → provisioned | provision_failed
//	provision_failed → provisioning              (operator-initiated retry)
//	provisioned      → active
//	active           → revoked | expired
//
// ai_reviewed is the audited "AI risk review complete" state the
// RiskReviewService moves a request into once a risk verdict is persisted; the
// canonical elevation path is requested → ai_reviewed → approved/denied →
// provisioning → provisioned → active → expired. The direct requested →
// approved/denied/cancelled edges are retained so internal callers that do not
// run the AI gate (the JML provisioning lane, the async workflow engine) and
// pre-existing requests keep working unchanged; approve/deny are therefore
// legal from both requested and ai_reviewed.
//
// Terminal states (denied, cancelled, revoked, expired) have no outgoing
// edges and are reported by IsTerminalState via their absence here.
var allowedTransitions = map[RequestState]map[RequestState]struct{}{
	StateRequested: {
		StateAIReviewed: {},
		StateApproved:   {},
		StateDenied:     {},
		StateCancelled:  {},
	},
	StateAIReviewed: {
		StateApproved:  {},
		StateDenied:    {},
		StateCancelled: {},
	},
	StateApproved: {
		StateProvisioning: {},
		StateCancelled:    {},
	},
	StateProvisioning: {
		StateProvisioned:     {},
		StateProvisionFailed: {},
	},
	StateProvisionFailed: {
		StateProvisioning: {},
	},
	StateProvisioned: {
		StateActive: {},
	},
	StateActive: {
		StateRevoked: {},
		StateExpired: {},
	},
}

// Transition validates whether a request may move from `from` to `to`. It
// returns nil iff the transition is in the allow-list and never mutates any
// state: it is the FSM gate, and the caller is responsible for reading the
// current state, writing the new state, and recording history.
func Transition(from, to RequestState) error {
	allowed, ok := allowedTransitions[from]
	if !ok {
		return fmt.Errorf("%w: %q is terminal or unknown (cannot move to %q)", ErrInvalidStateTransition, from, to)
	}
	if _, ok := allowed[to]; !ok {
		return fmt.Errorf("%w: %q → %q is not allowed", ErrInvalidStateTransition, from, to)
	}
	return nil
}

// IsTerminalState reports whether `s` has no outgoing transitions.
func IsTerminalState(s RequestState) bool {
	_, ok := allowedTransitions[s]
	return !ok
}

// AllowedNextStates returns a freshly-allocated slice of the legal "to" states
// from `from` (nil for terminal or unknown states). Intended for diagnostics
// and admin tooling; production code paths call Transition directly.
func AllowedNextStates(from RequestState) []RequestState {
	allowed, ok := allowedTransitions[from]
	if !ok {
		return nil
	}
	out := make([]RequestState, 0, len(allowed))
	for s := range allowed {
		out = append(out, s)
	}
	return out
}
