package models

import (
	"github.com/google/uuid"
	"gorm.io/datatypes"
)

// ConnectorSetupSuggestion persists one invocation of the AI connector-setup
// assistant: the structured plan the agent returned, the inputs that produced
// it, and provenance flags. It exists for auditability — the program contract
// requires the model's rationale + inputs to be persisted whenever AI advises
// an operator — and to let the console show the operator their prior setup
// guidance for a connector without re-invoking the agent.
//
// Tenant isolation: WorkspaceID scopes every row; the assistant is always
// invoked under the Auth → ResolveTenant → RequireTenant chain and the row is
// written with the workspace resolved from the validated tenant context, never
// from client input. ConnectorID is nullable because the assistant is typically
// run before the connector instance exists (during the setup wizard); once an
// instance is created the suggestion can be associated with it.
type ConnectorSetupSuggestion struct {
	Base
	WorkspaceID uuid.UUID  `gorm:"type:uuid;index;not null" json:"workspace_id"`
	ConnectorID *uuid.UUID `gorm:"type:uuid;index" json:"connector_id,omitempty"`
	Provider    string     `gorm:"not null;index" json:"provider"`
	Actor       string     `json:"actor"`
	AdminIntent string     `json:"admin_intent,omitempty"`
	Strategy    string     `json:"strategy,omitempty"`
	// Degraded records that the plan is the control plane's fail-open fallback
	// (the agent was unreachable) rather than a real assistant response, so an
	// auditor can tell advisory-from-AI apart from advisory-from-degradation.
	Degraded bool `json:"degraded"`
	// ModelUsed records whether the agent enriched the plan with the LLM (vs its
	// deterministic core).
	ModelUsed bool `json:"model_used"`
	// Plan is the structured setup plan (explanation + ordered steps) as JSON.
	Plan datatypes.JSON `json:"plan"`
	// Inputs is the exact payload sent to the assistant, retained for audit.
	Inputs datatypes.JSON `json:"inputs,omitempty"`
}
