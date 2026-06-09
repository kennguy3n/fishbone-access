package aiclient

import (
	"context"

	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
)

// ConnectorSetupInput is the payload for the connector_setup_assistant skill.
// Provider is the registry key of the connector being configured (required).
// AdminIntent is the operator's free-text goal (optional) and Category /
// Capabilities give the agent enough context to tailor the plan without a DB
// round-trip.
type ConnectorSetupInput struct {
	Provider     string   `json:"provider"`
	AdminIntent  string   `json:"admin_intent,omitempty"`
	Category     string   `json:"category,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
}

// ConnectorSetupFieldMapping is one IdP-attribute → platform-field mapping
// suggestion within a setup step.
type ConnectorSetupFieldMapping struct {
	Source string `json:"source"`
	Target string `json:"target"`
}

// ConnectorSetupStep is one ordered step in the guided setup plan.
type ConnectorSetupStep struct {
	Step             int                          `json:"step"`
	Title            string                       `json:"title"`
	Description      string                       `json:"description"`
	RequiredScopes   []string                     `json:"required_scopes,omitempty"`
	FieldMappings    []ConnectorSetupFieldMapping `json:"field_mappings,omitempty"`
	CommonPitfalls   []string                     `json:"common_pitfalls,omitempty"`
	EstimatedMinutes int                          `json:"estimated_minutes,omitempty"`
}

// ConnectorSetupPlan is the normalized result of a connector_setup_assistant
// call: the resolved iam-core strategy slug, the ordered steps, a prose
// explanation, and provenance flags. Degraded is true when the plan is the
// control plane's own fail-open fallback (agent unreachable) rather than an
// agent response; ModelUsed is true when the agent enriched the explanation
// with the LLM (as opposed to its deterministic core).
type ConnectorSetupPlan struct {
	Strategy    string               `json:"strategy"`
	Explanation string               `json:"explanation"`
	Steps       []ConnectorSetupStep `json:"steps"`
	ModelUsed   bool                 `json:"model_used"`
	Degraded    bool                 `json:"degraded"`
}

// connectorSetupSkillResponse is the wire shape returned by the Python skill.
// It is decoded directly (rather than via the unified SkillResponse envelope)
// because the setup plan carries skill-specific structured fields.
type connectorSetupSkillResponse struct {
	Explanation string               `json:"explanation"`
	Reason      string               `json:"reason"`
	Strategy    string               `json:"strategy"`
	Steps       []ConnectorSetupStep `json:"steps"`
	ModelUsed   bool                 `json:"model_used"`
}

// ConnectorSetup invokes the connector_setup_assistant skill and normalizes the
// response. It returns the raw error (including ErrAIUnconfigured) so callers
// that must distinguish outcomes can; most callers should prefer
// ConnectorSetupWithFallback, which is fail-OPEN.
func ConnectorSetup(ctx context.Context, c *AIClient, workspaceAITier string, in ConnectorSetupInput) (ConnectorSetupPlan, error) {
	var resp connectorSetupSkillResponse
	if err := c.InvokeSkillInto(ctx, SkillConnectorSetup, workspaceAITier, in, &resp); err != nil {
		return ConnectorSetupPlan{}, err
	}
	return ConnectorSetupPlan{
		Strategy:    resp.Strategy,
		Explanation: resp.Explanation,
		Steps:       resp.Steps,
		ModelUsed:   resp.ModelUsed,
	}, nil
}

// ConnectorSetupWithFallback never errors: on any agent failure it returns a
// degraded, manual-only plan so the setup wizard remains usable while the agent
// is down (fail-OPEN — an advisory outage must never block a human from
// configuring a connector). The fallback steps are deliberately
// provider-agnostic; the rich, provider-specific plan only comes from the
// agent. Callers MUST persist the returned plan (including Degraded) for audit.
func ConnectorSetupWithFallback(ctx context.Context, c *AIClient, workspaceAITier string, in ConnectorSetupInput) ConnectorSetupPlan {
	plan, err := ConnectorSetup(ctx, c, workspaceAITier, in)
	if err == nil {
		return plan
	}
	logger.Warnf(ctx, "aiclient: connector setup fallback for provider %q: %v", in.Provider, err)
	return fallbackConnectorSetupPlan(in)
}

// fallbackConnectorSetupPlan is the control plane's deterministic, manual setup
// guidance used when the agent is unreachable. It is intentionally minimal but
// real: it walks the operator through the same credential → test → enable arc
// the wizard enforces, so a model outage degrades the experience rather than
// breaking it.
func fallbackConnectorSetupPlan(in ConnectorSetupInput) ConnectorSetupPlan {
	return ConnectorSetupPlan{
		Strategy:    "unknown",
		Degraded:    true,
		ModelUsed:   false,
		Explanation: "The setup assistant is temporarily unavailable, so this is generic manual guidance. You can still configure the connector by hand: enter its credentials, test connectivity, then enable it.",
		Steps: []ConnectorSetupStep{
			{
				Step:             1,
				Title:            "Gather the connector's credentials",
				Description:      "Create an application / API credential for this provider in its admin console and copy the client secret or API key. The platform seals it at rest with AES-GCM.",
				EstimatedMinutes: 10,
			},
			{
				Step:             2,
				Title:            "Test connectivity",
				Description:      "Use the wizard's Test action to call VerifyPermissions against the provider. Resolve any scope or consent errors before continuing.",
				EstimatedMinutes: 3,
			},
			{
				Step:             3,
				Title:            "Enable the connector and run the first sync",
				Description:      "Create the connector instance and trigger the initial identity sync once the test is green.",
				EstimatedMinutes: 5,
			},
		},
	}
}
