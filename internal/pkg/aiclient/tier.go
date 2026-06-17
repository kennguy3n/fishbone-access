package aiclient

import "strings"

// AI tier identifiers stamped into the A2A envelope's workspace_ai_tier field.
// The agent routes the model per tier: the deterministic tier skips the LLM
// entirely (rule-based core only), local_4b and local_8b select the 4B and 8B
// quantized local models.
const (
	TierDeterministic = "deterministic"
	TierLocal4B       = "local_4b"
	TierLocal8B       = "local_8b"
)

// TierForPlan maps a workspace billing plan to the AI tier the agent uses to
// pick a model: Pro → local_4b, Ultimate → local_8b, and everything else (base
// plans, unknown values, or empty) → deterministic. It is the single source of
// truth for the plan→tier mapping shared by every service that scores through
// the agent, so the mapping cannot drift between call sites. Callers that load
// the plan from the database should pass an empty string on a lookup error,
// which fails safe to the cheapest (deterministic) tier.
func TierForPlan(plan string) string {
	switch strings.TrimSpace(strings.ToLower(plan)) {
	case "pro":
		return TierLocal4B
	case "ultimate":
		return TierLocal8B
	default:
		return TierDeterministic
	}
}
