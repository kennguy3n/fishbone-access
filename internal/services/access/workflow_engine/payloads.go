// Package workflow_engine orchestrates the ShieldNet Access JML
// (Joiner/Mover/Leaver) lifecycle, approval chains, and scheduled access
// reviews on top of the 1C lifecycle services and the 1B connector worker
// queue.
//
// The engine never re-implements the access-request FSM, the connector
// protocol, or the kill switch — it drives the existing lifecycle services
// (request / workflow / provisioning / JML / review) and the persisted
// access_jobs queue. Long-running or redelivery-prone work (SCIM JML events,
// provisioning, scheduled review sweeps) is enqueued as a workflow job and
// executed by JobProcessor, so an in-flight workflow survives a worker restart:
// the job stays queued until a worker claims and completes it, and every
// handler is idempotent so a redelivered job is safe.
package workflow_engine

import (
	"encoding/json"
	"fmt"

	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
)

// Workflow job types drained by JobProcessor. They are deliberately disjoint
// from the connector worker's job types (sync_identities / provision_access /
// revoke_access) so the two workers can share the access_jobs table while each
// claims only the jobs it can process (see workers.WithJobTypes).
const (
	// JobTypeJMLEvent re-runs a normalized SCIM event through the JML service.
	JobTypeJMLEvent = "workflow.jml_event"
	// JobTypeProvisionRequest drives an approved request to a live grant via the
	// provisioning service (idempotent: Provision no-ops a request already
	// active).
	JobTypeProvisionRequest = "workflow.provision_request"
	// JobTypeReviewSweep runs one scheduled certification sweep for a workspace.
	JobTypeReviewSweep = "workflow.review_sweep"
)

// AllJobTypes is the set of workflow job types, for wiring a type-filtered
// queue in the workflow-engine binary.
func AllJobTypes() []string {
	return []string{JobTypeJMLEvent, JobTypeProvisionRequest, JobTypeReviewSweep}
}

// jmlEventPayload carries a normalized SCIM event to be (re)processed by the JML
// service. The event is stored whole so the handler classifies + dispatches it
// exactly as a synchronous call would.
type jmlEventPayload struct {
	WorkspaceID string              `json:"workspace_id"`
	Event       lifecycle.SCIMEvent `json:"event"`
}

// provisionRequestPayload drives provisioning of an approved request.
type provisionRequestPayload struct {
	WorkspaceID string `json:"workspace_id"`
	RequestID   string `json:"request_id"`
	Actor       string `json:"actor"`
}

// reviewSweepPayload runs a scheduled certification campaign for a workspace and
// auto-decides each item via the AI review-automation skill, falling back to
// manual review when the agent is unavailable.
type reviewSweepPayload struct {
	WorkspaceID     string `json:"workspace_id"`
	CampaignName    string `json:"campaign_name"`
	Actor           string `json:"actor"`
	WorkspaceAITier string `json:"workspace_ai_tier,omitempty"`
}

func mustMarshal(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("workflow_engine: marshal payload: %w", err)
	}
	return b, nil
}
