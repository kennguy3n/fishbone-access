// Package connectorsetup backs the AI-assisted connector setup wizard. It wraps
// the access-ai-agent connector_setup_assistant skill (via internal/pkg/aiclient)
// with fail-OPEN semantics and persists every suggestion — the structured plan,
// the inputs that produced it, and its provenance — to a workspace-scoped audit
// trail.
//
// It is a separate package (not part of internal/services/access) because it
// links the audit hash chain in internal/services/lifecycle, which already
// imports the access registry; keeping this orchestration here avoids an import
// cycle while still validating providers against the live registry.
package connectorsetup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/aiclient"
	"github.com/kennguy3n/fishbone-access/internal/services/access"
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
)

// ErrValidation is returned for caller-supplied input that fails validation
// (missing workspace/provider, or an unknown provider). Handlers map it to 400.
var ErrValidation = errors.New("connectorsetup: validation failed")

// auditActionSetupSuggested is the audit-chain action recorded for every setup
// suggestion. State-changing/security-relevant advisory output is logged so the
// per-workspace hash chain captures that an operator was given AI guidance.
const auditActionSetupSuggested = "connector.setup_suggested"

// Service produces and persists AI connector-setup suggestions.
type Service struct {
	db  *gorm.DB
	ai  *aiclient.AIClient
	now func() time.Time
}

// NewService binds the service to the shared DB pool and AI client. ai may be
// an unconfigured client (no agent URL) — Suggest is fail-OPEN and returns a
// degraded manual plan in that case. db is required for persistence.
func NewService(db *gorm.DB, ai *aiclient.AIClient) *Service {
	return &Service{db: db, ai: ai, now: time.Now}
}

// SuggestInput is the validated, server-derived input for a suggestion. The
// workspace and actor come from the tenant context + token (never from the
// request body); Provider and AdminIntent are the operator's wizard inputs.
type SuggestInput struct {
	WorkspaceID     uuid.UUID
	Actor           string
	Provider        string
	AdminIntent     string
	ConnectorID     *uuid.UUID
	WorkspaceAITier string
}

// Result is the outcome of a Suggest call: the plan rendered to the operator
// and the id of the persisted suggestion row.
type Result struct {
	SuggestionID uuid.UUID                   `json:"suggestion_id"`
	Plan         aiclient.ConnectorSetupPlan `json:"plan"`
}

// Suggest validates the request, invokes the connector_setup_assistant skill
// (fail-OPEN: a model outage yields a degraded manual plan, never an error),
// then persists the plan + inputs and appends an audit-chain entry atomically.
// The persisted suggestion is the system of record for what guidance the
// operator was shown.
func (s *Service) Suggest(ctx context.Context, in SuggestInput) (Result, error) {
	if s.db == nil {
		return Result{}, fmt.Errorf("connectorsetup: service has no database handle")
	}
	if in.WorkspaceID == uuid.Nil {
		return Result{}, fmt.Errorf("%w: workspace is required", ErrValidation)
	}
	if in.Provider == "" {
		return Result{}, fmt.Errorf("%w: provider is required", ErrValidation)
	}

	// Validate the provider against the live registry and enrich the AI input
	// with its curated category + capabilities so the agent can tailor the plan.
	descriptor, ok := access.CapabilityDescriptorFor(in.Provider)
	if !ok {
		return Result{}, fmt.Errorf("%w: unknown connector provider %q", ErrValidation, in.Provider)
	}

	aiInput := aiclient.ConnectorSetupInput{
		Provider:     in.Provider,
		AdminIntent:  in.AdminIntent,
		Category:     descriptor.Category,
		Capabilities: enabledCapabilityKeys(descriptor),
	}

	// Fail-OPEN: never blocks the operator on an agent outage.
	plan := aiclient.ConnectorSetupWithFallback(ctx, s.ai, in.WorkspaceAITier, aiInput)

	planJSON, err := json.Marshal(plan)
	if err != nil {
		return Result{}, fmt.Errorf("connectorsetup: marshal plan: %w", err)
	}
	inputsJSON, err := json.Marshal(aiInput)
	if err != nil {
		return Result{}, fmt.Errorf("connectorsetup: marshal inputs: %w", err)
	}

	row := &models.ConnectorSetupSuggestion{
		WorkspaceID: in.WorkspaceID,
		ConnectorID: in.ConnectorID,
		Provider:    in.Provider,
		Actor:       in.Actor,
		AdminIntent: in.AdminIntent,
		Strategy:    plan.Strategy,
		Degraded:    plan.Degraded,
		ModelUsed:   plan.ModelUsed,
		Plan:        datatypes.JSON(planJSON),
		Inputs:      datatypes.JSON(inputsJSON),
	}

	now := s.now().UTC()
	// Persist the suggestion and its audit-chain entry atomically so a recorded
	// suggestion always has a matching audit event and vice-versa.
	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(row).Error; err != nil {
			return fmt.Errorf("connectorsetup: persist suggestion: %w", err)
		}
		meta, mErr := json.Marshal(map[string]interface{}{
			"provider":   in.Provider,
			"strategy":   plan.Strategy,
			"degraded":   plan.Degraded,
			"model_used": plan.ModelUsed,
			"step_count": len(plan.Steps),
		})
		if mErr != nil {
			return fmt.Errorf("connectorsetup: marshal audit metadata: %w", mErr)
		}
		return lifecycle.AppendAuditTx(ctx, tx, now, lifecycle.AuditInput{
			WorkspaceID: in.WorkspaceID,
			Actor:       in.Actor,
			Action:      auditActionSetupSuggested,
			TargetRef:   "connector:" + in.Provider,
			Metadata:    datatypes.JSON(meta),
		})
	}); err != nil {
		return Result{}, err
	}

	return Result{SuggestionID: row.ID, Plan: plan}, nil
}

// enabledCapabilityKeys flattens a descriptor's advertised capabilities into the
// string keys the agent understands, so the setup plan can reference what this
// connector actually supports.
func enabledCapabilityKeys(d access.CapabilityDescriptor) []string {
	keys := make([]string, 0, 12)
	add := func(on bool, key string) {
		if on {
			keys = append(keys, key)
		}
	}
	add(d.UserFacing.SyncIdentity, access.CapabilitySyncIdentity)
	add(d.UserFacing.ProvisionAccess, access.CapabilityProvisionAccess)
	add(d.UserFacing.ListEntitlements, access.CapabilityListEntitlements)
	add(d.UserFacing.GetAccessLog, access.CapabilityGetAccessLog)
	add(d.UserFacing.SSOFederation, access.CapabilitySSOFederation)
	add(d.Operational.GroupSync, access.CapabilityGroupSync)
	add(d.Operational.IdentityDeltaSync, access.CapabilityIdentityDeltaSync)
	add(d.Operational.AccessAuditStream, access.CapabilityAccessAuditOperations)
	add(d.Operational.SCIMProvisioning, access.CapabilitySCIMProvisioning)
	add(d.Operational.SessionRevoke, access.CapabilitySessionRevoke)
	add(d.Operational.SSOEnforcementCheck, access.CapabilitySSOEnforcementCheck)
	add(d.Operational.CredentialRenewal, access.CapabilityCredentialRenewal)
	return keys
}
