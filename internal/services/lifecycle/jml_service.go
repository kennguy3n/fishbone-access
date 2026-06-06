package lifecycle

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// JML change classes produced by ClassifyChange.
const (
	JMLJoiner = "joiner"
	JMLMover  = "mover"
	JMLLeaver = "leaver"
)

// Kill-switch layer names, in execution order.
const (
	LayerGrantRevoke     = "grant_revoke"
	LayerTeamRemove      = "team_remove"
	LayerIAMCoreDisable  = "iam_core_disable"
	LayerSessionRevoke   = "session_revoke"
	LayerSCIMDeprov4     = "scim_deprovision"
	LayerIdentityDisable = "identity_disable"
)

// Kill-switch layer outcome statuses.
const (
	LayerStatusDone    = "done"
	LayerStatusSkipped = "skipped"
	LayerStatusFailed  = "failed"
)

// IdentityDisabler disables (blocks) a user in the identity provider. The
// *iamcore.ManagementClient satisfies this via BlockUser. Defined as an
// interface so the JML service can be unit-tested without a live iam-core and
// so the kill switch degrades gracefully when no client is wired.
type IdentityDisabler interface {
	BlockUser(ctx context.Context, userID string) error
}

// SCIMEvent is a normalized inbound SCIM 2.0 change. The webhook handler maps
// the raw SCIM payload onto this; ClassifyChange routes it to a J/M/L lane.
type SCIMEvent struct {
	// Method is the SCIM HTTP verb: POST (create), PUT/PATCH (update),
	// DELETE (remove).
	Method string
	// UserExternalID is the connector-side user id the change concerns.
	UserExternalID string
	// Active is the SCIM `active` attribute when present (PUT/PATCH). A
	// false value routes to the leaver lane.
	Active *bool
	// Email / DisplayName are convenience copies of common attributes.
	Email       string
	DisplayName string
	// GroupsChanged is true when the update altered group membership (routes a
	// non-deactivating update to the mover lane).
	GroupsChanged bool
	// ResourceRef / Role drive baseline access for a joiner (optional).
	ResourceRef string
	Role        string
	// ConnectorID is the connector the webhook arrived from.
	ConnectorID *uuid.UUID
}

// ClassifyChange routes a SCIM event to a J/M/L lane:
//
//	POST                       → joiner
//	DELETE                     → leaver
//	PUT/PATCH active=false     → leaver
//	PUT/PATCH active=true      → joiner (reactivation)
//	PUT/PATCH (groups/attrs)   → mover
func ClassifyChange(e SCIMEvent) string {
	switch strings.ToUpper(strings.TrimSpace(e.Method)) {
	case "POST":
		return JMLJoiner
	case "DELETE":
		return JMLLeaver
	case "PUT", "PATCH":
		if e.Active != nil && !*e.Active {
			return JMLLeaver
		}
		if e.Active != nil && *e.Active {
			return JMLJoiner
		}
		return JMLMover
	default:
		return JMLMover
	}
}

// JMLService automates Joiner-Mover-Leaver lifecycle off inbound SCIM events.
// The leaver path runs the six-layer kill switch.
type JMLService struct {
	db          *gorm.DB
	requests    *AccessRequestService
	workflow    *WorkflowService
	provisioner *AccessProvisioningService
	resolver    ConnectorResolver
	disabler    IdentityDisabler
	now         func() time.Time
}

// NewJMLService wires the JML service. provisioner and resolver are required
// for the leaver kill switch; disabler may be nil (the iam-core disable layer
// then reports "skipped").
func NewJMLService(db *gorm.DB, requests *AccessRequestService, workflow *WorkflowService, provisioner *AccessProvisioningService, resolver ConnectorResolver, disabler IdentityDisabler) *JMLService {
	return &JMLService{
		db:          db,
		requests:    requests,
		workflow:    workflow,
		provisioner: provisioner,
		resolver:    resolver,
		disabler:    disabler,
		now:         time.Now,
	}
}

// SetClock overrides the time source (tests).
func (s *JMLService) SetClock(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

// HandleEvent classifies a SCIM event and dispatches to the matching lane.
func (s *JMLService) HandleEvent(ctx context.Context, workspaceID uuid.UUID, e SCIMEvent) (string, error) {
	class := ClassifyChange(e)
	switch class {
	case JMLJoiner:
		_, err := s.HandleJoiner(ctx, workspaceID, e)
		return class, err
	case JMLMover:
		_, err := s.HandleMover(ctx, workspaceID, e)
		return class, err
	case JMLLeaver:
		_, err := s.HandleLeaver(ctx, workspaceID, e)
		return class, err
	default:
		return class, fmt.Errorf("%w: unclassifiable SCIM event", ErrValidation)
	}
}

// HandleJoiner provisions baseline access for a new/reactivated user. When the
// event carries a baseline ResourceRef+Role it creates an access request for
// the user and runs it through the workflow (low-risk requests auto-approve);
// otherwise it records the joiner for audit and returns a nil request.
func (s *JMLService) HandleJoiner(ctx context.Context, workspaceID uuid.UUID, e SCIMEvent) (*models.AccessRequest, error) {
	if e.UserExternalID == "" {
		return nil, fmt.Errorf("%w: joiner event needs a user id", ErrValidation)
	}
	if e.ResourceRef == "" || e.Role == "" {
		// No baseline entitlement specified: nothing to provision, just audit.
		now := s.now()
		if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			return appendAudit(ctx, tx, now, auditEntry{
				WorkspaceID: workspaceID,
				Actor:       "scim",
				Action:      "jml.joiner.recorded",
				TargetRef:   e.UserExternalID,
			})
		}); err != nil {
			return nil, err
		}
		return nil, nil
	}

	req, err := s.requests.CreateRequest(ctx, CreateAccessRequestInput{
		WorkspaceID:   workspaceID,
		RequesterID:   "scim",
		TargetUserID:  e.UserExternalID,
		ConnectorID:   e.ConnectorID,
		ResourceRef:   e.ResourceRef,
		Role:          e.Role,
		Justification: "JML joiner baseline access",
		RiskLevel:     RiskLow,
	})
	if err != nil {
		return nil, err
	}
	if s.workflow != nil {
		if _, err := s.workflow.ExecuteWorkflow(ctx, workspaceID, req, "scim"); err != nil {
			return req, err
		}
	}
	return req, nil
}

// HandleMover records an attribute/group change and returns the user's current
// active grants so a downstream policy pass (or operator) can re-evaluate them.
// It is intentionally non-destructive: a mover never tears down access on its
// own.
func (s *JMLService) HandleMover(ctx context.Context, workspaceID uuid.UUID, e SCIMEvent) ([]models.AccessGrant, error) {
	if e.UserExternalID == "" {
		return nil, fmt.Errorf("%w: mover event needs a user id", ErrValidation)
	}
	var grants []models.AccessGrant
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND iam_core_user_id = ? AND state = ? AND revoked_at IS NULL", workspaceID, e.UserExternalID, GrantStateActive).
		Find(&grants).Error; err != nil {
		return nil, fmt.Errorf("lifecycle: load grants for mover: %w", err)
	}
	now := s.now()
	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return appendAudit(ctx, tx, now, auditEntry{
			WorkspaceID: workspaceID,
			Actor:       "scim",
			Action:      "jml.mover.recorded",
			TargetRef:   e.UserExternalID,
		})
	}); err != nil {
		return nil, err
	}
	return grants, nil
}

// KillSwitchLayerResult is the outcome of one kill-switch layer.
type KillSwitchLayerResult struct {
	Layer  string `json:"layer"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// LeaverResult aggregates the six-layer kill-switch outcome.
type LeaverResult struct {
	UserExternalID string                  `json:"user_external_id"`
	Layers         []KillSwitchLayerResult `json:"layers"`
	Errored        bool                    `json:"errored"`
}

// HandleLeaver runs the six-layer leaver kill switch for the event's user. The
// layers run in order; a failed layer is recorded and the cascade CONTINUES
// (a failure never silently skips the remaining layers). Each layer is
// idempotent, so the whole switch is safe to re-run. If any layer failed the
// returned LeaverResult.Errored is true and HandleLeaver returns a non-nil
// error, but only after every layer has been attempted.
func (s *JMLService) HandleLeaver(ctx context.Context, workspaceID uuid.UUID, e SCIMEvent) (*LeaverResult, error) {
	if e.UserExternalID == "" {
		return nil, fmt.Errorf("%w: leaver event needs a user id", ErrValidation)
	}
	user := e.UserExternalID
	result := &LeaverResult{UserExternalID: user}

	record := func(layer, status, detail string) {
		result.Layers = append(result.Layers, KillSwitchLayerResult{Layer: layer, Status: status, Detail: detail})
		if status == LayerStatusFailed {
			result.Errored = true
		}
		now := s.now()
		_ = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			return appendAudit(ctx, tx, now, auditEntry{
				WorkspaceID: workspaceID,
				Actor:       "scim",
				Action:      "jml.leaver." + layer + "." + status,
				TargetRef:   user,
			})
		})
	}

	// Layer 1: revoke every ShieldNet-managed grant for the user.
	s.layerGrantRevoke(ctx, workspaceID, user, record)
	// Layer 2: remove the user from all internal teams.
	s.layerTeamRemove(ctx, workspaceID, user, record)
	// Layer 3: disable the user in iam-core (the identity provider).
	s.layerIAMCoreDisable(ctx, user, record)
	// Layers 4 & 5: connector-side session revocation and SCIM deprovision.
	s.layerConnectorSweep(ctx, workspaceID, user, record)
	// Layer 6: finalize — verify nothing live remains and mark orphan records.
	s.layerIdentityDisable(ctx, workspaceID, user, record)

	if result.Errored {
		return result, fmt.Errorf("lifecycle: leaver kill switch completed with failures for user %s", user)
	}
	return result, nil
}

func (s *JMLService) layerGrantRevoke(ctx context.Context, workspaceID uuid.UUID, user string, record func(layer, status, detail string)) {
	var grants []models.AccessGrant
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND iam_core_user_id = ? AND state = ? AND revoked_at IS NULL", workspaceID, user, GrantStateActive).
		Find(&grants).Error; err != nil {
		record(LayerGrantRevoke, LayerStatusFailed, "load grants: "+err.Error())
		return
	}
	if len(grants) == 0 {
		record(LayerGrantRevoke, LayerStatusDone, "no active grants")
		return
	}
	var failed int
	for i := range grants {
		if err := s.provisioner.RevokeGrant(ctx, workspaceID, grants[i].ID, "scim", "leaver kill switch"); err != nil {
			failed++
		}
	}
	if failed > 0 {
		record(LayerGrantRevoke, LayerStatusFailed, fmt.Sprintf("%d/%d grant revocations failed", failed, len(grants)))
		return
	}
	record(LayerGrantRevoke, LayerStatusDone, fmt.Sprintf("revoked %d grants", len(grants)))
}

func (s *JMLService) layerTeamRemove(ctx context.Context, workspaceID uuid.UUID, user string, record func(layer, status, detail string)) {
	res := s.db.WithContext(ctx).
		Where("workspace_id = ? AND iam_core_user_id = ?", workspaceID, user).
		Delete(&models.TeamMember{})
	if res.Error != nil {
		record(LayerTeamRemove, LayerStatusFailed, res.Error.Error())
		return
	}
	record(LayerTeamRemove, LayerStatusDone, fmt.Sprintf("removed %d team memberships", res.RowsAffected))
}

func (s *JMLService) layerIAMCoreDisable(ctx context.Context, user string, record func(layer, status, detail string)) {
	if s.disabler == nil {
		record(LayerIAMCoreDisable, LayerStatusSkipped, "no iam-core management client wired")
		return
	}
	if err := s.disabler.BlockUser(ctx, user); err != nil {
		record(LayerIAMCoreDisable, LayerStatusFailed, err.Error())
		return
	}
	record(LayerIAMCoreDisable, LayerStatusDone, "blocked in iam-core")
}

// layerConnectorSweep performs layer 4 (session revocation) and layer 5 (SCIM
// deprovision) by iterating the workspace's active connectors and using their
// optional capabilities. Connectors that support neither capability cause both
// layers to be reported "skipped".
func (s *JMLService) layerConnectorSweep(ctx context.Context, workspaceID uuid.UUID, user string, record func(layer, status, detail string)) {
	var connectors []models.AccessConnector
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ?", workspaceID).
		Find(&connectors).Error; err != nil {
		record(LayerSessionRevoke, LayerStatusFailed, "load connectors: "+err.Error())
		record(LayerSCIMDeprov4, LayerStatusFailed, "load connectors: "+err.Error())
		return
	}

	var sessAttempted, sessFailed int
	var scimAttempted, scimFailed int
	for i := range connectors {
		resolved, err := s.resolver.Resolve(ctx, workspaceID, connectors[i].ID)
		if err != nil {
			// A connector we cannot resolve cannot be swept; count as a failure
			// for both connector layers but keep going.
			sessFailed++
			scimFailed++
			continue
		}
		if revoker, ok := resolved.Impl.(access.SessionRevoker); ok {
			sessAttempted++
			if err := revoker.RevokeSessions(ctx, resolved.Config, resolved.Secrets, user); err != nil {
				sessFailed++
			}
		}
		if _, ok := resolved.Impl.(access.SCIMProvisioner); ok {
			scimAttempted++
			if err := s.scimDeprovision(ctx, resolved, user); err != nil {
				scimFailed++
			}
		}
	}

	recordSweepLayer(record, LayerSessionRevoke, sessAttempted, sessFailed)
	recordSweepLayer(record, LayerSCIMDeprov4, scimAttempted, scimFailed)
}

// scimDeprovision removes a user's upstream access on a SCIM-capable connector
// by revoking every entitlement the provider still reports for them. This is
// idempotent (RevokeAccess is idempotent) and catches provider-managed access
// not represented as a ShieldNet grant.
func (s *JMLService) scimDeprovision(ctx context.Context, resolved *ResolvedConnector, user string) error {
	ents, err := resolved.Impl.ListEntitlements(ctx, resolved.Config, resolved.Secrets, user)
	if err != nil {
		return err
	}
	for _, ent := range ents {
		grant := access.AccessGrant{
			UserExternalID:     user,
			ResourceExternalID: ent.ResourceExternalID,
			Role:               ent.Role,
		}
		if err := resolved.Impl.RevokeAccess(ctx, resolved.Config, resolved.Secrets, grant); err != nil {
			return err
		}
	}
	return nil
}

func recordSweepLayer(record func(layer, status, detail string), layer string, attempted, failed int) {
	switch {
	case attempted == 0:
		record(layer, LayerStatusSkipped, "no connector supports this capability")
	case failed > 0:
		record(layer, LayerStatusFailed, fmt.Sprintf("%d/%d connectors failed", failed, attempted))
	default:
		record(layer, LayerStatusDone, fmt.Sprintf("swept %d connectors", attempted))
	}
}

// layerIdentityDisable is the final sweep: it verifies no active grant survived
// the cascade (a surviving grant means an earlier layer failed) and marks any
// orphan-account records for the user as disposition=disable so the orphan
// reconciler does not re-surface them.
func (s *JMLService) layerIdentityDisable(ctx context.Context, workspaceID uuid.UUID, user string, record func(layer, status, detail string)) {
	var remaining int64
	if err := s.db.WithContext(ctx).
		Model(&models.AccessGrant{}).
		Where("workspace_id = ? AND iam_core_user_id = ? AND state = ? AND revoked_at IS NULL", workspaceID, user, GrantStateActive).
		Count(&remaining).Error; err != nil {
		record(LayerIdentityDisable, LayerStatusFailed, "verify grants: "+err.Error())
		return
	}
	if remaining > 0 {
		record(LayerIdentityDisable, LayerStatusFailed, fmt.Sprintf("%d active grants still present", remaining))
		return
	}
	if err := s.db.WithContext(ctx).
		Model(&models.AccessOrphanAccount{}).
		Where("workspace_id = ? AND external_user_id = ?", workspaceID, user).
		Update("disposition", OrphanDispositionDisable).Error; err != nil {
		record(LayerIdentityDisable, LayerStatusFailed, "mark orphans: "+err.Error())
		return
	}
	record(LayerIdentityDisable, LayerStatusDone, "identity fully deprovisioned")
}
