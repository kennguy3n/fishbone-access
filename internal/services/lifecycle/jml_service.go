package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/iamcore"
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
	LayerSCIMDeprov      = "scim_deprovision"
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

// HandleEvent classifies a SCIM event and dispatches to the matching lane. For
// the leaver lane it also returns the six-layer kill-switch result (nil for the
// joiner/mover lanes) so callers can surface the per-layer breakdown — which
// layers ran, which failed, and why — even when the kill switch errors. Without
// this the structured result would be lost and a partial kill-switch failure
// would be indistinguishable from a generic internal error.
func (s *JMLService) HandleEvent(ctx context.Context, workspaceID uuid.UUID, e SCIMEvent) (string, *LeaverResult, error) {
	class := ClassifyChange(e)
	switch class {
	case JMLJoiner:
		_, err := s.HandleJoiner(ctx, workspaceID, e)
		return class, nil, err
	case JMLMover:
		_, err := s.HandleMover(ctx, workspaceID, e)
		return class, nil, err
	case JMLLeaver:
		res, err := s.HandleLeaver(ctx, workspaceID, e)
		return class, res, err
	default:
		return class, nil, fmt.Errorf("%w: unclassifiable SCIM event", ErrValidation)
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

	// A baseline entitlement (ResourceRef+Role) is meaningless without a
	// connector to provision it on. Fail fast and create nothing: otherwise we
	// would create a request, auto-approve it (low risk), then have Provision
	// reject it with ErrConnectorNotConfigured — leaving an approved-but-
	// unprovisionable request behind. Worse, because the idempotency check below
	// keys on a *live grant* (which never materializes), every SCIM redelivery of
	// the same connector-less event would create another dangling approved
	// request. Validating here keeps the failure actionable (422) and leak-free.
	if e.ConnectorID == nil || *e.ConnectorID == uuid.Nil {
		return nil, fmt.Errorf("%w: joiner baseline access (resource %q, role %q) requires a connector_id", ErrValidation, e.ResourceRef, e.Role)
	}

	// Idempotency: SCIM webhooks redeliver, so a joiner event may arrive more
	// than once. If the user already holds a live grant for this resource+role,
	// there is nothing to provision — creating another request would auto-approve
	// and materialize a duplicate grant. Skip and record the redelivery for audit.
	var live int64
	if err := s.db.WithContext(ctx).Model(&models.AccessGrant{}).
		Where("workspace_id = ? AND iam_core_user_id = ? AND resource_ref = ? AND role = ? AND state = ? AND revoked_at IS NULL",
			workspaceID, e.UserExternalID, e.ResourceRef, e.Role, GrantStateActive).
		Count(&live).Error; err != nil {
		return nil, fmt.Errorf("lifecycle: check existing joiner grant: %w", err)
	}
	if live > 0 {
		now := s.now()
		if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			return appendAudit(ctx, tx, now, auditEntry{
				WorkspaceID: workspaceID,
				Actor:       "scim",
				Action:      "jml.joiner.already_provisioned",
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
	if s.workflow == nil {
		// No workflow wired: leave the request in StateRequested for a human to
		// approve. Nothing to provision yet.
		return req, nil
	}
	decision, err := s.workflow.ExecuteWorkflow(ctx, workspaceID, req, "scim")
	if err != nil {
		return req, err
	}
	// A SCIM joiner has no human in the loop, so when the workflow auto-approves
	// the low-risk baseline request we must also materialize the grant on the
	// connector — otherwise the approved request sits idle forever and the
	// "provisions baseline access" contract is never honored. Medium/high or
	// sensitive-resource joiners are parked for human approval (Approved=false)
	// and are intentionally NOT auto-provisioned here. Provision is idempotent,
	// so a redelivered SCIM joiner event will not double-grant.
	if decision.Approved && s.provisioner != nil {
		if _, err := s.provisioner.Provision(ctx, workspaceID, req.ID, "scim"); err != nil {
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
	// The automatic SCIM-driven leaver lane runs the kill switch with the
	// "scim" actor. The same cascade is reachable with a human actor via
	// RunKillSwitch (a workflow run_kill_switch step or the standalone
	// emergency-offboard action).
	return s.RunKillSwitch(ctx, workspaceID, e.UserExternalID, "scim")
}

// RunKillSwitch executes the six-layer leaver kill switch for a user with an
// explicit actor, and is the single shared implementation behind every
// offboarding path: the automatic SCIM leaver lane (actor "scim"), a workflow
// run_kill_switch step, and the standalone emergency-offboard action (actor =
// the authenticated admin). The layers run in order; a failed layer is recorded
// and the cascade CONTINUES (a failure never silently skips the remaining
// layers). Each layer is idempotent, so the whole switch is safe to re-run. If
// any layer failed the returned LeaverResult.Errored is true and RunKillSwitch
// returns a non-nil error, but only after every layer has been attempted.
func (s *JMLService) RunKillSwitch(ctx context.Context, workspaceID uuid.UUID, userExternalID, actor string) (*LeaverResult, error) {
	if userExternalID == "" {
		return nil, fmt.Errorf("%w: kill switch needs a user id", ErrValidation)
	}
	if actor == "" {
		return nil, fmt.Errorf("%w: kill switch needs an actor", ErrValidation)
	}
	user := userExternalID
	result := &LeaverResult{UserExternalID: user}

	record := func(layer, status, detail string) {
		entry := KillSwitchLayerResult{Layer: layer, Status: status, Detail: detail}
		if status == LayerStatusFailed {
			result.Errored = true
		}
		now := s.now()
		if auditErr := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			return appendAudit(ctx, tx, now, auditEntry{
				WorkspaceID: workspaceID,
				Actor:       actor,
				Action:      "jml.leaver." + layer + "." + status,
				TargetRef:   user,
			})
		}); auditErr != nil {
			// A kill-switch layer whose tamper-evident audit row could not be
			// written is a compliance gap, not a no-op: surface it rather than
			// swallowing it. Mark the layer failed (annotating its detail) so
			// HandleLeaver returns an error and the per-layer breakdown shows the
			// audit failure. The cascade still continues to the remaining layers.
			result.Errored = true
			entry.Status = LayerStatusFailed
			if entry.Detail != "" {
				entry.Detail += "; "
			}
			entry.Detail += "audit write failed: " + auditErr.Error()
		}
		result.Layers = append(result.Layers, entry)
	}

	// Layer 1: revoke every ShieldNet-managed grant for the user, attributed to
	// the kill switch's actor ("scim" for the automatic lane, the admin for an
	// emergency offboard / workflow step).
	s.layerGrantRevoke(ctx, workspaceID, user, actor, record)
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

func (s *JMLService) layerGrantRevoke(ctx context.Context, workspaceID uuid.UUID, user, actor string, record func(layer, status, detail string)) {
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
		if err := s.provisioner.RevokeGrant(ctx, workspaceID, grants[i].ID, actor, "leaver kill switch"); err != nil {
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
		// A leaver who no longer exists in iam-core is already in the kill
		// switch's desired end state, not a failure. iam-core answers 404
		// (surfaced as ErrNotFound) when the user was never provisioned there
		// or was already removed, so treat "already gone" as success — this
		// also keeps a re-run after a partial prior run idempotent.
		if errors.Is(err, iamcore.ErrNotFound) {
			record(LayerIAMCoreDisable, LayerStatusDone, "user already absent in iam-core")
			return
		}
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
		record(LayerSCIMDeprov, LayerStatusFailed, "load connectors: "+err.Error())
		return
	}

	var sessAttempted, sessFailed int
	var scimAttempted, scimFailed int
	for i := range connectors {
		resolved, err := s.resolver.Resolve(ctx, workspaceID, connectors[i].ID)
		if err != nil {
			// A connector we cannot resolve (e.g. rotated DEK, missing provider
			// registration) cannot be swept. Count it as both attempted and
			// failed for both layers so the layer is reported "failed" (and the
			// kill switch errors) rather than misclassified as "skipped" when
			// every connector fails to resolve. Keep going so one bad connector
			// does not hide failures on the others.
			sessAttempted++
			sessFailed++
			scimAttempted++
			scimFailed++
			continue
		}
		if revoker, ok := resolved.Impl.(access.SessionRevoker); ok {
			sessAttempted++
			if err := revoker.RevokeUserSessions(ctx, resolved.Config, resolved.Secrets, user); err != nil {
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
	recordSweepLayer(record, LayerSCIMDeprov, scimAttempted, scimFailed)
}

// scimDeprovision removes a user's upstream access on a SCIM-capable connector
// by revoking every entitlement the provider still reports for them. This is
// idempotent (RevokeAccess is idempotent) and catches provider-managed access
// not represented as a ShieldNet grant.
//
// This is a security-critical kill-switch step, so it does NOT abort on the
// first failed revocation: a transient failure on one entitlement must not
// leave the remaining entitlements live. It attempts every entitlement and
// aggregates the failures, so a single run achieves maximal revocation; any
// returned error still marks the layer failed (and the kill switch errors), and
// a re-run idempotently retries whatever is left.
func (s *JMLService) scimDeprovision(ctx context.Context, resolved *ResolvedConnector, user string) error {
	ents, err := resolved.Impl.ListEntitlements(ctx, resolved.Config, resolved.Secrets, user)
	if err != nil {
		return err
	}
	var errs []error
	for _, ent := range ents {
		grant := access.AccessGrant{
			UserExternalID:     user,
			ResourceExternalID: ent.ResourceExternalID,
			Role:               ent.Role,
		}
		if err := resolved.Impl.RevokeAccess(ctx, resolved.Config, resolved.Secrets, grant); err != nil {
			errs = append(errs, fmt.Errorf("revoke %s/%s: %w", ent.ResourceExternalID, ent.Role, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%d/%d entitlement revocations failed: %w", len(errs), len(ents), errors.Join(errs...))
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
