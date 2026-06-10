package compliance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
)

// campaignItemInsertBatch bounds the multi-row INSERT size when seeding a
// campaign's items. CertificationItem has a handful of columns, so 500 rows per
// statement stays well under Postgres' 65535 bound-parameter ceiling while
// keeping the round-trip count low for large campaigns.
const campaignItemInsertBatch = 500

// GrantRevoker is the subset of the provisioning service the certification
// service needs to tear a grant down when a revoke decision is APPLIED at
// campaign close. It is the same contract the 1C review service uses; reusing
// it keeps a single revoke path (idempotent, connector-side teardown + grant
// state flip + audit) rather than a parallel one.
//
// RevokeGrant MUST be idempotent: revoking a grant that is already revoked (or
// otherwise no longer active) is a no-op that returns nil, NOT an error. The
// real implementation (AccessProvisioningService.RevokeGrant) honours this by
// short-circuiting on any non-active state. CloseCampaign's post-commit apply
// loop relies on this: a grant independently revoked between the preview
// snapshot and the apply (e.g. via /grants/:id/revoke or a concurrent close)
// must not abort the loop and strand the remaining staged revokes — the desired
// end state (grant revoked) is already satisfied, so the loop converges. Only a
// genuine teardown failure (connector error, missing grant) returns a non-nil
// error, which correctly aborts so a re-close can retry.
type GrantRevoker interface {
	RevokeGrant(ctx context.Context, workspaceID, grantID uuid.UUID, actor, reason string) error
}

// CertificationService runs full certification campaigns: scoped, reviewer-
// assigned, due-dated reviews whose per-grant decisions are STAGED and applied
// only at close. It builds on the 1C review-service primitives (live-grant
// enumeration, FOR UPDATE decision locking, idempotent terminal-decision guard,
// post-commit connector teardown) but adds scope, reviewers, due dates, overdue
// handling, and the deferred two-phase revoke so the destructive teardown is
// preview-able before it runs. Every transition appends to the workspace audit
// hash chain, so a campaign produces compliance evidence automatically.
type CertificationService struct {
	db      *gorm.DB
	revoker GrantRevoker
	now     func() time.Time
}

// NewCertificationService wires the service. revoker may be nil in read-only
// contexts; a close that must apply staged revokes then fails closed with
// ErrNoRevoker rather than marking grants revoked it cannot tear down.
func NewCertificationService(db *gorm.DB, revoker GrantRevoker) *CertificationService {
	return &CertificationService{db: db, revoker: revoker, now: time.Now}
}

// SetClock overrides the time source (tests).
func (s *CertificationService) SetClock(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

// CampaignInput is the operator-supplied scope for a new campaign. Every field
// except Name is optional; an empty scope field widens the match (e.g. no
// ScopeRole means "every role"). Actor and workspace are derived from the
// request context by the handler, never from this struct.
type CampaignInput struct {
	Name             string
	Framework        string
	ScopeResource    string
	ScopeRole        string
	ScopeConnectorID *uuid.UUID
	Reviewers        []string
	DueAt            *time.Time
}

// StartCampaign creates a running campaign and enumerates every live grant
// matching the scope into a pending item, all in one transaction. Reviewers (if
// any) are assigned round-robin so a reviewer worklist can filter to its queue.
// Returns the campaign and the number of items created.
func (s *CertificationService) StartCampaign(ctx context.Context, workspaceID uuid.UUID, in CampaignInput, actor string) (*models.CertificationCampaign, int, error) {
	if workspaceID == uuid.Nil {
		return nil, 0, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	if in.Name == "" {
		return nil, 0, fmt.Errorf("%w: campaign name is required", ErrValidation)
	}
	if in.Framework != "" {
		if _, ok := ValidFramework(in.Framework); !ok {
			return nil, 0, fmt.Errorf("%w: unknown framework %q", ErrValidation, in.Framework)
		}
	}
	if in.DueAt != nil && in.DueAt.IsZero() {
		in.DueAt = nil
	}

	reviewersJSON, err := marshalReviewers(in.Reviewers)
	if err != nil {
		return nil, 0, err
	}

	now := s.now().UTC()
	campaign := &models.CertificationCampaign{
		WorkspaceID:      workspaceID,
		Name:             in.Name,
		State:            models.CertificationStateRunning,
		Framework:        in.Framework,
		ScopeResource:    in.ScopeResource,
		ScopeRole:        in.ScopeRole,
		ScopeConnectorID: in.ScopeConnectorID,
		Reviewers:        reviewersJSON,
		DueAt:            in.DueAt,
		StartedAt:        &now,
	}
	campaign.CreatedAt = now
	campaign.UpdatedAt = now

	itemCount := 0
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Validate the connector scope belongs to this workspace so a campaign
		// can never be scoped (and leak items) across tenants.
		if in.ScopeConnectorID != nil {
			var n int64
			if err := tx.WithContext(ctx).Model(&models.AccessConnector{}).
				Where("workspace_id = ? AND id = ?", workspaceID, *in.ScopeConnectorID).
				Count(&n).Error; err != nil {
				return fmt.Errorf("compliance: verify connector scope: %w", err)
			}
			if n == 0 {
				return fmt.Errorf("%w: scope connector not found in workspace", ErrValidation)
			}
		}

		if err := tx.Create(campaign).Error; err != nil {
			return fmt.Errorf("compliance: insert campaign: %w", err)
		}

		// Model() is explicit (rather than relying on Find(&grants) to infer the
		// table) so the soft-delete scope and the table are obvious at the query
		// head, matching the pack-writer convention.
		q := tx.WithContext(ctx).Model(&models.AccessGrant{}).
			Where("workspace_id = ? AND state = ? AND revoked_at IS NULL", workspaceID, lifecycle.GrantStateActive)
		if in.ScopeResource != "" {
			// Prefix match so a campaign can target a resource hierarchy
			// (e.g. "prod/db/") as well as an exact resource ref. The explicit
			// ESCAPE makes backslash the escape char on SQLite too (Postgres
			// defaults to it), so a literal _/% in a ref can't widen the match.
			q = q.Where("resource_ref LIKE ? ESCAPE '\\'", likePrefix(in.ScopeResource))
		}
		if in.ScopeRole != "" {
			q = q.Where("role = ?", in.ScopeRole)
		}
		if in.ScopeConnectorID != nil {
			q = q.Where("connector_id = ?", *in.ScopeConnectorID)
		}
		var grants []models.AccessGrant
		if err := q.Order("created_at asc, id asc").Find(&grants).Error; err != nil {
			return fmt.Errorf("compliance: enumerate grants for campaign: %w", err)
		}

		// Materialize the items then bulk-insert in batches: a campaign can scope
		// thousands of grants, and a per-row INSERT loop would be that many round
		// trips inside the transaction. CreateInBatches collapses them into a few
		// multi-row INSERTs (still one transaction, so the all-or-nothing
		// guarantee is unchanged) — a meaningful win at the 5000-tenant scale.
		items := make([]models.CertificationItem, len(grants))
		for i := range grants {
			items[i] = models.CertificationItem{
				WorkspaceID: workspaceID,
				CampaignID:  campaign.ID,
				GrantID:     grants[i].ID,
				Decision:    models.CertificationDecisionPending,
				Reviewer:    assignReviewer(in.Reviewers, i),
			}
			items[i].CreatedAt = now
			items[i].UpdatedAt = now
		}
		if len(items) > 0 {
			if err := tx.CreateInBatches(items, campaignItemInsertBatch).Error; err != nil {
				return fmt.Errorf("compliance: insert campaign items: %w", err)
			}
		}
		itemCount = len(items)

		meta := map[string]any{
			"name":       in.Name,
			"item_count": itemCount,
		}
		if in.Framework != "" {
			meta["framework"] = in.Framework
		}
		if scope := scopeMeta(in); len(scope) > 0 {
			meta["scope"] = scope
		}
		if len(in.Reviewers) > 0 {
			meta["reviewers"] = in.Reviewers
		}
		if in.DueAt != nil {
			meta["due_at"] = in.DueAt.UTC()
		}
		return lifecycle.AppendAuditTx(ctx, tx, now, lifecycle.AuditInput{
			WorkspaceID: workspaceID,
			Actor:       actor,
			Action:      "certification.campaign.started",
			TargetRef:   campaign.ID.String(),
			Metadata:    mustJSON(meta),
		})
	})
	if err != nil {
		return nil, 0, err
	}
	return campaign, itemCount, nil
}

// SubmitDecision records a certify / revoke / escalate decision on one item. A
// revoke here is STAGED only: the grant is NOT torn down until the campaign is
// closed, so the operator can preview the impact first (PreviewRevocations).
// The item load, terminal-decision guard, and write run in one FOR UPDATE
// transaction so concurrent decisions on the same item serialize.
//
// Idempotency depends on whether the existing decision is TERMINAL:
//   - certify / revoke are terminal. Re-submitting the same terminal decision is
//     a no-op (recorded once); flipping to a different terminal decision is
//     rejected with ErrItemDecided.
//   - escalate is an intermediate state that may later be overridden to
//     certify/revoke, so it is deliberately NOT terminal. Re-submitting escalate
//     re-writes the item and appends a fresh certification.item.decision.escalate
//     evidence event — each escalation is a distinct, audit-worthy act (e.g. a
//     re-escalation with a new reason), not a no-op.
func (s *CertificationService) SubmitDecision(ctx context.Context, workspaceID, campaignID, itemID uuid.UUID, decision, decidedBy, reason string) error {
	switch decision {
	case models.CertificationDecisionCertify, models.CertificationDecisionRevoke, models.CertificationDecisionEscalate:
	default:
		return fmt.Errorf("%w: unknown certification decision %q", ErrValidation, decision)
	}

	now := s.now().UTC()
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var campaign models.CertificationCampaign
		if err := tx.WithContext(ctx).
			Where("workspace_id = ? AND id = ?", workspaceID, campaignID).
			Take(&campaign).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrCampaignNotFound
			}
			return fmt.Errorf("compliance: load campaign: %w", err)
		}
		if campaign.State == models.CertificationStateClosed {
			return ErrCampaignClosed
		}

		var item models.CertificationItem
		if err := forUpdate(tx.WithContext(ctx)).
			Where("workspace_id = ? AND campaign_id = ? AND id = ?", workspaceID, campaignID, itemID).
			Take(&item).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrItemNotFound
			}
			return fmt.Errorf("compliance: load campaign item: %w", err)
		}

		// A terminal decision (certify/revoke) is final: reject flipping it to a
		// different terminal decision. Re-submitting the SAME decision is an
		// idempotent no-op (records the trail exactly once).
		alreadyTerminal := item.Decision == models.CertificationDecisionCertify || item.Decision == models.CertificationDecisionRevoke
		if alreadyTerminal && item.Decision != decision {
			return fmt.Errorf("%w: item %s is %s", ErrItemDecided, itemID, item.Decision)
		}
		if alreadyTerminal && item.Decision == decision {
			return nil
		}

		if err := tx.Model(&models.CertificationItem{}).
			Where("workspace_id = ? AND id = ?", workspaceID, itemID).
			Updates(map[string]any{
				"decision":   decision,
				"decided_by": decidedBy,
				"decided_at": now,
				"reason":     reason,
				"updated_at": now,
			}).Error; err != nil {
			return fmt.Errorf("compliance: update campaign item: %w", err)
		}
		return lifecycle.AppendAuditTx(ctx, tx, now, lifecycle.AuditInput{
			WorkspaceID: workspaceID,
			Actor:       decidedBy,
			Action:      "certification.item.decision." + decision,
			TargetRef:   itemID.String(),
			Metadata:    mustJSON(map[string]any{"campaign_id": campaignID, "grant_id": item.GrantID, "reason": reason}),
		})
	})
}

// RevocationPreview is one staged revoke that CloseCampaign would apply. It is
// the dry-run surface that lets an operator see exactly which grants will be
// torn down before they commit to closing the campaign — the same
// test-before-effect guardrail the policy promote path enforces.
type RevocationPreview struct {
	ItemID      uuid.UUID `json:"item_id"`
	GrantID     uuid.UUID `json:"grant_id"`
	ResourceRef string    `json:"resource_ref"`
	Role        string    `json:"role"`
	Subject     string    `json:"subject"`
	DecidedBy   string    `json:"decided_by"`
	Reason      string    `json:"reason"`
}

// PreviewRevocations lists the grants that closing the campaign would revoke:
// items decided "revoke" that are not already torn down. Read-only.
func (s *CertificationService) PreviewRevocations(ctx context.Context, workspaceID, campaignID uuid.UUID) ([]RevocationPreview, error) {
	if err := s.assertCampaign(ctx, workspaceID, campaignID); err != nil {
		return nil, err
	}
	var rows []RevocationPreview
	if err := s.db.WithContext(ctx).
		Model(&models.CertificationItem{}).
		Select("certification_items.id AS item_id, certification_items.grant_id AS grant_id, "+
			"access_grants.resource_ref AS resource_ref, access_grants.role AS role, "+
			"access_grants.iam_core_user_id AS subject, certification_items.decided_by AS decided_by, "+
			"certification_items.reason AS reason").
		Joins("JOIN access_grants ON access_grants.id = certification_items.grant_id").
		Where("certification_items.workspace_id = ? AND certification_items.campaign_id = ? AND certification_items.decision = ? AND certification_items.revoked_at IS NULL",
			workspaceID, campaignID, models.CertificationDecisionRevoke).
		Order("certification_items.created_at asc, certification_items.id asc").
		Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("compliance: preview revocations: %w", err)
	}
	return rows, nil
}

// CloseCampaign closes the campaign and APPLIES the staged revoke decisions.
// The state flip + audit are written in one transaction; the connector-side
// teardown then runs AFTER commit (network I/O, idempotent) for every revoke
// item not yet torn down. Closing is idempotent and re-entrant: a re-close
// re-drives any revoke whose teardown previously failed, so the campaign is
// guaranteed to converge on the decided end state.
func (s *CertificationService) CloseCampaign(ctx context.Context, workspaceID, campaignID uuid.UUID, actor string) (CampaignReport, error) {
	// Fail closed: if there are staged revokes but no revoker is wired, refuse
	// to close rather than mark the campaign closed with grants left live.
	pendingRevokes, err := s.PreviewRevocations(ctx, workspaceID, campaignID)
	if err != nil {
		return CampaignReport{}, err
	}
	if len(pendingRevokes) > 0 && s.revoker == nil {
		return CampaignReport{}, ErrNoRevoker
	}

	now := s.now().UTC()
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var campaign models.CertificationCampaign
		if err := forUpdate(tx.WithContext(ctx)).
			Where("workspace_id = ? AND id = ?", workspaceID, campaignID).
			Take(&campaign).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrCampaignNotFound
			}
			return fmt.Errorf("compliance: load campaign: %w", err)
		}
		if campaign.State == models.CertificationStateClosed {
			return nil // idempotent: teardown of any outstanding revokes still runs below
		}
		if err := tx.Model(&models.CertificationCampaign{}).
			Where("workspace_id = ? AND id = ?", workspaceID, campaignID).
			Updates(map[string]any{"state": models.CertificationStateClosed, "closed_at": now, "updated_at": now}).Error; err != nil {
			return fmt.Errorf("compliance: close campaign: %w", err)
		}
		// Record the count of revokes this close is STAGING for teardown, not a
		// success tally. This event commits atomically with the state change inside
		// the transaction, whereas the revocations are applied post-commit (they
		// touch external connectors and must not run under the row lock). Naming it
		// "staged_revocations" keeps the evidence honest — it never overstates what
		// was applied. The authoritative per-grant outcome is the individual
		// access_grant.revoked event each RevokeGrant appends, and a partial
		// teardown converges on re-close (idempotent RevokeGrant), so the applied
		// count is always reconstructable from the chain.
		return lifecycle.AppendAuditTx(ctx, tx, now, lifecycle.AuditInput{
			WorkspaceID: workspaceID,
			Actor:       actor,
			Action:      "certification.campaign.closed",
			TargetRef:   campaignID.String(),
			Metadata:    mustJSON(map[string]any{"staged_revocations": len(pendingRevokes)}),
		})
	})
	if err != nil {
		return CampaignReport{}, err
	}

	// Apply staged revokes post-commit. RevokeGrant is idempotent (see the
	// GrantRevoker contract): a grant already revoked out-of-band returns nil
	// rather than erroring, so an independently-revoked grant does not strand
	// the remaining staged revokes. It appends its own access_grant.revoked
	// evidence; we then stamp revoked_at so a re-close skips already-applied
	// items. A genuine teardown failure aborts so a re-close can retry.
	for i := range pendingRevokes {
		p := pendingRevokes[i]
		if err := s.revoker.RevokeGrant(ctx, workspaceID, p.GrantID, actor, defaultReason(p.Reason, "revoked by certification campaign")); err != nil {
			return CampaignReport{}, fmt.Errorf("compliance: apply revocation for grant %s: %w", p.GrantID, err)
		}
		if err := s.db.WithContext(ctx).Model(&models.CertificationItem{}).
			Where("workspace_id = ? AND id = ? AND revoked_at IS NULL", workspaceID, p.ItemID).
			Update("revoked_at", s.now().UTC()).Error; err != nil {
			return CampaignReport{}, fmt.Errorf("compliance: stamp revoked item %s: %w", p.ItemID, err)
		}
	}
	return s.Report(ctx, workspaceID, campaignID)
}

// EnforceOverdue stamps overdue_at on every running campaign that is past its
// due date and still has OPEN items, appending a certification.campaign.overdue
// evidence event exactly once per campaign. An item is open if it lacks a
// terminal decision: both pending and escalated count, because escalation is an
// intermediate state that still needs resolving to certify/revoke. It is safe to
// call repeatedly (a scheduled sweep): campaigns already stamped are skipped.
// Returns the number newly marked overdue.
func (s *CertificationService) EnforceOverdue(ctx context.Context, workspaceID uuid.UUID) (int, error) {
	now := s.now().UTC()
	var campaigns []models.CertificationCampaign
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND state = ? AND overdue_at IS NULL AND due_at IS NOT NULL AND due_at < ?",
			workspaceID, models.CertificationStateRunning, now).
		Find(&campaigns).Error; err != nil {
		return 0, fmt.Errorf("compliance: scan overdue campaigns: %w", err)
	}

	marked := 0
	for i := range campaigns {
		c := campaigns[i]
		var open int64
		if err := s.db.WithContext(ctx).Model(&models.CertificationItem{}).
			Where("workspace_id = ? AND campaign_id = ? AND decision IN ?", workspaceID, c.ID,
				[]string{models.CertificationDecisionPending, models.CertificationDecisionEscalate}).
			Count(&open).Error; err != nil {
			return marked, fmt.Errorf("compliance: count open items: %w", err)
		}
		if open == 0 {
			continue // every item carries a terminal decision; not overdue even if past due
		}
		err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			// Re-check under the row lock so two sweeps don't both stamp + audit.
			var locked models.CertificationCampaign
			if err := forUpdate(tx.WithContext(ctx)).
				Where("workspace_id = ? AND id = ? AND overdue_at IS NULL", workspaceID, c.ID).
				Take(&locked).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return nil // another sweep won the race
				}
				return fmt.Errorf("compliance: lock campaign for overdue: %w", err)
			}
			if err := tx.Model(&models.CertificationCampaign{}).
				Where("workspace_id = ? AND id = ?", workspaceID, c.ID).
				Updates(map[string]any{"overdue_at": now, "updated_at": now}).Error; err != nil {
				return fmt.Errorf("compliance: stamp overdue: %w", err)
			}
			return lifecycle.AppendAuditTx(ctx, tx, now, lifecycle.AuditInput{
				WorkspaceID: workspaceID,
				Actor:       "system",
				Action:      "certification.campaign.overdue",
				TargetRef:   c.ID.String(),
				Metadata:    mustJSON(map[string]any{"due_at": c.DueAt, "open_items": open}),
			})
		})
		if err != nil {
			return marked, err
		}
		marked++
	}
	return marked, nil
}

// CampaignReport is the decision tally + lifecycle summary for a campaign.
type CampaignReport struct {
	CampaignID uuid.UUID  `json:"campaign_id"`
	Name       string     `json:"name"`
	State      string     `json:"state"`
	Framework  string     `json:"framework,omitempty"`
	Total      int        `json:"total"`
	Pending    int        `json:"pending"`
	Certified  int        `json:"certified"`
	Revoked    int        `json:"revoked"`
	Escalated  int        `json:"escalated"`
	DueAt      *time.Time `json:"due_at,omitempty"`
	Overdue    bool       `json:"overdue"`
	AllDecided bool       `json:"all_decided"`
}

// Report tallies a campaign's items by decision and derives the overdue /
// all-decided signals (rather than storing them, so they cannot drift).
func (s *CertificationService) Report(ctx context.Context, workspaceID, campaignID uuid.UUID) (CampaignReport, error) {
	var campaign models.CertificationCampaign
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND id = ?", workspaceID, campaignID).
		Take(&campaign).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return CampaignReport{}, ErrCampaignNotFound
		}
		return CampaignReport{}, fmt.Errorf("compliance: load campaign for report: %w", err)
	}

	var items []models.CertificationItem
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND campaign_id = ?", workspaceID, campaignID).
		Find(&items).Error; err != nil {
		return CampaignReport{}, fmt.Errorf("compliance: load items for report: %w", err)
	}

	report := CampaignReport{
		CampaignID: campaignID,
		Name:       campaign.Name,
		State:      campaign.State,
		Framework:  campaign.Framework,
		Total:      len(items),
		DueAt:      campaign.DueAt,
	}
	for i := range items {
		switch items[i].Decision {
		case models.CertificationDecisionCertify:
			report.Certified++
		case models.CertificationDecisionRevoke:
			report.Revoked++
		case models.CertificationDecisionEscalate:
			report.Escalated++
		default:
			report.Pending++
		}
	}
	// "Decided" means a TERMINAL decision (certify/revoke). Escalated items are
	// intermediate and still need resolving, so they do NOT count as decided —
	// an all-escalated campaign is not complete.
	report.AllDecided = report.Total > 0 && report.Pending == 0 && report.Escalated == 0
	// A campaign is overdue if it is still running, past its due date, and still
	// has OPEN items lacking a terminal decision (pending OR escalated) — whether
	// or not the periodic sweep has stamped it yet.
	report.Overdue = campaign.State == models.CertificationStateRunning &&
		campaign.DueAt != nil && s.now().UTC().After(campaign.DueAt.UTC()) &&
		(report.Pending+report.Escalated) > 0
	return report, nil
}

// ListCampaigns returns the workspace's campaigns, newest first.
func (s *CertificationService) ListCampaigns(ctx context.Context, workspaceID uuid.UUID) ([]models.CertificationCampaign, error) {
	var campaigns []models.CertificationCampaign
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ?", workspaceID).
		Order("created_at desc, id desc").
		Find(&campaigns).Error; err != nil {
		return nil, fmt.Errorf("compliance: list campaigns: %w", err)
	}
	return campaigns, nil
}

// CampaignItemView is one worklist row: the certification item plus the grant
// detail a reviewer needs to decide (who has what access where).
type CampaignItemView struct {
	ItemID      uuid.UUID  `json:"item_id"`
	GrantID     uuid.UUID  `json:"grant_id"`
	ResourceRef string     `json:"resource_ref"`
	Role        string     `json:"role"`
	Subject     string     `json:"subject"`
	Reviewer    string     `json:"reviewer,omitempty"`
	Decision    string     `json:"decision"`
	DecidedBy   string     `json:"decided_by,omitempty"`
	DecidedAt   *time.Time `json:"decided_at,omitempty"`
	Reason      string     `json:"reason,omitempty"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
}

// ListItems returns a campaign's worklist. When reviewer is non-empty the list
// is filtered to that reviewer's assigned queue. The campaign's existence is
// verified first so an unknown / cross-tenant id returns ErrCampaignNotFound
// rather than a misleading empty 200.
func (s *CertificationService) ListItems(ctx context.Context, workspaceID, campaignID uuid.UUID, reviewer string) ([]CampaignItemView, error) {
	if err := s.assertCampaign(ctx, workspaceID, campaignID); err != nil {
		return nil, err
	}
	q := s.db.WithContext(ctx).
		Model(&models.CertificationItem{}).
		Select("certification_items.id AS item_id, certification_items.grant_id AS grant_id, "+
			"access_grants.resource_ref AS resource_ref, access_grants.role AS role, "+
			"access_grants.iam_core_user_id AS subject, certification_items.reviewer AS reviewer, "+
			"certification_items.decision AS decision, certification_items.decided_by AS decided_by, "+
			"certification_items.decided_at AS decided_at, certification_items.reason AS reason, "+
			"certification_items.revoked_at AS revoked_at").
		Joins("JOIN access_grants ON access_grants.id = certification_items.grant_id").
		Where("certification_items.workspace_id = ? AND certification_items.campaign_id = ?", workspaceID, campaignID)
	if reviewer != "" {
		q = q.Where("certification_items.reviewer = ?", reviewer)
	}
	var rows []CampaignItemView
	if err := q.Order("certification_items.created_at asc, certification_items.id asc").Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("compliance: list campaign items: %w", err)
	}
	return rows, nil
}

// assertCampaign returns ErrCampaignNotFound unless the campaign exists in the
// workspace. Used by read paths so a cross-tenant id is a 404, not empty data.
func (s *CertificationService) assertCampaign(ctx context.Context, workspaceID, campaignID uuid.UUID) error {
	if err := s.db.WithContext(ctx).
		Model(&models.CertificationCampaign{}).
		Select("1").
		Where("workspace_id = ? AND id = ?", workspaceID, campaignID).
		Take(new(int)).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrCampaignNotFound
		}
		return fmt.Errorf("compliance: assert campaign: %w", err)
	}
	return nil
}

// forUpdate adds a row-level write lock on Postgres so two concurrent decisions
// on the same item serialize; a no-op on SQLite (which serializes writers with
// a single global write lock). Mirrors the lifecycle package's helper.
func forUpdate(tx *gorm.DB) *gorm.DB {
	if tx.Dialector != nil && tx.Name() == "postgres" {
		return tx.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	return tx
}

func marshalReviewers(reviewers []string) (datatypes.JSON, error) {
	if len(reviewers) == 0 {
		return nil, nil
	}
	b, err := json.Marshal(reviewers)
	if err != nil {
		return nil, fmt.Errorf("%w: reviewers: %v", ErrValidation, err)
	}
	return datatypes.JSON(b), nil
}

// assignReviewer distributes items across reviewers round-robin so each
// reviewer gets a roughly even worklist. Empty reviewers leaves the item
// unassigned (any operator may decide it).
func assignReviewer(reviewers []string, i int) string {
	if len(reviewers) == 0 {
		return ""
	}
	return reviewers[i%len(reviewers)]
}

func scopeMeta(in CampaignInput) map[string]any {
	scope := map[string]any{}
	if in.ScopeResource != "" {
		scope["resource"] = in.ScopeResource
	}
	if in.ScopeRole != "" {
		scope["role"] = in.ScopeRole
	}
	if in.ScopeConnectorID != nil {
		scope["connector_id"] = in.ScopeConnectorID.String()
	}
	return scope
}

func defaultReason(reason, fallback string) string {
	if reason == "" {
		return fallback
	}
	return reason
}

// likePrefix escapes LIKE metacharacters in a scope prefix so a literal "_" or
// "%" in a resource ref can't widen the match, then appends the wildcard. The
// result is always passed through a parameterized `?` placeholder with an
// explicit ESCAPE '\\', so this is the only injection surface and all three
// metacharacters (\\, %, _) are escaped here — there is no SQL-injection path.
func likePrefix(prefix string) string {
	var b []byte
	for i := 0; i < len(prefix); i++ {
		switch prefix[i] {
		case '\\', '%', '_':
			b = append(b, '\\')
		}
		b = append(b, prefix[i])
	}
	return string(b) + "%"
}

func mustJSON(v map[string]any) datatypes.JSON {
	b, err := json.Marshal(v)
	if err != nil {
		// The inputs are plain strings/ids/ints we control, so marshaling cannot
		// fail in practice; fall back to an empty object rather than panicking in
		// an audit path.
		return datatypes.JSON([]byte("{}"))
	}
	return datatypes.JSON(b)
}
