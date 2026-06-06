package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

// Access-review campaign states.
const (
	ReviewStateDraft     = "draft"
	ReviewStateActive    = "active"
	ReviewStateCompleted = "completed"
)

// Per-grant review decisions.
const (
	ReviewDecisionPending  = "pending"
	ReviewDecisionCertify  = "certify"
	ReviewDecisionRevoke   = "revoke"
	ReviewDecisionEscalate = "escalate"
)

// GrantRevoker is the subset of AccessProvisioningService the review service
// needs to tear down a grant when a reviewer revokes it. Defined here so the
// review service does not require the full provisioning service in tests.
type GrantRevoker interface {
	RevokeGrant(ctx context.Context, workspaceID, grantID uuid.UUID, actor, reason string) error
}

// ReviewService runs access-certification campaigns: it snapshots the
// workspace's live grants into per-grant review items, records certify / revoke
// / escalate decisions, drives revocations through the GrantRevoker, and
// reports campaign progress. Everything is workspace-scoped.
type ReviewService struct {
	db      *gorm.DB
	revoker GrantRevoker
	now     func() time.Time
}

// NewReviewService wires the review service. revoker may be nil in contexts
// that never revoke (e.g. read-only reporting), in which case a revoke decision
// is recorded but returns an error prompting the caller to wire a revoker.
func NewReviewService(db *gorm.DB, revoker GrantRevoker) *ReviewService {
	return &ReviewService{db: db, revoker: revoker, now: time.Now}
}

// SetClock overrides the time source (tests).
func (s *ReviewService) SetClock(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

// StartCampaign creates an active review and enumerates every live grant in the
// workspace into a pending review item, all in one transaction. Returns the
// review and the number of items created.
func (s *ReviewService) StartCampaign(ctx context.Context, workspaceID uuid.UUID, name, actor string) (*models.AccessReview, int, error) {
	if workspaceID == uuid.Nil {
		return nil, 0, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	if name == "" {
		return nil, 0, fmt.Errorf("%w: campaign name is required", ErrValidation)
	}

	now := s.now()
	review := &models.AccessReview{
		WorkspaceID: workspaceID,
		Name:        name,
		State:       ReviewStateActive,
		StartedAt:   &now,
	}
	review.CreatedAt = now
	review.UpdatedAt = now

	itemCount := 0
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(review).Error; err != nil {
			return fmt.Errorf("lifecycle: insert review: %w", err)
		}
		var grants []models.AccessGrant
		if err := tx.WithContext(ctx).
			Where("workspace_id = ? AND state = ? AND revoked_at IS NULL", workspaceID, GrantStateActive).
			Find(&grants).Error; err != nil {
			return fmt.Errorf("lifecycle: enumerate grants for review: %w", err)
		}
		for i := range grants {
			item := &models.AccessReviewItem{
				WorkspaceID: workspaceID,
				ReviewID:    review.ID,
				GrantID:     grants[i].ID,
				Decision:    ReviewDecisionPending,
			}
			item.CreatedAt = now
			item.UpdatedAt = now
			if err := tx.Create(item).Error; err != nil {
				return fmt.Errorf("lifecycle: insert review item: %w", err)
			}
			itemCount++
		}
		return appendAudit(ctx, tx, now, auditEntry{
			WorkspaceID: workspaceID,
			Actor:       actor,
			Action:      "access_review.started",
			TargetRef:   review.ID.String(),
		})
	})
	if err != nil {
		return nil, 0, err
	}
	return review, itemCount, nil
}

// SubmitDecision records a certify / revoke / escalate decision on one review
// item. The item load, the terminal-decision guard, and the decision write all
// happen inside one transaction that takes a row-level FOR UPDATE lock on the
// item (on Postgres), so two concurrent decisions on the same item serialize
// instead of both reading "pending" and racing to write (a TOCTOU that could
// leave a torn-down grant marked "certified"). A revoke decision then drives
// the connector-side grant teardown AFTER the decision commits: the revoke does
// network I/O and is idempotent, so it must not run inside the locked
// transaction (which also serializes the grant's own write transaction on
// SQLite). Decisions on a completed campaign are rejected.
func (s *ReviewService) SubmitDecision(ctx context.Context, workspaceID, reviewID, itemID uuid.UUID, decision, decidedBy, reason string) error {
	switch decision {
	case ReviewDecisionCertify, ReviewDecisionRevoke, ReviewDecisionEscalate:
	default:
		return fmt.Errorf("%w: unknown review decision %q", ErrValidation, decision)
	}
	// Validate the revoker up front so we never commit a revoke decision we
	// cannot then act on.
	if decision == ReviewDecisionRevoke && s.revoker == nil {
		return fmt.Errorf("%w: review service has no grant revoker wired", ErrValidation)
	}

	now := s.now()
	var grantID uuid.UUID
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var review models.AccessReview
		if err := tx.WithContext(ctx).
			Where("workspace_id = ? AND id = ?", workspaceID, reviewID).
			Take(&review).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrReviewNotFound
			}
			return fmt.Errorf("lifecycle: load review: %w", err)
		}
		if review.State == ReviewStateCompleted {
			return ErrReviewClosed
		}

		// FOR UPDATE (on Postgres) so a concurrent decision on the same item
		// waits here, then re-reads the committed decision below and is rejected
		// by the terminal-decision guard instead of overwriting it.
		var item models.AccessReviewItem
		if err := forUpdate(tx.WithContext(ctx)).
			Where("workspace_id = ? AND review_id = ? AND id = ?", workspaceID, reviewID, itemID).
			Take(&item).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrReviewNotFound
			}
			return fmt.Errorf("lifecycle: load review item: %w", err)
		}
		// A terminal decision (certify/revoke) is final: reject flipping it to a
		// *different* terminal decision (e.g. revoke→certify, which would leave a
		// torn-down grant marked "certified"). Re-submitting the SAME decision is
		// allowed and idempotent, which is what lets a revoke whose connector
		// teardown failed below be safely retried.
		if (item.Decision == ReviewDecisionCertify || item.Decision == ReviewDecisionRevoke) && item.Decision != decision {
			return fmt.Errorf("%w: item %s is %s", ErrReviewItemDecided, itemID, item.Decision)
		}
		grantID = item.GrantID

		if err := tx.Model(&models.AccessReviewItem{}).
			Where("workspace_id = ? AND id = ?", workspaceID, itemID).
			Updates(map[string]any{
				"decision":   decision,
				"decided_by": decidedBy,
				"decided_at": now,
				"reason":     reason,
				"updated_at": now,
			}).Error; err != nil {
			return fmt.Errorf("lifecycle: update review item: %w", err)
		}
		return appendAudit(ctx, tx, now, auditEntry{
			WorkspaceID: workspaceID,
			Actor:       decidedBy,
			Action:      "access_review.decision." + decision,
			TargetRef:   itemID.String(),
		})
	})
	if err != nil {
		return err
	}

	// Decision committed. Drive the connector-side teardown for a revoke. This
	// is idempotent (RevokeGrant no-ops an already-revoked grant), so if it
	// fails the caller can re-submit the same revoke decision to re-drive it.
	if decision == ReviewDecisionRevoke {
		if err := s.revoker.RevokeGrant(ctx, workspaceID, grantID, decidedBy, defaultReason(reason, "revoked by access review")); err != nil {
			return err
		}
	}
	return nil
}

// CompleteCampaign closes a campaign. It is idempotent on an already-completed
// review. Pending items are left as-is (an operator can choose to escalate or
// auto-revoke them via separate calls); the returned report shows the final
// tally.
func (s *ReviewService) CompleteCampaign(ctx context.Context, workspaceID, reviewID uuid.UUID, actor string) (ReviewReport, error) {
	var review models.AccessReview
	err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND id = ?", workspaceID, reviewID).
		Take(&review).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ReviewReport{}, ErrReviewNotFound
	}
	if err != nil {
		return ReviewReport{}, fmt.Errorf("lifecycle: load review: %w", err)
	}

	if review.State != ReviewStateCompleted {
		now := s.now()
		if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			if err := tx.Model(&models.AccessReview{}).
				Where("workspace_id = ? AND id = ?", workspaceID, reviewID).
				Updates(map[string]any{"state": ReviewStateCompleted, "completed_at": now, "updated_at": now}).Error; err != nil {
				return fmt.Errorf("lifecycle: complete review: %w", err)
			}
			return appendAudit(ctx, tx, now, auditEntry{
				WorkspaceID: workspaceID,
				Actor:       actor,
				Action:      "access_review.completed",
				TargetRef:   reviewID.String(),
			})
		}); err != nil {
			return ReviewReport{}, err
		}
	}
	return s.Report(ctx, workspaceID, reviewID)
}

// ReviewReport is the decision tally for a campaign.
type ReviewReport struct {
	ReviewID  uuid.UUID `json:"review_id"`
	Name      string    `json:"name"`
	State     string    `json:"state"`
	Total     int       `json:"total"`
	Pending   int       `json:"pending"`
	Certified int       `json:"certified"`
	Revoked   int       `json:"revoked"`
	Escalated int       `json:"escalated"`
}

// Report tallies a campaign's review items by decision.
func (s *ReviewService) Report(ctx context.Context, workspaceID, reviewID uuid.UUID) (ReviewReport, error) {
	var review models.AccessReview
	err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND id = ?", workspaceID, reviewID).
		Take(&review).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ReviewReport{}, ErrReviewNotFound
	}
	if err != nil {
		return ReviewReport{}, fmt.Errorf("lifecycle: load review for report: %w", err)
	}

	var items []models.AccessReviewItem
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND review_id = ?", workspaceID, reviewID).
		Find(&items).Error; err != nil {
		return ReviewReport{}, fmt.Errorf("lifecycle: load review items for report: %w", err)
	}

	report := ReviewReport{ReviewID: reviewID, Name: review.Name, State: review.State, Total: len(items)}
	for i := range items {
		switch items[i].Decision {
		case ReviewDecisionCertify:
			report.Certified++
		case ReviewDecisionRevoke:
			report.Revoked++
		case ReviewDecisionEscalate:
			report.Escalated++
		default:
			report.Pending++
		}
	}
	return report, nil
}

// ListItems returns a campaign's review items.
func (s *ReviewService) ListItems(ctx context.Context, workspaceID, reviewID uuid.UUID) ([]models.AccessReviewItem, error) {
	var items []models.AccessReviewItem
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND review_id = ?", workspaceID, reviewID).
		Order("created_at asc, id asc").
		Find(&items).Error; err != nil {
		return nil, fmt.Errorf("lifecycle: list review items: %w", err)
	}
	return items, nil
}
