package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

// SodService owns the sod_rules table: the CRUD surface operators use to manage
// their Separation-of-Duties toxic-combination ruleset. Rule EVALUATION lives in
// SodEngine; this service only curates the rules the engine reads.
type SodService struct {
	db  *gorm.DB
	now func() time.Time
}

// NewSodService wires the SoD rule service.
func NewSodService(db *gorm.DB) *SodService {
	return &SodService{db: db, now: time.Now}
}

// SetClock overrides the time source (tests).
func (s *SodService) SetClock(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

// CreateSodRuleInput is the contract for CreateRule. An empty resource/role
// selector segment means "*" (wildcard).
type CreateSodRuleInput struct {
	WorkspaceID uuid.UUID
	Name        string
	Description string
	Severity    string
	ResourceA   string
	RoleA       string
	ResourceB   string
	RoleB       string
	Actor       string
}

// validSeverities is the closed set accepted by CreateRule.
var validSeverities = map[string]bool{
	models.SodSeverityLow:      true,
	models.SodSeverityMedium:   true,
	models.SodSeverityHigh:     true,
	models.SodSeverityCritical: true,
}

// normalizeSelectorSegment maps an empty segment to the explicit "*" wildcard so
// the stored rule is unambiguous and the engine's wildcard test is exact.
func normalizeSelectorSegment(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "*"
	}
	return s
}

// selectorIsWildcard reports whether a selector matches every entitlement (both
// segments wildcard) — a rule with such a selector would flag every pair, so it
// is rejected at creation.
func selectorIsWildcard(resource, role string) bool {
	return sodWildcard(resource) && sodWildcard(role)
}

// CreateRule validates and persists a new SoD rule (enabled), appending a
// sod.rule.created audit row in the same transaction. Both selectors must be
// specific in at least one dimension (resource or role): a fully-wildcard
// selector would match every entitlement and make the rule meaningless.
func (s *SodService) CreateRule(ctx context.Context, in CreateSodRuleInput) (*models.SodRule, error) {
	if in.WorkspaceID == uuid.Nil {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	if strings.TrimSpace(in.Name) == "" {
		return nil, fmt.Errorf("%w: sod rule name is required", ErrValidation)
	}
	severity := strings.TrimSpace(in.Severity)
	if severity == "" {
		severity = models.SodSeverityHigh
	}
	if !validSeverities[severity] {
		return nil, fmt.Errorf("%w: sod rule severity must be low|medium|high|critical, got %q", ErrValidation, in.Severity)
	}
	resA := normalizeSelectorSegment(in.ResourceA)
	roleA := normalizeSelectorSegment(in.RoleA)
	resB := normalizeSelectorSegment(in.ResourceB)
	roleB := normalizeSelectorSegment(in.RoleB)
	if selectorIsWildcard(resA, roleA) || selectorIsWildcard(resB, roleB) {
		return nil, fmt.Errorf("%w: each sod selector must constrain a resource or a role (a fully-wildcard selector matches everything)", ErrValidation)
	}

	now := s.now()
	rule := &models.SodRule{
		WorkspaceID: in.WorkspaceID,
		Name:        strings.TrimSpace(in.Name),
		Description: strings.TrimSpace(in.Description),
		Severity:    severity,
		Enabled:     true,
		ResourceA:   resA,
		RoleA:       roleA,
		ResourceB:   resB,
		RoleB:       roleB,
	}
	rule.CreatedAt = now
	rule.UpdatedAt = now

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(rule).Error; err != nil {
			return fmt.Errorf("lifecycle: insert sod rule: %w", err)
		}
		meta, _ := json.Marshal(map[string]any{
			"severity":   severity,
			"selector_a": map[string]string{"resource": resA, "role": roleA},
			"selector_b": map[string]string{"resource": resB, "role": roleB},
		})
		return appendAudit(ctx, tx, now, auditEntry{
			WorkspaceID: in.WorkspaceID,
			Actor:       in.Actor,
			Action:      "sod.rule.created",
			TargetRef:   rule.ID.String(),
			Metadata:    datatypes.JSON(meta),
		})
	})
	if err != nil {
		return nil, err
	}
	return rule, nil
}

// ListRules returns the workspace's SoD rules, newest first.
func (s *SodService) ListRules(ctx context.Context, workspaceID uuid.UUID) ([]models.SodRule, error) {
	var out []models.SodRule
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ?", workspaceID).
		Order("created_at desc").
		Find(&out).Error; err != nil {
		return nil, fmt.Errorf("lifecycle: list sod rules: %w", err)
	}
	return out, nil
}

// DeleteRule soft-deletes a SoD rule and appends a sod.rule.deleted audit row.
// Returns ErrSodRuleNotFound when the id matches no rule in the workspace.
func (s *SodService) DeleteRule(ctx context.Context, workspaceID, ruleID uuid.UUID, actor string) error {
	now := s.now()
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var rule models.SodRule
		err := tx.Where("workspace_id = ? AND id = ?", workspaceID, ruleID).Take(&rule).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrSodRuleNotFound
		}
		if err != nil {
			return fmt.Errorf("lifecycle: load sod rule: %w", err)
		}
		if err := tx.Delete(&rule).Error; err != nil {
			return fmt.Errorf("lifecycle: delete sod rule: %w", err)
		}
		return appendAudit(ctx, tx, now, auditEntry{
			WorkspaceID: workspaceID,
			Actor:       actor,
			Action:      "sod.rule.deleted",
			TargetRef:   ruleID.String(),
		})
	})
}
