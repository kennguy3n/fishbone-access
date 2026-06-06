package lifecycle

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// GrantExpirer is the subset of AccessProvisioningService the expiry enforcer
// needs. It exists so the enforcer can be unit-tested with a stub.
type GrantExpirer interface {
	ExpireGrant(ctx context.Context, workspaceID, grantID uuid.UUID, actor string) error
}

// ExpiryEnforcer is the cron-driven sweep that revokes grants past their
// ExpiresAt. It is workspace-scoped per run so a multi-tenant cron iterates
// workspaces explicitly rather than ever running an unscoped query.
type ExpiryEnforcer struct {
	db      *gorm.DB
	expirer GrantExpirer
	now     func() time.Time
}

// NewExpiryEnforcer wires the enforcer.
func NewExpiryEnforcer(db *gorm.DB, expirer GrantExpirer) *ExpiryEnforcer {
	return &ExpiryEnforcer{db: db, expirer: expirer, now: time.Now}
}

// SetClock overrides the time source (tests).
func (s *ExpiryEnforcer) SetClock(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

// EnforceResult summarizes an expiry sweep.
type EnforceResult struct {
	Examined int `json:"examined"`
	Expired  int `json:"expired"`
	Failed   int `json:"failed"`
}

// EnforceExpired finds the workspace's active grants whose ExpiresAt is in the
// past and expires each (revoking it on the provider and flipping its request
// to expired). A per-grant failure is counted and the sweep continues, so one
// stuck connector cannot block expiry of the rest.
func (s *ExpiryEnforcer) EnforceExpired(ctx context.Context, workspaceID uuid.UUID) (EnforceResult, error) {
	if workspaceID == uuid.Nil {
		return EnforceResult{}, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	now := s.now()
	var grants []models.AccessGrant
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND state = ? AND revoked_at IS NULL AND expires_at IS NOT NULL AND expires_at < ?", workspaceID, GrantStateActive, now).
		Find(&grants).Error; err != nil {
		return EnforceResult{}, fmt.Errorf("lifecycle: load expiring grants: %w", err)
	}

	result := EnforceResult{Examined: len(grants)}
	for i := range grants {
		if err := s.expirer.ExpireGrant(ctx, workspaceID, grants[i].ID, "expiry-enforcer"); err != nil {
			result.Failed++
			continue
		}
		result.Expired++
	}
	return result, nil
}

// SSOEnforcementChecker reports whether SSO is enforced on a connector's tenant.
// It surfaces local-password / SSO-bypass risk for compliance dashboards.
type SSOEnforcementChecker struct {
	db       *gorm.DB
	resolver ConnectorResolver
	now      func() time.Time
}

// NewSSOEnforcementChecker wires the checker.
func NewSSOEnforcementChecker(db *gorm.DB, resolver ConnectorResolver) *SSOEnforcementChecker {
	return &SSOEnforcementChecker{db: db, resolver: resolver, now: time.Now}
}

// SetClock overrides the time source (tests).
func (s *SSOEnforcementChecker) SetClock(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

// SSOStatus is the result of an SSO-enforcement check for one connector.
type SSOStatus struct {
	ConnectorID uuid.UUID `json:"connector_id"`
	Supported   bool      `json:"supported"`
	Enforced    bool      `json:"enforced"`
	// Details carries the connector's short human-readable hint when SSO is
	// not enforced (e.g. "password login still allowed for 3 users"), so an
	// operator can act on a regression without opening the connector.
	Details string `json:"details,omitempty"`
}

// Check resolves a connector and, if it implements the optional
// SSOEnforcementChecker capability, reports whether SSO is enforced. Connectors
// without the capability return Supported=false (a soft signal, not an error).
func (s *SSOEnforcementChecker) Check(ctx context.Context, workspaceID, connectorID uuid.UUID) (SSOStatus, error) {
	resolved, err := s.resolver.Resolve(ctx, workspaceID, connectorID)
	if err != nil {
		// Preserve Resolve's classification: it wraps a genuinely unusable
		// connector with ErrConnectorNotConfigured (→422) but leaves transient
		// DB/decode errors unwrapped (→500); re-wrapping here would misreport a
		// DB outage as "connector not configured".
		return SSOStatus{}, err
	}
	status := SSOStatus{ConnectorID: connectorID}
	checker, ok := resolved.Impl.(access.SSOEnforcementChecker)
	if !ok {
		return status, nil
	}
	status.Supported = true
	enforced, details, err := checker.CheckSSOEnforcement(ctx, resolved.Config, resolved.Secrets)
	if err != nil {
		return status, fmt.Errorf("lifecycle: check sso enforcement: %w", err)
	}
	status.Enforced = enforced
	status.Details = details

	now := s.now()
	action := "sso.not_enforced"
	if enforced {
		action = "sso.enforced"
	}
	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return appendAudit(ctx, tx, now, auditEntry{
			WorkspaceID: workspaceID,
			Actor:       "system",
			Action:      action,
			TargetRef:   connectorID.String(),
		})
	}); err != nil {
		return status, err
	}
	return status, nil
}
