package square

import (
	"context"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// FetchAccessAuditLogs implements access.AccessAuditor for Square.
//
// Square's public REST surface does not expose a tenant-scoped
// access-audit API. We surveyed the following candidates during the
// audit-pipeline backfill:
//
//   - /v2/labor/shifts and /v2/labor/workweek-configs: labour-management,
//     not security-audit. Surfaces a "who clocked in/out when" feed
//     rather than admin activity, so it cannot replace audit logs.
//   - /v2/team-members/search: returns the current team-member roster
//     plus the createdAt/updatedAt cursors but no per-event activity
//     stream — the historical action who/when/what is not retrievable.
//   - Webhooks event-history (event subscriptions): debugging-only, not
//     a tenant-wide audit feed of dashboard actions.
//   - Square Connect "Activity Log" UI: visible to seller admins but
//     not exposed over the public REST API at the time of writing.
//
// The connector therefore continues to surface
// access.ErrAuditNotAvailable so the access-audit worker soft-skips
// Square on every tick. The optional-capability registry
// (connector_list_service.go) still flags Square as audit-aware so it
// can be backfilled the moment Square ships a public audit endpoint.
func (c *SquareAccessConnector) FetchAccessAuditLogs(
	_ context.Context,
	configRaw, secretsRaw map[string]interface{},
	_ map[string]time.Time,
	_ func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error,
) error {
	if _, _, err := c.decodeBoth(configRaw, secretsRaw); err != nil {
		return err
	}
	return access.ErrAuditNotAvailable
}

var _ access.AccessAuditor = (*SquareAccessConnector)(nil)
