package bitsight

import (
	"context"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// FetchAccessAuditLogs implements access.AccessAuditor for BitSight.
//
// BitSight exposes per-company security ratings rather than a
// per-tenant access-audit feed; there is no audit-log endpoint to
// drain. The connector therefore always surfaces
// access.ErrAuditNotAvailable so the access_audit worker soft-skips
// this provider on every tick while still letting the
// optional-capability registry flag the connector as audit-aware.
func (c *BitSightAccessConnector) FetchAccessAuditLogs(
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

var _ access.AccessAuditor = (*BitSightAccessConnector)(nil)
