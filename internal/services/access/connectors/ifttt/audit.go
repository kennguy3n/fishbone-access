package ifttt

import (
	"context"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// FetchAccessAuditLogs implements access.AccessAuditor for IFTTT.
//
// IFTTT does not expose a tenant-scoped audit-log REST API. The
// connector therefore always surfaces access.ErrAuditNotAvailable so
// the access_audit worker soft-skips this provider on every tick,
// while still allowing the optional-capability registry
// (connector_list_service.go) to flag the connector as audit-aware
// for completeness.
func (c *IftttAccessConnector) FetchAccessAuditLogs(
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

var _ access.AccessAuditor = (*IftttAccessConnector)(nil)
