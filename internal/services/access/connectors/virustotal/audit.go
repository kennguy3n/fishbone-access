package virustotal

import (
	"context"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// FetchAccessAuditLogs implements access.AccessAuditor for VirusTotal.
//
// VirusTotal is a lookup / search API (files, URLs, IPs) and exposes no
// per-tenant access-audit feed. The connector therefore always
// surfaces access.ErrAuditNotAvailable so the access_audit worker
// soft-skips this provider on every tick while still letting the
// optional-capability registry flag the connector as audit-aware.
func (c *VirusTotalAccessConnector) FetchAccessAuditLogs(
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

var _ access.AccessAuditor = (*VirusTotalAccessConnector)(nil)
