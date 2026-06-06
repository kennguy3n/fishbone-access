package chargebee

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func TestChargebeeFetchAccessAuditLogs_AlwaysUnavailable(t *testing.T) {
	c := New()
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if !errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v; want ErrAuditNotAvailable", err)
	}
}

func TestChargebeeFetchAccessAuditLogs_InvalidSecrets(t *testing.T) {
	c := New()
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(),
		map[string]interface{}{},
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err == nil || errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v; want secrets validation error", err)
	}
}
