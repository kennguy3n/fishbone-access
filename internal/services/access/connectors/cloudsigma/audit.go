package cloudsigma

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const (
	cloudsigmaAuditPageSize = 100
	cloudsigmaAuditMaxPages = 200
)

// FetchAccessAuditLogs streams CloudSigma per-region audit logs into
// the access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /api/2.0/logs/?limit=100&offset=N
//
// Authentication uses HTTP Basic with the connector's existing
// email/password secrets. Accounts whose plan does not expose audit
// logs receive 401 / 403 / 404 which the connector soft-skips via
// access.ErrAuditNotAvailable.
//
// CloudSigma's logs API is per-region; the region is taken from
// connector config. Pagination uses limit/offset semantics. The
// connector buffers every page before invoking the handler so a
// partial sweep does not advance the persisted cursor.
func (c *CloudSigmaAccessConnector) FetchAccessAuditLogs(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	sincePartitions map[string]time.Time,
	handler func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	since := sincePartitions[access.DefaultAuditPartition]
	base := c.baseURL(cfg) + "/api/2.0/logs/"

	var collected []cloudsigmaAuditEvent
	offset := 0
	for pages := 0; pages < cloudsigmaAuditMaxPages; pages++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("limit", fmt.Sprintf("%d", cloudsigmaAuditPageSize))
		q.Set("offset", fmt.Sprintf("%d", offset))
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("cloudsigma: audit log: %w", err)
		}
		body, readErr := readCSAuditBody(resp)
		if readErr != nil {
			return readErr
		}
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("cloudsigma: audit log: status %d: %s", resp.StatusCode, string(body))
		}
		var parsed cloudsigmaAuditResponse
		if err := json.Unmarshal(body, &parsed); err != nil {
			return fmt.Errorf("cloudsigma: decode audit log: %w", err)
		}
		olderThanCursor := false
		for i := range parsed.Objects {
			ts := parseCSAuditTime(parsed.Objects[i].Time)
			if !since.IsZero() && !ts.IsZero() && !ts.After(since) {
				olderThanCursor = true
				continue
			}
			collected = append(collected, parsed.Objects[i])
		}
		if olderThanCursor || len(parsed.Objects) < cloudsigmaAuditPageSize {
			break
		}
		offset += len(parsed.Objects)
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapCSAuditEvent(&collected[i])
		if entry == nil {
			continue
		}
		if entry.Timestamp.After(batchMax) {
			batchMax = entry.Timestamp
		}
		batch = append(batch, entry)
	}
	if len(batch) == 0 {
		return nil
	}
	return handler(batch, batchMax, access.DefaultAuditPartition)
}

type cloudsigmaAuditResponse struct {
	Objects []cloudsigmaAuditEvent `json:"objects"`
	Meta    struct {
		Limit  int `json:"limit"`
		Offset int `json:"offset"`
		Total  int `json:"total_count"`
	} `json:"meta"`
}

type cloudsigmaAuditEvent struct {
	UUID     string `json:"uuid"`
	Time     string `json:"time"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	OpName   string `json:"op_name"`
	User     struct {
		UUID  string `json:"uuid"`
		Email string `json:"email"`
	} `json:"user"`
}

func mapCSAuditEvent(e *cloudsigmaAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.UUID) == "" {
		return nil
	}
	ts := parseCSAuditTime(e.Time)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	outcome := "success"
	if sev := strings.ToLower(strings.TrimSpace(e.Severity)); sev == "error" || sev == "critical" {
		outcome = "failure"
	}
	action := strings.TrimSpace(e.OpName)
	if action == "" {
		action = strings.TrimSpace(e.Message)
	}
	return &access.AuditLogEntry{
		EventID:         e.UUID,
		EventType:       strings.TrimSpace(e.OpName),
		Action:          action,
		Timestamp:       ts,
		ActorExternalID: strings.TrimSpace(e.User.UUID),
		ActorEmail:      strings.TrimSpace(e.User.Email),
		Outcome:         outcome,
		RawData:         rawMap,
	}
}

func parseCSAuditTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	if ts, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return ts.UTC()
	}
	if ts, err := time.Parse(time.RFC3339, s); err == nil {
		return ts.UTC()
	}
	if ts, err := time.Parse("2006-01-02T15:04:05.000000", s); err == nil {
		return ts.UTC()
	}
	if ts, err := time.Parse("2006-01-02T15:04:05", s); err == nil {
		return ts.UTC()
	}
	return time.Time{}
}

func readCSAuditBody(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, errors.New("cloudsigma: empty response")
	}
	defer resp.Body.Close()
	const max = 1 << 20
	buf := make([]byte, 0, 1024)
	tmp := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if len(buf) >= max {
				break
			}
		}
		if err != nil {
			break
		}
	}
	return buf, nil
}

var _ access.AccessAuditor = (*CloudSigmaAccessConnector)(nil)
