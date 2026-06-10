package pipedrive

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const (
	pipedriveAuditPageSize = 100
	pipedriveAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Pipedrive audit-log entries into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /v1/auditLogs?start=N&limit=100&since={iso}
//
// baseURL() already includes the /v1 prefix, so the path passed to
// newRequest is /auditLogs (without /v1) to avoid double-prefixing.
//
// Authentication is the api_token (sent as Bearer per existing
// connector). Pipedrive scopes audit access to Enterprise plans;
// other tenants return 401 / 403 / 404 which the connector
// soft-skips via access.ErrAuditNotAvailable.
func (c *PipedriveAccessConnector) FetchAccessAuditLogs(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	sincePartitions map[string]time.Time,
	handler func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error,
) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	since := sincePartitions[access.DefaultAuditPartition]

	var collected []pipedriveAuditEvent
	start := 0
	for pages := 0; pages < pipedriveAuditMaxPages; pages++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		path := fmt.Sprintf("/auditLogs?start=%d&limit=%d", start, pipedriveAuditPageSize)
		if !since.IsZero() {
			path += "&since=" + since.UTC().Format(time.RFC3339)
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("pipedrive: audit log: %w", err)
		}
		body, readErr := readPipedriveAuditBody(resp)
		if readErr != nil {
			return readErr
		}
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("pipedrive: audit log: status %d: %s", resp.StatusCode, string(body))
		}
		var p pipedriveAuditPage
		if err := json.Unmarshal(body, &p); err != nil {
			return fmt.Errorf("pipedrive: decode audit log: %w", err)
		}
		if !p.Success {
			return access.ErrAuditNotAvailable
		}
		collected = append(collected, p.Data...)
		if !p.AdditionalData.Pagination.MoreItems {
			break
		}
		start = p.AdditionalData.Pagination.NextStart
		if start == 0 {
			break
		}
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapPipedriveAuditEvent(&collected[i])
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

type pipedriveAuditPage struct {
	Success        bool                  `json:"success"`
	Data           []pipedriveAuditEvent `json:"data"`
	AdditionalData struct {
		Pagination struct {
			Start     int  `json:"start"`
			Limit     int  `json:"limit"`
			MoreItems bool `json:"more_items_in_collection"`
			NextStart int  `json:"next_start"`
		} `json:"pagination"`
	} `json:"additional_data"`
}

type pipedriveAuditEvent struct {
	ID         string `json:"id"`
	Action     string `json:"action"`
	UserID     int    `json:"user_id"`
	UserEmail  string `json:"user_email"`
	ObjectType string `json:"object_type"`
	ObjectID   string `json:"object_id"`
	Timestamp  string `json:"timestamp"`
}

func mapPipedriveAuditEvent(e *pipedriveAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parsePipedriveAuditTime(e.Timestamp)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:          e.ID,
		EventType:        strings.TrimSpace(e.Action),
		Action:           strings.TrimSpace(e.Action),
		Timestamp:        ts,
		ActorExternalID:  fmt.Sprintf("%d", e.UserID),
		ActorEmail:       strings.TrimSpace(e.UserEmail),
		TargetExternalID: strings.TrimSpace(e.ObjectID),
		TargetType:       strings.TrimSpace(e.ObjectType),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parsePipedriveAuditTime(s string) time.Time {
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
	if ts, err := time.Parse("2006-01-02 15:04:05", s); err == nil {
		return ts.UTC()
	}
	return time.Time{}
}

func readPipedriveAuditBody(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, errors.New("pipedrive: empty response")
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

var _ access.AccessAuditor = (*PipedriveAccessConnector)(nil)
