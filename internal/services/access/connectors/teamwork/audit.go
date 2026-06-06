package teamwork

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const (
	teamworkAuditPageSize = 100
	teamworkAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Teamwork audit events into the access
// audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /projects/api/v3/audit.json?page=N&pageSize=100
//
// Audit log access requires an admin-tier API key; lower-tier keys
// receive 401 / 403 / 404 which the connector soft-skips via
// access.ErrAuditNotAvailable.
func (c *TeamworkAccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL(cfg) + "/projects/api/v3/audit.json"

	var collected []teamworkAuditEvent
	for page := 1; page <= teamworkAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("page", fmt.Sprintf("%d", page))
		q.Set("pageSize", fmt.Sprintf("%d", teamworkAuditPageSize))
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("teamwork: audit log: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("teamwork: audit log: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope teamworkAuditResponse
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("teamwork: decode audit log: %w", err)
		}
		for i := range envelope.AuditTrail {
			ts := parseTeamworkAuditTime(envelope.AuditTrail[i].EventDate)
			if !since.IsZero() && !ts.IsZero() && !ts.After(since) {
				// Older than the watermark: skip this event but keep paging.
				// The v3 audit endpoint exposes no server-side time filter and
				// does not guarantee a sort order, so encountering an older
				// event must NOT terminate the sweep — newer events may still
				// sit on later pages. Termination is bounded by the final short
				// page or teamworkAuditMaxPages.
				continue
			}
			collected = append(collected, envelope.AuditTrail[i])
		}
		if len(envelope.AuditTrail) < teamworkAuditPageSize {
			break
		}
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapTeamworkAuditEvent(&collected[i])
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

type teamworkAuditEvent struct {
	ID         int64  `json:"id"`
	Event      string `json:"event"`
	EventDate  string `json:"eventDate"`
	UserID     int64  `json:"userId"`
	UserEmail  string `json:"userEmail"`
	IPAddress  string `json:"ipAddress"`
	ObjectType string `json:"objectType"`
	ObjectID   int64  `json:"objectId"`
}

type teamworkAuditResponse struct {
	AuditTrail []teamworkAuditEvent `json:"audit_trail"`
	Meta       struct {
		Page  int `json:"page"`
		Total int `json:"total"`
	} `json:"meta"`
}

func mapTeamworkAuditEvent(e *teamworkAuditEvent) *access.AuditLogEntry {
	if e == nil || e.ID == 0 {
		return nil
	}
	ts := parseTeamworkAuditTime(e.EventDate)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:          fmt.Sprintf("%d", e.ID),
		EventType:        strings.TrimSpace(e.Event),
		Action:           strings.TrimSpace(e.Event),
		Timestamp:        ts,
		ActorExternalID:  fmt.Sprintf("%d", e.UserID),
		ActorEmail:       strings.TrimSpace(e.UserEmail),
		TargetExternalID: fmt.Sprintf("%d", e.ObjectID),
		TargetType:       strings.TrimSpace(e.ObjectType),
		IPAddress:        strings.TrimSpace(e.IPAddress),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseTeamworkAuditTime(s string) time.Time {
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
	return time.Time{}
}
