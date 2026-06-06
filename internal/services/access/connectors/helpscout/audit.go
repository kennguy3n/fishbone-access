package helpscout

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// FetchAccessAuditLogs streams Help Scout user-activity events into
// the access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /v2/users/activity?start={ts}&page=N&size=50
//
// The response is a HAL-style envelope with `_embedded.activity` and
// `page.totalPages`. Pagination is page-numbered; iteration stops once
// `page.number >= page.totalPages`. Tenants without the audit/activity
// feature (no Plus/Pro plan) receive 401/403/404 which collapses to
// access.ErrAuditNotAvailable so the worker soft-skips the tenant.
func (c *HelpScoutAccessConnector) FetchAccessAuditLogs(
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
	cursor := since
	page := 1
	const size = 50
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("size", strconv.Itoa(size))
		q.Set("page", strconv.Itoa(page))
		if !since.IsZero() {
			q.Set("start", since.UTC().Format(time.RFC3339))
		}
		path := "/users/activity?" + q.Encode()
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		resp, err := c.doRaw(req)
		if err != nil {
			return err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("helpscout: users/activity: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope helpscoutActivityPage
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("helpscout: decode activity page: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(envelope.Embedded.Activity))
		batchMax := cursor
		for i := range envelope.Embedded.Activity {
			entry := mapHelpscoutActivity(&envelope.Embedded.Activity[i])
			if entry == nil {
				continue
			}
			if entry.Timestamp.After(batchMax) {
				batchMax = entry.Timestamp
			}
			batch = append(batch, entry)
		}
		if err := handler(batch, batchMax, access.DefaultAuditPartition); err != nil {
			return err
		}
		cursor = batchMax
		if envelope.Page.TotalPages <= 0 || page >= envelope.Page.TotalPages {
			return nil
		}
		page++
	}
}

type helpscoutActivityPage struct {
	Embedded struct {
		Activity []helpscoutActivity `json:"activity"`
	} `json:"_embedded"`
	Page struct {
		Number     int `json:"number"`
		TotalPages int `json:"totalPages"`
		Size       int `json:"size,omitempty"`
		Total      int `json:"totalElements,omitempty"`
	} `json:"page"`
}

type helpscoutActivity struct {
	ID          json.Number `json:"id"`
	Type        string      `json:"type"`
	Action      string      `json:"action,omitempty"`
	Timestamp   string      `json:"timestamp"`
	UserID      json.Number `json:"userId"`
	UserName    string      `json:"userName,omitempty"`
	UserEmail   string      `json:"userEmail,omitempty"`
	ObjectID    json.Number `json:"objectId,omitempty"`
	ObjectType  string      `json:"objectType,omitempty"`
	IPAddress   string      `json:"ipAddress,omitempty"`
	UserAgent   string      `json:"userAgent,omitempty"`
	Description string      `json:"description,omitempty"`
}

func mapHelpscoutActivity(e *helpscoutActivity) *access.AuditLogEntry {
	if e == nil {
		return nil
	}
	id := strings.TrimSpace(e.ID.String())
	if id == "" || id == "0" {
		return nil
	}
	ts := parseHelpscoutTime(e.Timestamp)
	if ts.IsZero() {
		return nil
	}
	rawMap := map[string]interface{}{}
	raw, _ := json.Marshal(e)
	_ = json.Unmarshal(raw, &rawMap)
	action := strings.TrimSpace(e.Action)
	if action == "" {
		action = strings.TrimSpace(e.Type)
	}
	actor := strings.TrimSpace(e.UserID.String())
	if actor == "0" {
		actor = ""
	}
	target := strings.TrimSpace(e.ObjectID.String())
	if target == "0" {
		target = ""
	}
	return &access.AuditLogEntry{
		EventID:          id,
		EventType:        strings.TrimSpace(e.Type),
		Action:           action,
		Timestamp:        ts,
		ActorExternalID:  actor,
		ActorEmail:       strings.TrimSpace(e.UserEmail),
		TargetExternalID: target,
		TargetType:       strings.TrimSpace(e.ObjectType),
		IPAddress:        strings.TrimSpace(e.IPAddress),
		UserAgent:        strings.TrimSpace(e.UserAgent),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

// parseHelpscoutTime parses Help Scout's activity timestamps. Help Scout
// emits RFC3339; older payloads omit fractional seconds.
func parseHelpscoutTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	if ts, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return ts
	}
	if ts, err := time.Parse(time.RFC3339, s); err == nil {
		return ts
	}
	return time.Time{}
}

var _ access.AccessAuditor = (*HelpScoutAccessConnector)(nil)
