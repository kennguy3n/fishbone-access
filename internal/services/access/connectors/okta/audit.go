package okta

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

// FetchAccessAuditLogs streams Okta System Log events into the access
// audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /api/v1/logs?since={since}&sortOrder=ASCENDING
//
// Pagination uses the RFC-5988 `Link: rel="next"` header (already
// supported by parseNextLink in connector.go).
//
// Outcome maps from Okta's outcome.result: "SUCCESS" / "ALLOW" become
// "success", anything else becomes "failure".
func (c *OktaAccessConnector) FetchAccessAuditLogs(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	sincePartitions map[string]time.Time,
	handler func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error,
) error {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	since := sincePartitions[access.DefaultAuditPartition]
	// When `since` is zero we omit the parameter so Okta returns
	// events from the start of its retention window (~90 days).
	query := "sortOrder=ASCENDING&limit=200"
	if !since.IsZero() {
		query += "&since=" + url.QueryEscape(since.UTC().Format(time.RFC3339))
	}
	startURL := c.absURL(cfg, "/api/v1/logs?"+query)

	cursor := since
	for next := startURL; next != ""; {
		if err := ctx.Err(); err != nil {
			return err
		}
		reqURL := next
		if c.urlOverride != "" {
			reqURL = c.rewriteForTest(reqURL)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "SSWS "+strings.TrimPrefix(secrets.APIToken, "SSWS "))
		req.Header.Set("Accept", "application/json")
		resp, err := c.doRaw(req)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			_ = resp.Body.Close()
			return fmt.Errorf("okta: audit logs status %d: %s", resp.StatusCode, string(body))
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return err
		}
		var events []oktaAuditEvent
		if err := json.Unmarshal(body, &events); err != nil {
			return fmt.Errorf("okta: decode audit logs: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(events))
		batchMax := cursor
		for i := range events {
			entry := mapOktaAuditEvent(&events[i])
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
		next = parseNextLink(resp.Header.Get("Link"))
	}
	return nil
}

type oktaAuditEvent struct {
	UUID           string `json:"uuid"`
	Published      string `json:"published"`
	EventType      string `json:"eventType"`
	DisplayMessage string `json:"displayMessage"`
	Outcome        struct {
		Result string `json:"result"`
		Reason string `json:"reason"`
	} `json:"outcome"`
	Actor  oktaLogActor   `json:"actor"`
	Target []oktaLogActor `json:"target"`
	Client struct {
		IPAddress string `json:"ipAddress"`
		UserAgent struct {
			RawUserAgent string `json:"rawUserAgent"`
		} `json:"userAgent"`
	} `json:"client"`
}

func mapOktaAuditEvent(e *oktaAuditEvent) *access.AuditLogEntry {
	if e == nil || e.UUID == "" {
		return nil
	}
	// Skip events whose published timestamp is empty or unparseable:
	// delivering a zero-timestamp audit entry would never advance the
	// delta-sync cursor and could be mis-ordered/mis-filtered by the
	// pipeline. This mirrors the ovhcloud auditor's behaviour.
	ts, err := time.Parse(time.RFC3339, e.Published)
	if err != nil || ts.IsZero() {
		return nil
	}
	ts = ts.UTC()
	var targetID, targetType string
	if len(e.Target) > 0 {
		targetID = e.Target[0].ID
		targetType = e.Target[0].Type
	}
	outcome := "success"
	result := strings.ToUpper(strings.TrimSpace(e.Outcome.Result))
	if result != "" && result != "SUCCESS" && result != "ALLOW" {
		outcome = "failure"
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:          e.UUID,
		EventType:        e.EventType,
		Action:           e.EventType,
		Timestamp:        ts,
		ActorExternalID:  e.Actor.ID,
		ActorEmail:       e.Actor.AlternateID,
		TargetExternalID: targetID,
		TargetType:       targetType,
		IPAddress:        e.Client.IPAddress,
		UserAgent:        e.Client.UserAgent.RawUserAgent,
		Outcome:          outcome,
		RawData:          rawMap,
	}
}

var _ access.AccessAuditor = (*OktaAccessConnector)(nil)
