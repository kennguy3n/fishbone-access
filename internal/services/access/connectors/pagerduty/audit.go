package pagerduty

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// FetchAccessAuditLogs streams PagerDuty audit records into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /audit/records?since={since}&cursor={cursor}&limit=100
//
// PagerDuty paginates by `cursor`; the handler is called once per
// page in chronological order so callers can persist the monotonic
// `nextSince` cursor between runs.
func (c *PagerDutyAccessConnector) FetchAccessAuditLogs(
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
	pageCursor := ""
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("limit", "100")
		if !since.IsZero() {
			q.Set("since", since.UTC().Format(time.RFC3339))
		}
		if pageCursor != "" {
			q.Set("cursor", pageCursor)
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, "/audit/records?"+q.Encode())
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var page pdAuditPage
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("pagerduty: decode audit records: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(page.Records))
		batchMax := cursor
		for i := range page.Records {
			entry := mapPagerDutyAuditRecord(&page.Records[i])
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
		next := strings.TrimSpace(page.NextCursor)
		if next == "" || !page.More {
			return nil
		}
		pageCursor = next
	}
}

type pdAuditPage struct {
	Records    []pdAuditRecord `json:"records"`
	NextCursor string          `json:"next_cursor"`
	More       bool            `json:"more"`
}

type pdAuditRecord struct {
	ID            string `json:"id"`
	Self          string `json:"self"`
	ExecutionTime string `json:"execution_time"`
	Action        string `json:"action"`
	Actors        []struct {
		ID    string `json:"id"`
		Type  string `json:"type"`
		Email string `json:"email"`
	} `json:"actors"`
	Method struct {
		TruncatedToken string `json:"truncated_token"`
		Description    string `json:"description"`
	} `json:"method"`
	RootResource struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	} `json:"root_resource"`
}

func mapPagerDutyAuditRecord(r *pdAuditRecord) *access.AuditLogEntry {
	if r == nil || r.ID == "" {
		return nil
	}
	ts, _ := time.Parse(time.RFC3339Nano, r.ExecutionTime)
	if ts.IsZero() {
		ts, _ = time.Parse(time.RFC3339, r.ExecutionTime)
	}
	// Skip records whose execution_time is missing/unparseable: a
	// zero-timestamp audit entry would never advance the delta-sync
	// cursor (batchMax) and could be mis-ordered downstream. Mirrors
	// the okta/ovhcloud auditors.
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(r)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	var actorID, actorEmail string
	if len(r.Actors) > 0 {
		actorID = r.Actors[0].ID
		actorEmail = r.Actors[0].Email
	}
	return &access.AuditLogEntry{
		EventID:          r.ID,
		EventType:        r.Action,
		Action:           r.Action,
		Timestamp:        ts,
		ActorExternalID:  actorID,
		ActorEmail:       actorEmail,
		TargetExternalID: r.RootResource.ID,
		TargetType:       r.RootResource.Type,
		Outcome:          "success",
		RawData:          rawMap,
	}
}

var _ access.AccessAuditor = (*PagerDutyAccessConnector)(nil)
