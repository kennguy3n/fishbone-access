package mailchimp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// mailchimpAuditMaxPages bounds a single sweep to ~20k chatter
// entries. Mailchimp's chimp-chatter feed is reverse-chronological
// (newest first) via offset pagination, so this only kicks in on the
// very first sync of a long-dormant account; the `since={iso}` filter
// narrows the window on every subsequent run.
const mailchimpAuditMaxPages = 200

// mailchimpAuditPageSize matches Mailchimp's documented maximum page
// size on the chimp-chatter activity feed.
const mailchimpAuditPageSize = 100

// FetchAccessAuditLogs streams Mailchimp account activity into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /3.0/activity-feed/chimp-chatter?count=100&offset=N&since={iso}
//
// Mailchimp does not expose a dedicated audit-log API; its
// account-wide activity feed (chimp-chatter) is the closest available
// surface and is the same feed shown to operators in the dashboard.
// Tenants on plans that don't expose the feed surface 401/403/404
// which the connector soft-skips via access.ErrAuditNotAvailable.
//
// The chimp-chatter feed is reverse-chronological (newest first) and
// the AccessAuditor contract requires that any `nextSince` passed to
// the handler cover only events already yielded — the worker persists
// this cursor even on partial failure (see
// internal/workers/handlers/access_audit.go). To honour the contract
// under reverse-chronological pagination we collect the full sweep
// first, then reverse the entire collection into chronological
// (oldest-first) order and call the handler exactly once with the
// maximum timestamp as `nextSince`. If any page fails mid-sweep (or
// the handler call itself fails) the cursor is never advanced past
// un-yielded events, so a retry replays the same window rather than
// silently skipping older entries below the persisted cursor.
func (c *MailchimpAccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL(secrets) + "/3.0/activity-feed/chimp-chatter"

	var collected []mailchimpChatter
	offset := 0
	for page := 0; page < mailchimpAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("count", fmt.Sprintf("%d", mailchimpAuditPageSize))
		q.Set("offset", fmt.Sprintf("%d", offset))
		if !since.IsZero() {
			q.Set("since", since.UTC().Format(time.RFC3339))
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("mailchimp: chimp-chatter: %w", err)
		}
		body, readErr := readMailchimpBody(resp)
		if readErr != nil {
			return readErr
		}
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("mailchimp: chimp-chatter: status %d: %s", resp.StatusCode, string(body))
		}
		var p mailchimpChatterPage
		if err := json.Unmarshal(body, &p); err != nil {
			return fmt.Errorf("mailchimp: decode chimp-chatter: %w", err)
		}
		if len(p.ChimpChatter) == 0 {
			break
		}
		stopBackfill := false
		for i := range p.ChimpChatter {
			ts := parseMailchimpTime(p.ChimpChatter[i].UpdateTime)
			if !since.IsZero() && !ts.IsZero() && !ts.After(since) {
				stopBackfill = true
				continue
			}
			collected = append(collected, p.ChimpChatter[i])
		}
		if stopBackfill || len(p.ChimpChatter) < mailchimpAuditPageSize {
			break
		}
		offset += len(p.ChimpChatter)
	}

	if len(collected) == 0 {
		return nil
	}

	// Walk the collected entries oldest-first so the handler sees a
	// chronologically ascending batch and `nextSince` covers every
	// event we just yielded.
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := len(collected) - 1; i >= 0; i-- {
		entry := mapMailchimpChatter(&collected[i])
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

type mailchimpChatterPage struct {
	ChimpChatter []mailchimpChatter `json:"chimp_chatter"`
	TotalItems   int                `json:"total_items"`
}

type mailchimpChatter struct {
	Type       string `json:"type"`
	Title      string `json:"title"`
	Message    string `json:"message"`
	UpdateTime string `json:"update_time"`
	URL        string `json:"url"`
	CampaignID string `json:"campaign_id,omitempty"`
	ListID     string `json:"list_id,omitempty"`
}

func mapMailchimpChatter(e *mailchimpChatter) *access.AuditLogEntry {
	if e == nil {
		return nil
	}
	ts := parseMailchimpTime(e.UpdateTime)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	target := strings.TrimSpace(e.CampaignID)
	if target == "" {
		target = strings.TrimSpace(e.ListID)
	}
	// Mailchimp doesn't return a stable event ID on the chatter feed;
	// derive a deterministic ID from (type, update_time, target) plus a
	// content hash of the full entry. Hashing title/message/url too keeps
	// two entries that share the same type, timestamp, and target (e.g.
	// multiple chatter items for one campaign in the same second) from
	// collapsing onto the same EventID and being deduplicated downstream.
	sum := sha256.Sum256(raw)
	id := fmt.Sprintf("%s/%s/%s/%s", strings.TrimSpace(e.Type), e.UpdateTime, target, hex.EncodeToString(sum[:8]))
	return &access.AuditLogEntry{
		EventID:          id,
		EventType:        strings.TrimSpace(e.Type),
		Action:           strings.TrimSpace(e.Type),
		Timestamp:        ts,
		TargetExternalID: target,
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseMailchimpTime(s string) time.Time {
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
	// Mailchimp sometimes returns "YYYY-MM-DD HH:MM:SS" without
	// timezone.
	if ts, err := time.Parse("2006-01-02 15:04:05", s); err == nil {
		return ts.UTC()
	}
	return time.Time{}
}

func readMailchimpBody(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, errors.New("mailchimp: empty response")
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

var _ access.AccessAuditor = (*MailchimpAccessConnector)(nil)
