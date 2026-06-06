package discord

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const (
	discordAuditPageSize = 100
	// discordAuditMaxPages bounds a single sweep to ~20k events. The
	// `since` cursor narrows the window between runs so this only
	// kicks in on the very first sync of a long-dormant guild.
	discordAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Discord guild audit-log entries into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /api/v10/guilds/{guild_id}/audit-logs?limit=100&before={entry_id}
//
// Discord paginates audit logs reverse-chronologically by snowflake id
// (snowflakes are monotonically increasing timestamps so `before=`
// walks history). The timestamp is extracted from the snowflake high
// bits — Discord's epoch is 2015-01-01T00:00:00Z + 22-bit shift.
//
// The AccessAuditor contract requires that any `nextSince` passed to
// the handler cover only events already yielded to the handler — the
// worker persists this cursor even on partial failure (see
// internal/workers/handlers/access_audit.go). To honour the contract
// under reverse-chronological pagination we collect the full sweep
// first, then reverse the entire collection into chronological
// (oldest-first) order, then call the handler exactly once with the
// maximum timestamp as `nextSince`. If any page fails mid-sweep (or
// the handler call itself fails) the cursor is never advanced past
// un-yielded events, so a retry replays the same window rather than
// silently skipping older entries below the persisted cursor.
//
// Permissions outside the `VIEW_AUDIT_LOG` bot scope surface as
// 401/403 → soft skip via access.ErrAuditNotAvailable.
func (c *DiscordAccessConnector) FetchAccessAuditLogs(
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
	base := fmt.Sprintf("%s/api/v10/guilds/%s/audit-logs",
		c.baseURL(), url.PathEscape(strings.TrimSpace(cfg.GuildID)))

	var collected []discordAuditEntry
	before := ""
	stopBackfill := false
	for page := 0; page < discordAuditMaxPages && !stopBackfill; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("limit", strconv.Itoa(discordAuditPageSize))
		if before != "" {
			q.Set("before", before)
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("discord: audit log: %w", err)
		}
		body, readErr := readDiscordBody(resp)
		if readErr != nil {
			return readErr
		}
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound {
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("discord: audit log: status %d: %s", resp.StatusCode, string(body))
		}
		var pageData discordAuditLogPage
		if err := json.Unmarshal(body, &pageData); err != nil {
			return fmt.Errorf("discord: decode audit log: %w", err)
		}
		if len(pageData.AuditLogEntries) == 0 {
			break
		}
		oldestOnPage := ""
		for i := range pageData.AuditLogEntries {
			id := pageData.AuditLogEntries[i].ID
			ts := discordSnowflakeTime(id)
			if !since.IsZero() && !ts.After(since) {
				// Walked past the persisted cursor; drop this and
				// every older entry on subsequent pages.
				stopBackfill = true
				continue
			}
			collected = append(collected, pageData.AuditLogEntries[i])
			oldestOnPage = id
		}
		if oldestOnPage == "" || len(pageData.AuditLogEntries) < discordAuditPageSize {
			break
		}
		before = oldestOnPage
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
		entry := mapDiscordAuditEntry(&collected[i])
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

type discordAuditLogPage struct {
	AuditLogEntries []discordAuditEntry `json:"audit_log_entries"`
}

type discordAuditEntry struct {
	ID         string                   `json:"id"`
	UserID     string                   `json:"user_id"`
	TargetID   string                   `json:"target_id"`
	ActionType int                      `json:"action_type"`
	Reason     string                   `json:"reason,omitempty"`
	Changes    []map[string]interface{} `json:"changes,omitempty"`
}

// discordEpochMs is Discord's snowflake epoch (2015-01-01T00:00:00Z).
const discordEpochMs int64 = 1420070400000

func discordSnowflakeTime(id string) time.Time {
	id = strings.TrimSpace(id)
	if id == "" {
		return time.Time{}
	}
	v, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return time.Time{}
	}
	ms := int64(v>>22) + discordEpochMs
	return time.UnixMilli(ms).UTC()
}

func mapDiscordAuditEntry(e *discordAuditEntry) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := discordSnowflakeTime(e.ID)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:          e.ID,
		EventType:        discordActionName(e.ActionType),
		Action:           discordActionName(e.ActionType),
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.UserID),
		TargetExternalID: strings.TrimSpace(e.TargetID),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

// discordActionName returns the Discord audit-log action name for the
// supplied numeric action type. Codes follow the upstream enum at
// https://discord.com/developers/docs/resources/audit-log#audit-log-entry-object-audit-log-events.
func discordActionName(code int) string {
	switch code {
	case 1:
		return "guild_update"
	case 10, 11, 12, 13, 14, 15:
		return "channel_change"
	case 20, 21, 22, 23, 24, 25, 26, 27, 28:
		return "member_change"
	case 30, 31, 32:
		return "role_change"
	case 40, 41, 42:
		return "invite_change"
	case 50, 51, 52:
		return "webhook_change"
	case 60, 61, 62:
		return "emoji_change"
	case 72, 73, 74, 75:
		return "message_change"
	default:
		return fmt.Sprintf("action_%d", code)
	}
}

func readDiscordBody(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, errors.New("discord: empty response")
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

var _ access.AccessAuditor = (*DiscordAccessConnector)(nil)
