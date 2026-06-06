package bamboohr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// FetchAccessAuditLogs streams BambooHR employee-change events into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /v1/employees/changed?since={RFC3339}&type=all
//
// BambooHR returns the full delta in one response (no cursor), so we
// emit a single page. Each `employees` map entry surfaces as one
// AuditLogEntry whose action mirrors the change type ("Inserted",
// "Updated", "Deleted") and whose timestamp is the `lastChanged`
// value. Tenants whose plan doesn't expose the changed endpoint return
// 403/404 which collapses to access.ErrAuditNotAvailable.
func (c *BambooHRAccessConnector) FetchAccessAuditLogs(
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
	if since.IsZero() {
		// BambooHR's /employees/changed requires a `since` parameter.
		// Default to 7 days ago to seed the first backfill — the worker
		// will advance the cursor monotonically thereafter.
		since = time.Now().Add(-7 * 24 * time.Hour)
	}

	q := url.Values{}
	q.Set("since", since.UTC().Format(time.RFC3339))
	q.Set("type", "all")
	fullURL := c.baseURL(cfg) + "/v1/employees/changed?" + q.Encode()

	req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
	if err != nil {
		return err
	}
	// Use the connector's shared do() helper so we inherit the
	// typed httpStatusError and can branch on StatusCode via
	// errors.As — matches the delta_sync.go path and keeps both
	// audit + delta consumers of /v1/employees/changed on the same
	// error abstraction. Previously this hand-rolled c.client().Do
	// + readBambooResponse, which dropped the typed error and made
	// the audit code the only odd one out in the package.
	body, err := c.do(req)
	if err != nil {
		var hse *httpStatusError
		if errors.As(err, &hse) {
			switch hse.StatusCode {
			case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
				// Tier-gated / endpoint disabled / creds rotated.
				// Collapsing to ErrAuditNotAvailable lets the
				// audit pipeline fall back to its no-op path
				// rather than hard-failing the worker.
				return access.ErrAuditNotAvailable
			}
		}
		return fmt.Errorf("bamboohr: audit changed: %w", err)
	}

	var page bambooChangedPage
	if err := json.Unmarshal(body, &page); err != nil {
		return fmt.Errorf("bamboohr: decode changed: %w", err)
	}

	type kv struct {
		EmployeeID string
		Change     bambooChangedEmployee
		changedAt  time.Time
	}
	pairs := make([]kv, 0, len(page.Employees))
	for id, change := range page.Employees {
		change.EmployeeID = id
		// Parse lastChanged once here rather than inside the sort
		// comparator, which would re-parse the same strings O(n log n)
		// times for large deltas.
		pairs = append(pairs, kv{EmployeeID: id, Change: change, changedAt: parseBambooTime(change.LastChanged)})
	}
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].changedAt.Before(pairs[j].changedAt)
	})

	batch := make([]*access.AuditLogEntry, 0, len(pairs))
	batchMax := since
	for i := range pairs {
		entry := mapBambooChangedEvent(&pairs[i].Change)
		if entry == nil {
			continue
		}
		if entry.Timestamp.After(batchMax) {
			batchMax = entry.Timestamp
		}
		batch = append(batch, entry)
	}
	if len(batch) == 0 {
		// Nothing mapped (empty delta, or every event had an
		// unparseable lastChanged and was dropped). Skip the
		// handler entirely — there's no progress to record and
		// batchMax == since, so calling it would be a no-op. This
		// mirrors the basecamp/bigcommerce audit paths.
		return nil
	}
	return handler(batch, batchMax, access.DefaultAuditPartition)
}

type bambooChangedPage struct {
	Employees map[string]bambooChangedEmployee `json:"employees"`
}

type bambooChangedEmployee struct {
	// EmployeeID is populated from the JSON object key in
	// FetchAccessAuditLogs (change.EmployeeID = id), not from the
	// value body — BambooHR's /employees/changed response keys each
	// change by employee ID rather than carrying it as a field.
	// Hence json:"-": it must never be (re)decoded from the value.
	EmployeeID  string `json:"-"`
	Action      string `json:"action"`
	LastChanged string `json:"lastChanged"`
}

func mapBambooChangedEvent(c *bambooChangedEmployee) *access.AuditLogEntry {
	if c == nil || strings.TrimSpace(c.EmployeeID) == "" {
		return nil
	}
	ts := parseBambooTime(c.LastChanged)
	if ts.IsZero() {
		// Drop changes with an unparseable lastChanged: a zero
		// timestamp would not advance the batchMax cursor and would be
		// re-fetched on every sync. Matches the other audit mappers.
		return nil
	}
	action := strings.ToLower(strings.TrimSpace(c.Action))
	if action == "" {
		action = "updated"
	}
	return &access.AuditLogEntry{
		EventID:          fmt.Sprintf("%s:%s", c.EmployeeID, c.LastChanged),
		EventType:        "employee." + action,
		Action:           action,
		Timestamp:        ts,
		TargetExternalID: c.EmployeeID,
		TargetType:       "employee",
		Outcome:          "success",
	}
}

// parseBambooTime parses BambooHR's lastChanged timestamps, trying
// RFC3339Nano first (with fractional seconds) and falling back to
// plain RFC3339. The API has been observed to emit both shapes.
func parseBambooTime(s string) time.Time {
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

var _ access.AccessAuditor = (*BambooHRAccessConnector)(nil)
