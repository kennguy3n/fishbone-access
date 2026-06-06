// Package bamboohr — IdentityDeltaSyncer via /v1/employees/changed.
//
// BambooHR exposes a documented change-feed endpoint that returns
// the set of employee records whose state has changed since a
// supplied timestamp:
//
//   GET /api/gateway.php/{subdomain}/v1/employees/changed
//       ?since={RFC3339}&type={inserted|updated|deleted}
//
// The `type` parameter is optional; when absent BambooHR returns
// all changes. We omit it so a single API call surfaces the full
// lifecycle (inserts, updates, and deletes).
//
// Response shape (an object keyed by employee id, NOT an array):
//
//   {
//     "employees": {
//       "12345": {
//         "id": "12345",
//         "action": "Updated",        // "Inserted" | "Updated" | "Deleted"
//         "lastChanged": "2025-05-10T12:00:00+00:00"
//       }
//     }
//   }
//
// Cursor semantics (per optional_interfaces.go contract):
//   - The returned cursor is `max(lastChanged) + 1ns` across every
//     observed change in this page. This eliminates the
//     wall-clock race where a change lands between the API filter
//     evaluation and the response capture: by keying off the data
//     BambooHR actually returned, we are guaranteed that any change
//     not seen in this response had `lastChanged > cursorMax`, and
//     will be picked up on the next sync. If the page is empty we
//     fall back to `time.Now().UTC()` so the cursor still advances.
//   - Malformed cursor string -> ErrDeltaTokenExpired
//   - 400 (malformed `since`)  -> ErrDeltaTokenExpired (drop cursor,
//     orchestrator falls back to full SyncIdentities)
//   - 403 (capability gated by plan tier) -> ErrDeltaTokenExpired
//     (full SyncIdentities uses /v1/employees/directory which is
//     not tier-gated; the orchestrator can recover)
//   - 401 (auth failure) -> hard error so the orchestrator surfaces
//     credential rot instead of masking it as a delta-expiry signal
//     that would still fail on the full-sync path with 401.
//   - Any other non-2xx -> hard error (retryable).
//
// Identity enrichment: the change feed only emits {id, action,
// lastChanged}. Emitting Identity records with only ExternalID
// would leave downstream consumers without DisplayName / Email /
// Status, defeating the purpose of incremental sync (since they'd
// then have to issue a separate lookup per record themselves). We
// enrich inserted/updated rows in-line via
// `GET /v1/employees/{id}?fields=...` using a small canonical set
// of fields, matching the shape produced by SyncIdentities's full
// /v1/employees/directory walk. A 404 from the enrichment lookup
// (employee just deleted in the window between change-feed emit
// and enrichment) is mapped to a tombstone so the orchestrator
// converges on the right state; any other enrichment error fails
// the sync so the cursor is not advanced past unverified data.
package bamboohr

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

// delta-sync employee enrichment fields. Kept in one place so the
// emitted Identity shape stays in lockstep with SyncIdentities (see
// connector.go) — adding a column there should be reflected here.
const bambooDeltaEnrichmentFields = "id,displayName,firstName,lastName,workEmail,jobTitle,status"

// SyncIdentitiesDelta walks /v1/employees/changed from the supplied
// cursor, emitting one Identity per inserted/updated change and one
// tombstone per deleted change. The returned cursor is derived from
// max(lastChanged) across the response so it does not depend on the
// caller's wall clock.
func (c *BambooHRAccessConnector) SyncIdentitiesDelta(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	deltaLink string,
	handler func(batch []*access.Identity, removedExternalIDs []string, nextLink string) error,
) (string, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return "", err
	}
	// Parse the cursor through the same helper audit.go uses so
	// both consumers of /v1/employees/changed are guaranteed to
	// accept the same set of timestamp shapes. A zero return from
	// parseBambooTime on a non-empty input signals a malformed
	// cursor — surface ErrDeltaTokenExpired so the orchestrator
	// drops the cursor and falls back to full SyncIdentities.
	var since time.Time
	if s := strings.TrimSpace(deltaLink); s != "" {
		parsed := parseBambooTime(s)
		if parsed.IsZero() {
			return "", access.ErrDeltaTokenExpired
		}
		since = parsed.UTC()
	}
	if since.IsZero() {
		since = time.Now().UTC().Add(-1 * time.Hour)
	}

	q := url.Values{}
	// Use RFC3339Nano on the wire so the cursor advancement
	// (cursorMax + 1ns) actually round-trips end-to-end. RFC3339
	// truncates the nanosecond and effectively re-sends the same
	// max(lastChanged) on every invocation — re-fetching and
	// re-processing the boundary event each cycle. BambooHR
	// accepts ISO 8601 with sub-second precision per their docs;
	// the format is structurally a strict superset of RFC3339 so
	// tenants without nanosecond data are unaffected.
	q.Set("since", since.Format(time.RFC3339Nano))
	target := c.baseURL(cfg) + "/v1/employees/changed?" + q.Encode()
	req, err := c.newRequest(ctx, secrets, http.MethodGet, target)
	if err != nil {
		return "", err
	}
	body, err := c.do(req)
	if err != nil {
		// Inspect the typed status error so we don't have to
		// string-match on Error() — see httpStatusError in
		// connector.go.
		var hse *httpStatusError
		if errors.As(err, &hse) {
			switch hse.StatusCode {
			case http.StatusBadRequest:
				// Malformed `since` -> orchestrator drops
				// cursor and falls back to full sync.
				return "", access.ErrDeltaTokenExpired
			case http.StatusForbidden:
				// Plan-tier gating: the change feed is
				// disabled for this tenant. Full sync uses a
				// different endpoint and is typically not
				// gated, so signal token-expired to trigger
				// the fallback.
				return "", access.ErrDeltaTokenExpired
			case http.StatusUnauthorized:
				// Credentials are bad. Full sync will also
				// 401, so masking as ErrDeltaTokenExpired
				// would just produce an immediate second
				// failure with a less informative error.
				// Surface the auth failure as-is.
				return "", fmt.Errorf("bamboohr: delta sync auth failure (rotate api_key): %w", err)
			}
		}
		return "", err
	}

	var page bambooChangedPage
	if err := json.Unmarshal(body, &page); err != nil {
		return "", fmt.Errorf("bamboohr: decode delta page: %w", err)
	}

	// Pre-scan the page to (a) compute max(lastChanged) for the
	// cursor and (b) split inserted/updated from deleted before
	// issuing any enrichment lookups. Deletes do not require an
	// enrichment fetch (the employee is gone).
	var cursorMax time.Time
	type pendingInsert struct {
		EmployeeID  string
		LastChanged time.Time
	}
	pending := make([]pendingInsert, 0, len(page.Employees))
	removed := make([]string, 0)
	for id, change := range page.Employees {
		externalID := strings.TrimSpace(id)
		if externalID == "" {
			continue
		}
		ts := parseBambooTime(change.LastChanged)
		if !ts.IsZero() && ts.After(cursorMax) {
			cursorMax = ts
		}
		action := strings.TrimSpace(strings.ToLower(change.Action))
		switch action {
		case "inserted", "updated":
			pending = append(pending, pendingInsert{
				EmployeeID:  externalID,
				LastChanged: ts,
			})
		case "deleted":
			removed = append(removed, externalID)
		default:
			// Unknown action — skip silently; the full sync
			// will reconcile if BambooHR ships a new
			// lifecycle action.
		}
	}

	// Enrich inserted/updated rows with the same field set
	// SyncIdentities emits, so callers see equivalent records
	// across the full-sync and delta-sync code paths.
	batch := make([]*access.Identity, 0, len(pending))
	for _, p := range pending {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		emp, ok, err := c.getEmployeeForDelta(ctx, cfg, secrets, p.EmployeeID)
		if err != nil {
			return "", err
		}
		if !ok {
			// Employee was deleted between change-feed emit
			// and enrichment lookup. Convert the
			// inserted/updated signal into a tombstone so
			// downstream state converges.
			removed = append(removed, p.EmployeeID)
			continue
		}
		batch = append(batch, identityFromBambooEmployee(emp))
	}

	if err := handler(batch, removed, ""); err != nil {
		return "", err
	}

	// Advance the cursor past max(lastChanged) so the next
	// invocation does not re-process this exact event. BambooHR
	// accepts nanosecond precision via RFC3339Nano. If the page
	// was empty we fall back to wall-clock now() so the cursor
	// still advances and we don't repeat the lookback window.
	var next time.Time
	if cursorMax.IsZero() {
		next = time.Now().UTC()
	} else {
		next = cursorMax.UTC().Add(1 * time.Nanosecond)
	}
	return next.Format(time.RFC3339Nano), nil
}

// getEmployeeForDelta fetches the canonical employee shape from the
// /v1/employees/{id} endpoint and returns (emp, true, nil) on
// success, (nil, false, nil) on 404 (the employee was deleted
// between change-feed emit and lookup), or (nil, false, err) on any
// other failure. Kept package-private to delta_sync because no
// other caller currently needs single-employee lookups; if a
// second caller appears, promote it onto the connector.
func (c *BambooHRAccessConnector) getEmployeeForDelta(
	ctx context.Context,
	cfg Config,
	secrets Secrets,
	employeeID string,
) (*bambooEmployee, bool, error) {
	target := c.baseURL(cfg) + "/v1/employees/" + url.PathEscape(employeeID) +
		"?fields=" + url.QueryEscape(bambooDeltaEnrichmentFields)
	req, err := c.newRequest(ctx, secrets, http.MethodGet, target)
	if err != nil {
		return nil, false, err
	}
	body, err := c.do(req)
	if err != nil {
		var hse *httpStatusError
		if errors.As(err, &hse) && hse.StatusCode == http.StatusNotFound {
			return nil, false, nil
		}
		return nil, false, err
	}
	var emp bambooEmployee
	if err := json.Unmarshal(body, &emp); err != nil {
		return nil, false, fmt.Errorf("bamboohr: decode employee %s: %w", employeeID, err)
	}
	// BambooHR sometimes omits `id` in single-employee responses
	// when the caller requested `id` explicitly; backfill from the
	// path so the emitted Identity has a stable ExternalID.
	if strings.TrimSpace(emp.ID) == "" {
		emp.ID = employeeID
	}
	return &emp, true, nil
}

// InitialDeltaCursor returns an RFC3339Nano "now" timestamp the
// orchestrator persists as the baseline cursor after a successful
// full sync, so the very next run enters the delta path against
// /v1/employees/changed. parseBambooTime accepts RFC3339Nano (and
// plain RFC3339) so the round-trip is symmetric. No network call.
func (c *BambooHRAccessConnector) InitialDeltaCursor(
	_ context.Context,
	_ map[string]interface{},
	_ map[string]interface{},
) (string, error) {
	return time.Now().UTC().Format(time.RFC3339Nano), nil
}

var _ access.IdentityDeltaSyncer = (*BambooHRAccessConnector)(nil)
