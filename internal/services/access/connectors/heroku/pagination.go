package heroku

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// herokuMaxPages bounds Range-based pagination so a misbehaving upstream
// (e.g. a Next-Range header that never terminates) cannot loop forever.
// Heroku's default page size is 200, so 10_000 pages covers multi-million-row
// enterprise audit windows and team rosters while still failing closed on a
// runaway cursor.
const herokuMaxPages = 10000

// auditTrailAccept is the versioned media type that unlocks the Heroku
// Enterprise audit-trail representation of the events endpoint.
const auditTrailAccept = "application/vnd.heroku+json; version=3.audit-trail"

// readBodyFull reads an HTTP response body in full.
//
// Heroku audit windows and large team rosters routinely exceed the fixed
// 1 MiB cap that the connector previously imposed. Truncating the body at a
// byte boundary silently dropped audit events — a data-integrity defect — and
// also yielded malformed JSON that failed to decode. Bounding is instead the
// responsibility of Range pagination (see doPaged), which keeps each page
// small while readBodyFull guarantees no individual page is partially
// consumed.
func readBodyFull(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, errors.New("heroku: empty response")
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// doPaged issues GET requests for path, transparently following Heroku's
// Range/Next-Range pagination, and invokes onPage with the fully-read body of
// each successful page.
//
// Heroku signals that more rows are available by returning a non-empty
// `Next-Range` response header (alongside HTTP 206 Partial Content); the value
// must be echoed back verbatim in the `Range` header of the next request.
// Absence of the header means the listing is complete. Reading only the first
// response — as the connector did before — therefore truncated every result
// set that spanned more than one page, dropping audit events and team members.
//
// The first page's HTTP status is returned to the caller so it can apply its
// own soft-skip / error mapping (e.g. the audit pipeline maps 401/403/404/422
// to access.ErrAuditNotAvailable) before consuming the accumulated pages. On a
// non-2xx status onPage is never invoked and the returned error carries the
// status and body. Each page body is streamed to onPage rather than
// concatenated so callers decode incrementally instead of materialising the
// whole dataset as one buffer.
func (c *HerokuAccessConnector) doPaged(
	ctx context.Context,
	secrets Secrets,
	accept string,
	path string,
	onPage func(body []byte) error,
) (status int, err error) {
	rangeHeader := ""
	seen := make(map[string]struct{})
	for page := 0; page < herokuMaxPages; page++ {
		if cerr := ctx.Err(); cerr != nil {
			return status, cerr
		}
		req, rerr := c.newRequest(ctx, secrets, http.MethodGet, path)
		if rerr != nil {
			return status, rerr
		}
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		if rangeHeader != "" {
			req.Header.Set("Range", rangeHeader)
		}
		resp, derr := c.client().Do(req)
		if derr != nil {
			return status, fmt.Errorf("heroku: %s %s: %w", req.Method, req.URL.Path, derr)
		}
		body, readErr := readBodyFull(resp)
		if page == 0 {
			status = resp.StatusCode
		}
		next := strings.TrimSpace(resp.Header.Get("Next-Range"))
		if readErr != nil {
			return status, readErr
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return resp.StatusCode, fmt.Errorf("heroku: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
		}
		if perr := onPage(body); perr != nil {
			return status, perr
		}
		if next == "" {
			return status, nil
		}
		if _, dup := seen[next]; dup {
			// A repeated Next-Range means the upstream is no longer advancing
			// the cursor; stop rather than spin against the page cap.
			return status, nil
		}
		seen[next] = struct{}{}
		rangeHeader = next
	}
	return status, fmt.Errorf("heroku: %s: exceeded %d pages", path, herokuMaxPages)
}
