package access

import (
	"bytes"
	"net/http"
	"strings"
)

// Helpers in this file codify the connector-side mapping rules from
// docs/architecture.md §2, so each AccessConnector implementation can use
// the same predicate names instead of re-rolling the status / error
// classification inline. Adopting these helpers in new connectors is
// strongly preferred; existing connectors may migrate opportunistically.
//
// Contract recap (from docs/architecture.md §2):
//
//   - ProvisionAccess MUST be idempotent on
//     (grant.UserExternalID, grant.ResourceExternalID).
//     409 / "already exists" / "duplicate" / "already a member" responses
//     from the provider MUST be treated as success.
//   - RevokeAccess MUST be idempotent on the same key.
//     404 / "not found" / "not a member" responses MUST be treated as
//     success.
//   - Any other 4xx is a permanent failure (no retry).
//   - Any 5xx is a transient failure (retry with backoff in the worker).
//
// The helpers below are pure functions over (statusCode, responseBody)
// so they can be called from any connector's status switch without
// pulling provider-specific deps into the access package.

// IsIdempotentProvisionStatus returns true if the supplied HTTP status
// code and response body indicate that the grant the connector tried to
// create already exists on the provider — in which case ProvisionAccess
// should return nil (idempotent success) instead of an error.
//
// Recognised signals:
//
//   - HTTP 409 Conflict (RFC 7231 standard "already exists" code).
//   - HTTP 400/422 paired with body text matching common provider
//     phrasings: "already", "duplicate", "exists", "subscribed",
//     "is a member".
//
// Connectors with provider-specific signals (e.g. Smartsheet error
// code 1020, Monday GraphQL error messages) should add their own
// checks on top of this helper rather than replacing it.
func IsIdempotentProvisionStatus(statusCode int, responseBody []byte) bool {
	if statusCode == http.StatusConflict {
		return true
	}
	if statusCode == http.StatusBadRequest || statusCode == http.StatusUnprocessableEntity {
		return bodyContainsAny(responseBody, idempotentProvisionPhrases)
	}
	return false
}

// IsIdempotentRevokeStatus returns true if the supplied HTTP status
// code and response body indicate that the grant the connector tried to
// remove was not present on the provider — in which case RevokeAccess
// should return nil (idempotent success) instead of an error.
//
// Recognised signals:
//
//   - HTTP 404 Not Found (the canonical "no such resource" response).
//   - HTTP 400/410/422 paired with body text matching: "not found",
//     "not a member", "not subscribed", "does not exist", "no such".
//
// Connectors whose provider returns a non-standard 200 envelope with
// an embedded "not found" error (e.g. some GraphQL endpoints) should
// keep their existing inline checks; this helper covers REST-style
// status-driven mapping only.
func IsIdempotentRevokeStatus(statusCode int, responseBody []byte) bool {
	if statusCode == http.StatusNotFound {
		return true
	}
	if statusCode == http.StatusBadRequest ||
		statusCode == http.StatusGone ||
		statusCode == http.StatusUnprocessableEntity {
		return bodyContainsAny(responseBody, idempotentRevokePhrases)
	}
	return false
}

// IsTransientStatus returns true for HTTP status codes the worker
// should retry with exponential backoff (per docs/architecture.md §2: 5xx and a
// small set of 429-style throttling responses).
func IsTransientStatus(statusCode int) bool {
	if statusCode >= 500 && statusCode <= 599 {
		return true
	}
	return statusCode == http.StatusTooManyRequests
}

var (
	idempotentProvisionPhrases = [][]byte{
		[]byte("already"),
		[]byte("duplicate"),
		[]byte("exists"),
		[]byte("subscribed"),
		[]byte("is a member"),
	}
	idempotentRevokePhrases = [][]byte{
		[]byte("not found"),
		[]byte("not a member"),
		[]byte("not subscribed"),
		[]byte("does not exist"),
		[]byte("no such"),
	}
)

// bodyContainsAny reports whether body (case-folded) contains any of
// the supplied byte phrases. Phrases must already be lowercase.
func bodyContainsAny(body []byte, phrases [][]byte) bool {
	if len(body) == 0 {
		return false
	}
	lower := bytes.ToLower(body)
	for _, p := range phrases {
		if bytes.Contains(lower, p) {
			return true
		}
	}
	return false
}

// IsIdempotentMessage returns true if the supplied free-form error
// message (e.g. a GraphQL error string) contains any of the phrases
// the connector layer maps to idempotent success. Use this when the
// provider returns 200 with an embedded error envelope rather than a
// status code (e.g. Monday GraphQL "already subscribed").
//
// Pass the set of phrases that count as idempotent for the given
// operation, in lowercase. The helper case-folds the input before
// comparing.
func IsIdempotentMessage(message string, phrases []string) bool {
	if message == "" || len(phrases) == 0 {
		return false
	}
	lower := strings.ToLower(message)
	for _, p := range phrases {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}
