// Package httputil contains the shared HTTP client used by every
// access connector that talks to an upstream SaaS API. The package
// centralises four concerns that every connector needs but that
// were previously re-implemented (or omitted) per connector:
//
//   - Retry policy for transient failures: 429 (rate limit), 502,
//     503, 504 — these are upstream-side conditions a polite
//     client SHOULD retry rather than surfacing as a hard
//     ProvisionTaskFailed. RFC 9110 §15.6.4 (503) and §15.5.10
//     (429) explicitly invite retries; the others are CDN /
//     gateway hiccups that resolve quickly.
//   - Honouring Retry-After: when the server tells us "wait 5
//     seconds" we wait that long, not the exponential-backoff
//     default. Connectors that ignored Retry-After in the past
//     would burn quota on a 429-loop until the rate window reset.
//   - Bounded backoff with jitter: the default schedule is
//     200ms, 400ms, 800ms with ±50% jitter so a stampede on the
//     same upstream API (e.g. all Okta connectors retrying at
//     once after a 503) doesn't synchronise.
//   - Context-cancellation respect: every sleep between retries
//     is interruptible. A connector whose worker context is
//     cancelled does NOT keep retrying for the remainder of
//     MaxAttempts × MaxBackoff.
//
// The client deliberately does NOT retry 4xx codes other than 429:
// those are bugs in the request (bad credentials, wrong tenant ID,
// missing scope) and retrying just amplifies the failure. The
// caller is responsible for body / response decoding; this package
// only owns transport-level retry semantics.
package httputil

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// DefaultMaxAttempts is the cap on retries. The first attempt
// is attempt #1, so MaxAttempts=3 yields up to two retries
// after the initial call. Higher values risk amplifying
// upstream incidents; lower values turn transient CDN blips
// into ProvisionTaskFailed.
const DefaultMaxAttempts = 3

// DefaultInitialBackoff is the base for the exponential-backoff
// schedule. 200ms is short enough that a 503 from a healthy CDN
// (e.g. a deploy-window blip) resolves within one retry, and
// long enough to avoid hammering a recovering upstream.
const DefaultInitialBackoff = 200 * time.Millisecond

// DefaultMaxBackoff caps each individual sleep. Without this a
// 503 followed by a 60-second Retry-After could pin a worker
// goroutine for a minute even though the caller's context will
// be cancelled long before.
const DefaultMaxBackoff = 30 * time.Second

// DefaultRequestTimeout is the per-attempt deadline. The connector
// sees a wrapping context.Context; THIS timeout protects the case
// where the upstream accepts the connection but never responds.
const DefaultRequestTimeout = 30 * time.Second

// RetryClient wraps *http.Client with the retry policy described in
// the package comment. The zero value is NOT useful — construct via
// NewRetryClient. The wrapped client is exported so the caller can
// install custom Transport (e.g. for mTLS to a private VPC connector)
// without re-implementing the retry loop.
type RetryClient struct {
	HTTP           *http.Client
	MaxAttempts    int
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	// Sleep is overridable in tests so the retry loop is
	// instantly verifiable without burning real wall time.
	// Production callers leave it nil to fall through to
	// the package-default time.Sleep.
	Sleep func(context.Context, time.Duration) error
	// Now is overridable in tests for Retry-After date parsing.
	Now func() time.Time
}

// NewRetryClient constructs a RetryClient with safe production
// defaults. timeout controls the per-attempt deadline on the
// underlying *http.Client; pass 0 to use DefaultRequestTimeout.
//
// The returned *http.Client honours the standard Go connection
// pool; callers that need a custom transport should construct the
// RetryClient struct literal directly.
func NewRetryClient(timeout time.Duration) *RetryClient {
	if timeout <= 0 {
		timeout = DefaultRequestTimeout
	}
	return &RetryClient{
		HTTP:           &http.Client{Timeout: timeout},
		MaxAttempts:    DefaultMaxAttempts,
		InitialBackoff: DefaultInitialBackoff,
		MaxBackoff:     DefaultMaxBackoff,
	}
}

// ErrMaxAttemptsExceeded is returned when the policy exhausted its
// retry budget and the last attempt still returned a retryable
// status. The caller can inspect Last to surface the final HTTP
// response details to the operator (status code + body excerpt
// in the connector's error envelope).
var ErrMaxAttemptsExceeded = errors.New("httputil: retry budget exhausted")

// MaxAttemptsError carries the final response so callers that
// want to surface "upstream returned 503 after 3 attempts" in
// their audit log can do so without re-issuing the request.
type MaxAttemptsError struct {
	Attempts   int
	LastStatus int
	LastBody   string
}

func (e *MaxAttemptsError) Error() string {
	return fmt.Sprintf("httputil: %d attempts exhausted (last status=%d body=%q)", e.Attempts, e.LastStatus, e.LastBody)
}

func (e *MaxAttemptsError) Is(target error) bool { return target == ErrMaxAttemptsExceeded }

// Do executes req with the configured retry policy. The body MUST
// be re-readable across attempts; callers passing a non-nil body
// should construct the request with http.NewRequestWithContext +
// a bytes.Reader / bytes.Buffer, OR call SetBodyGetter on req via
// req.GetBody so the retry loop can rewind. When req.Body is
// non-nil and not rewindable, only the first attempt sees the
// body and any retry sends an empty body — Do enforces this with
// an error rather than silently corrupting the request.
func (r *RetryClient) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	if r == nil {
		return nil, errors.New("httputil: RetryClient is nil")
	}
	if r.HTTP == nil {
		return nil, errors.New("httputil: RetryClient.HTTP is nil")
	}
	if req == nil {
		return nil, errors.New("httputil: request is nil")
	}
	if req.Body != nil && req.GetBody == nil {
		return nil, errors.New("httputil: request body present without GetBody — set req.GetBody so retries can re-read the body, or use http.NewRequest with a *bytes.Reader / *bytes.Buffer / *strings.Reader")
	}
	maxAttempts := r.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = DefaultMaxAttempts
	}
	initialBackoff := r.InitialBackoff
	if initialBackoff <= 0 {
		initialBackoff = DefaultInitialBackoff
	}
	maxBackoff := r.MaxBackoff
	if maxBackoff <= 0 {
		maxBackoff = DefaultMaxBackoff
	}
	sleep := r.Sleep
	if sleep == nil {
		sleep = defaultSleep
	}
	now := r.Now
	if now == nil {
		now = time.Now
	}

	// The request the *http.Client receives carries the caller's
	// ctx, so the underlying RoundTripper cancellation matches
	// the retry-loop cancellation exactly.
	if ctx == nil {
		ctx = context.Background()
	}
	req = req.WithContext(ctx)

	var (
		lastStatus int
		lastBody   string
	)
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		// Clone a fresh *Request for every attempt. Go's http.Client.Do
		// documents "the caller should not mutate or reuse the request
		// after calling Do"; handing each attempt its own clone keeps us
		// strictly within that contract (and safe if a future stdlib
		// revision mutates the request during redirect handling). The
		// body, which Do consumes, is re-derived from GetBody so the
		// clone always carries a rewound reader.
		attemptReq := req.Clone(ctx)
		if attemptReq.GetBody != nil {
			body, err := attemptReq.GetBody()
			if err != nil {
				return nil, fmt.Errorf("httputil: GetBody on attempt %d: %w", attempt, err)
			}
			attemptReq.Body = body
		}

		resp, err := r.HTTP.Do(attemptReq)
		if err != nil {
			// Network-level errors are returned directly. The
			// caller decides whether to surface "context
			// deadline exceeded" vs "connection refused"
			// differently; retrying a refused connection here
			// would risk a hot loop against an upstream that
			// has been removed from DNS.
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, fmt.Errorf("httputil: attempt %d: %w", attempt, err)
		}
		if !shouldRetry(resp.StatusCode) {
			return resp, nil
		}

		// Retryable: capture the response details for the
		// final error envelope, then close the body so we
		// don't leak the connection during backoff. Close
		// error here is unactionable — we are already in
		// the retry/backoff path and the next attempt opens
		// a fresh connection.
		lastStatus = resp.StatusCode
		lastBody = readBodyExcerpt(resp)
		_ = resp.Body.Close()

		if attempt >= maxAttempts {
			break
		}
		wait := parseRetryAfter(resp.Header.Get("Retry-After"), now)
		if wait <= 0 {
			wait = expBackoffWithJitter(initialBackoff, attempt)
		}
		if wait > maxBackoff {
			wait = maxBackoff
		}
		if err := sleep(ctx, wait); err != nil {
			return nil, err
		}
	}

	return nil, &MaxAttemptsError{Attempts: maxAttempts, LastStatus: lastStatus, LastBody: lastBody}
}

// shouldRetry reports whether the supplied HTTP status warrants a
// retry. The set is deliberately small: 429 (rate-limited), 502
// (bad gateway), 503 (service unavailable), 504 (gateway timeout).
// 408 is not in the list — most upstreams that legitimately
// return 408 are misbehaving and retrying the same request just
// wastes the connector's budget.
func shouldRetry(status int) bool {
	switch status {
	case http.StatusTooManyRequests,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

// parseRetryAfter parses an HTTP Retry-After header per RFC 9110
// §10.2.3 — either a delta-seconds integer ("5") or an HTTP-date
// ("Wed, 21 Oct 2026 07:28:00 GMT"). Returns 0 when the header is
// missing / malformed so the caller falls back to the exponential
// schedule instead of waiting forever.
func parseRetryAfter(h string, now func() time.Time) time.Duration {
	h = strings.TrimSpace(h)
	if h == "" {
		return 0
	}
	if secs, err := strconv.Atoi(h); err == nil {
		if secs <= 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(h); err == nil {
		d := t.Sub(now())
		if d > 0 {
			return d
		}
	}
	return 0
}

// expBackoffWithJitter returns initial * 2^(attempt-1) bounded by
// ±50% uniform jitter. attempt is 1-indexed (first retry = 1, etc).
// Uses crypto/rand so a deterministic test seed isn't required —
// production callers care about decorrelating concurrent retries,
// not reproducibility.
//
// Overflow safety: the shift `initial << (attempt-1)` is int64
// arithmetic and would wrap on a pathological caller that sets
// MaxAttempts very large (e.g. attempt-1 ≥ 63). Two layers defend:
//
//   - The `base <= 0` branch below catches a sign-flip (the most
//     common overflow shape) and falls back to initial.
//   - For a moderate-but-positive overflow that wraps to a large
//     positive duration (e.g. years), the caller in Do() applies
//     `if wait > maxBackoff { wait = maxBackoff }` BEFORE sleeping,
//     so the actual sleep is always ≤ MaxBackoff.
//
// The defaults (InitialBackoff=200ms, MaxAttempts=3) yield a max
// shift of 2, so this is purely a defense-in-depth path —
// production never reaches the overflow region.
func expBackoffWithJitter(initial time.Duration, attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	base := initial << (attempt - 1)
	if base <= 0 {
		// Overflow safeguard: see the package-level comment on
		// shouldRetry + the MaxBackoff clamp in Do(). A sign-flip
		// here returns initial so the next attempt sleeps for the
		// configured base instead of a near-instant retry.
		return initial
	}
	// Jitter range: [base/2, 3*base/2). crypto/rand never
	// errors on a small modulus so we treat the failure path
	// as "no jitter".
	span := big.NewInt(int64(base))
	jit, err := rand.Int(rand.Reader, span)
	if err != nil {
		return base
	}
	return base/2 + time.Duration(jit.Int64())
}

// defaultSleep is the production sleep function. It returns
// ctx.Err() as soon as the context is cancelled so a stuck
// retry loop unblocks the worker goroutine.
func defaultSleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// readBodyExcerpt drains up to bodyExcerptLimit bytes from the
// response body so the final error message can include a snippet
// of what the upstream returned (most APIs include a useful
// reason phrase even on 5xx, e.g. Okta's "E0000047 API call
// exceeded rate limit").
const bodyExcerptLimit = 512

func readBodyExcerpt(resp *http.Response) string {
	if resp == nil || resp.Body == nil {
		return ""
	}
	buf := make([]byte, bodyExcerptLimit)
	n, _ := io.ReadFull(resp.Body, buf)
	return strings.TrimSpace(string(buf[:n]))
}
