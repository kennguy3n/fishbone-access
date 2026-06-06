// Tests for the shared retry HTTP client. The tests exercise the
// real retry loop against an httptest.Server so the request /
// response cycle is end-to-end, not mocked at the transport layer.
// The only stub is RetryClient.Sleep — production sleep is replaced
// with a "record the requested duration and return immediately"
// recorder so the suite runs in milliseconds instead of seconds.
package httputil

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// recordedSleeper is the test-side replacement for time.Sleep. It
// captures every requested wait duration so the test can assert the
// retry schedule honoured Retry-After / exponential backoff without
// the test taking the actual wall time.
type recordedSleeper struct {
	waits []time.Duration
	// when nonzero, the sleeper returns ctx.Err() immediately
	// to simulate a cancelled retry loop.
	errAfter int
	calls    atomic.Int32
}

func (s *recordedSleeper) sleep(ctx context.Context, d time.Duration) error {
	n := int(s.calls.Add(1))
	s.waits = append(s.waits, d)
	if s.errAfter > 0 && n >= s.errAfter {
		return context.Canceled
	}
	return nil
}

func newClientUnderTest(t *testing.T) (*RetryClient, *recordedSleeper) {
	t.Helper()
	sleeper := &recordedSleeper{}
	c := &RetryClient{
		HTTP:           &http.Client{Timeout: 5 * time.Second},
		MaxAttempts:    3,
		InitialBackoff: 10 * time.Millisecond,
		MaxBackoff:     10 * time.Second,
		Sleep:          sleeper.sleep,
		Now:            time.Now,
	}
	return c, sleeper
}

// TestRetryClient_HappyPath2xx asserts that a single 200 response is
// returned without any retry sleep and the body reaches the caller
// intact.
func TestRetryClient_HappyPath2xx(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer srv.Close()

	c, sleeper := newClientUnderTest(t)
	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := c.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != `{"ok":true}` {
		t.Fatalf("unexpected body: %s", body)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("expected 1 upstream call, got %d", got)
	}
	if len(sleeper.waits) != 0 {
		t.Fatalf("expected no sleeps, got %v", sleeper.waits)
	}
}

// TestRetryClient_Retries503ThenSucceeds verifies the canonical
// transient-failure path: two 503s followed by a 200. The retry
// loop must surface the eventual 200 and the sleeper must be called
// exactly twice (between the three attempts).
func TestRetryClient_Retries503ThenSucceeds(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `ok`)
	}))
	defer srv.Close()

	c, sleeper := newClientUnderTest(t)
	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := c.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Fatalf("expected body=ok, got %q", body)
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("expected 3 upstream calls, got %d", got)
	}
	if len(sleeper.waits) != 2 {
		t.Fatalf("expected 2 sleeps, got %d (%v)", len(sleeper.waits), sleeper.waits)
	}
}

// TestRetryClient_HonoursRetryAfterSeconds ensures the
// delta-seconds form of Retry-After is parsed and used in place
// of the exponential backoff.
func TestRetryClient_HonoursRetryAfterSeconds(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n == 1 {
			w.Header().Set("Retry-After", "2")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, sleeper := newClientUnderTest(t)
	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := c.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if len(sleeper.waits) != 1 {
		t.Fatalf("expected 1 sleep, got %d", len(sleeper.waits))
	}
	if got := sleeper.waits[0]; got != 2*time.Second {
		t.Fatalf("expected 2s sleep from Retry-After, got %v", got)
	}
}

// TestRetryClient_HonoursRetryAfterHTTPDate confirms the HTTP-date
// form of Retry-After (RFC 7231 §7.1.3) is respected.
func TestRetryClient_HonoursRetryAfterHTTPDate(t *testing.T) {
	var calls atomic.Int32
	// Choose a date 3 seconds in the "future" relative to the
	// fixed Now we install on the client. The retry schedule
	// should sleep for that delta.
	fixedNow := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	retryAt := fixedNow.Add(3 * time.Second).UTC().Format(http.TimeFormat)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n == 1 {
			w.Header().Set("Retry-After", retryAt)
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, sleeper := newClientUnderTest(t)
	c.Now = func() time.Time { return fixedNow }
	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := c.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if len(sleeper.waits) != 1 {
		t.Fatalf("expected 1 sleep, got %d", len(sleeper.waits))
	}
	// HTTP-date precision is whole seconds.
	if got := sleeper.waits[0]; got != 3*time.Second {
		t.Fatalf("expected 3s sleep from Retry-After HTTP-date, got %v", got)
	}
}

// TestRetryClient_MaxAttemptsExceeded confirms the loop returns the
// MaxAttemptsError sentinel after the configured budget is spent,
// and that the error carries the last status + body excerpt so the
// caller can surface a useful audit log entry.
func TestRetryClient_MaxAttemptsExceeded(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, "upstream barfed")
	}))
	defer srv.Close()

	c, sleeper := newClientUnderTest(t)
	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	_, err = c.Do(context.Background(), req)
	if err == nil {
		t.Fatalf("expected error after MaxAttempts, got nil")
	}
	if !errors.Is(err, ErrMaxAttemptsExceeded) {
		t.Fatalf("expected ErrMaxAttemptsExceeded, got %T %v", err, err)
	}
	me := &MaxAttemptsError{}
	if !errors.As(err, &me) {
		t.Fatalf("expected MaxAttemptsError, got %T", err)
	}
	if me.Attempts != 3 {
		t.Fatalf("expected Attempts=3, got %d", me.Attempts)
	}
	if me.LastStatus != http.StatusBadGateway {
		t.Fatalf("expected LastStatus=502, got %d", me.LastStatus)
	}
	if !strings.Contains(me.LastBody, "upstream barfed") {
		t.Fatalf("expected LastBody to contain upstream excerpt, got %q", me.LastBody)
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("expected 3 upstream calls, got %d", got)
	}
	// MaxAttempts=3 → 2 inter-attempt sleeps.
	if len(sleeper.waits) != 2 {
		t.Fatalf("expected 2 sleeps, got %d", len(sleeper.waits))
	}
}

// TestRetryClient_DoesNotRetryNonRetryable4xx ensures that 401 / 403
// / 404 return immediately without consuming retry budget. Retrying
// these would only amplify the upstream's quota usage for no benefit.
func TestRetryClient_DoesNotRetryNonRetryable4xx(t *testing.T) {
	for _, status := range []int{
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusConflict,
	} {
		var calls atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			w.WriteHeader(status)
		}))

		c, sleeper := newClientUnderTest(t)
		req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
		resp, err := c.Do(context.Background(), req)
		if err != nil {
			t.Fatalf("status=%d: unexpected error: %v", status, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != status {
			t.Fatalf("status=%d: got %d", status, resp.StatusCode)
		}
		if got := calls.Load(); got != 1 {
			t.Fatalf("status=%d: expected 1 call, got %d", status, got)
		}
		if len(sleeper.waits) != 0 {
			t.Fatalf("status=%d: expected no sleeps, got %d", status, len(sleeper.waits))
		}
		srv.Close()
	}
}

// TestRetryClient_ContextCancellationStopsRetryLoop ensures a
// cancelled context unblocks the inter-attempt sleep immediately
// and surfaces context.Canceled to the caller.
func TestRetryClient_ContextCancellationStopsRetryLoop(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c, sleeper := newClientUnderTest(t)
	sleeper.errAfter = 1
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := c.Do(ctx, req)
	if err == nil {
		t.Fatalf("expected error after cancellation, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

// TestRetryClient_RequestBodyRewinds confirms the retry loop
// successfully replays the request body on a retry. Without the
// GetBody plumbing, the second attempt would send an empty body
// and the upstream would reject it as malformed.
func TestRetryClient_RequestBodyRewinds(t *testing.T) {
	var calls atomic.Int32
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		buf, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(buf))
		if n < 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, _ := newClientUnderTest(t)
	payload := `{"key":"value"}`
	req, err := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader(payload))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := c.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if len(bodies) != 2 {
		t.Fatalf("expected 2 attempts, got %d", len(bodies))
	}
	for i, b := range bodies {
		if b != payload {
			t.Fatalf("attempt %d: body=%q want=%q", i+1, b, payload)
		}
	}
}

// TestRetryClient_RequestBodyWithoutGetBodyRejected confirms the
// client refuses to retry when the caller passed a non-replayable
// body. Silently sending an empty body on retry would be a worse
// failure mode than refusing up-front.
func TestRetryClient_RequestBodyWithoutGetBodyRejected(t *testing.T) {
	c, _ := newClientUnderTest(t)
	// http.NewRequest sets GetBody automatically for *bytes.Reader,
	// *bytes.Buffer, and *strings.Reader. To trigger the guard we
	// build the request with an io.Reader that lacks the special
	// case and clear GetBody.
	body := &nonRewindableReader{r: bytes.NewBufferString("payload")}
	req, _ := http.NewRequest(http.MethodPost, "http://invalid.test", body)
	req.GetBody = nil
	_, err := c.Do(context.Background(), req)
	if err == nil {
		t.Fatalf("expected error for non-rewindable body, got nil")
	}
	if !strings.Contains(err.Error(), "GetBody") {
		t.Fatalf("expected error to mention GetBody, got %v", err)
	}
}

type nonRewindableReader struct{ r io.Reader }

func (n *nonRewindableReader) Read(p []byte) (int, error) { return n.r.Read(p) }

// TestParseRetryAfter exercises the header parser independently of
// the retry loop so each parsing branch is verified in isolation.
func TestParseRetryAfter(t *testing.T) {
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := func() time.Time { return fixed }

	cases := []struct {
		name   string
		header string
		want   time.Duration
	}{
		{"empty", "", 0},
		{"zero seconds", "0", 0},
		{"negative seconds", "-5", 0},
		{"five seconds", "5", 5 * time.Second},
		{"http date future", fixed.Add(7 * time.Second).Format(http.TimeFormat), 7 * time.Second},
		{"http date past", fixed.Add(-1 * time.Hour).Format(http.TimeFormat), 0},
		{"malformed", "tomorrow", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseRetryAfter(tc.header, now)
			// HTTP-date precision is whole seconds; tolerate
			// 1-second jitter on the future case.
			if got != tc.want && (tc.want <= 0 || (got-tc.want).Abs() > time.Second) {
				t.Fatalf("got=%v want=%v", got, tc.want)
			}
		})
	}
}

// TestExpBackoffWithJitter ensures the returned duration falls
// inside the documented [base/2, 3*base/2) window. Run the
// generator enough times that a single mis-sized window would be
// caught.
func TestExpBackoffWithJitter(t *testing.T) {
	base := 100 * time.Millisecond
	for attempt := 1; attempt <= 4; attempt++ {
		want := base << (attempt - 1)
		lo := want / 2
		hi := want + want/2
		for i := 0; i < 200; i++ {
			got := expBackoffWithJitter(base, attempt)
			if got < lo || got > hi {
				t.Fatalf("attempt=%d got=%v want in [%v, %v]", attempt, got, lo, hi)
			}
		}
	}
}

// TestRetryClient_MaxBackoffCap confirms a Retry-After value larger
// than MaxBackoff is clamped — otherwise an upstream could pin a
// worker indefinitely by returning "Retry-After: 3600".
func TestRetryClient_MaxBackoffCap(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n == 1 {
			w.Header().Set("Retry-After", "3600")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, sleeper := newClientUnderTest(t)
	c.MaxBackoff = 50 * time.Millisecond
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	resp, err := c.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = resp.Body.Close()
	if len(sleeper.waits) != 1 {
		t.Fatalf("expected 1 sleep, got %d", len(sleeper.waits))
	}
	if got := sleeper.waits[0]; got > 50*time.Millisecond {
		t.Fatalf("expected Retry-After clamped to MaxBackoff=50ms, got %v", got)
	}
}
