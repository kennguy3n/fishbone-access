package splunk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

type noNetworkRoundTripper struct{}

func (noNetworkRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return nil, errors.New("network call attempted")
}

func validConfig() map[string]interface{} {
	return map[string]interface{}{"base_url": "https://acme.splunkcloud.com:8089"}
}
func validSecrets() map[string]interface{} {
	return map[string]interface{}{"token": "spkAAAA1234bbbbCCCC"}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_RejectsMissing(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), map[string]interface{}{}, validSecrets()); err == nil {
		t.Error("missing base_url")
	}
	if err := c.Validate(context.Background(), validConfig(), map[string]interface{}{}); err == nil {
		t.Error("missing token")
	}
}

func TestValidate_PureLocal(t *testing.T) {
	prev := http.DefaultTransport
	http.DefaultTransport = noNetworkRoundTripper{}
	t.Cleanup(func() { http.DefaultTransport = prev })
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestRegistryIntegration(t *testing.T) {
	if got, _ := access.GetAccessConnector(ProviderName); got == nil {
		t.Fatal("not registered")
	}
}

func TestSync_PaginatesUsers(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("expected Bearer auth")
		}
		if r.URL.Path != "/services/authentication/users" {
			t.Errorf("path = %q", r.URL.Path)
		}
		offset := r.URL.Query().Get("offset")
		body := map[string]interface{}{"entry": []map[string]interface{}{}, "paging": map[string]interface{}{"total": pageSize + 1}}
		if calls == 1 && offset != "0" {
			t.Errorf("offset = %q", offset)
		}
		if calls == 2 && offset != fmt.Sprintf("%d", pageSize) {
			t.Errorf("offset = %q", offset)
		}
		if calls == 1 {
			res := make([]map[string]interface{}, 0, pageSize)
			for i := 0; i < pageSize; i++ {
				res = append(res, map[string]interface{}{"name": fmt.Sprintf("user%d", i), "content": map[string]interface{}{"email": fmt.Sprintf("u%d@x.com", i), "realname": fmt.Sprintf("User %d", i), "locked-out": false}})
			}
			body["entry"] = res
		} else {
			body["entry"] = []map[string]interface{}{{"name": "lockout", "content": map[string]interface{}{"email": "lock@x.com", "realname": "Locked", "locked-out": true}}}
		}
		b, _ := json.Marshal(body)
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var got []*access.Identity
	err := c.SyncIdentities(context.Background(), validConfig(), validSecrets(), "", func(b []*access.Identity, _ string) error {
		got = append(got, b...)
		return nil
	})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(got) != pageSize+1 {
		t.Fatalf("len = %d", len(got))
	}
	if calls != 2 {
		t.Fatalf("calls = %d", calls)
	}
	if got[len(got)-1].Status != "locked" {
		t.Errorf("last status = %q", got[len(got)-1].Status)
	}
}

func TestConnect_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.Connect(context.Background(), validConfig(), validSecrets()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("Connect err = %v; want 401", err)
	}
}

func TestGetCredentialsMetadata_RedactsToken(t *testing.T) {
	md, err := New().GetCredentialsMetadata(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	short, _ := md["token_short"].(string)
	if short == "" || strings.Contains(short, "AAAA1234") {
		t.Errorf("token_short = %q", short)
	}
}

// TestSplunk_SyncIdentities_MaxPagesGuard verifies the defense-in-depth
// cap on pagination loops in SyncIdentities. A misconfigured / malicious
// upstream that returns a perpetually inflated paging.total combined
// with a non-empty page on every request would otherwise loop forever
// (the secondary next-empty guard never trips). The cap surfaces a
// clear error so the worker fails fast instead of hanging — same
// pattern the bot flagged + we applied in groups.go.
func TestSplunk_SyncIdentities_MaxPagesGuard(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount++
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"entry": []map[string]interface{}{
				{"name": "u", "content": map[string]interface{}{"email": "u@x.com", "realname": "U", "locked-out": false}},
			},
			"paging": map[string]interface{}{"total": 1 << 30, "perPage": 100, "offset": 0},
		})
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.SyncIdentities(context.Background(), validConfig(), validSecrets(), "", func(_ []*access.Identity, _ string) error { return nil })
	if err == nil {
		t.Fatalf("err = nil; want pagination cap error")
	}
	if !strings.Contains(err.Error(), "pagination exceeded") {
		t.Errorf("err = %q; want 'pagination exceeded' surface", err.Error())
	}
	if callCount != splunkIdentitiesMaxPages {
		t.Errorf("callCount = %d; want %d", callCount, splunkIdentitiesMaxPages)
	}
}

// TestSplunk_FormatErrorBody_TruncatesAtRuneBoundary verifies that
// the JSON-body truncation in formatErrorBody walks back to a UTF-8
// rune start so the returned surface is valid UTF-8 even when the
// 4 KB cap falls inside a multi-byte rune. Bot flagged this as an
// edge case; downstream consumers (Datadog log pipelines, OTLP
// exporters, JSON-serialised audit records) reject invalid UTF-8.
func TestSplunk_FormatErrorBody_TruncatesAtRuneBoundary(t *testing.T) {
	// Build a JSON body whose byte at index splunkErrorBodyJSONCap
	// falls in the middle of a 3-byte rune (e.g. ELLIPSIS U+2026
	// = 0xE2 0x80 0xA6). Pad with ASCII '{' + spaces so the kind
	// detector classifies as JSON, then insert ellipses around
	// the boundary.
	const ellipsis = "\u2026"
	prefix := "{" + strings.Repeat(" ", splunkErrorBodyJSONCap-2)
	body := []byte(prefix + ellipsis + strings.Repeat(ellipsis, 100))
	if !utf8.Valid(body) {
		t.Fatalf("test fixture is not valid UTF-8")
	}
	if utf8.RuneStart(body[splunkErrorBodyJSONCap]) {
		t.Fatalf("test fixture does not exercise the boundary case: byte at cap is a rune start")
	}
	out := formatErrorBody(body)
	if !utf8.ValidString(out) {
		t.Errorf("formatErrorBody output is not valid UTF-8: %q", out)
	}
	if !strings.HasSuffix(out, "…(truncated)") {
		t.Errorf("formatErrorBody output missing truncation marker: %q", out[len(out)-32:])
	}
	// The visible payload must end on a rune boundary — drop the
	// truncation marker and verify the remainder is valid.
	visible := strings.TrimSuffix(out, " …(truncated)")
	if !utf8.ValidString(visible) {
		t.Errorf("visible prefix is not valid UTF-8: ends with bytes %x", []byte(visible)[len(visible)-4:])
	}
	// And the visible length must be strictly less than the cap
	// (we walked back at least one byte to reach the rune start).
	if len(visible) > splunkErrorBodyJSONCap {
		t.Errorf("visible len = %d; want <= cap %d", len(visible), splunkErrorBodyJSONCap)
	}
}

// TestSplunk_TruncateAtRune_NoPanicAtBoundary exercises the function's
// own precondition guard. The earlier implementation clamped max but
// then indexed body[end] where end==len(body), causing a panic when
// max == len(body). The current call site happens to never trip this,
// but a future caller relaxing the precondition would crash. This
// test pins the contract.
func TestSplunk_TruncateAtRune_NoPanicAtBoundary(t *testing.T) {
	body := []byte("hello\u2026world") // mix of ASCII + multi-byte rune
	// max == len(body): the entire body must round-trip.
	if got := truncateAtRune(body, len(body)); got != string(body) {
		t.Errorf("truncateAtRune(body, len(body)) = %q; want %q", got, string(body))
	}
	// max > len(body): same — must not index past end.
	if got := truncateAtRune(body, len(body)+10); got != string(body) {
		t.Errorf("truncateAtRune(body, len(body)+10) = %q; want %q", got, string(body))
	}
	// max == 0: empty prefix.
	if got := truncateAtRune(body, 0); got != "" {
		t.Errorf("truncateAtRune(body, 0) = %q; want empty", got)
	}
	// Empty body / max anything: empty prefix.
	if got := truncateAtRune(nil, 8); got != "" {
		t.Errorf("truncateAtRune(nil, 8) = %q; want empty", got)
	}
	if got := truncateAtRune([]byte{}, 0); got != "" {
		t.Errorf("truncateAtRune(empty, 0) = %q; want empty", got)
	}
}
