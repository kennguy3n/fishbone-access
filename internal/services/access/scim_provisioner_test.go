package access

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// scimMockServer wires an httptest.Server with a hand-rolled
// router that records inbound requests and returns programmable
// responses. The struct exposes the captured request fields so
// tests assert against them after the call.
type scimMockServer struct {
	t        *testing.T
	server   *httptest.Server
	handlers map[string]scimMockResponse
	captured []scimCapturedRequest
}

type scimMockResponse struct {
	status int
	body   string
}

type scimCapturedRequest struct {
	Method     string
	Path       string
	AuthHeader string
	Body       string
}

func newSCIMMockServer(t *testing.T) *scimMockServer {
	t.Helper()
	m := &scimMockServer{
		t:        t,
		handlers: map[string]scimMockResponse{},
	}
	m.server = httptest.NewServer(http.HandlerFunc(m.handle))
	t.Cleanup(m.server.Close)
	return m
}

func (m *scimMockServer) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	m.captured = append(m.captured, scimCapturedRequest{
		Method:     r.Method,
		Path:       r.URL.Path,
		AuthHeader: r.Header.Get("Authorization"),
		Body:       string(body),
	})
	key := r.Method + " " + r.URL.Path
	resp, ok := m.handlers[key]
	if !ok {
		// Default to a 2xx empty body so happy-path setup is one
		// line — tests register explicit handlers when they care
		// about the response shape.
		resp = scimMockResponse{status: http.StatusCreated, body: `{"id":"upstream-id"}`}
	}
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(resp.status)
	_, _ = w.Write([]byte(resp.body))
}

func (m *scimMockServer) on(method, path string, status int, body string) {
	m.handlers[method+" "+path] = scimMockResponse{status: status, body: body}
}

func (m *scimMockServer) lastRequest() scimCapturedRequest {
	if len(m.captured) == 0 {
		m.t.Fatalf("no captured requests")
	}
	return m.captured[len(m.captured)-1]
}

// TestSCIMClient_PushSCIMUser_HappyPath asserts a 201 response
// with a JSON-shaped {"id": ...} body returns no error.
func TestSCIMClient_PushSCIMUser_HappyPath(t *testing.T) {
	t.Parallel()
	ms := newSCIMMockServer(t)
	ms.on(http.MethodPost, "/scim/v2/Users", http.StatusCreated, `{"id":"upstream-001"}`)

	client := NewSCIMClient().WithHTTPClient(ms.server.Client())
	cfg := map[string]interface{}{scimProvisionerConfigKey: ms.server.URL + "/scim/v2"}
	secrets := map[string]interface{}{scimProvisionerSecretKey: "Bearer alice"}

	err := client.PushSCIMUser(context.Background(), cfg, secrets, SCIMUser{
		ExternalID: "ext-001",
		UserName:   "alice@example.com",
		Email:      "alice@example.com",
		Active:     true,
	})
	if err != nil {
		t.Fatalf("PushSCIMUser: %v", err)
	}
	got := ms.lastRequest()
	if got.AuthHeader != "Bearer alice" {
		t.Errorf("AuthHeader = %q; want %q", got.AuthHeader, "Bearer alice")
	}
	if !strings.Contains(got.Body, `"externalId":"ext-001"`) {
		t.Errorf("body missing externalId: %s", got.Body)
	}
	if !strings.Contains(got.Body, `"userName":"alice@example.com"`) {
		t.Errorf("body missing userName: %s", got.Body)
	}
}

// TestSCIMClient_PushSCIMUser_Conflict asserts a 409 surfaces as
// ErrSCIMRemoteConflict. JML callers can errors.Is against the
// sentinel and treat it as an idempotent success.
func TestSCIMClient_PushSCIMUser_Conflict(t *testing.T) {
	t.Parallel()
	ms := newSCIMMockServer(t)
	ms.on(http.MethodPost, "/scim/v2/Users", http.StatusConflict, `{"detail":"already exists"}`)

	client := NewSCIMClient().WithHTTPClient(ms.server.Client())
	cfg := map[string]interface{}{scimProvisionerConfigKey: ms.server.URL + "/scim/v2"}
	secrets := map[string]interface{}{scimProvisionerSecretKey: "Bearer alice"}

	err := client.PushSCIMUser(context.Background(), cfg, secrets, SCIMUser{
		ExternalID: "ext-002",
		UserName:   "bob@example.com",
	})
	if !errors.Is(err, ErrSCIMRemoteConflict) {
		t.Errorf("err = %v; want errors.Is(err, ErrSCIMRemoteConflict)", err)
	}
}

// TestSCIMClient_PushSCIMGroup_HappyPath asserts the group push
// hits /Groups with the expected schema URN and member list.
func TestSCIMClient_PushSCIMGroup_HappyPath(t *testing.T) {
	t.Parallel()
	ms := newSCIMMockServer(t)
	ms.on(http.MethodPost, "/scim/v2/Groups", http.StatusCreated, `{"id":"grp-001"}`)

	client := NewSCIMClient().WithHTTPClient(ms.server.Client())
	cfg := map[string]interface{}{scimProvisionerConfigKey: ms.server.URL + "/scim/v2"}
	secrets := map[string]interface{}{}

	err := client.PushSCIMGroup(context.Background(), cfg, secrets, SCIMGroup{
		ExternalID:  "ext-grp-001",
		DisplayName: "platform-eng",
		MemberIDs:   []string{"u1", "u2"},
	})
	if err != nil {
		t.Fatalf("PushSCIMGroup: %v", err)
	}
	got := ms.lastRequest()
	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(got.Body), &payload); err != nil {
		t.Fatalf("decode group payload: %v\nbody: %s", err, got.Body)
	}
	if payload["displayName"] != "platform-eng" {
		t.Errorf("displayName = %v; want platform-eng", payload["displayName"])
	}
	members, ok := payload["members"].([]interface{})
	if !ok || len(members) != 2 {
		t.Errorf("members = %v; want 2 entries", payload["members"])
	}
}

// TestSCIMClient_DeleteSCIMResource_HappyPath asserts a 204
// response is treated as success and routed to /Users/:id.
func TestSCIMClient_DeleteSCIMResource_HappyPath(t *testing.T) {
	t.Parallel()
	ms := newSCIMMockServer(t)
	ms.on(http.MethodDelete, "/scim/v2/Users/upstream-001", http.StatusNoContent, "")

	client := NewSCIMClient().WithHTTPClient(ms.server.Client())
	cfg := map[string]interface{}{scimProvisionerConfigKey: ms.server.URL + "/scim/v2"}
	secrets := map[string]interface{}{}

	if err := client.DeleteSCIMResource(context.Background(), cfg, secrets, "Users", "upstream-001"); err != nil {
		t.Fatalf("DeleteSCIMResource: %v", err)
	}
	if got, want := ms.lastRequest().Path, "/scim/v2/Users/upstream-001"; got != want {
		t.Errorf("Path = %q; want %q", got, want)
	}
}

// TestSCIMClient_DeleteSCIMResource_NotFoundIsIdempotent asserts
// that a 404 response is treated as a successful idempotent
// delete (no error returned).
func TestSCIMClient_DeleteSCIMResource_NotFoundIsIdempotent(t *testing.T) {
	t.Parallel()
	ms := newSCIMMockServer(t)
	ms.on(http.MethodDelete, "/scim/v2/Users/missing", http.StatusNotFound, `{"detail":"not found"}`)

	client := NewSCIMClient().WithHTTPClient(ms.server.Client())
	cfg := map[string]interface{}{scimProvisionerConfigKey: ms.server.URL + "/scim/v2"}
	secrets := map[string]interface{}{}

	err := client.DeleteSCIMResource(context.Background(), cfg, secrets, "Users", "missing")
	if err != nil {
		t.Errorf("DeleteSCIMResource(missing): %v; want nil (idempotent delete)", err)
	}
}

// TestSCIMClient_PushSCIMUser_Unauthorized asserts a 401 surfaces
// as ErrSCIMRemoteUnauthorized.
func TestSCIMClient_PushSCIMUser_Unauthorized(t *testing.T) {
	t.Parallel()
	ms := newSCIMMockServer(t)
	ms.on(http.MethodPost, "/scim/v2/Users", http.StatusUnauthorized, `{"detail":"bad token"}`)

	client := NewSCIMClient().WithHTTPClient(ms.server.Client())
	cfg := map[string]interface{}{scimProvisionerConfigKey: ms.server.URL + "/scim/v2"}
	secrets := map[string]interface{}{scimProvisionerSecretKey: "Bearer bogus"}

	err := client.PushSCIMUser(context.Background(), cfg, secrets, SCIMUser{
		UserName: "x@y.com",
	})
	if !errors.Is(err, ErrSCIMRemoteUnauthorized) {
		t.Errorf("err = %v; want errors.Is(err, ErrSCIMRemoteUnauthorized)", err)
	}
}

// TestSCIMClient_PushSCIMUser_ServerError asserts 5xx surfaces as
// ErrSCIMRemoteServer.
func TestSCIMClient_PushSCIMUser_ServerError(t *testing.T) {
	t.Parallel()
	ms := newSCIMMockServer(t)
	ms.on(http.MethodPost, "/scim/v2/Users", http.StatusInternalServerError, `{"detail":"boom"}`)

	client := NewSCIMClient().WithHTTPClient(ms.server.Client())
	cfg := map[string]interface{}{scimProvisionerConfigKey: ms.server.URL + "/scim/v2"}
	secrets := map[string]interface{}{}

	err := client.PushSCIMUser(context.Background(), cfg, secrets, SCIMUser{UserName: "x"})
	if !errors.Is(err, ErrSCIMRemoteServer) {
		t.Errorf("err = %v; want errors.Is(err, ErrSCIMRemoteServer)", err)
	}
}

// TestSCIMClient_ConfigValidation asserts the (config, secrets)
// shape errors before any HTTP call.
func TestSCIMClient_ConfigValidation(t *testing.T) {
	t.Parallel()
	client := NewSCIMClient()

	cases := []struct {
		name    string
		config  map[string]interface{}
		secrets map[string]interface{}
		op      func(*SCIMClient, map[string]interface{}, map[string]interface{}) error
	}{
		{
			"missing base_url",
			map[string]interface{}{},
			map[string]interface{}{},
			func(c *SCIMClient, cfg, sec map[string]interface{}) error {
				return c.PushSCIMUser(context.Background(), cfg, sec, SCIMUser{UserName: "x"})
			},
		},
		{
			"unparseable timeout",
			map[string]interface{}{
				scimProvisionerConfigKey:  "http://example",
				scimProvisionerTimeoutKey: "not-a-duration",
			},
			map[string]interface{}{},
			func(c *SCIMClient, cfg, sec map[string]interface{}) error {
				return c.PushSCIMUser(context.Background(), cfg, sec, SCIMUser{UserName: "x"})
			},
		},
		{
			"unknown resource type",
			map[string]interface{}{scimProvisionerConfigKey: "http://example"},
			map[string]interface{}{},
			func(c *SCIMClient, cfg, sec map[string]interface{}) error {
				return c.DeleteSCIMResource(context.Background(), cfg, sec, "Widgets", "x")
			},
		},
		{
			"empty external id on delete",
			map[string]interface{}{scimProvisionerConfigKey: "http://example"},
			map[string]interface{}{},
			func(c *SCIMClient, cfg, sec map[string]interface{}) error {
				return c.DeleteSCIMResource(context.Background(), cfg, sec, "Users", "")
			},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.op(client, tc.config, tc.secrets)
			if !errors.Is(err, ErrSCIMConfigInvalid) {
				t.Errorf("err = %v; want errors.Is(err, ErrSCIMConfigInvalid)", err)
			}
		})
	}
}

// TestSCIMClient_Truncate_HandlesUTF8Boundary asserts truncate
// counts runes, not bytes — a multi-byte UTF-8 sequence in the
// upstream payload must never be sliced mid-rune (or the embedded
// excerpt would be invalid UTF-8 and crash JSON encoders downstream).
//
// Regression: the previous implementation used s[:n] which is a byte
// slice, so a body of all 3-byte runes (e.g. "你好世界...") would be
// cut between bytes of one rune and the appended ellipsis would
// produce invalid UTF-8.
func TestSCIMClient_Truncate_HandlesUTF8Boundary(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		n    int
		want string
	}{
		{"ascii within bound", "hello", 10, "hello"},
		{"ascii at bound", "hello", 5, "hello"},
		{"ascii over bound", "helloworld", 5, "hello\u2026"},
		{"multi-byte within bound", "你好", 5, "你好"},
		{"multi-byte at bound", "你好", 2, "你好"},
		{"multi-byte over bound", "你好世界", 2, "你好\u2026"},
		{"mixed over bound", "hi你好世", 3, "hi你\u2026"},
		{"zero n", "hello", 0, ""},
		{"negative n", "hello", -1, ""},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := truncate(tc.in, tc.n)
			if got != tc.want {
				t.Errorf("truncate(%q, %d) = %q; want %q", tc.in, tc.n, got, tc.want)
			}
			// Always returns valid UTF-8 — that's the actual
			// invariant the bug broke.
			for _, r := range got {
				if r == '\uFFFD' {
					t.Errorf("truncate produced replacement rune in %q", got)
				}
			}
		})
	}
}

// TestSCIMClient_TimeoutOverride asserts that the scim_timeout
// config key is respected (the request fails with deadline
// exceeded against a slow server).
func TestSCIMClient_TimeoutOverride(t *testing.T) {
	t.Parallel()
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(150 * time.Millisecond)
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(slow.Close)

	client := NewSCIMClient().WithHTTPClient(slow.Client())
	cfg := map[string]interface{}{
		scimProvisionerConfigKey:  slow.URL,
		scimProvisionerTimeoutKey: "10ms",
	}
	err := client.PushSCIMUser(context.Background(), cfg, map[string]interface{}{}, SCIMUser{UserName: "x"})
	if err == nil {
		t.Fatalf("PushSCIMUser: want timeout error, got nil")
	}
}

// TestJoinSCIMURL_PreservesPercentEncodedBase pins the GitLab
// nested-group case: base URL contains `%2F` and the joiner must
// not silently re-encode it to `%252F`.
func TestJoinSCIMURL_PreservesPercentEncodedBase(t *testing.T) {
	got, err := joinSCIMURL("https://gitlab.example.com/api/scim/v2/groups/acme%2Fdevops", "Users")
	if err != nil {
		t.Fatalf("joinSCIMURL: %v", err)
	}
	want := "https://gitlab.example.com/api/scim/v2/groups/acme%2Fdevops/Users"
	if got != want {
		t.Errorf("joinSCIMURL with %%2F-encoded base = %q\nwant %q", got, want)
	}
}

// TestJoinSCIMURL_PreservesPreEscapedPathSegment pins the
// DeleteSCIMResource case: path argument arrives pre-escaped
// (e.g. "Users/user%40example.com" from url.PathEscape). The
// joiner must transmit that encoding verbatim — NOT
// double-encode it into "user%2540example.com".
func TestJoinSCIMURL_PreservesPreEscapedPathSegment(t *testing.T) {
	got, err := joinSCIMURL("https://example.com/scim/v2", "Users/user%40example.com")
	if err != nil {
		t.Fatalf("joinSCIMURL: %v", err)
	}
	want := "https://example.com/scim/v2/Users/user%40example.com"
	if got != want {
		t.Errorf("joinSCIMURL with pre-escaped path segment = %q\nwant %q (NOT double-encoded)", got, want)
	}
}

// TestJoinSCIMURL_PlainBaseAndPathHasNoTrailingRawPath pins that
// the happy-path output (no escaping anywhere) is still the
// canonical short form, with u.RawPath cleared.
func TestJoinSCIMURL_PlainBaseAndPathHasNoTrailingRawPath(t *testing.T) {
	got, err := joinSCIMURL("https://example.com/scim/v2", "Users")
	if err != nil {
		t.Fatalf("joinSCIMURL: %v", err)
	}
	want := "https://example.com/scim/v2/Users"
	if got != want {
		t.Errorf("joinSCIMURL happy path = %q want %q", got, want)
	}
}

// TestJoinSCIMURL_RejectsInvalidPercentEncoding pins that a
// malformed percent-encoding in the path argument surfaces as
// ErrSCIMConfigInvalid rather than garbling the URL silently.
func TestJoinSCIMURL_RejectsInvalidPercentEncoding(t *testing.T) {
	_, err := joinSCIMURL("https://example.com/scim/v2", "Users/abc%ZZ")
	if err == nil {
		t.Fatal("joinSCIMURL: expected error for invalid percent-encoding, got nil")
	}
	if !errors.Is(err, ErrSCIMConfigInvalid) {
		t.Errorf("joinSCIMURL err = %v; want errors.Is ErrSCIMConfigInvalid", err)
	}
}
