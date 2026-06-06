package salesforce

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestRevokeUserSessions_DeletesEachActiveSession(t *testing.T) {
	var deleteCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/query"):
			_, _ = w.Write([]byte(`{"records":[{"Id":"s1"},{"Id":"s2"}]}`))
		case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/AuthSession/"):
			atomic.AddInt32(&deleteCount, 1)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	if err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(), "005xxxx"); err != nil {
		t.Fatalf("RevokeUserSessions: %v", err)
	}
	if atomic.LoadInt32(&deleteCount) != 2 {
		t.Errorf("deleteCount=%d; want 2", deleteCount)
	}
}

func TestRevokeUserSessions_EmptySessionListIsIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"records":[]}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	if err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(), "005xxxx"); err != nil {
		t.Fatalf("empty list should be idempotent: %v", err)
	}
}

func TestRevokeUserSessions_ListHTTPFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	if err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(), "005xxxx"); err == nil {
		t.Fatal("err=nil; want non-nil on 403")
	}
}

func TestRevokeUserSessions_ValidationEmptyID(t *testing.T) {
	c := New()
	if err := c.RevokeUserSessions(context.Background(), nil, nil, ""); err == nil {
		t.Fatal("err=nil; want validation error")
	}
}

// TestRevokeUserSessions_EscapesSOQLLiteral guards against SOQL
// injection / malformed queries: a userExternalID containing a single
// quote must be SOQL-escaped (and URL-encoded) before being
// interpolated into the AuthSession query, matching the escaping used
// elsewhere in the connector.
func TestRevokeUserSessions_EscapesSOQLLiteral(t *testing.T) {
	var rawQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/query") {
			rawQuery = r.URL.RawQuery
			_, _ = w.Write([]byte(`{"records":[]}`))
			return
		}
		t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	if err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(), "005x' OR Id!='"); err != nil {
		t.Fatalf("RevokeUserSessions: %v", err)
	}
	// The decoded query the server received must contain the escaped
	// literal (\') rather than a bare quote that would break out of the
	// UsersId string literal.
	decoded, err := url.QueryUnescape(rawQuery)
	if err != nil {
		t.Fatalf("decode raw query: %v", err)
	}
	if !strings.Contains(decoded, `UsersId='005x\' OR Id!=\''`) {
		t.Errorf("query literal not SOQL-escaped: %q", decoded)
	}
}
