package notion

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRevokeUserSessions_HappyPath verifies the kill switch hits the
// enterprise SCIM endpoint (PATCH {base}/scim/v2/Users/{id}) with the
// RFC 7644 PatchOp body that sets active:false — NOT the public v1
// users route, which is read-only and would 404 (silent no-op).
func TestRevokeUserSessions_HappyPath(t *testing.T) {
	var seenMethod, seenPath string
	var seenBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenMethod = r.Method
		seenPath = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &seenBody)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.RevokeUserSessions(context.Background(), nil, validSecrets(), "user-1"); err != nil {
		t.Fatalf("RevokeUserSessions: %v", err)
	}
	if seenMethod != http.MethodPatch {
		t.Errorf("method=%q; want PATCH", seenMethod)
	}
	// Must target the SCIM Users collection, never the read-only
	// public v1 users endpoint.
	if !strings.HasSuffix(seenPath, "/scim/v2/Users/user-1") {
		t.Errorf("path=%q; want suffix /scim/v2/Users/user-1", seenPath)
	}
	if strings.Contains(seenPath, "/v1/users/") {
		t.Errorf("path=%q; must not use the read-only /v1/users/ endpoint", seenPath)
	}
	// Body must be a SCIM PatchOp that replaces active -> false.
	schemas, _ := seenBody["schemas"].([]interface{})
	if len(schemas) != 1 || schemas[0] != "urn:ietf:params:scim:api:messages:2.0:PatchOp" {
		t.Errorf("schemas=%v; want the SCIM PatchOp schema", seenBody["schemas"])
	}
	ops, _ := seenBody["Operations"].([]interface{})
	if len(ops) != 1 {
		t.Fatalf("Operations=%v; want exactly one op", seenBody["Operations"])
	}
	op, _ := ops[0].(map[string]interface{})
	if op["op"] != "replace" || op["path"] != "active" {
		t.Errorf("op=%v; want replace active", op)
	}
	if active, ok := op["value"].(bool); !ok || active {
		t.Errorf("value=%v; want bool false", op["value"])
	}
}

func TestRevokeUserSessions_NotFoundIsIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.RevokeUserSessions(context.Background(), nil, validSecrets(), "user-1"); err != nil {
		t.Fatalf("RevokeUserSessions on 404: %v; want nil (idempotent)", err)
	}
}

func TestRevokeUserSessions_NoContentIsSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.RevokeUserSessions(context.Background(), nil, validSecrets(), "user-1"); err != nil {
		t.Fatalf("RevokeUserSessions on 204: %v; want nil", err)
	}
}

func TestRevokeUserSessions_HTTPFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.RevokeUserSessions(context.Background(), nil, validSecrets(), "user-1"); err == nil {
		t.Fatal("err = nil; want non-nil on 500")
	}
}

func TestRevokeUserSessions_ValidationEmptyID(t *testing.T) {
	c := New()
	if err := c.RevokeUserSessions(context.Background(), nil, nil, ""); err == nil {
		t.Fatal("err = nil; want validation error on empty userExternalID")
	}
	// Whitespace-only IDs must also be rejected.
	if err := c.RevokeUserSessions(context.Background(), nil, nil, "   "); err == nil {
		t.Fatal("err = nil; want validation error on whitespace userExternalID")
	}
}
