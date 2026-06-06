package gcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func TestGCP_RevokeUserSessions_HappyPath(t *testing.T) {
	var (
		mu      sync.Mutex
		listed  = 0
		disable = 0
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/keys"):
			listed++
			if !strings.Contains(r.URL.Path, "ci-runner@uney-prod.iam.gserviceaccount.com") {
				t.Errorf("path = %q", r.URL.Path)
			}
			_, _ = w.Write([]byte(`{"keys":[
				{"name":"projects/uney-prod/serviceAccounts/ci-runner@uney-prod.iam.gserviceaccount.com/keys/k1","disabled":false},
				{"name":"projects/uney-prod/serviceAccounts/ci-runner@uney-prod.iam.gserviceaccount.com/keys/k2","disabled":true},
				{"name":"projects/uney-prod/serviceAccounts/ci-runner@uney-prod.iam.gserviceaccount.com/keys/k3","disabled":false}
			]}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, ":disable"):
			disable++
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
	if err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(),
		"ci-runner@uney-prod.iam.gserviceaccount.com"); err != nil {
		t.Fatalf("RevokeUserSessions: %v", err)
	}
	if listed != 1 {
		t.Errorf("listed = %d; want 1", listed)
	}
	if disable != 2 {
		t.Errorf("disable = %d; want 2 (skip already-disabled k2)", disable)
	}
}

func TestGCP_RevokeUserSessions_StripsServiceAccountPrefix(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "serviceAccount:") {
			t.Errorf("path contains unescaped prefix: %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
	if err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(),
		"serviceAccount:ci-runner@uney-prod.iam.gserviceaccount.com"); err != nil {
		t.Fatalf("RevokeUserSessions: %v", err)
	}
}

func TestGCP_RevokeUserSessions_NotFoundIsIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"code":404}}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
	if err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(),
		"gone@uney-prod.iam.gserviceaccount.com"); err != nil {
		t.Errorf("404 should be idempotent; got %v", err)
	}
}

func TestGCP_RevokeUserSessions_RejectsHumanUser(t *testing.T) {
	c := New()
	err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(), "user:alice@uney.com")
	if err == nil || !strings.Contains(err.Error(), "human / group principal") {
		t.Errorf("err = %v; want rejection with hint to use google_workspace connector", err)
	}
}

func TestGCP_RevokeUserSessions_EmptyRejected(t *testing.T) {
	c := New()
	err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(), "")
	if err == nil || !strings.Contains(err.Error(), "userExternalID is required") {
		t.Errorf("err = %v; want missing-id rejection", err)
	}
}

func TestGCP_RevokeUserSessions_InvalidEmailRejected(t *testing.T) {
	c := New()
	err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(), "not-an-email")
	if err == nil || !strings.Contains(err.Error(), "not a valid service account email") {
		t.Errorf("err = %v; want email validation rejection", err)
	}
}

func TestGCP_RevokeUserSessions_DisableFailurePropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"keys":[{"name":"projects/p/serviceAccounts/sa@p.iam.gserviceaccount.com/keys/k1"}]}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":{"code":500,"message":"boom"}}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
	err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(),
		"sa@p.iam.gserviceaccount.com")
	if err == nil || !strings.Contains(err.Error(), "status 500") {
		t.Errorf("err = %v; want 500", err)
	}
}

func TestGCP_SatisfiesSessionRevokerInterface(t *testing.T) {
	var _ access.SessionRevoker = New()
}

// TestGCP_RevokeUserSessions_RequestsUserManagedKeysOnly pins that
// listServiceAccountKeys passes keyTypes=USER_MANAGED so the IAM
// API never returns SYSTEM_MANAGED keys (which keys.disable rejects
// with FAILED_PRECONDITION).
func TestGCP_RevokeUserSessions_RequestsUserManagedKeysOnly(t *testing.T) {
	var (
		mu       sync.Mutex
		listedQ  string
		disabled = 0
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/keys"):
			listedQ = r.URL.RawQuery
			_, _ = w.Write([]byte(`{"keys":[
{"name":"projects/uney-prod/serviceAccounts/sa@uney-prod.iam.gserviceaccount.com/keys/u1","keyType":"USER_MANAGED","disabled":false}
]}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, ":disable"):
			disabled++
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
	if err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(),
		"sa@uney-prod.iam.gserviceaccount.com"); err != nil {
		t.Fatalf("RevokeUserSessions: %v", err)
	}
	if !strings.Contains(listedQ, "keyTypes=USER_MANAGED") {
		t.Errorf("list query = %q; want keyTypes=USER_MANAGED filter", listedQ)
	}
	if disabled != 1 {
		t.Errorf("disabled = %d; want 1", disabled)
	}
}

// TestGCP_RevokeUserSessions_SkipsSystemManagedKeysDefenceInDepth
// pins that even if the IAM API mistakenly returns a SYSTEM_MANAGED
// key in the list response, the revoke loop refuses to call
// keys.disable on it. keys.disable on a SYSTEM_MANAGED key returns
// FAILED_PRECONDITION; aborting on that error would leave the
// leaver's USER_MANAGED keys live.
func TestGCP_RevokeUserSessions_SkipsSystemManagedKeysDefenceInDepth(t *testing.T) {
	var (
		mu       sync.Mutex
		disabled = []string{}
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/keys"):
			_, _ = w.Write([]byte(`{"keys":[
{"name":"projects/uney-prod/serviceAccounts/sa@uney-prod.iam.gserviceaccount.com/keys/sys1","keyType":"SYSTEM_MANAGED","disabled":false},
{"name":"projects/uney-prod/serviceAccounts/sa@uney-prod.iam.gserviceaccount.com/keys/usr1","keyType":"USER_MANAGED","disabled":false}
]}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, ":disable"):
			disabled = append(disabled, r.URL.Path)
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
	if err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(),
		"sa@uney-prod.iam.gserviceaccount.com"); err != nil {
		t.Fatalf("RevokeUserSessions: %v", err)
	}
	if len(disabled) != 1 {
		t.Fatalf("disabled paths = %v; want exactly 1 (USER_MANAGED only)", disabled)
	}
	if !strings.Contains(disabled[0], "/usr1") {
		t.Errorf("disabled path = %q; want usr1 (SYSTEM_MANAGED must be skipped)", disabled[0])
	}
}
