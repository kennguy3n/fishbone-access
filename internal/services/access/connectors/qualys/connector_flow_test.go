package qualys

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func qualysFlowValidConfig() map[string]interface{} {
	return map[string]interface{}{"platform": "us1"}
}
func qualysFlowValidSecrets() map[string]interface{} {
	return map[string]interface{}{"username": "alice@example.com", "password": "secret123"}
}

func TestQualysConnectorFlow_FullLifecycle(t *testing.T) {
	const userLogin = "alice"
	const role = "Manager"

	var mu sync.Mutex
	state := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			t.Errorf("authorization header missing")
		}
		q := r.URL.Query()
		action := q.Get("action")
		mu.Lock()
		defer mu.Unlock()
		switch action {
		case "add":
			if err := r.ParseForm(); err != nil {
				t.Errorf("ParseForm: %v", err)
			}
			if got := r.PostForm.Get("user_login"); got != userLogin {
				t.Errorf("add form user_login=%q, want %q", got, userLogin)
			}
			if got := r.PostForm.Get("user_role"); got != role {
				t.Errorf("add form user_role=%q, want %q", got, role)
			}
			if got := r.PostForm.Get("first_name"); got == userLogin {
				t.Errorf("add form first_name must not echo user_login %q", got)
			}
			if got := r.PostForm.Get("email"); got == userLogin {
				t.Errorf("add form email must not echo user_login %q", got)
			}
			if got := r.PostForm.Get("email"); !strings.Contains(got, "@") {
				t.Errorf("add form email=%q must be an addr-spec", got)
			}
			if state != "" {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`<RESPONSE><CODE>1905</CODE><TEXT>already_exists</TEXT></RESPONSE>`))
				return
			}
			state = role
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<USER_OUTPUT><RESPONSE><USER><USER_LOGIN>` + userLogin + `</USER_LOGIN><USER_ROLE>` + role + `</USER_ROLE></USER></RESPONSE></USER_OUTPUT>`))
		case "delete":
			if state == "" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			state = ""
			w.WriteHeader(http.StatusOK)
		case "list":
			login := q.Get("login")
			if state == "" || !strings.EqualFold(login, userLogin) {
				_, _ = w.Write([]byte(`<USER_LIST_OUTPUT><RESPONSE><USER_LIST></USER_LIST></RESPONSE></USER_LIST_OUTPUT>`))
				return
			}
			_, _ = w.Write([]byte(`<USER_LIST_OUTPUT><RESPONSE><USER_LIST><USER><USER_LOGIN>` + userLogin + `</USER_LOGIN><USER_ROLE>` + state + `</USER_ROLE></USER></USER_LIST></RESPONSE></USER_LIST_OUTPUT>`))
		default:
			t.Errorf("unexpected action %q", action)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := qualysFlowValidConfig()
	secrets := qualysFlowValidSecrets()
	grant := access.AccessGrant{UserExternalID: userLogin, ResourceExternalID: role}

	if err := c.Validate(context.Background(), cfg, secrets); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	ents, err := c.ListEntitlements(context.Background(), cfg, secrets, userLogin)
	if err != nil {
		t.Fatalf("ListEntitlements after provision: %v", err)
	}
	if len(ents) != 1 || ents[0].ResourceExternalID != role || ents[0].Source != "direct" {
		t.Fatalf("ents = %#v, want 1 with role=%s source=direct", ents, role)
	}
	for i := 0; i < 2; i++ {
		if err := c.RevokeAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("RevokeAccess[%d]: %v", i, err)
		}
	}
	ents, err = c.ListEntitlements(context.Background(), cfg, secrets, userLogin)
	if err != nil {
		t.Fatalf("ListEntitlements after revoke: %v", err)
	}
	if len(ents) != 0 {
		t.Fatalf("expected empty, got %#v", ents)
	}
}

func TestQualysProvisionAccess_HonoursScopeIdentityFields(t *testing.T) {
	got := struct {
		first, last, email string
	}{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("action") != "add" {
			t.Fatalf("unexpected action=%q", r.URL.Query().Get("action"))
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		got.first = r.PostForm.Get("first_name")
		got.last = r.PostForm.Get("last_name")
		got.email = r.PostForm.Get("email")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	grant := access.AccessGrant{
		UserExternalID:     "alice",
		ResourceExternalID: "Manager",
		Scope: map[string]interface{}{
			"first_name": "Alice",
			"last_name":  "Liddell",
			"email":      "alice@example.com",
		},
	}
	if err := c.ProvisionAccess(context.Background(), qualysFlowValidConfig(), qualysFlowValidSecrets(), grant); err != nil {
		t.Fatalf("ProvisionAccess: %v", err)
	}
	if got.first != "Alice" || got.last != "Liddell" || got.email != "alice@example.com" {
		t.Fatalf("scope override not honoured: %#v", got)
	}
}

func TestQualysProvisionAccess_FallsBackToInvalidTLD(t *testing.T) {
	var capturedEmail string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		capturedEmail = r.PostForm.Get("email")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	grant := access.AccessGrant{UserExternalID: "alice", ResourceExternalID: "Manager"}
	if err := c.ProvisionAccess(context.Background(), qualysFlowValidConfig(), qualysFlowValidSecrets(), grant); err != nil {
		t.Fatalf("ProvisionAccess: %v", err)
	}
	if capturedEmail != "alice@user.invalid" {
		t.Fatalf("expected fallback email alice@user.invalid, got %q", capturedEmail)
	}
}

func TestQualysConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		qualysFlowValidConfig(), qualysFlowValidSecrets(),
		access.AccessGrant{UserExternalID: "alice", ResourceExternalID: "Manager"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
