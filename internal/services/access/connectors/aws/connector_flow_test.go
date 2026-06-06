package aws

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// TestConnectorFlow_FullLifecycle exercises AWS IAM
// AttachUserPolicy/DetachUserPolicy/ListAttachedUserPolicies via a single
// httptest mock that branches on the IAM Action form parameter.
func TestConnectorFlow_FullLifecycle(t *testing.T) {
	var attached bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		switch r.Form.Get("Action") {
		case "AttachUserPolicy":
			attached = true
			_, _ = w.Write([]byte(`<AttachUserPolicyResponse/>`))
		case "DetachUserPolicy":
			if !attached {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>NoSuchEntity</Code></Error></ErrorResponse>`))
				return
			}
			attached = false
			_, _ = w.Write([]byte(`<DetachUserPolicyResponse/>`))
		case "ListAttachedUserPolicies":
			if attached {
				_, _ = w.Write([]byte(`<ListAttachedUserPoliciesResponse><ListAttachedUserPoliciesResult><IsTruncated>false</IsTruncated><AttachedPolicies><member><PolicyName>ReadOnlyAccess</PolicyName><PolicyArn>arn:aws:iam::aws:policy/ReadOnlyAccess</PolicyArn></member></AttachedPolicies></ListAttachedUserPoliciesResult></ListAttachedUserPoliciesResponse>`))
			} else {
				_, _ = w.Write([]byte(`<ListAttachedUserPoliciesResponse><ListAttachedUserPoliciesResult><IsTruncated>false</IsTruncated><AttachedPolicies></AttachedPolicies></ListAttachedUserPoliciesResult></ListAttachedUserPoliciesResponse>`))
			}
		default:
			_, _ = w.Write([]byte(`<EmptyResponse/>`))
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	c.timeOverride = func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) }

	if err := c.Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	grant := access.AccessGrant{UserExternalID: "alice", ResourceExternalID: "arn:aws:iam::aws:policy/ReadOnlyAccess"}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}

	ents, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "alice")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(ents) == 0 {
		t.Fatalf("expected provisioned grant to appear, got 0")
	}

	for i := 0; i < 2; i++ {
		if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
			t.Fatalf("RevokeAccess[%d]: %v", i, err)
		}
	}

	ents, _ = c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "alice")
	if len(ents) != 0 {
		t.Fatalf("ListEntitlements after revoke: got %d, want 0", len(ents))
	}
}

func TestConnectorFlow_ProvisionFailsOnNoSuchEntity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>NoSuchEntity</Code><Message>user does not exist</Message></Error></ErrorResponse>`))
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	c.timeOverride = func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) }

	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "ghost", ResourceExternalID: "arn:aws:iam::aws:policy/ReadOnlyAccess",
	})
	if err == nil {
		t.Fatal("ProvisionAccess with NoSuchEntity: expected error, got nil")
	}
}
