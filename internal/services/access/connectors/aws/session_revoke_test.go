package aws

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func TestAWS_RevokeUserSessions_HappyPath(t *testing.T) {
	var (
		mu                   sync.Mutex
		deleteLoginCalled    bool
		listAccessKeysCalled bool
		deleteAccessKeyCalls []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		params := readIAMAction(t, r)
		mu.Lock()
		defer mu.Unlock()
		switch params.Get("Action") {
		case "DeleteLoginProfile":
			if params.Get("UserName") != "alice" {
				t.Errorf("DeleteLoginProfile UserName=%q", params.Get("UserName"))
			}
			deleteLoginCalled = true
			_, _ = w.Write([]byte(`<DeleteLoginProfileResponse/>`))
		case "ListAccessKeys":
			if params.Get("UserName") != "alice" {
				t.Errorf("ListAccessKeys UserName=%q", params.Get("UserName"))
			}
			listAccessKeysCalled = true
			_, _ = w.Write([]byte(`<ListAccessKeysResponse><ListAccessKeysResult><IsTruncated>false</IsTruncated><AccessKeyMetadata><member><AccessKeyId>AKIA1</AccessKeyId><Status>Active</Status></member><member><AccessKeyId>AKIA2</AccessKeyId><Status>Inactive</Status></member></AccessKeyMetadata></ListAccessKeysResult></ListAccessKeysResponse>`))
		case "DeleteAccessKey":
			deleteAccessKeyCalls = append(deleteAccessKeyCalls, params.Get("AccessKeyId"))
			_, _ = w.Write([]byte(`<DeleteAccessKeyResponse/>`))
		default:
			t.Fatalf("unexpected action %q", params.Get("Action"))
		}
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	if err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(), "alice"); err != nil {
		t.Fatalf("RevokeUserSessions: %v", err)
	}
	if !deleteLoginCalled {
		t.Error("DeleteLoginProfile not called")
	}
	if !listAccessKeysCalled {
		t.Error("ListAccessKeys not called")
	}
	if len(deleteAccessKeyCalls) != 2 {
		t.Errorf("DeleteAccessKey calls = %d; want 2", len(deleteAccessKeyCalls))
	}
}

func TestAWS_RevokeUserSessions_NoSuchEntityIsIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		params := readIAMAction(t, r)
		if params.Get("Action") == "DeleteLoginProfile" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>NoSuchEntity</Code><Message>The user with name alice cannot be found.</Message></Error></ErrorResponse>`))
			return
		}
		if params.Get("Action") == "ListAccessKeys" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>NoSuchEntity</Code></Error></ErrorResponse>`))
			return
		}
		t.Fatalf("unexpected action %q", params.Get("Action"))
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	if err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(), "alice"); err != nil {
		t.Fatalf("expected idempotent success; got %v", err)
	}
}

func TestAWS_RevokeUserSessions_EmptyUserNameRejected(t *testing.T) {
	c := New()
	err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(), "")
	if err == nil {
		t.Error("want error for empty userExternalID")
	}
	if !strings.Contains(err.Error(), "userExternalID") {
		t.Errorf("error message should mention userExternalID; got %v", err)
	}
}

func TestAWS_RevokeUserSessions_ServerErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(), "alice")
	if err == nil {
		t.Error("want error for 500")
	}
}

func TestAWS_SatisfiesSessionRevokerInterface(t *testing.T) {
	var _ access.SessionRevoker = New()
}
