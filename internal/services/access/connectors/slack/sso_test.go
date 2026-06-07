package slack

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSlackGetSSOMetadata_NilWhenNonEnterprise(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/team.info") {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"ok":true,"team":{"id":"T1","name":"Acme","domain":"acme"}}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	got, err := c.GetSSOMetadata(context.Background(), nil, validSecrets())
	if err != nil {
		t.Fatalf("GetSSOMetadata: %v", err)
	}
	if got != nil {
		t.Fatalf("got = %+v; want nil (non-Enterprise)", got)
	}
}

func TestSlackGetSSOMetadata_EnterpriseGridReturnsSAML(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/team.info") {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"ok":true,"team":{"id":"T1","name":"Acme","domain":"acme","enterprise_id":"E1","enterprise_name":"Acme Grid"}}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	got, err := c.GetSSOMetadata(context.Background(), nil, validSecrets())
	if err != nil {
		t.Fatalf("GetSSOMetadata: %v", err)
	}
	if got == nil {
		t.Fatal("got = nil; want SAML metadata for Enterprise Grid")
	}
	if got.Protocol != "saml" {
		t.Errorf("Protocol = %q; want saml", got.Protocol)
	}
	if got.MetadataURL != "https://acme.slack.com/sso/saml/metadata" {
		t.Errorf("MetadataURL = %q", got.MetadataURL)
	}
	if got.EntityID != "https://slack.com/E1" {
		t.Errorf("EntityID = %q", got.EntityID)
	}
}

func TestSlackGetSSOMetadata_NilWhenAPIErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":false,"error":"invalid_auth"}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	got, err := c.GetSSOMetadata(context.Background(), nil, validSecrets())
	if err != nil {
		t.Fatalf("GetSSOMetadata err = %v; want nil (graceful downgrade)", err)
	}
	if got != nil {
		t.Fatalf("got = %+v; want nil on API error", got)
	}
}
