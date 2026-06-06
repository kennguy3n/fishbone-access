package sage_intacct

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func TestSageIntacctFetchAccessAuditLogs_Maps(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "AUDITHISTORY") {
			t.Errorf("missing AUDITHISTORY in body: %s", string(body))
		}
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<?xml version="1.0"?><response><operation><authentication><status>success</status></authentication><result><status>success</status><data listtype="audithistory" count="1"><audithistory><RECORDNO>R1</RECORDNO><ACCESSTIME>2024-08-01 12:00:00</ACCESSTIME><USERID>u1</USERID><EMAILADDRESS>u1@example.com</EMAILADDRESS><OPERATION>UPDATE</OPERATION><OBJECT>USERINFO</OBJECT><KEY>USER-1</KEY></audithistory></data></result></operation></response>`))
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var got []*access.AuditLogEntry
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Time{}},
		func(batch []*access.AuditLogEntry, _ time.Time, _ string) error {
			got = batch
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(got) != 1 || got[0].EventID != "R1" || got[0].TargetType != "USERINFO" {
		t.Fatalf("got = %#v", got)
	}
}

func TestSageIntacctFetchAccessAuditLogs_NotAvailableHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(), nil,
		func([]*access.AuditLogEntry, time.Time, string) error { return nil })
	if err != access.ErrAuditNotAvailable {
		t.Fatalf("err = %v; want ErrAuditNotAvailable", err)
	}
}

func TestSageIntacctFetchAccessAuditLogs_NotAvailableAuthFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<?xml version="1.0"?><response><operation><authentication><status>failure</status><errormessage><error><description2>User does not have Permission to access audit history</description2></error></errormessage></authentication></operation></response>`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(), nil,
		func([]*access.AuditLogEntry, time.Time, string) error { return nil })
	if err != access.ErrAuditNotAvailable {
		t.Fatalf("err = %v; want ErrAuditNotAvailable", err)
	}
}

func TestSageIntacctFetchAccessAuditLogs_QueryFilterEscaping(t *testing.T) {
	var seenBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seenBody = string(body)
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<?xml version="1.0"?><response><operation><authentication><status>success</status></authentication><result><status>success</status><data listtype="audithistory" count="0"></data></result></operation></response>`))
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	since := time.Date(2024, 8, 1, 12, 0, 0, 0, time.UTC)
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: since},
		func([]*access.AuditLogEntry, time.Time, string) error { return nil })
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if !strings.Contains(seenBody, "ACCESSTIME &gt; &#39;2024-08-01 12:00:00&#39;") {
		t.Fatalf("request body missing single-escaped > operator: %s", seenBody)
	}
	if strings.Contains(seenBody, "&amp;gt;") {
		t.Fatalf("request body double-escapes > as &amp;gt;: %s", seenBody)
	}
}

func TestSageIntacctFetchAccessAuditLogs_TransientFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(), nil,
		func([]*access.AuditLogEntry, time.Time, string) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("err = %v", err)
	}
}
