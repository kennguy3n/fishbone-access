package sage_intacct

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const sageIntacctAuditMaxPages = 200

// FetchAccessAuditLogs streams Sage Intacct audit-trail events into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	POST /ia/xml/xmlgw.phtml
//	XML readByQuery against AUDITHISTORY (sender/user/company creds in the
//	envelope; pagesize=100; offset paginated).
//
// Audit history visibility requires the user role to include "View
// Audit Trail"; lower roles return XML error envelopes with auth/
// permission markers (the connector also soft-skips on HTTP 401/403/
// 404 per docs/architecture.md §2).
func (c *SageIntacctAccessConnector) FetchAccessAuditLogs(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	sincePartitions map[string]time.Time,
	handler func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	since := sincePartitions[access.DefaultAuditPartition]

	var collected []sageIntacctAuditEntry
	for page := 0; page < sageIntacctAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		body := buildSageIntacctAuditXML(cfg, secrets, page*pageSize, since)
		respBody, status, rerr := c.postAuditXML(ctx, body)
		if rerr != nil {
			return rerr
		}
		switch status {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if status < 200 || status >= 300 {
			return fmt.Errorf("sage_intacct: audit: status %d: %s", status, string(respBody))
		}
		entries, denied, err := parseSageIntacctAuditXML(respBody)
		if err != nil {
			return err
		}
		if denied {
			return access.ErrAuditNotAvailable
		}
		collected = append(collected, entries...)
		if len(entries) < pageSize {
			break
		}
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapSageIntacctAuditEntry(&collected[i])
		if entry == nil {
			continue
		}
		if entry.Timestamp.After(batchMax) {
			batchMax = entry.Timestamp
		}
		batch = append(batch, entry)
	}
	if len(batch) == 0 {
		return nil
	}
	return handler(batch, batchMax, access.DefaultAuditPartition)
}

func (c *SageIntacctAccessConnector) postAuditXML(ctx context.Context, body string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL()+"/ia/xml/xmlgw.phtml", strings.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("Accept", "application/xml")
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("sage_intacct: audit post: %w", err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return out, resp.StatusCode, nil
}

func buildSageIntacctAuditXML(cfg Config, secrets Secrets, offset int, since time.Time) string {
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	sb.WriteString(`<request><control><senderid>`)
	_ = xml.EscapeText(&sb, []byte(strings.TrimSpace(secrets.SenderID)))
	sb.WriteString(`</senderid><password>`)
	_ = xml.EscapeText(&sb, []byte(strings.TrimSpace(secrets.SenderPassword)))
	sb.WriteString(`</password></control><operation><authentication><login><userid>`)
	_ = xml.EscapeText(&sb, []byte(strings.TrimSpace(secrets.UserID)))
	sb.WriteString(`</userid><companyid>`)
	_ = xml.EscapeText(&sb, []byte(strings.TrimSpace(cfg.CompanyID)))
	sb.WriteString(`</companyid><password>`)
	_ = xml.EscapeText(&sb, []byte(strings.TrimSpace(secrets.UserPassword)))
	sb.WriteString(`</password></login></authentication><content><function controlid="audit"><readByQuery><object>AUDITHISTORY</object><query>`)
	if !since.IsZero() {
		_ = xml.EscapeText(&sb, []byte("ACCESSTIME > '"+since.UTC().Format("2006-01-02 15:04:05")+"'"))
	}
	sb.WriteString(`</query><pagesize>`)
	fmt.Fprintf(&sb, "%d", pageSize)
	sb.WriteString(`</pagesize><offset>`)
	fmt.Fprintf(&sb, "%d", offset)
	sb.WriteString(`</offset></readByQuery></function></content></operation></request>`)
	return sb.String()
}

type sageIntacctAuditEntry struct {
	RecordNo   string `xml:"RECORDNO"`
	AccessTime string `xml:"ACCESSTIME"`
	UserID     string `xml:"USERID"`
	UserEmail  string `xml:"EMAILADDRESS"`
	Operation  string `xml:"OPERATION"`
	ObjectType string `xml:"OBJECT"`
	ObjectKey  string `xml:"KEY"`
}

type sageIntacctAuditResult struct {
	Status string                  `xml:"status"`
	Data   []sageIntacctAuditEntry `xml:"data>audithistory"`
}

type sageIntacctAuditEnvelope struct {
	XMLName    xml.Name `xml:"response"`
	Operations []struct {
		Authentication struct {
			Status   string `xml:"status"`
			ErrorMsg string `xml:"errormessage>error>description2"`
		} `xml:"authentication"`
		Result sageIntacctAuditResult `xml:"result"`
	} `xml:"operation"`
}

func parseSageIntacctAuditXML(body []byte) ([]sageIntacctAuditEntry, bool, error) {
	var env sageIntacctAuditEnvelope
	if err := xml.NewDecoder(bytes.NewReader(body)).Decode(&env); err != nil {
		return nil, false, fmt.Errorf("sage_intacct: decode audit xml: %w", err)
	}
	// Sage Intacct returns at most one <operation> per <function>
	// call envelope; we issue exactly one function (readByQuery /
	// readMore) per request so only the first operation is
	// authoritative — extra operations would be a contract drift
	// from the API and are intentionally ignored.
	if len(env.Operations) == 0 {
		return nil, false, nil
	}
	op := env.Operations[0]
	if !strings.EqualFold(op.Authentication.Status, "success") {
		if sageIntacctAuditAuthDenied(op.Authentication.ErrorMsg) {
			return nil, true, nil
		}
		return nil, false, fmt.Errorf("sage_intacct: audit auth: %s", op.Authentication.ErrorMsg)
	}
	if !strings.EqualFold(op.Result.Status, "success") {
		return nil, false, nil
	}
	return op.Result.Data, false, nil
}

func mapSageIntacctAuditEntry(e *sageIntacctAuditEntry) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.RecordNo) == "" {
		return nil
	}
	ts := parseSageIntacctTime(e.AccessTime)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	action := strings.TrimSpace(e.Operation)
	return &access.AuditLogEntry{
		EventID:          strings.TrimSpace(e.RecordNo),
		EventType:        strings.TrimSpace(e.Operation),
		Action:           action,
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.UserID),
		ActorEmail:       strings.TrimSpace(e.UserEmail),
		TargetExternalID: strings.TrimSpace(e.ObjectKey),
		TargetType:       strings.TrimSpace(e.ObjectType),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseSageIntacctTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	if ts, err := time.Parse("2006-01-02 15:04:05", s); err == nil {
		return ts.UTC()
	}
	if ts, err := time.Parse(time.RFC3339, s); err == nil {
		return ts.UTC()
	}
	return time.Time{}
}

func sageIntacctAuditAuthDenied(msg string) bool {
	low := strings.ToLower(strings.TrimSpace(msg))
	return strings.Contains(low, "permission") ||
		strings.Contains(low, "unauthorized") ||
		strings.Contains(low, "not authorized") ||
		strings.Contains(low, "forbidden")
}

var _ access.AccessAuditor = (*SageIntacctAccessConnector)(nil)
