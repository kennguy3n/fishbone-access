package sage_intacct

import (
	"context"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// TestSageEscapeQueryLiteral_DoublesSingleQuotes covers the standard
// SQL-style single-quote escaping used inside Sage Intacct
// readByQuery filters. xml.EscapeText alone is not sufficient — it
// does not escape single quotes, which are the literal delimiter.
func TestSageEscapeQueryLiteral_DoublesSingleQuotes(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{"no quotes", "bob", "bob"},
		{"single quote", "bob'sql", "bob''sql"},
		{"injection attempt", "bob' OR '1'='1", "bob'' OR ''1''=''1"},
		{"trailing quote", "bob'", "bob''"},
		{"only quotes", "'''", "''''''"},
		{"empty", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := sageEscapeQueryLiteral(tc.in); got != tc.want {
				t.Fatalf("sageEscapeQueryLiteral(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestSageValidateGrant_RejectsUnsafeIdentifiers asserts the
// belt-and-suspenders rejection in sageValidateGrant: single quotes
// and control characters in UserExternalID / ResourceExternalID are
// refused so the malformed value never reaches the upstream API.
func TestSageValidateGrant_RejectsUnsafeIdentifiers(t *testing.T) {
	for _, tc := range []struct {
		name     string
		grant    access.AccessGrant
		wantErr  bool
		wantSubs string
	}{
		{
			name:    "valid",
			grant:   access.AccessGrant{UserExternalID: "bob", ResourceExternalID: "admin"},
			wantErr: false,
		},
		{
			name:     "quote in user",
			grant:    access.AccessGrant{UserExternalID: "bob' OR '1'='1", ResourceExternalID: "admin"},
			wantErr:  true,
			wantSubs: "single-quote",
		},
		{
			name:     "quote in role",
			grant:    access.AccessGrant{UserExternalID: "bob", ResourceExternalID: "admin'--"},
			wantErr:  true,
			wantSubs: "single-quote",
		},
		{
			name:     "newline in user",
			grant:    access.AccessGrant{UserExternalID: "bo\nb", ResourceExternalID: "admin"},
			wantErr:  true,
			wantSubs: "control",
		},
		{
			name:     "null byte in role",
			grant:    access.AccessGrant{UserExternalID: "bob", ResourceExternalID: "admin\x00"},
			wantErr:  true,
			wantSubs: "control",
		},
		{
			name:     "missing user",
			grant:    access.AccessGrant{UserExternalID: "", ResourceExternalID: "admin"},
			wantErr:  true,
			wantSubs: "UserExternalID is required",
		},
		{
			name:     "missing role",
			grant:    access.AccessGrant{UserExternalID: "bob", ResourceExternalID: ""},
			wantErr:  true,
			wantSubs: "ResourceExternalID is required",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := sageValidateGrant(tc.grant)
			if tc.wantErr && err == nil {
				t.Fatalf("sageValidateGrant(%+v) = nil; want error containing %q", tc.grant, tc.wantSubs)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("sageValidateGrant(%+v) = %v; want nil", tc.grant, err)
			}
			if tc.wantErr && !strings.Contains(err.Error(), tc.wantSubs) {
				t.Fatalf("sageValidateGrant(%+v) = %v; want error containing %q", tc.grant, err, tc.wantSubs)
			}
		})
	}
}

// TestBuildUserQueryXML_EscapesSingleQuotes asserts the query body
// embeds the user identifier with single quotes doubled so a quote
// in the value cannot break out of the USERID = '...' literal once
// the upstream XML parser decodes &#39; back to a single quote and
// hands the text to Sage Intacct's query engine.
func TestBuildUserQueryXML_EscapesSingleQuotes(t *testing.T) {
	c := &SageIntacctAccessConnector{}
	cfg := Config{CompanyID: "ACME"}
	secrets := Secrets{
		SenderID:       "sender",
		SenderPassword: "spw",
		UserID:         "alice",
		UserPassword:   "upw",
	}
	body := c.buildUserQueryXML(cfg, secrets, "bob' OR '1'='1")

	// Decode the XML envelope and inspect the parsed <query> text;
	// the application-layer doubling must survive XML entity decode
	// so the query engine sees 'bob'' OR ''1''=''1' (escaped) rather
	// than 'bob' OR '1'='1' (injected).
	type readByQuery struct {
		Query string `xml:"query"`
	}
	type fn struct {
		ReadByQuery readByQuery `xml:"readByQuery"`
	}
	type content struct {
		Function fn `xml:"function"`
	}
	type operation struct {
		Content content `xml:"content"`
	}
	type request struct {
		Operation operation `xml:"operation"`
	}
	var parsed request
	if err := xml.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("xml.Unmarshal: %v", err)
	}
	got := parsed.Operation.Content.Function.ReadByQuery.Query
	const want = "USERID = 'bob'' OR ''1''=''1'"
	if got != want {
		t.Fatalf("decoded <query> = %q, want %q", got, want)
	}
	// And the bare-injection form must never appear once decoded.
	if got == "USERID = 'bob' OR '1'='1'" {
		t.Fatalf("decoded <query> contains un-escaped injection literal")
	}
}

// TestListEntitlements_RejectsUnsafeUserID asserts the ListEntitlements
// entrypoint also rejects quote-bearing values, matching the
// validation applied to ProvisionAccess / RevokeAccess.
func TestListEntitlements_RejectsUnsafeUserID(t *testing.T) {
	c := &SageIntacctAccessConnector{}
	_, err := c.ListEntitlements(context.Background(),
		map[string]interface{}{"company_id": "ACME"},
		map[string]interface{}{
			"sender_id": "s", "sender_password": "sp",
			"user_id": "u", "user_password": "up",
		},
		"bob' OR '1'='1",
	)
	if err == nil {
		t.Fatal("ListEntitlements(quote-bearing user) returned nil; want validation error")
	}
	if !strings.Contains(err.Error(), "single-quote") {
		t.Fatalf("ListEntitlements error = %v; want single-quote rejection", err)
	}
}
