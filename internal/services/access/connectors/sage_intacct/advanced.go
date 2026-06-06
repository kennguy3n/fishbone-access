package sage_intacct

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// advanced-capability mapping for sage_intacct:
//
//   - ProvisionAccess  -> POST /ia/xml/xmlgw.phtml  with a
//     <function controlid="...">.<create>.<USERINFO> envelope.
//   - RevokeAccess     -> POST /ia/xml/xmlgw.phtml  with a
//     <function>.<delete>.<USERINFO>.USERID envelope.
//   - ListEntitlements -> POST /ia/xml/xmlgw.phtml  with a
//     <readByQuery><object>USERINFO</object><query>USERID = '...'
//     filter; the connector reports the user's STATUS as their role.
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Sage Intacct USERID
//   - grant.ResourceExternalID -> ROLEID (admin|user|...) — surfaced
//     in the USERINFO create envelope and echoed back from list.
//
// Idempotent on (UserExternalID, ResourceExternalID) per docs/architecture.md §2.
// Sage Intacct surfaces "already exists" / "does not exist" via the
// <errormessage> stanza inside the 200 OK envelope; the helpers below
// detect those wordings instead of relying on HTTP status alone.

func sageValidateGrant(g access.AccessGrant) error {
	user := strings.TrimSpace(g.UserExternalID)
	if user == "" {
		return errors.New("sage_intacct: grant.UserExternalID is required")
	}
	if err := sageRejectUnsafeIdentifier("UserExternalID", user); err != nil {
		return err
	}
	role := strings.TrimSpace(g.ResourceExternalID)
	if role == "" {
		return errors.New("sage_intacct: grant.ResourceExternalID is required")
	}
	if err := sageRejectUnsafeIdentifier("ResourceExternalID", role); err != nil {
		return err
	}
	return nil
}

// sageEscapeQueryLiteral escapes a value for embedding inside a Sage
// Intacct readByQuery <query> string literal delimited by single
// quotes (e.g. USERID = '...'). xml.EscapeText handles the XML
// structural characters (<, >, &, ") but does NOT escape single
// quotes, which are the literal delimiter — without doubling them a
// caller-supplied value containing ' can break out of the literal
// and inject arbitrary query predicates.
func sageEscapeQueryLiteral(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

// sageRejectUnsafeIdentifier blocks UserExternalID / ResourceExternalID
// values that contain characters which have no legitimate meaning in a
// Sage Intacct USERID / ROLEID and which would otherwise need special
// escaping (null bytes, CR / LF, and embedded single quotes). The
// query builder also escapes single quotes via sageEscapeQueryLiteral,
// but rejecting them here is defense-in-depth: the malformed value
// never reaches the upstream API in the first place.
func sageRejectUnsafeIdentifier(field, value string) error {
	for _, r := range value {
		switch r {
		case '\x00', '\r', '\n':
			return fmt.Errorf("sage_intacct: grant.%s contains forbidden control character", field)
		case '\'':
			return fmt.Errorf("sage_intacct: grant.%s contains forbidden single-quote character", field)
		}
	}
	return nil
}

// buildUserMutationXML emits the create/delete request body. action is
// either "create" or "delete".
func (c *SageIntacctAccessConnector) buildUserMutationXML(action string, cfg Config, secrets Secrets, userID, role string) string {
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
	sb.WriteString(`</password></login></authentication><content><function controlid="users">`)
	switch action {
	case "create":
		sb.WriteString(`<create><USERINFO><USERID>`)
		_ = xml.EscapeText(&sb, []byte(strings.TrimSpace(userID)))
		sb.WriteString(`</USERID><USERTYPE>business user</USERTYPE><ROLES><ROLE><ROLEID>`)
		_ = xml.EscapeText(&sb, []byte(strings.TrimSpace(role)))
		sb.WriteString(`</ROLEID></ROLE></ROLES></USERINFO></create>`)
	case "delete":
		sb.WriteString(`<delete><object>USERINFO</object><keys>`)
		_ = xml.EscapeText(&sb, []byte(strings.TrimSpace(userID)))
		sb.WriteString(`</keys></delete>`)
	}
	sb.WriteString(`</function></content></operation></request>`)
	return sb.String()
}

func (c *SageIntacctAccessConnector) buildUserQueryXML(cfg Config, secrets Secrets, userID string) string {
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
	sb.WriteString(`</password></login></authentication><content><function controlid="users-query"><readByQuery><object>USERINFO</object><query>USERID = '`)
	_ = xml.EscapeText(&sb, []byte(sageEscapeQueryLiteral(strings.TrimSpace(userID))))
	sb.WriteString(`'</query><pagesize>100</pagesize></readByQuery></function></content></operation></request>`)
	return sb.String()
}

// doXMLStatus is the status-aware sibling of c.doXML. It does not
// raise an error on non-2xx so the caller can run the body through
// the idempotency helpers.
func (c *SageIntacctAccessConnector) doXMLStatus(ctx context.Context, body string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL()+"/ia/xml/xmlgw.phtml", strings.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("Accept", "application/xml")
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("sage_intacct: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, out, nil
}

func sageBodyIsAlreadyExists(body []byte) bool {
	return access.IsIdempotentMessage(string(body),
		[]string{"already", "duplicate", "exists"})
}

func sageBodyIsNotFound(body []byte) bool {
	return access.IsIdempotentMessage(string(body),
		[]string{"not found", "does not exist", "no such", "not a member"})
}

func (c *SageIntacctAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := sageValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	body := c.buildUserMutationXML("create", cfg, secrets,
		grant.UserExternalID, grant.ResourceExternalID)
	status, resp, err := c.doXMLStatus(ctx, body)
	if err != nil {
		return err
	}
	switch {
	case status >= 200 && status < 300:
		if sageBodyIsAlreadyExists(resp) {
			return nil
		}
		if sageBodyIsError(resp) {
			return fmt.Errorf("sage_intacct: provision response: %s", string(resp))
		}
		return nil
	case access.IsIdempotentProvisionStatus(status, resp):
		return nil
	case access.IsTransientStatus(status):
		return fmt.Errorf("sage_intacct: provision transient status %d: %s", status, string(resp))
	default:
		return fmt.Errorf("sage_intacct: provision status %d: %s", status, string(resp))
	}
}

func (c *SageIntacctAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := sageValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	body := c.buildUserMutationXML("delete", cfg, secrets,
		grant.UserExternalID, grant.ResourceExternalID)
	status, resp, err := c.doXMLStatus(ctx, body)
	if err != nil {
		return err
	}
	switch {
	case status >= 200 && status < 300:
		if sageBodyIsNotFound(resp) {
			return nil
		}
		if sageBodyIsError(resp) {
			return fmt.Errorf("sage_intacct: revoke response: %s", string(resp))
		}
		return nil
	case access.IsIdempotentRevokeStatus(status, resp):
		return nil
	case access.IsTransientStatus(status):
		return fmt.Errorf("sage_intacct: revoke transient status %d: %s", status, string(resp))
	default:
		return fmt.Errorf("sage_intacct: revoke status %d: %s", status, string(resp))
	}
}

type sageRoleEntry struct {
	RoleID string `xml:"ROLEID"`
}

type sageUserEntitlement struct {
	UserID string          `xml:"USERID"`
	Roles  []sageRoleEntry `xml:"ROLES>ROLE"`
}

type sageEntitlementData struct {
	Users []sageUserEntitlement `xml:"USERINFO"`
}

type sageEntitlementResult struct {
	Status string              `xml:"status"`
	Data   sageEntitlementData `xml:"data"`
}

type sageEntitlementOperation struct {
	Result sageEntitlementResult `xml:"result"`
}

type sageEntitlementResponse struct {
	XMLName   xml.Name                 `xml:"response"`
	Operation sageEntitlementOperation `xml:"operation"`
}

func (c *SageIntacctAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("sage_intacct: user external id is required")
	}
	if err := sageRejectUnsafeIdentifier("UserExternalID", user); err != nil {
		return nil, err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	body := c.buildUserQueryXML(cfg, secrets, user)
	status, resp, err := c.doXMLStatus(ctx, body)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("sage_intacct: list entitlements status %d: %s", status, string(resp))
	}
	if sageBodyIsNotFound(resp) {
		return nil, nil
	}
	var parsed sageEntitlementResponse
	if err := xml.Unmarshal(resp, &parsed); err != nil {
		return nil, fmt.Errorf("sage_intacct: decode entitlements: %w", err)
	}
	out := make([]access.Entitlement, 0)
	for _, u := range parsed.Operation.Result.Data.Users {
		if !strings.EqualFold(strings.TrimSpace(u.UserID), user) {
			continue
		}
		for _, r := range u.Roles {
			role := strings.TrimSpace(r.RoleID)
			if role == "" {
				continue
			}
			out = append(out, access.Entitlement{
				ResourceExternalID: role,
				Role:               role,
				Source:             "direct",
			})
		}
	}
	return out, nil
}

func sageBodyIsError(body []byte) bool {
	return strings.Contains(strings.ToLower(string(body)), "<errormessage")
}
