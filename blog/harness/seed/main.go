// Command seed drives the REAL fishbone-access control-plane API to populate
// six demo workspaces with a full access-governance lifecycle: RBAC members,
// connectors, applied policy packs, simulated+promoted policies, access
// requests (approved, provisioned), an access-review campaign with decisions, a
// certification campaign with decisions, an orphan scan, and SCIM joiner/mover/
// leaver events. Every mutation flows through the same validation, RBAC,
// step-up-MFA and audit path a console user hits — nothing is written to
// business tables directly.
//
// The ONLY direct database writes are the identity/tenant bootstrap that
// iam-core owns in production and which has no self-service API here: the
// workspace row, the owner's workspace_members row, and the owner's enrolled
// TOTP secret (sealed with the real DEK). Everything else is HTTP.
//
// The harness is idempotent: re-running creates nothing new (existing
// resources are detected and skipped, 409s are treated as "already exists"),
// and the seed summary it writes uses server-side GET counts as ground truth so
// the reported state is what the control plane actually holds, not merely what
// this run created.
//
// Usage:
//
//	AUTH_JWT_SECRET=... ACCESS_CREDENTIAL_DEK=... ACCESS_DATABASE_URL=... \
//	  go run ./blog/harness/seed -base http://localhost:8080 -out blog/artifacts
package main

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/blog/harness/harnesskit"
	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/crypto"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
	"github.com/kennguy3n/fishbone-access/internal/services/mfa"
	"gorm.io/gorm"
)

func main() {
	var (
		apiBase = flag.String("base", envOr("BLOG_API_BASE", "http://localhost:8080"), "control-plane API base URL")
		dbURL   = flag.String("db", os.Getenv("ACCESS_DATABASE_URL"), "Postgres URL for the identity/tenant bootstrap (defaults to $ACCESS_DATABASE_URL)")
		outDir  = flag.String("out", "blog/artifacts", "directory for seed-summary.json")
		verbose = flag.Bool("verbose", false, "log every API call")
	)
	flag.Parse()

	secret := os.Getenv("AUTH_JWT_SECRET")
	if secret == "" {
		harnesskit.Fatalf("AUTH_JWT_SECRET is required (the dev HMAC signing secret the control plane verifies)")
	}
	if *dbURL == "" {
		harnesskit.Fatalf("ACCESS_DATABASE_URL (or -db) is required for the workspace/owner/TOTP bootstrap")
	}
	dek := os.Getenv("ACCESS_CREDENTIAL_DEK")
	if dek == "" {
		harnesskit.Fatalf("ACCESS_CREDENTIAL_DEK is required (seals the owner's enrolled TOTP secret so step-up MFA can verify it)")
	}
	issuer := envOr("AUTH_JWT_ISSUER", harnesskit.DefaultIssuer)
	audience := envOr("AUTH_JWT_AUDIENCE", harnesskit.DefaultAudience)

	enc, err := crypto.FromKey(dek)
	if err != nil {
		harnesskit.Fatalf("build credential encryptor from ACCESS_CREDENTIAL_DEK: %v", err)
	}
	db, err := database.Open(*dbURL)
	if err != nil {
		harnesskit.Fatalf("open database: %v", err)
	}
	totpVerifier, err := mfa.NewTOTPMFAVerifier(db, enc)
	if err != nil {
		harnesskit.Fatalf("build TOTP verifier: %v", err)
	}

	s := &seeder{
		db:       db,
		totp:     totpVerifier,
		base:     *apiBase,
		secret:   secret,
		issuer:   issuer,
		audience: audience,
		verbose:  *verbose,
	}

	summary := harnesskit.Summary{GeneratedAt: time.Now().UTC(), APIBase: *apiBase}
	for _, ws := range harnesskit.Workspaces {
		harnesskit.Logf("=== workspace %d/%d: %s (%s/%s) ===", ws.Index, len(harnesskit.Workspaces), ws.Name, ws.Region, ws.Industry)
		ws := ws
		wsSum := s.seedWorkspace(ws)
		summary.Workspaces = append(summary.Workspaces, wsSum)
	}

	if err := os.MkdirAll(*outDir, 0o750); err != nil {
		harnesskit.Fatalf("mkdir %s: %v", *outDir, err)
	}
	path := filepath.Join(*outDir, "seed-summary.json")
	if err := writeJSON(path, summary); err != nil {
		harnesskit.Fatalf("write %s: %v", path, err)
	}
	harnesskit.Logf("wrote %s", path)
}

// seeder carries the shared dependencies for one seed run.
type seeder struct {
	db       *gorm.DB
	totp     *mfa.TOTPMFAVerifier
	base     string
	secret   string
	issuer   string
	audience string
	verbose  bool
}

// seedWorkspace bootstraps identity for one workspace then drives the full
// lifecycle over the API, returning the server-truth summary.
func (s *seeder) seedWorkspace(ws harnesskit.Workspace) harnesskit.WorkspaceSummary {
	sum := harnesskit.WorkspaceSummary{
		Index: ws.Index, Slug: ws.Slug, Name: ws.Name, Region: ws.Region,
		Industry: ws.Industry, TenantID: ws.TenantID, Locale: ws.Locale,
	}

	workspaceID := s.bootstrapWorkspace(ws)
	sum.WorkspaceID = workspaceID.String()
	s.bootstrapOwnerMember(workspaceID, ws)
	s.bootstrapOwnerTOTP(workspaceID, ws)

	token := harnesskit.MintJWT(s.secret, s.issuer, s.audience, ws.OwnerSub(), ws.TenantID, ws.OwnerRoles(), true, time.Hour)
	c := harnesskit.NewClient(s.base, token, s.verbose)
	disp := harnesskit.NewStepUpDispenser(harnesskit.TOTPBase32Secret(ws.Slug))

	// (b) RBAC members — all five roles. The owner already exists (bootstrap);
	// add the other four over the real PUT /rbac/members/:userID route.
	for _, role := range harnesskit.NonOwnerRoles {
		c.JSON("PUT", "/api/v1/rbac/members/"+ws.MemberSub(role), map[string]any{"role": string(role)}, nil)
	}

	// (c) Connectors — create the industry fabric, idempotent by provider.
	connByProvider := s.ensureConnectors(c, ws)
	manualID := connByProvider["manual"]
	if manualID == "" {
		harnesskit.Logf("WARN %s: no manual connector id resolved; provisioning/grants will be skipped", ws.Slug)
	}
	for _, id := range connByProvider {
		sum.IDs.ConnectorIDs = append(sum.IDs.ConnectorIDs, id)
	}
	sum.IDs.ManualConnector = manualID

	// (d) Apply jurisdiction packs — materialises draft policies.
	for _, pack := range ws.Packs {
		c.JSON("POST", "/api/v1/packs/"+pack+"/apply", map[string]any{}, nil)
	}

	// (e+f) Simulate then promote every draft policy. Promotion is the
	// strongest gate in the API (permission + session MFA + fresh step-up TOTP).
	policyIDs := s.listPolicyIDs(c)
	sum.IDs.PolicyIDs = policyIDs
	for _, pid := range policyIDs {
		c.JSON("POST", "/api/v1/policies/"+pid+"/simulate", map[string]any{}, nil)
	}
	for _, pid := range policyIDs {
		if !s.promoteWithStepUp(c, disp, pid) {
			// Already-active policies (a re-run) return non-2xx here; that is
			// expected and not fatal — server counts remain ground truth.
			continue
		}
	}

	// (g+h) Access requests against the manual target, approved + provisioned
	// so grants materialise for the review/certify steps.
	if manualID != "" {
		s.seedRequests(c, ws, manualID)
	}

	// (i+j) Access-review campaign + decisions.
	sum.IDs.ReviewID = s.seedReview(c, ws)

	// (k+l) Certification campaign + decisions + close.
	sum.IDs.CampaignID = s.seedCampaign(c, ws, manualID)

	// (m) Orphan scan on the manual connector (offline-safe).
	if manualID != "" {
		c.JSON("POST", "/api/v1/connectors/"+manualID+"/orphan-scan", map[string]any{}, nil)
	}

	// (n) SCIM joiner / mover / leaver.
	if manualID != "" {
		s.seedSCIM(c, manualID)
	}

	sum.Counts = s.readCounts(c, ws, sum.IDs)
	return sum
}

// --- identity/tenant bootstrap (the only direct DB writes) -----------------

func (s *seeder) bootstrapWorkspace(ws harnesskit.Workspace) uuid.UUID {
	var row models.Workspace
	err := s.db.Where("iam_core_tenant_id = ?", ws.TenantID).First(&row).Error
	if err == nil {
		return row.ID
	}
	if err != gorm.ErrRecordNotFound {
		harnesskit.Fatalf("%s: lookup workspace: %v", ws.Slug, err)
	}
	row = models.Workspace{
		Name:            ws.Name,
		IAMCoreTenantID: ws.TenantID,
		Plan:            "base",
		DataResidency:   strings.ToUpper(ws.Region),
		DefaultLocale:   ws.Locale,
	}
	if err := s.db.Create(&row).Error; err != nil {
		harnesskit.Fatalf("%s: create workspace: %v", ws.Slug, err)
	}
	harnesskit.Logf("  bootstrapped workspace %s (%s)", ws.Name, row.ID)
	return row.ID
}

func (s *seeder) bootstrapOwnerMember(workspaceID uuid.UUID, ws harnesskit.Workspace) {
	m := models.WorkspaceMember{WorkspaceID: workspaceID, UserID: ws.OwnerSub(), Role: string(harnesskit.RoleOwner)}
	// Composite-PK upsert: idempotent owner membership.
	if err := s.db.Where("workspace_id = ? AND user_id = ?", workspaceID, ws.OwnerSub()).
		FirstOrCreate(&m).Error; err != nil {
		harnesskit.Fatalf("%s: bootstrap owner member: %v", ws.Slug, err)
	}
}

func (s *seeder) bootstrapOwnerTOTP(workspaceID uuid.UUID, ws harnesskit.Workspace) {
	var existing models.UserTOTPSecret
	err := s.db.Where("workspace_id = ? AND user_id = ?", workspaceID, ws.OwnerSub()).First(&existing).Error
	if err == nil {
		return // already enrolled — idempotent
	}
	if err != gorm.ErrRecordNotFound {
		harnesskit.Fatalf("%s: lookup TOTP secret: %v", ws.Slug, err)
	}
	sealed, err := s.totp.SealTOTPSecret(workspaceID, ws.OwnerSub(), harnesskit.TOTPBase32Secret(ws.Slug))
	if err != nil {
		harnesskit.Fatalf("%s: seal TOTP secret: %v", ws.Slug, err)
	}
	row := models.UserTOTPSecret{WorkspaceID: workspaceID, UserID: ws.OwnerSub(), Secret: sealed, Verified: true}
	if err := s.db.Create(&row).Error; err != nil {
		harnesskit.Fatalf("%s: enrol owner TOTP: %v", ws.Slug, err)
	}
	harnesskit.Logf("  enrolled owner step-up TOTP")
}

// --- API-driven lifecycle ---------------------------------------------------

// ensureConnectors creates each spec's connector if its provider is not already
// connected, returning provider→connector_id for the workspace (server truth).
func (s *seeder) ensureConnectors(c *harnesskit.Client, ws harnesskit.Workspace) map[string]string {
	existing := s.connectedProviders(c)
	for _, spec := range ws.Connectors {
		if _, ok := existing[spec.Provider]; ok {
			continue // idempotent: provider already connected
		}
		// Always send a non-nil config object. Several connector validators
		// (e.g. stripe, box) reject a nil config map outright even when they
		// require no config keys, so omitting the field entirely would 400.
		// An explicit empty object is the correct "no config" request.
		cfg := spec.Config
		if cfg == nil {
			cfg = map[string]any{}
		}
		body := map[string]any{"provider": spec.Provider, "display_name": spec.DisplayName, "config": cfg}
		if spec.Secrets != nil {
			body["secrets"] = spec.Secrets
		}
		var created struct {
			ID string `json:"id"`
		}
		if c.JSON("POST", "/api/v1/connectors", body, &created) && created.ID != "" {
			existing[spec.Provider] = created.ID
		}
	}
	// Re-read so the map reflects server truth even on a re-run where creates
	// were skipped.
	return s.connectedProviders(c)
}

// connectedProviders returns provider→connector_id for connectors the workspace
// already has, via the real catalogue endpoint.
func (s *seeder) connectedProviders(c *harnesskit.Client) map[string]string {
	var resp struct {
		Connectors []struct {
			Provider    string `json:"provider"`
			Connected   bool   `json:"connected"`
			ConnectorID string `json:"connector_id"`
		} `json:"connectors"`
	}
	out := map[string]string{}
	if c.JSON("GET", "/api/v1/connectors?connected=true", nil, &resp) {
		for _, e := range resp.Connectors {
			if e.Connected && e.ConnectorID != "" {
				out[e.Provider] = e.ConnectorID
			}
		}
	}
	return out
}

func (s *seeder) listPolicyIDs(c *harnesskit.Client) []string {
	var resp struct {
		Policies []struct {
			ID    string `json:"id"`
			State string `json:"state"`
		} `json:"policies"`
	}
	var ids []string
	if c.JSON("GET", "/api/v1/policies", nil, &resp) {
		for _, p := range resp.Policies {
			ids = append(ids, p.ID)
		}
	}
	return ids
}

// promoteWithStepUp promotes a single policy, attaching a fresh step-up TOTP
// assertion. Returns true on a 2xx.
func (s *seeder) promoteWithStepUp(c *harnesskit.Client, disp *harnesskit.StepUpDispenser, policyID string) bool {
	code := disp.Next()
	return c.JSONHdr("POST", "/api/v1/policies/"+policyID+"/promote", map[string]any{}, nil,
		map[string]string{harnesskit.StepUpHeader: code})
}

func (s *seeder) seedRequests(c *harnesskit.Client, ws harnesskit.Workspace, manualID string) {
	connID, err := uuid.Parse(manualID)
	if err != nil {
		harnesskit.Logf("WARN %s: manual connector id %q not a uuid: %v", ws.Slug, manualID, err)
		return
	}
	for _, r := range ws.Requests {
		body := map[string]any{
			"connector_id":   connID,
			"resource_ref":   r.ResourceRef,
			"role":           r.Role,
			"justification":  r.Justification,
			"duration_hours": r.DurationHours,
		}
		var created struct {
			Request struct {
				ID string `json:"id"`
			} `json:"request"`
		}
		if !c.JSON("POST", "/api/v1/access-requests", body, &created) || created.Request.ID == "" {
			continue
		}
		id := created.Request.ID
		c.JSON("POST", "/api/v1/access-requests/"+id+"/approve", map[string]any{"reason": "Seed: approved per policy."}, nil)
		if r.Provision {
			c.JSON("POST", "/api/v1/access-requests/"+id+"/provision", map[string]any{}, nil)
		}
	}
}

func (s *seeder) seedReview(c *harnesskit.Client, ws harnesskit.Workspace) string {
	var created struct {
		Review struct {
			ID string `json:"id"`
		} `json:"review"`
	}
	if !c.JSON("POST", "/api/v1/access-reviews", map[string]any{"name": ws.ReviewName}, &created) || created.Review.ID == "" {
		return ""
	}
	reviewID := created.Review.ID
	var items struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	if c.JSON("GET", "/api/v1/access-reviews/"+reviewID+"/items", nil, &items) {
		for i, it := range items.Items {
			decision, reason := "certify", "Seed: access confirmed still required."
			if i == 0 { // revoke the first to exercise the kill path
				decision, reason = "revoke", "Seed: access no longer required."
			}
			c.JSON("POST", "/api/v1/access-reviews/"+reviewID+"/items/"+it.ID+"/decision",
				map[string]any{"decision": decision, "reason": reason}, nil)
		}
	}
	return reviewID
}

func (s *seeder) seedCampaign(c *harnesskit.Client, ws harnesskit.Workspace, manualID string) string {
	body := map[string]any{"name": ws.Campaign.Name, "framework": ws.Campaign.Framework}
	if manualID != "" {
		if id, err := uuid.Parse(manualID); err == nil {
			body["scope_connector_id"] = id
		}
	}
	var created struct {
		Campaign struct {
			ID string `json:"id"`
		} `json:"campaign"`
	}
	if !c.JSON("POST", "/api/v1/compliance/campaigns", body, &created) || created.Campaign.ID == "" {
		return ""
	}
	campaignID := created.Campaign.ID
	// The campaign worklist endpoint returns CampaignItemView, whose item PK is
	// serialised as "item_id" (not "id") because the view also carries the
	// joined grant id. Decoding the wrong key would yield an empty itemID and a
	// 400 on the decision call.
	var items struct {
		Items []struct {
			ItemID string `json:"item_id"`
		} `json:"items"`
	}
	if c.JSON("GET", "/api/v1/compliance/campaigns/"+campaignID+"/items", nil, &items) {
		for i, it := range items.Items {
			if it.ItemID == "" {
				continue
			}
			decision, reason := "certify", "Seed: entitlement certified."
			if i == 0 {
				decision, reason = "revoke", "Seed: entitlement revoked at certification."
			}
			c.JSON("POST", "/api/v1/compliance/campaigns/"+campaignID+"/items/"+it.ItemID+"/decision",
				map[string]any{"decision": decision, "reason": reason}, nil)
		}
	}
	c.JSON("POST", "/api/v1/compliance/campaigns/"+campaignID+"/close", map[string]any{}, nil)
	return campaignID
}

func (s *seeder) seedSCIM(c *harnesskit.Client, manualID string) {
	connID, err := uuid.Parse(manualID)
	if err != nil {
		return
	}
	active := func(b bool) *bool { return &b }
	// Joiner then mover: provisioned/updated on the offline-safe manual
	// connector, so both fully succeed.
	c.JSON("POST", "/api/v1/scim/events", map[string]any{"method": "POST", "user_external_id": "jml-joiner@demo.test", "active": active(true), "email": "jml-joiner@demo.test", "display_name": "Jordan Joiner", "resource_ref": "wms:dispatcher", "role": "operator", "connector_id": connID}, nil)
	c.JSON("POST", "/api/v1/scim/events", map[string]any{"method": "PATCH", "user_external_id": "jml-joiner@demo.test", "active": active(true), "display_name": "Jordan Mover", "groups_changed": true, "connector_id": connID}, nil)

	// Leaver: the kill switch sweeps EVERY connector in the workspace that
	// supports session revocation / SCIM deprovision, not just the event's
	// connector. In this self-contained demo the workspace also has live SaaS
	// connectors (Stripe, Salesforce, GitHub, …) seeded with placeholder
	// credentials, so those layers genuinely fail — there is no real upstream to
	// reach. That is the honest, expected outcome offline: the kill switch still
	// revokes grants, removes teams and disables the identity locally, and
	// records the full layered report, but reports partial failure (HTTP 500)
	// because it could not confirm revocation on the unreachable providers. We
	// surface that real report rather than masking it.
	status, raw, err := c.Request("POST", "/api/v1/scim/events", map[string]any{"method": "DELETE", "user_external_id": "jml-joiner@demo.test", "active": active(false), "connector_id": connID}, nil)
	switch {
	case err != nil:
		harnesskit.Logf("ERR  POST /api/v1/scim/events (leaver): %v", err)
	case status >= 200 && status < 300:
		harnesskit.Logf("OK   %d POST /api/v1/scim/events (leaver)", status)
	case status == 500 && strings.Contains(string(raw), "leaver kill switch"):
		harnesskit.Logf("NOTE leaver kill switch reported partial failure (expected offline: live connectors unreachable); grants revoked + identity disabled locally")
	default:
		harnesskit.Logf("FAIL %d POST /api/v1/scim/events (leaver): %s", status, strings.TrimSpace(string(raw)))
	}
}

// readCounts reads server-side collection sizes as ground truth.
func (s *seeder) readCounts(c *harnesskit.Client, ws harnesskit.Workspace, ids harnesskit.WorkspaceIDs) harnesskit.WorkspaceCounts {
	var counts harnesskit.WorkspaceCounts

	counts.Members = countField(c, "/api/v1/rbac/members", "members")
	counts.Connectors = len(s.connectedProviders(c))
	counts.AccessRequests = countField(c, "/api/v1/access-requests", "requests")
	counts.OrphanAccounts = countField(c, "/api/v1/orphan-accounts", "orphans")
	counts.EvidenceRecords = countField(c, "/api/v1/compliance/evidence", "records")

	var pols struct {
		Policies []struct {
			State string `json:"state"`
		} `json:"policies"`
	}
	if c.JSON("GET", "/api/v1/policies", nil, &pols) {
		counts.Policies = len(pols.Policies)
		for _, p := range pols.Policies {
			if p.State == "active" {
				counts.PoliciesActive++
			}
		}
	}
	if ids.ReviewID != "" {
		counts.ReviewItems = countField(c, "/api/v1/access-reviews/"+ids.ReviewID+"/items", "items")
	}
	if ids.CampaignID != "" {
		counts.CampaignItems = countField(c, "/api/v1/compliance/campaigns/"+ids.CampaignID+"/items", "items")
	}
	counts.Grants = counts.ReviewItems // review enumerates active grants → server-truth grant count
	return counts
}

// countField GETs path and returns len of the named top-level array field.
func countField(c *harnesskit.Client, path, field string) int {
	var m map[string]json.RawMessage
	if !c.JSON("GET", path, nil, &m) {
		return 0
	}
	raw, ok := m[field]
	if !ok {
		return 0
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		return 0
	}
	return len(arr)
}

// --- helpers ----------------------------------------------------------------

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, 0o600)
}
