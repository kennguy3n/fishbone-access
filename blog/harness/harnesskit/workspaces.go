package harnesskit

// Role is a workspace RBAC role seeded for each workspace. The owner is
// bootstrapped as the harness identity; the other four are added over the real
// PUT /rbac/members/:userID route.
type Role string

const (
	RoleOwner    Role = "owner"
	RoleAdmin    Role = "admin"
	RoleSecurity Role = "security_admin"
	RoleOperator Role = "operator"
	RoleAuditor  Role = "auditor"
)

// NonOwnerRoles are the roles seeded via the RBAC API (the owner is the
// bootstrapped harness identity and already exists as a member).
var NonOwnerRoles = []Role{RoleAdmin, RoleSecurity, RoleOperator, RoleAuditor}

// ConnectorSpec is one connector to create in a workspace. Config/Secrets are
// the minimal well-formed inputs each provider's Validate accepts offline (no
// network) — they are demo credentials, never real. Manual marks the
// manually-fulfilled target the lifecycle provisions grants against (the only
// provider whose ProvisionAccess succeeds without a live upstream).
type ConnectorSpec struct {
	Provider    string
	DisplayName string
	Config      map[string]any
	Secrets     map[string]any
	Manual      bool
}

// AccessRequestSpec is one access request to create, approve and (for the
// manual target) provision, yielding an active grant that access reviews and
// certification campaigns then enumerate.
type AccessRequestSpec struct {
	ResourceRef   string
	Role          string
	Justification string
	DurationHours int
	// Provision is set only for requests against the manual connector — the
	// grant materialises locally so downstream review/certify steps have items.
	Provision bool
}

// PAMTargetSpec is one privileged target (a cloud VM over SSH, a managed
// database over its native wire protocol, or a Kubernetes API) the harness
// registers in the PAM vault. Address is a demo endpoint that is never dialed
// in the self-contained run (the control-plane lease lifecycle is exercised
// over HTTP; an actual recorded session needs the pam-gateway and a reachable
// upstream — see the PAM post's "where we fall short"). Kind is a human label
// for the narrative ("cloud VM", "database", "Kubernetes"). When Lease is set
// the harness drives the full just-in-time lifecycle against the target:
// request lease → sponsor approval (step-up MFA) → mint connect-token (step-up
// MFA when RequireMFA) → expire.
type PAMTargetSpec struct {
	Name       string
	Protocol   string // ssh, postgres, mysql, k8s-exec, …
	Address    string
	Username   string
	Kind       string
	RequireMFA bool
	LeaseTTL   int // seconds; the short JIT window the target allows
	Lease      bool
}

// ContractorSpec is one time-boxed, sponsor-approved external/contractor grant.
// Every contractor grant carries a mandatory expiry and a named internal
// sponsor; the harness drives create → sponsor approval, then either a
// sponsor-approved extension (Extend) or an early revoke (Revoke) so the
// time-box history is non-trivial. Grants are issued against the workspace's
// manual (offline-safe) connector so provisioning succeeds without an upstream.
type ContractorSpec struct {
	ContractorUserID string
	DisplayName      string
	ResourceRef      string
	Role             string
	SponsorID        string
	Justification    string
	Days             int // expiry = now + Days
	Extend           bool
	Revoke           bool
}

// SodRuleSpec is one separation-of-duties toxic-combination rule: holding both
// (ResourceA/RoleA) and (ResourceB/RoleB) is a conflict the engine flags during
// access simulation and surfaces as an anomaly when a real grant set violates
// it.
type SodRuleSpec struct {
	Name        string
	Description string
	Severity    string
	ResourceA   string
	RoleA       string
	ResourceB   string
	RoleB       string
}

// Workspace is one demo tenant: a country/industry scenario with its
// jurisdiction packs, connector fabric, and a realistic access-request set.
type Workspace struct {
	Index    int    // 1-based; drives the s{n}- artifact prefix
	Slug     string // artifact slug, e.g. "sg-acme-payments"
	Name     string
	Region   string // pack region filter: sg, us, de, vn, ae, au
	Industry string
	TenantID string // iam_core_tenant_id claim → workspace resolution
	Locale   string // default UI locale, for the multi-locale screenshot story

	Packs       []string
	Connectors  []ConnectorSpec
	Requests    []AccessRequestSpec
	ReviewName  string
	Campaign    CampaignSpec
	PAMTargets  []PAMTargetSpec
	Contractors []ContractorSpec
	SodRules    []SodRuleSpec
}

// CampaignSpec parameterises the certification campaign started for a workspace.
type CampaignSpec struct {
	Name      string
	Framework string
}

// OwnerSub returns the bootstrapped owner identity for the workspace.
func (w Workspace) OwnerSub() string { return w.Slug + "-owner" }

// MemberSub returns the deterministic subject for a seeded RBAC member role.
func (w Workspace) MemberSub(r Role) string { return w.Slug + "-" + string(r) }

// Roles minted into the workspace owner's token. Cosmetic for tenant RBAC
// (which is resolved from the workspace_members row), but mirrors how an
// iam-core token would carry global roles.
func (w Workspace) OwnerRoles() []string { return []string{string(RoleOwner)} }

// Workspaces is the canonical six-workspace cast for the blog series. Pack IDs
// are the real catalogue IDs served by GET /api/v1/packs.
var Workspaces = []Workspace{
	{
		Index: 1, Slug: "sg-acme-payments", Name: "Acme Payments", Region: "sg",
		Industry: "finance", TenantID: "tenant-sg-acme-payments", Locale: "en",
		Packs: []string{"sg-pdpa-mas-trm", "pci-dss-v4"},
		Connectors: []ConnectorSpec{
			{Provider: "stripe", DisplayName: "Stripe — payments", Config: map[string]any{}, Secrets: map[string]any{"secret_key": "sk_test_acme_payments_demo"}},
			{Provider: "salesforce", DisplayName: "Salesforce — CRM", Config: map[string]any{"instance_url": "https://acme-pay.my.salesforce.com"}, Secrets: map[string]any{"access_token": "00Dxx_demo_acme_salesforce_token"}},
			{Provider: "github", DisplayName: "GitHub — engineering", Config: map[string]any{"organization": "acme-payments"}, Secrets: map[string]any{"access_token": "ghp_demo_acme_payments_token0001"}},
			{Provider: "manual", DisplayName: "MAS TRM privileged ops (manual)", Config: map[string]any{"system_name": "Core ledger admin console", "resource_kind": "shared-account", "fulfilment_contact": "platform-ops"}, Manual: true},
		},
		Requests: []AccessRequestSpec{
			{ResourceRef: "ledger:admin", Role: "operator", Justification: "Quarterly MAS TRM privileged-access recertification requires temporary ledger admin.", DurationHours: 24, Provision: true},
			{ResourceRef: "ledger:reconcile", Role: "operator", Justification: "Month-end reconciliation run for the finance close.", DurationHours: 12, Provision: true},
			{ResourceRef: "cde:pci-scope", Role: "auditor", Justification: "Quarterly PCI-DSS audit requires read access to the CDE for evidence sampling.", DurationHours: 48},
		},
		ReviewName: "Q2 2026 MAS TRM privileged-access review",
		Campaign:   CampaignSpec{Name: "Q2 2026 PCI-DSS v4 cardholder-data certification", Framework: "PCI-DSS"},
		PAMTargets: []PAMTargetSpec{
			{Name: "Ledger DB host (prod-sg-1)", Protocol: "ssh", Address: "ledger-db-1.acme-pay.internal:22", Username: "ops", Kind: "cloud VM", RequireMFA: true, LeaseTTL: 1800, Lease: true},
			{Name: "Core ledger (PostgreSQL)", Protocol: "postgres", Address: "ledger-db-1.acme-pay.internal:5432", Username: "ledger_admin", Kind: "database", RequireMFA: true, LeaseTTL: 1800},
		},
		Contractors: []ContractorSpec{
			{ContractorUserID: "ext-paytech-integrator@vendor.example", DisplayName: "PayTech integration contractor", ResourceRef: "ledger:reconcile", Role: "operator", SponsorID: "sg-admin", Justification: "6-week payment-rails integration; sponsor: Head of Platform.", Days: 42, Extend: true},
			{ContractorUserID: "ext-pentest@security.example", DisplayName: "External penetration tester", ResourceRef: "cde:pci-scope", Role: "auditor", SponsorID: "sg-security_admin", Justification: "PCI-DSS 11.3 annual penetration test, read-only CDE.", Days: 10, Revoke: true},
		},
		SodRules: []SodRuleSpec{
			{Name: "Ledger admin must not also approve reconciliation", Description: "MAS TRM segregation: the same identity cannot both administer the ledger and sign off reconciliation.", Severity: "critical", ResourceA: "ledger:admin", RoleA: "operator", ResourceB: "ledger:reconcile", RoleB: "operator"},
		},
	},
	{
		Index: 2, Slug: "us-globex-health", Name: "Globex Health", Region: "us",
		Industry: "healthcare", TenantID: "tenant-us-globex-health", Locale: "en",
		Packs: []string{"hipaa-security-rule", "us-ccpa-cpra"},
		Connectors: []ConnectorSpec{
			{Provider: "okta", DisplayName: "Okta — workforce SSO", Config: map[string]any{"okta_domain": "globex-health.okta.com"}, Secrets: map[string]any{"api_token": "SSWS_demo_globex_health_okta_tok"}},
			{Provider: "box", DisplayName: "Box — clinical documents", Secrets: map[string]any{"access_token": "demo_globex_box_access_token_0001"}},
			{Provider: "manual", DisplayName: "Epic EHR clinical role (manual)", Config: map[string]any{"system_name": "Epic EHR", "resource_kind": "application-role", "fulfilment_contact": "clinical-systems"}, Manual: true},
		},
		Requests: []AccessRequestSpec{
			{ResourceRef: "ehr:clinician", Role: "operator", Justification: "New hire onboarding to ePHI clinical systems under HIPAA minimum-necessary.", DurationHours: 720, Provision: true},
			{ResourceRef: "ehr:billing", Role: "operator", Justification: "Revenue-cycle analyst needs billing module for claims processing.", DurationHours: 168, Provision: true},
			{ResourceRef: "phi:export", Role: "auditor", Justification: "CCPA/CPRA consumer data-subject access request fulfilment.", DurationHours: 24},
		},
		ReviewName: "Q2 2026 HIPAA ePHI access review",
		Campaign:   CampaignSpec{Name: "Q2 2026 HIPAA Security Rule certification", Framework: "SOC 2"},
		PAMTargets: []PAMTargetSpec{
			{Name: "EHR app server (clinical-app-1)", Protocol: "ssh", Address: "clinical-app-1.globex.internal:22", Username: "ehr-ops", Kind: "cloud VM", RequireMFA: true, LeaseTTL: 900, Lease: true},
			{Name: "ePHI datastore (PostgreSQL)", Protocol: "postgres", Address: "ehr-db-1.globex.internal:5432", Username: "phi_reader", Kind: "database", RequireMFA: true, LeaseTTL: 900},
		},
		Contractors: []ContractorSpec{
			{ContractorUserID: "ext-coding-vendor@billing.example", DisplayName: "Medical-coding vendor", ResourceRef: "ehr:billing", Role: "operator", SponsorID: "us-admin", Justification: "Revenue-cycle coding backlog; minimum-necessary billing module only.", Days: 30, Extend: true},
		},
		SodRules: []SodRuleSpec{
			{Name: "Clinician role must not hold billing export", Description: "HIPAA minimum-necessary: clinical access and billing/claims export are mutually exclusive.", Severity: "high", ResourceA: "ehr:clinician", RoleA: "operator", ResourceB: "ehr:billing", RoleB: "operator"},
		},
	},
	{
		Index: 3, Slug: "de-initech-retail", Name: "Initech Retail", Region: "de",
		Industry: "retail", TenantID: "tenant-de-initech-retail", Locale: "de",
		Packs: []string{"de-bdsg-c5", "gdpr-personal-data", "pci-dss-v4"},
		Connectors: []ConnectorSpec{
			{Provider: "github", DisplayName: "GitHub — e-commerce platform", Config: map[string]any{"organization": "initech-retail"}, Secrets: map[string]any{"access_token": "ghp_demo_initech_retail_token0001"}},
			{Provider: "datadog", DisplayName: "Datadog — observability", Secrets: map[string]any{"api_key": "demo_initech_dd_api_key_000000001", "application_key": "demo_initech_dd_app_key_0000000001"}},
			{Provider: "azure", DisplayName: "Azure — cloud infra", Config: map[string]any{"tenant_id": "initech.onmicrosoft.com", "subscription_id": "00000000-0000-0000-0000-0000000000de"}, Secrets: map[string]any{"client_id": "00000000-0000-0000-0000-00000000c1de", "client_secret": "demo_initech_azure_client_secret"}},
			{Provider: "manual", DisplayName: "SAP retail POS (manual)", Config: map[string]any{"system_name": "SAP retail POS", "resource_kind": "application-role", "fulfilment_contact": "retail-it"}, Manual: true},
		},
		Requests: []AccessRequestSpec{
			{ResourceRef: "pos:store-manager", Role: "operator", Justification: "Seasonal store-manager onboarding under BDSG works-council policy.", DurationHours: 2160, Provision: true},
			{ResourceRef: "pos:cardholder-data", Role: "operator", Justification: "PCI-DSS CDE access for payment-terminal maintenance window.", DurationHours: 8, Provision: true},
			{ResourceRef: "customer:gdpr-export", Role: "auditor", Justification: "GDPR Article 15 data-subject access request export.", DurationHours: 24},
		},
		ReviewName: "Q2 2026 BSI C5 + GDPR access review",
		Campaign:   CampaignSpec{Name: "Q2 2026 BSI C5 logical-access certification", Framework: "ISO 27001"},
		PAMTargets: []PAMTargetSpec{
			{Name: "Azure POS jump host (de-pos-1)", Protocol: "ssh", Address: "pos-jump-1.initech.internal:22", Username: "pos-ops", Kind: "cloud VM", RequireMFA: true, LeaseTTL: 1800, Lease: true},
			{Name: "SAP POS database (MySQL)", Protocol: "mysql", Address: "sap-pos-db-1.initech.internal:3306", Username: "pos_admin", Kind: "database", RequireMFA: true, LeaseTTL: 1800},
		},
		Contractors: []ContractorSpec{
			{ContractorUserID: "ext-pos-integrator@vendor.example", DisplayName: "Seasonal POS integrator", ResourceRef: "pos:store-manager", Role: "operator", SponsorID: "de-admin", Justification: "Holiday-season POS rollout; works-council-approved fixed term.", Days: 60, Extend: true},
		},
		SodRules: []SodRuleSpec{
			{Name: "Store-manager must not hold cardholder-data access", Description: "PCI-DSS 7.x: POS store-manager duties and direct cardholder-data access must be separated.", Severity: "critical", ResourceA: "pos:store-manager", RoleA: "operator", ResourceB: "pos:cardholder-data", RoleB: "operator"},
		},
	},
	{
		Index: 4, Slug: "vn-umbrella-logistics", Name: "Umbrella Logistics", Region: "vn",
		Industry: "any", TenantID: "tenant-vn-umbrella-logistics", Locale: "vi",
		Packs: []string{"vn-pdpd-decree13"},
		Connectors: []ConnectorSpec{
			{Provider: "github", DisplayName: "GitHub — logistics platform", Config: map[string]any{"organization": "umbrella-logistics"}, Secrets: map[string]any{"access_token": "ghp_demo_umbrella_logi_token00001"}},
			{Provider: "slack", DisplayName: "Slack — operations", Secrets: map[string]any{"bot_token": "xoxb-demo-umbrella-logistics-0001"}},
			{Provider: "manual", DisplayName: "Warehouse WMS (manual)", Config: map[string]any{"system_name": "Warehouse management system", "resource_kind": "application-role", "fulfilment_contact": "warehouse-ops"}, Manual: true},
		},
		Requests: []AccessRequestSpec{
			{ResourceRef: "wms:dispatcher", Role: "operator", Justification: "Dispatcher onboarding under PDPD Decree 13 data-handling controls.", DurationHours: 720, Provision: true},
			{ResourceRef: "wms:inventory", Role: "operator", Justification: "Peak-season inventory reconciliation access.", DurationHours: 168, Provision: true},
			{ResourceRef: "pii:decree13-register", Role: "auditor", Justification: "PDPD personal-data processing register review.", DurationHours: 24},
		},
		ReviewName: "Q2 2026 PDPD Decree 13 access review",
		Campaign:   CampaignSpec{Name: "Q2 2026 PDPD Decree 13 certification", Framework: "ISO 27001"},
		PAMTargets: []PAMTargetSpec{
			{Name: "WMS application server (wms-1)", Protocol: "ssh", Address: "wms-1.umbrella.internal:22", Username: "wms-ops", Kind: "cloud VM", RequireMFA: true, LeaseTTL: 1800, Lease: true},
		},
		Contractors: []ContractorSpec{
			{ContractorUserID: "ext-3pl-partner@logistics.example", DisplayName: "3PL partner operator", ResourceRef: "wms:dispatcher", Role: "operator", SponsorID: "vn-admin", Justification: "Peak-season third-party logistics dispatch support.", Days: 45, Revoke: true},
		},
		SodRules: []SodRuleSpec{
			{Name: "Dispatcher must not also adjust inventory", Description: "PDPD operational integrity: dispatch and inventory-adjustment duties are separated to prevent shrinkage fraud.", Severity: "medium", ResourceA: "wms:dispatcher", RoleA: "operator", ResourceB: "wms:inventory", RoleB: "operator"},
		},
	},
	{
		Index: 5, Slug: "ae-northwind-finance", Name: "Northwind Finance", Region: "ae",
		Industry: "finance", TenantID: "tenant-ae-northwind-finance", Locale: "ar",
		Packs: []string{"ae-pdpl-desc", "iso27001-annexa"},
		Connectors: []ConnectorSpec{
			{Provider: "salesforce", DisplayName: "Salesforce — wealth CRM", Config: map[string]any{"instance_url": "https://northwind.my.salesforce.com"}, Secrets: map[string]any{"access_token": "00Dxx_demo_northwind_sfdc_token"}},
			{Provider: "okta", DisplayName: "Okta — workforce SSO", Config: map[string]any{"okta_domain": "northwind.okta.com"}, Secrets: map[string]any{"api_token": "SSWS_demo_northwind_okta_token01"}},
			{Provider: "manual", DisplayName: "Temenos T24 core banking (manual)", Config: map[string]any{"system_name": "Temenos T24", "resource_kind": "privileged-account", "fulfilment_contact": "core-banking-ops"}, Manual: true},
		},
		Requests: []AccessRequestSpec{
			{ResourceRef: "t24:privileged-admin", Role: "operator", Justification: "DESC privileged-access review requires temporary core-banking admin.", DurationHours: 8, Provision: true},
			{ResourceRef: "t24:treasury", Role: "operator", Justification: "Treasury settlement run for end-of-day processing.", DurationHours: 12, Provision: true},
			{ResourceRef: "pdpl:dsr", Role: "auditor", Justification: "UAE PDPL data-subject request fulfilment.", DurationHours: 24},
		},
		ReviewName: "Q2 2026 DESC privileged-access review",
		Campaign:   CampaignSpec{Name: "Q2 2026 ISO 27001 Annex A access certification", Framework: "ISO 27001"},
		PAMTargets: []PAMTargetSpec{
			{Name: "Temenos T24 core-banking host (t24-prod-1)", Protocol: "ssh", Address: "t24-prod-1.northwind.internal:22", Username: "t24-admin", Kind: "cloud VM", RequireMFA: true, LeaseTTL: 900, Lease: true},
			{Name: "Treasury ledger (PostgreSQL)", Protocol: "postgres", Address: "treasury-db-1.northwind.internal:5432", Username: "treasury_ro", Kind: "database", RequireMFA: true, LeaseTTL: 900, Lease: true},
		},
		Contractors: []ContractorSpec{
			{ContractorUserID: "ext-desc-auditor@regulator.example", DisplayName: "DESC external auditor", ResourceRef: "pdpl:dsr", Role: "auditor", SponsorID: "ae-security_admin", Justification: "DESC annual assessment, read-only audit window.", Days: 14, Extend: true},
		},
		SodRules: []SodRuleSpec{
			{Name: "Core-banking admin must not run treasury settlement", Description: "DESC + ISO 27001 A.5.3: privileged core-banking administration and treasury settlement are a catastrophic toxic combination.", Severity: "critical", ResourceA: "t24:privileged-admin", RoleA: "operator", ResourceB: "t24:treasury", RoleB: "operator"},
		},
	},
	{
		Index: 6, Slug: "au-contoso-saas", Name: "Contoso SaaS", Region: "au",
		Industry: "saas", TenantID: "tenant-au-contoso-saas", Locale: "en",
		Packs: []string{"au-privacy-e8", "soc2-logical-access"},
		Connectors: []ConnectorSpec{
			{Provider: "github", DisplayName: "GitHub — product engineering", Config: map[string]any{"organization": "contoso-saas"}, Secrets: map[string]any{"access_token": "ghp_demo_contoso_saas_token000001"}},
			{Provider: "gcp", DisplayName: "GCP — production", Config: map[string]any{"project_id": "contoso-saas-prod"}, Secrets: map[string]any{"service_account_json": `{"type":"service_account","project_id":"contoso-saas-prod","private_key_id":"demo","private_key":"-----BEGIN PRIVATE KEY-----\nMIIDEMOKEYdemo\n-----END PRIVATE KEY-----\n","client_email":"svc@contoso-saas-prod.iam.gserviceaccount.com"}`}},
			{Provider: "slack", DisplayName: "Slack — engineering", Secrets: map[string]any{"bot_token": "xoxb-demo-contoso-saas-00000001"}},
			{Provider: "manual", DisplayName: "Billing console (manual)", Config: map[string]any{"system_name": "Billing console", "resource_kind": "application-role", "fulfilment_contact": "revops"}, Manual: true},
		},
		Requests: []AccessRequestSpec{
			{ResourceRef: "billing:admin", Role: "operator", Justification: "SOC 2 CC6 privileged-access onboarding for revenue operations.", DurationHours: 168, Provision: true},
			{ResourceRef: "prod:deploy", Role: "operator", Justification: "Essential Eight admin-privilege restriction: time-boxed deploy access.", DurationHours: 8, Provision: true},
			{ResourceRef: "soc2:evidence", Role: "auditor", Justification: "SOC 2 Type II auditor evidence sampling.", DurationHours: 72},
		},
		ReviewName: "Q2 2026 SOC 2 Type II recertification",
		Campaign:   CampaignSpec{Name: "Q2 2026 SOC 2 logical-access certification", Framework: "SOC 2"},
		PAMTargets: []PAMTargetSpec{
			{Name: "GCP production VM (prod-au-1)", Protocol: "ssh", Address: "prod-au-1.contoso-saas.internal:22", Username: "sre", Kind: "cloud VM", RequireMFA: true, LeaseTTL: 1800, Lease: true},
			{Name: "Production datastore (PostgreSQL)", Protocol: "postgres", Address: "prod-db-1.contoso-saas.internal:5432", Username: "app_ro", Kind: "database", RequireMFA: true, LeaseTTL: 1800, Lease: true},
		},
		Contractors: []ContractorSpec{
			{ContractorUserID: "ext-sre-oncall@vendor.example", DisplayName: "On-call SRE vendor", ResourceRef: "prod:deploy", Role: "operator", SponsorID: "au-admin", Justification: "Follow-the-sun production on-call cover; Essential Eight time-boxed admin.", Days: 21, Extend: true},
		},
		SodRules: []SodRuleSpec{
			{Name: "Production deploy must not also hold billing admin", Description: "SOC 2 CC6.3 / Essential Eight: production-change and billing-administration duties are separated.", Severity: "high", ResourceA: "prod:deploy", RoleA: "operator", ResourceB: "billing:admin", RoleB: "operator"},
		},
	},
}
