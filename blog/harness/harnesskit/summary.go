package harnesskit

import "time"

// Summary is the authoritative record the seed harness writes to
// blog/artifacts/seed-summary.json. Counts are server-side (read back via GET
// after seeding) so a re-run reports the true present state rather than only
// what a single run created. The IDs let the capture harness fill path
// parameters (review id, campaign id, connector ids) without guessing.
type Summary struct {
	GeneratedAt time.Time          `json:"generated_at"`
	APIBase     string             `json:"api_base"`
	Workspaces  []WorkspaceSummary `json:"workspaces"`
}

// WorkspaceSummary is one workspace's seeded state.
type WorkspaceSummary struct {
	Index       int    `json:"index"`
	Slug        string `json:"slug"`
	Name        string `json:"name"`
	Region      string `json:"region"`
	Industry    string `json:"industry"`
	TenantID    string `json:"tenant_id"`
	WorkspaceID string `json:"workspace_id"`
	Locale      string `json:"locale"`

	Counts WorkspaceCounts `json:"counts"`
	IDs    WorkspaceIDs    `json:"ids"`
}

// WorkspaceCounts are the server-side collection sizes used as ground truth.
type WorkspaceCounts struct {
	Members         int `json:"members"`
	Connectors      int `json:"connectors"`
	Policies        int `json:"policies"`
	PoliciesActive  int `json:"policies_active"`
	AccessRequests  int `json:"access_requests"`
	Grants          int `json:"grants"`
	ReviewItems     int `json:"review_items"`
	CampaignItems   int `json:"campaign_items"`
	OrphanAccounts  int `json:"orphan_accounts"`
	EvidenceRecords int `json:"evidence_records"`
}

// WorkspaceIDs are the identifiers the capture harness needs to address
// per-workspace detail endpoints.
type WorkspaceIDs struct {
	ReviewID        string   `json:"review_id"`
	CampaignID      string   `json:"campaign_id"`
	ManualConnector string   `json:"manual_connector_id"`
	ConnectorIDs    []string `json:"connector_ids"`
	PolicyIDs       []string `json:"policy_ids"`
}
