package access

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

// ErrValidation is the access-package sentinel for a caller-supplied input that
// fails validation (e.g. a catalogue query missing its workspace, or a setup
// assistant request without a provider). Handlers map it to HTTP 400 so a
// client mistake is never reported as an internal fault.
var ErrValidation = errors.New("access: validation failed")

// ConnectorCatalogueEntry is one row in the response to GET /api/v1/connectors.
// It pairs the static, registry-derived capability descriptor for a connector
// (which capabilities the binary exposes for that provider) with the
// workspace-scoped connection state (whether the operator has actually
// connected this provider to the workspace yet).
//
// The shape is intentionally wider than a bare connector row because the
// catalogue is what the Admin UI's connector gallery renders — it must show
// every provider the binary ships, not just the ones that already have an
// access_connectors row.
type ConnectorCatalogueEntry struct {
	CapabilityDescriptor
	// Connected is true when the workspace already has at least one
	// access_connectors row for this provider.
	Connected bool `json:"connected"`
	// ConnectorID is the access_connectors.id for the workspace's existing
	// connection when Connected is true. Empty otherwise. Surfaced so the
	// gallery can deep-link the tile straight into the connector detail page
	// without a second query.
	ConnectorID string `json:"connector_id,omitempty"`
	// Status mirrors access_connectors.status for the workspace's existing row
	// when Connected is true. Empty otherwise.
	Status string `json:"status,omitempty"`
}

// ConnectorCatalogueQuery is the input contract for ListCatalogue. WorkspaceID
// is required so the per-workspace connection enrichment can be scoped to one
// tenant; the catalogue is never served unscoped across workspaces.
//
// The optional filters are ANDed together. Capability matches either a
// user-facing or an operational capability key. Tier and Category match
// case-insensitively. Connected is a tri-state filter on the per-workspace
// connection state: nil means "don't filter" (return all providers), a pointer
// to true restricts to providers the workspace has already connected, and a
// pointer to false restricts to providers it has not — so connected=false is
// distinguishable from an omitted filter (a plain bool's zero value could not
// express that distinction).
type ConnectorCatalogueQuery struct {
	WorkspaceID uuid.UUID
	Capability  string
	Tier        string
	Category    string
	Connected   *bool
}

// AccessConnectorCatalogueService backs GET /api/v1/connectors. It enumerates
// the curated connector catalog (which is pinned to the process-global registry
// by the completeness test) rather than reading connector definitions from the
// DB, so the catalogue is the single source of truth for "which connectors does
// this binary ship and what can each one do?".
type AccessConnectorCatalogueService struct {
	db *gorm.DB
}

// NewAccessConnectorCatalogueService returns a service bound to db. db may be
// nil — the service still enumerates the catalog but every entry comes back
// Connected=false (the per-workspace enrichment is skipped). This keeps dev
// binaries and unit tests functional without a database.
func NewAccessConnectorCatalogueService(db *gorm.DB) *AccessConnectorCatalogueService {
	return &AccessConnectorCatalogueService{db: db}
}

// ListCatalogue returns one entry per curated connector, sorted by provider
// key, after applying q's filters. When q.WorkspaceID is set and the service
// has a DB, entries for providers the workspace has connected are enriched with
// the matching access_connectors row's id + status (the most-recently-updated
// row wins when a workspace has several connections for one provider, e.g. two
// AWS accounts).
func (s *AccessConnectorCatalogueService) ListCatalogue(ctx context.Context, q ConnectorCatalogueQuery) ([]ConnectorCatalogueEntry, error) {
	if q.WorkspaceID == uuid.Nil {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}

	descriptors := ListCapabilityDescriptors()
	connected, err := s.connectedProviders(ctx, q.WorkspaceID)
	if err != nil {
		return nil, err
	}

	out := make([]ConnectorCatalogueEntry, 0, len(descriptors))
	for _, d := range descriptors {
		if !matchesCatalogueFilter(d, q) {
			continue
		}
		entry := ConnectorCatalogueEntry{CapabilityDescriptor: d}
		if row, ok := connected[d.Provider]; ok {
			entry.Connected = true
			entry.ConnectorID = row.ID.String()
			entry.Status = row.Status
		}
		if q.Connected != nil && *q.Connected != entry.Connected {
			continue
		}
		out = append(out, entry)
	}
	return out, nil
}

// connectedProviders returns the freshest access_connectors row per provider
// for the workspace. Returns an empty map (never an error) when the service has
// no DB so the catalogue degrades to "nothing connected yet".
func (s *AccessConnectorCatalogueService) connectedProviders(ctx context.Context, workspaceID uuid.UUID) (map[string]models.AccessConnector, error) {
	if s == nil || s.db == nil {
		return map[string]models.AccessConnector{}, nil
	}
	var rows []models.AccessConnector
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ?", workspaceID).
		Order("provider asc, updated_at desc").
		Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("access: list access_connectors for catalogue: %w", err)
	}
	connected := make(map[string]models.AccessConnector, len(rows))
	for i := range rows {
		row := rows[i]
		// Order is "provider asc, updated_at desc" so the first row seen per
		// provider is the freshest; later rows for the same provider are
		// ignored for catalogue deep-linking purposes.
		if _, exists := connected[row.Provider]; exists {
			continue
		}
		connected[row.Provider] = row
	}
	return connected, nil
}

// CatalogueEntryFor returns the single catalogue entry for one provider,
// enriched with the workspace's connection state, for the connector detail
// page. The bool is false when the provider key has no curated catalog entry
// (the handler maps that to 404). workspaceID is required so the connection
// enrichment is scoped to one tenant.
func (s *AccessConnectorCatalogueService) CatalogueEntryFor(ctx context.Context, workspaceID uuid.UUID, provider string) (ConnectorCatalogueEntry, bool, error) {
	if workspaceID == uuid.Nil {
		return ConnectorCatalogueEntry{}, false, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	d, ok := CapabilityDescriptorFor(provider)
	if !ok {
		return ConnectorCatalogueEntry{}, false, nil
	}
	entry := ConnectorCatalogueEntry{CapabilityDescriptor: d}
	connected, err := s.connectedProviders(ctx, workspaceID)
	if err != nil {
		return ConnectorCatalogueEntry{}, false, err
	}
	if row, ok := connected[provider]; ok {
		entry.Connected = true
		entry.ConnectorID = row.ID.String()
		entry.Status = row.Status
	}
	return entry, true, nil
}

// matchesCatalogueFilter reports whether a descriptor satisfies every non-empty
// filter in q (the filters are ANDed). The Connected dimension is
// applied by the caller after enrichment, so it is not handled here.
func matchesCatalogueFilter(d CapabilityDescriptor, q ConnectorCatalogueQuery) bool {
	if q.Capability != "" && !d.HasCapability(q.Capability) {
		return false
	}
	if q.Tier != "" && !strings.EqualFold(d.Tier, q.Tier) {
		return false
	}
	if q.Category != "" && !strings.EqualFold(d.Category, q.Category) {
		return false
	}
	return true
}

// CatalogueFacets is the set of distinct filter values present across the whole
// catalog, so the UI can render its tier / category / capability filter
// controls without hard-coding the vocabulary.
type CatalogueFacets struct {
	Tiers                   []string `json:"tiers"`
	Categories              []string `json:"categories"`
	UserFacingCapabilities  []string `json:"user_facing_capabilities"`
	OperationalCapabilities []string `json:"operational_capabilities"`
}

// Facets returns the distinct tiers and categories present in the catalog
// (sorted) plus the fixed capability vocabularies. It powers the gallery's
// filter controls.
func (s *AccessConnectorCatalogueService) Facets() CatalogueFacets {
	tierSet := map[string]struct{}{}
	catSet := map[string]struct{}{}
	for _, d := range connectorCatalog {
		tierSet[d.Tier] = struct{}{}
		catSet[d.Category] = struct{}{}
	}
	return CatalogueFacets{
		Tiers:      sortedKeys(tierSet),
		Categories: sortedKeys(catSet),
		UserFacingCapabilities: []string{
			CapabilitySyncIdentity,
			CapabilityProvisionAccess,
			CapabilityListEntitlements,
			CapabilityGetAccessLog,
			CapabilitySSOFederation,
		},
		OperationalCapabilities: []string{
			CapabilityGroupSync,
			CapabilityIdentityDeltaSync,
			CapabilityAccessAuditOperations,
			CapabilitySCIMProvisioning,
			CapabilitySessionRevoke,
			CapabilitySSOEnforcementCheck,
			CapabilityCredentialRenewal,
		},
	}
}

func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
