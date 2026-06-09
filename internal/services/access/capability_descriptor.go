package access

import "sort"

// Tier values are the five adoption tiers the connector catalog is grouped by,
// ordered by how often a typical SME brings the connection up first (T1 = core
// identity, day-one; T5 = vertical / niche). They mirror the published matrix.
const (
	TierCoreIdentity        = "T1"
	TierCloudInfrastructure = "T2"
	TierBusinessSaaS        = "T3"
	TierHRFinanceLegal      = "T4"
	TierVerticalNiche       = "T5"
)

// User-facing capability keys. These are the five product surfaces every
// connector is measured against in the catalog. They double as the filter
// vocabulary accepted by the catalogue endpoint (?capability=sync_identity).
const (
	CapabilitySyncIdentity     = "sync_identity"
	CapabilityProvisionAccess  = "provision_access"
	CapabilityListEntitlements = "list_entitlements"
	CapabilityGetAccessLog     = "get_access_log"
	CapabilitySSOFederation    = "sso_federation"
)

// Operational capability keys. These map 1:1 onto the optional Go interfaces a
// connector may implement and are derived purely by type-assertion, so they can
// never drift from the code actually shipped in the binary.
const (
	CapabilityGroupSync             = "group_sync"
	CapabilityIdentityDeltaSync     = "identity_delta_sync"
	CapabilitySCIMProvisioning      = "scim_provisioning"
	CapabilitySessionRevoke         = "session_revoke"
	CapabilitySSOEnforcementCheck   = "sso_enforcement_check"
	CapabilityCredentialRenewal     = "credential_renewal" // #nosec G101 -- capability taxonomy key, not a credential
	CapabilityAccessAuditOperations = "access_audit_stream"
)

// UserFacingCapabilities is the five-dimension product-surface snapshot for a
// connector, sourced from the curated catalog. A flag is true when the upstream
// provider's API actually backs the capability — not merely when the Go method
// exists (every connector implements the mandatory contract, so method presence
// is not evidence of support).
type UserFacingCapabilities struct {
	SyncIdentity     bool `json:"sync_identity"`
	ProvisionAccess  bool `json:"provision_access"`
	ListEntitlements bool `json:"list_entitlements"`
	GetAccessLog     bool `json:"get_access_log"`
	SSOFederation    bool `json:"sso_federation"`
}

// OperationalCapabilities is the optional-interface snapshot for a connector,
// derived at lookup time by type-asserting the registered connector instance
// against the optional interfaces declared in optional_interfaces.go. Because
// the flags come from the live registry they are guaranteed consistent with the
// binary; the completeness test asserts they match the type assertions exactly.
type OperationalCapabilities struct {
	GroupSync           bool `json:"group_sync"`
	IdentityDeltaSync   bool `json:"identity_delta_sync"`
	AccessAuditStream   bool `json:"access_audit_stream"`
	SCIMProvisioning    bool `json:"scim_provisioning"`
	SessionRevoke       bool `json:"session_revoke"`
	SSOEnforcementCheck bool `json:"sso_enforcement_check"`
	CredentialRenewal   bool `json:"credential_renewal"`
}

// CapabilityDescriptor is the complete, structured capability snapshot for one
// connector: its curated product metadata, the five user-facing capability
// flags, and the type-asserted operational capability flags. It is the shape
// the capability-matrix API and UI render. Registered reports whether the
// provider key actually resolves to a connector in the process registry — a
// descriptor with Registered=false is a curated row whose blank-import never
// ran (a build/wiring bug the completeness test guards against).
type CapabilityDescriptor struct {
	Provider    string                  `json:"provider"`
	DisplayName string                  `json:"display_name"`
	Tier        string                  `json:"tier"`
	Category    string                  `json:"category"`
	Registered  bool                    `json:"registered"`
	UserFacing  UserFacingCapabilities  `json:"user_facing"`
	Operational OperationalCapabilities `json:"operational"`
}

// operationalCapabilitiesFor derives the optional-interface flags for the
// connector registered under provider via type-assertion. A provider that is
// not registered (missing blank-import) yields the zero value (every flag
// false), which is exactly what the caller needs to surface "this connector is
// declared in the catalog but not compiled into the binary".
func operationalCapabilitiesFor(provider string) (OperationalCapabilities, bool) {
	conn, err := GetAccessConnector(provider)
	if err != nil || conn == nil {
		return OperationalCapabilities{}, false
	}
	var caps OperationalCapabilities
	if _, ok := conn.(GroupSyncer); ok {
		caps.GroupSync = true
	}
	if _, ok := conn.(IdentityDeltaSyncer); ok {
		caps.IdentityDeltaSync = true
	}
	if _, ok := conn.(AccessAuditor); ok {
		caps.AccessAuditStream = true
	}
	if _, ok := conn.(SCIMProvisioner); ok {
		caps.SCIMProvisioning = true
	}
	if _, ok := conn.(SessionRevoker); ok {
		caps.SessionRevoke = true
	}
	if _, ok := conn.(SSOEnforcementChecker); ok {
		caps.SSOEnforcementCheck = true
	}
	if _, ok := conn.(CredentialRenewer); ok {
		caps.CredentialRenewal = true
	}
	return caps, true
}

// CapabilityDescriptorFor returns the complete capability descriptor for a
// single provider key. The bool is false when the key has no curated catalog
// entry. The Registered flag and operational capabilities are resolved against
// the live registry so the descriptor reflects the running binary, not just the
// static catalog.
func CapabilityDescriptorFor(provider string) (CapabilityDescriptor, bool) {
	data, ok := connectorCatalog[provider]
	if !ok {
		return CapabilityDescriptor{}, false
	}
	op, registered := operationalCapabilitiesFor(provider)
	return CapabilityDescriptor{
		Provider:    provider,
		DisplayName: data.DisplayName,
		Tier:        data.Tier,
		Category:    data.Category,
		Registered:  registered,
		UserFacing: UserFacingCapabilities{
			SyncIdentity:     data.SyncIdentity,
			ProvisionAccess:  data.ProvisionAccess,
			ListEntitlements: data.ListEntitlements,
			GetAccessLog:     data.GetAccessLog,
			SSOFederation:    data.SSOFederation,
		},
		Operational: op,
	}, true
}

// ListCapabilityDescriptors returns the capability descriptor for every curated
// connector, sorted by provider key. It is the source for the capability-matrix
// view: one row per connector, every capability dimension resolved.
func ListCapabilityDescriptors() []CapabilityDescriptor {
	out := make([]CapabilityDescriptor, 0, len(connectorCatalog))
	for provider := range connectorCatalog {
		d, ok := CapabilityDescriptorFor(provider)
		if !ok {
			continue
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Provider < out[j].Provider })
	return out
}

// HasUserFacingCapability reports whether the descriptor advertises the given
// user-facing capability key. Unknown keys return false. Used by the catalogue
// endpoint's ?capability= filter.
func (d CapabilityDescriptor) HasUserFacingCapability(key string) bool {
	switch key {
	case CapabilitySyncIdentity:
		return d.UserFacing.SyncIdentity
	case CapabilityProvisionAccess:
		return d.UserFacing.ProvisionAccess
	case CapabilityListEntitlements:
		return d.UserFacing.ListEntitlements
	case CapabilityGetAccessLog:
		return d.UserFacing.GetAccessLog
	case CapabilitySSOFederation:
		return d.UserFacing.SSOFederation
	default:
		return false
	}
}

// HasOperationalCapability reports whether the descriptor advertises the given
// operational capability key. Unknown keys return false.
func (d CapabilityDescriptor) HasOperationalCapability(key string) bool {
	switch key {
	case CapabilityGroupSync:
		return d.Operational.GroupSync
	case CapabilityIdentityDeltaSync:
		return d.Operational.IdentityDeltaSync
	case CapabilityAccessAuditOperations:
		return d.Operational.AccessAuditStream
	case CapabilitySCIMProvisioning:
		return d.Operational.SCIMProvisioning
	case CapabilitySessionRevoke:
		return d.Operational.SessionRevoke
	case CapabilitySSOEnforcementCheck:
		return d.Operational.SSOEnforcementCheck
	case CapabilityCredentialRenewal:
		return d.Operational.CredentialRenewal
	default:
		return false
	}
}

// HasCapability reports whether the descriptor advertises the given capability
// key, checking both the user-facing and operational dimensions. This is the
// predicate the catalogue ?capability= filter uses so an operator can filter on
// any capability without knowing which dimension it belongs to.
func (d CapabilityDescriptor) HasCapability(key string) bool {
	return d.HasUserFacingCapability(key) || d.HasOperationalCapability(key)
}
