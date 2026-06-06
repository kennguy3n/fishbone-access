package access

import (
	"context"
	"testing"
)

// MockAccessConnector is a fully configurable AccessConnector double for use
// in unit tests. Each method dispatches to the matching FuncXxx field if
// non-nil, otherwise returns the zero value. Tests construct one of these,
// optionally inject it into the registry via SwapConnector, and assert
// behaviour through the Last* fields.
type MockAccessConnector struct {
	FuncValidate               func(ctx context.Context, config, secrets map[string]interface{}) error
	FuncConnect                func(ctx context.Context, config, secrets map[string]interface{}) error
	FuncVerifyPermissions      func(ctx context.Context, config, secrets map[string]interface{}, capabilities []string) ([]string, error)
	FuncCountIdentities        func(ctx context.Context, config, secrets map[string]interface{}) (int, error)
	FuncSyncIdentities         func(ctx context.Context, config, secrets map[string]interface{}, checkpoint string, handler func(batch []*Identity, nextCheckpoint string) error) error
	FuncProvisionAccess        func(ctx context.Context, config, secrets map[string]interface{}, grant AccessGrant) error
	FuncRevokeAccess           func(ctx context.Context, config, secrets map[string]interface{}, grant AccessGrant) error
	FuncListEntitlements       func(ctx context.Context, config, secrets map[string]interface{}, userExternalID string) ([]Entitlement, error)
	FuncGetSSOMetadata         func(ctx context.Context, config, secrets map[string]interface{}) (*SSOMetadata, error)
	FuncGetCredentialsMetadata func(ctx context.Context, config, secrets map[string]interface{}) (map[string]interface{}, error)

	// Call counters for assertions.
	ValidateCalls               int
	ConnectCalls                int
	VerifyPermissionsCalls      int
	CountIdentitiesCalls        int
	SyncIdentitiesCalls         int
	ProvisionAccessCalls        int
	RevokeAccessCalls           int
	ListEntitlementsCalls       int
	GetSSOMetadataCalls         int
	GetCredentialsMetadataCalls int
}

// Validate implements AccessConnector.
func (m *MockAccessConnector) Validate(ctx context.Context, config, secrets map[string]interface{}) error {
	m.ValidateCalls++
	if m.FuncValidate != nil {
		return m.FuncValidate(ctx, config, secrets)
	}
	return nil
}

// Connect implements AccessConnector.
func (m *MockAccessConnector) Connect(ctx context.Context, config, secrets map[string]interface{}) error {
	m.ConnectCalls++
	if m.FuncConnect != nil {
		return m.FuncConnect(ctx, config, secrets)
	}
	return nil
}

// VerifyPermissions implements AccessConnector.
func (m *MockAccessConnector) VerifyPermissions(ctx context.Context, config, secrets map[string]interface{}, capabilities []string) ([]string, error) {
	m.VerifyPermissionsCalls++
	if m.FuncVerifyPermissions != nil {
		return m.FuncVerifyPermissions(ctx, config, secrets, capabilities)
	}
	return nil, nil
}

// CountIdentities implements AccessConnector.
func (m *MockAccessConnector) CountIdentities(ctx context.Context, config, secrets map[string]interface{}) (int, error) {
	m.CountIdentitiesCalls++
	if m.FuncCountIdentities != nil {
		return m.FuncCountIdentities(ctx, config, secrets)
	}
	return 0, nil
}

// SyncIdentities implements AccessConnector.
func (m *MockAccessConnector) SyncIdentities(ctx context.Context, config, secrets map[string]interface{}, checkpoint string, handler func(batch []*Identity, nextCheckpoint string) error) error {
	m.SyncIdentitiesCalls++
	if m.FuncSyncIdentities != nil {
		return m.FuncSyncIdentities(ctx, config, secrets, checkpoint, handler)
	}
	return nil
}

// ProvisionAccess implements AccessConnector.
func (m *MockAccessConnector) ProvisionAccess(ctx context.Context, config, secrets map[string]interface{}, grant AccessGrant) error {
	m.ProvisionAccessCalls++
	if m.FuncProvisionAccess != nil {
		return m.FuncProvisionAccess(ctx, config, secrets, grant)
	}
	return nil
}

// RevokeAccess implements AccessConnector.
func (m *MockAccessConnector) RevokeAccess(ctx context.Context, config, secrets map[string]interface{}, grant AccessGrant) error {
	m.RevokeAccessCalls++
	if m.FuncRevokeAccess != nil {
		return m.FuncRevokeAccess(ctx, config, secrets, grant)
	}
	return nil
}

// ListEntitlements implements AccessConnector.
func (m *MockAccessConnector) ListEntitlements(ctx context.Context, config, secrets map[string]interface{}, userExternalID string) ([]Entitlement, error) {
	m.ListEntitlementsCalls++
	if m.FuncListEntitlements != nil {
		return m.FuncListEntitlements(ctx, config, secrets, userExternalID)
	}
	return nil, nil
}

// GetSSOMetadata implements AccessConnector.
func (m *MockAccessConnector) GetSSOMetadata(ctx context.Context, config, secrets map[string]interface{}) (*SSOMetadata, error) {
	m.GetSSOMetadataCalls++
	if m.FuncGetSSOMetadata != nil {
		return m.FuncGetSSOMetadata(ctx, config, secrets)
	}
	return nil, nil
}

// GetCredentialsMetadata implements AccessConnector.
func (m *MockAccessConnector) GetCredentialsMetadata(ctx context.Context, config, secrets map[string]interface{}) (map[string]interface{}, error) {
	m.GetCredentialsMetadataCalls++
	if m.FuncGetCredentialsMetadata != nil {
		return m.FuncGetCredentialsMetadata(ctx, config, secrets)
	}
	return nil, nil
}

// SwapConnector replaces the registry entry for provider with mock for the
// duration of the test, restoring the previous entry (or removing the slot
// entirely if there was no previous entry) via t.Cleanup.
//
// This is the only safe way for tests to swap registry entries — production
// code never re-registers a connector, and RegisterAccessConnector panics on
// duplicate registration to enforce that.
func SwapConnector(t *testing.T, provider string, mock AccessConnector) {
	t.Helper()

	registryMu.Lock()
	previous, hadPrevious := registry[provider]
	registry[provider] = mock
	registryMu.Unlock()

	t.Cleanup(func() {
		registryMu.Lock()
		defer registryMu.Unlock()
		if hadPrevious {
			registry[provider] = previous
		} else {
			delete(registry, provider)
		}
	})
}
