package discovery

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
	"github.com/kennguy3n/fishbone-access/internal/services/access"
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
	"github.com/kennguy3n/fishbone-access/internal/services/pam"
)

// --- test harness ----------------------------------------------------------

// testDEK is a deterministic 32-byte AES-256 key (base64) for the static
// EnvelopeEncryptor used in tests.
var testDEK = base64.StdEncoding.EncodeToString(make([]byte, 32))

var fixedNow = time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)

func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := database.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := database.AutoMigrate(db); err != nil {
		t.Fatalf("auto-migrate: %v", err)
	}
	return db
}

func newTestEncryptor(t *testing.T) access.CredentialEncryptor {
	t.Helper()
	enc, err := access.CredentialEncryptorFromKey(testDEK)
	if err != nil {
		t.Fatalf("encryptor: %v", err)
	}
	return enc
}

// harness bundles an engine with its DB and the fakes wired into it so tests
// can both drive the engine and assert on the persisted rows.
type harness struct {
	db     *gorm.DB
	enc    access.CredentialEncryptor
	vault  *pam.Vault
	engine *Engine
	dialer *fakeDialer
	binder *fakeBinder
	dbEnum *fakeDBEnum
	res    *fakeResolver
}

func newHarness(t *testing.T, opts ...Option) *harness {
	t.Helper()
	db := newTestDB(t)
	enc := newTestEncryptor(t)
	vault := pam.NewVault(db, enc, nil)
	vault.SetClock(func() time.Time { return fixedNow })
	h := &harness{
		db:     db,
		enc:    enc,
		vault:  vault,
		dialer: &fakeDialer{open: map[string]bool{}},
		binder: &fakeBinder{},
		dbEnum: &fakeDBEnum{},
		res:    &fakeResolver{},
	}
	base := []Option{
		WithEncryptor(enc),
		WithClock(func() time.Time { return fixedNow }),
		WithDialer(h.dialer),
		WithBinder(h.binder),
		WithDBEnumerator(h.dbEnum),
		WithConnectorResolver(h.res),
	}
	h.engine = NewEngine(db, vault, append(base, opts...)...)
	return h
}

func seedWorkspace(t *testing.T, db *gorm.DB, tenant string) uuid.UUID {
	t.Helper()
	ws := &models.Workspace{Name: tenant, IAMCoreTenantID: tenant, Plan: "base"}
	if err := db.Create(ws).Error; err != nil {
		t.Fatalf("seed workspace: %v", err)
	}
	return ws.ID
}

// seedAsset inserts a discovered asset directly for reconcile/onboard tests.
func (h *harness) seedAsset(t *testing.T, ws uuid.UUID, source, externalID, protocol, address, status string) models.DiscoveredAsset {
	t.Helper()
	a := models.DiscoveredAsset{
		WorkspaceID: ws,
		Source:      source,
		ExternalID:  externalID,
		Name:        address,
		Protocol:    protocol,
		Address:     address,
		Status:      status,
		FirstSeenAt: fixedNow,
		LastSeenAt:  fixedNow,
	}
	if err := h.db.Create(&a).Error; err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	return a
}

func (h *harness) auditCount(t *testing.T, ws uuid.UUID, action string) int64 {
	t.Helper()
	var n int64
	if err := h.db.Model(&models.AuditEvent{}).
		Where("workspace_id = ? AND action = ?", ws, action).Count(&n).Error; err != nil {
		t.Fatalf("count audit %q: %v", action, err)
	}
	return n
}

func (h *harness) targetCount(t *testing.T, ws uuid.UUID) int64 {
	t.Helper()
	var n int64
	if err := h.db.Model(&models.PAMTarget{}).
		Where("workspace_id = ?", ws).Count(&n).Error; err != nil {
		t.Fatalf("count targets: %v", err)
	}
	return n
}

// --- fakes -----------------------------------------------------------------

type fakeDialer struct {
	open map[string]bool // addr -> reachable
	err  error
}

func (f *fakeDialer) DialThroughAgent(_ context.Context, _, _ uuid.UUID, addr string) (net.Conn, error) {
	if f.err != nil {
		return nil, f.err
	}
	if !f.open[addr] {
		return nil, errors.New("connection refused")
	}
	// Close the peer end immediately so each successful probe doesn't leak a
	// pipe goroutine/fd; probeOne only closes the conn, it never reads/writes.
	client, peer := net.Pipe()
	_ = peer.Close()
	return client, nil
}

type fakeBinder struct {
	calls int
	err   error
}

func (f *fakeBinder) BindTarget(_ context.Context, _, _, _ uuid.UUID, _ string) error {
	f.calls++
	return f.err
}

type fakeDBEnum struct {
	accounts []EnumeratedAccount
	err      error
}

func (f *fakeDBEnum) Enumerate(_ context.Context, _, _, _, _ string, _ time.Duration) ([]EnumeratedAccount, error) {
	return f.accounts, f.err
}

// fakeConn implements just enough of access.AccessConnector via an embedded nil
// interface so the struct satisfies the contract; only DiscoverAssets is ever
// called by ConnectorInventory (after the type assertion), so the promoted nil
// methods are never invoked.
type fakeConn struct {
	access.AccessConnector
	specs []access.DiscoveredAssetSpec
	err   error
}

func (f *fakeConn) DiscoverAssets(_ context.Context, _ map[string]interface{}, _ map[string]interface{}) ([]access.DiscoveredAssetSpec, error) {
	return f.specs, f.err
}

type fakeResolver struct {
	impl     access.AccessConnector
	provider string
	err      error
}

func (f *fakeResolver) Resolve(_ context.Context, _, _ uuid.UUID) (*lifecycle.ResolvedConnector, error) {
	if f.err != nil {
		return nil, f.err
	}
	p := f.provider
	if p == "" {
		p = "fake"
	}
	return &lifecycle.ResolvedConnector{Provider: p, Impl: f.impl, Config: map[string]any{}, Secrets: map[string]any{}}, nil
}

// --- helpers tests ---------------------------------------------------------

func TestProtocolForPort(t *testing.T) {
	cases := map[int]string{22: "ssh", 3389: "rdp", 5432: "postgres", 3306: "mysql", 1433: "mssql", 27017: "mongodb", 6379: "redis", 8080: ""}
	for port, want := range cases {
		if got := protocolForPort(port); got != want {
			t.Errorf("protocolForPort(%d) = %q, want %q", port, got, want)
		}
	}
}

func TestKindAndDefaultProtocol(t *testing.T) {
	if k := kindForProtocol(models.PAMProtocolPostgres); k != access.AssetKindDatabase {
		t.Errorf("postgres kind = %q, want database", k)
	}
	if k := kindForProtocol("ssh"); k != access.AssetKindHost {
		t.Errorf("ssh kind = %q, want host", k)
	}
	if p := defaultProtocolForKind(access.AssetKindDatabase); p != "postgres" {
		t.Errorf("default db protocol = %q", p)
	}
	if p := defaultProtocolForKind(access.AssetKindHost); p != "ssh" {
		t.Errorf("default host protocol = %q", p)
	}
}

func TestExpandHosts(t *testing.T) {
	tests := []struct {
		name    string
		hosts   []string
		cidrs   []string
		want    []string
		wantErr bool
	}{
		{name: "dedup hosts", hosts: []string{"10.0.0.1", "10.0.0.1", " 10.0.0.2 "}, want: []string{"10.0.0.1", "10.0.0.2"}},
		{name: "slash30 drops network+broadcast", cidrs: []string{"10.0.0.0/30"}, want: []string{"10.0.0.1", "10.0.0.2"}},
		{name: "slash31 keeps both hosts (RFC 3021)", cidrs: []string{"10.0.0.0/31"}, want: []string{"10.0.0.0", "10.0.0.1"}},
		{name: "slash32 single host", cidrs: []string{"10.0.0.5/32"}, want: []string{"10.0.0.5"}},
		{name: "ipv6 rejected", cidrs: []string{"fe80::/120"}, wantErr: true},
		{name: "larger than /24 rejected", cidrs: []string{"10.0.0.0/23"}, wantErr: true},
		{name: "bad cidr", cidrs: []string{"not-a-cidr"}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := expandHosts(tc.hosts, tc.cidrs)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %v", got)
				}
				if !errors.Is(err, ErrValidation) {
					t.Errorf("error = %v, want ErrValidation", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			sort.Strings(got)
			sort.Strings(tc.want)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestExpandHostsSlash24Count(t *testing.T) {
	got, err := expandHosts(nil, []string{"10.0.0.0/24"})
	if err != nil {
		t.Fatalf("expand /24: %v", err)
	}
	// 256 addresses minus network + broadcast.
	if len(got) != 254 {
		t.Fatalf("/24 expanded to %d hosts, want 254", len(got))
	}
}

func TestValidateRules(t *testing.T) {
	tests := []struct {
		name    string
		rules   []AutoOnboardRule
		wantErr bool
	}{
		{name: "ok protocol", rules: []AutoOnboardRule{{Name: "ssh", Protocols: []string{"ssh"}}}},
		{name: "ok cidr", rules: []AutoOnboardRule{{Name: "net", CIDRs: []string{"10.0.0.0/24"}}}},
		{name: "empty matches everything", rules: []AutoOnboardRule{{Name: "all"}}, wantErr: true},
		{name: "bad cidr", rules: []AutoOnboardRule{{Name: "bad", CIDRs: []string{"oops"}}}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRules(tc.rules)
			if tc.wantErr != (err != nil) {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestMatchRule(t *testing.T) {
	asset := &models.DiscoveredAsset{Protocol: "ssh", Source: models.DiscoverySourceAgentSweep, Address: "10.0.0.5:22"}
	tests := []struct {
		name string
		rule AutoOnboardRule
		want bool
	}{
		{name: "protocol match", rule: AutoOnboardRule{Protocols: []string{"ssh"}}, want: true},
		{name: "protocol mismatch", rule: AutoOnboardRule{Protocols: []string{"rdp"}}, want: false},
		{name: "cidr match", rule: AutoOnboardRule{CIDRs: []string{"10.0.0.0/24"}}, want: true},
		{name: "cidr mismatch", rule: AutoOnboardRule{CIDRs: []string{"192.168.0.0/24"}}, want: false},
		{name: "all facets AND", rule: AutoOnboardRule{Protocols: []string{"ssh"}, Sources: []string{models.DiscoverySourceAgentSweep}, CIDRs: []string{"10.0.0.0/24"}}, want: true},
		{name: "one facet fails", rule: AutoOnboardRule{Protocols: []string{"ssh"}, Sources: []string{models.DiscoverySourceConnector}}, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchRule(asset, tc.rule); got != tc.want {
				t.Errorf("matchRule = %v, want %v", got, tc.want)
			}
		})
	}
}

// --- reconcile + classification --------------------------------------------

func TestReconcileAssetsIdempotentAndClassify(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	ws := seedWorkspace(t, h.db, "acme")

	// A managed PAM target at 10.0.0.9:22 so a matching discovered asset is
	// classified managed; the other stays unmanaged.
	requireMFA := true
	if _, err := h.vault.CreateTarget(ctx, pam.CreateTargetInput{
		WorkspaceID: ws, Name: "managed-host", Protocol: "ssh", Address: "10.0.0.9:22",
		Username: "root", RequireMFA: &requireMFA, Secret: pam.Secret{Password: "pw"}, Actor: "tester",
	}); err != nil {
		t.Fatalf("create managed target: %v", err)
	}

	specs := []access.DiscoveredAssetSpec{
		{ExternalID: "host:10.0.0.5:22", Kind: access.AssetKindHost, Name: "10.0.0.5", Protocol: "ssh", Address: "10.0.0.5:22"},
		{ExternalID: "host:10.0.0.9:22", Kind: access.AssetKindHost, Name: "10.0.0.9", Protocol: "ssh", Address: "10.0.0.9:22"},
		{ExternalID: "", Kind: access.AssetKindHost}, // skipped (no external id)
	}
	found, fresh, err := h.engine.reconcileAssets(ctx, ws, models.DiscoverySourceAgentSweep, specs, nil, nil)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if found != 2 || fresh != 2 {
		t.Fatalf("first reconcile found=%d fresh=%d, want 2/2", found, fresh)
	}

	// Re-run: idempotent — no new rows.
	found, fresh, err = h.engine.reconcileAssets(ctx, ws, models.DiscoverySourceAgentSweep, specs, nil, nil)
	if err != nil {
		t.Fatalf("reconcile rerun: %v", err)
	}
	if found != 2 || fresh != 0 {
		t.Fatalf("rerun found=%d fresh=%d, want 2/0", found, fresh)
	}

	var managed, unmanaged int64
	h.db.Model(&models.DiscoveredAsset{}).Where("workspace_id = ? AND status = ?", ws, models.DiscoveryStatusManaged).Count(&managed)
	h.db.Model(&models.DiscoveredAsset{}).Where("workspace_id = ? AND status = ?", ws, models.DiscoveryStatusUnmanaged).Count(&unmanaged)
	if managed != 1 || unmanaged != 1 {
		t.Fatalf("classification managed=%d unmanaged=%d, want 1/1", managed, unmanaged)
	}
}

func TestReconcileNeverDowngradesIgnored(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	ws := seedWorkspace(t, h.db, "acme")
	h.seedAsset(t, ws, models.DiscoverySourceAgentSweep, "host:10.0.0.5:22", "ssh", "10.0.0.5:22", models.DiscoveryStatusIgnored)

	specs := []access.DiscoveredAssetSpec{{ExternalID: "host:10.0.0.5:22", Kind: access.AssetKindHost, Address: "10.0.0.5:22", Protocol: "ssh"}}
	if _, _, err := h.engine.reconcileAssets(ctx, ws, models.DiscoverySourceAgentSweep, specs, nil, nil); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var a models.DiscoveredAsset
	h.db.Where("workspace_id = ? AND external_id = ?", ws, "host:10.0.0.5:22").Take(&a)
	if a.Status != models.DiscoveryStatusIgnored {
		t.Fatalf("ignored asset downgraded to %q on re-scan", a.Status)
	}
}

// TestReconcileClassifiesPortNormalized proves a target registered without an
// explicit port still classifies a discovered host:port (and the reverse) as
// managed, so a trivial port-format difference no longer causes a false
// "unmanaged" that would offer to re-onboard an already-managed endpoint.
func TestReconcileClassifiesPortNormalized(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	ws := seedWorkspace(t, h.db, "acme")
	requireMFA := true
	// Target stored port-less; discovery reports it with the default SSH port.
	if _, err := h.vault.CreateTarget(ctx, pam.CreateTargetInput{
		WorkspaceID: ws, Name: "portless-ssh", Protocol: "ssh", Address: "10.0.0.9",
		Username: "root", RequireMFA: &requireMFA, Secret: pam.Secret{Password: "pw"}, Actor: "tester",
	}); err != nil {
		t.Fatalf("create port-less target: %v", err)
	}
	// Target stored with explicit port; discovery reports it port-less.
	if _, err := h.vault.CreateTarget(ctx, pam.CreateTargetInput{
		WorkspaceID: ws, Name: "ported-pg", Protocol: "postgres", Address: "db.internal:5432",
		Username: "root", RequireMFA: &requireMFA, Secret: pam.Secret{Password: "pw"}, Actor: "tester",
	}); err != nil {
		t.Fatalf("create ported target: %v", err)
	}

	specs := []access.DiscoveredAssetSpec{
		{ExternalID: "host:10.0.0.9:22", Kind: access.AssetKindHost, Name: "10.0.0.9", Protocol: "ssh", Address: "10.0.0.9:22"},
		{ExternalID: "db:db.internal", Kind: access.AssetKindDatabase, Name: "db.internal", Protocol: "postgres", Address: "db.internal"},
	}
	if _, _, err := h.engine.reconcileAssets(ctx, ws, models.DiscoverySourceAgentSweep, specs, nil, nil); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var managed int64
	h.db.Model(&models.DiscoveredAsset{}).Where("workspace_id = ? AND status = ?", ws, models.DiscoveryStatusManaged).Count(&managed)
	if managed != 2 {
		t.Fatalf("managed=%d, want 2 (both endpoints should match despite port-format differences)", managed)
	}
}

func TestNormalizeEndpoint(t *testing.T) {
	cases := []struct {
		name     string
		address  string
		protocol string
		want     string
	}{
		{"fills default ssh port", "10.0.0.9", "ssh", "10.0.0.9:22"},
		{"fills default postgres port", "db.internal", "postgres", "db.internal:5432"},
		{"keeps explicit port", "10.0.0.9:2222", "ssh", "10.0.0.9:2222"},
		{"lowercases host", "DB.Internal:5432", "postgres", "db.internal:5432"},
		{"unknown protocol host-only", "10.0.0.9", "weird", "10.0.0.9"},
		{"ipv6 with port", "[2001:db8::1]:22", "ssh", "[2001:db8::1]:22"},
		{"bracketed ipv6 fills default port", "[2001:db8::1]", "ssh", "[2001:db8::1]:22"},
		{"bracketed ipv6 unknown protocol unwraps", "[2001:db8::1]", "weird", "2001:db8::1"},
		{"bare ipv6 fills default port", "2001:db8::1", "ssh", "[2001:db8::1]:22"},
		{"trims whitespace", "  10.0.0.9:22 ", "ssh", "10.0.0.9:22"},
		{"empty stays empty", "", "ssh", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeEndpoint(tc.address, tc.protocol); got != tc.want {
				t.Fatalf("normalizeEndpoint(%q, %q) = %q, want %q", tc.address, tc.protocol, got, tc.want)
			}
		})
	}
}

// --- agent sweep -----------------------------------------------------------

func TestAgentSweep(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	ws := seedWorkspace(t, h.db, "acme")
	agentID := uuid.New()
	h.dialer.open["10.0.0.1:22"] = true
	h.dialer.open["10.0.0.1:5432"] = true

	res, err := h.engine.AgentSweep(ctx, ws, AgentSweepRequest{
		AgentID: agentID, Hosts: []string{"10.0.0.1"}, Ports: []int{22, 3389, 5432}, Actor: "tester",
	})
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if res.Probed != 3 {
		t.Fatalf("probed = %d, want 3", res.Probed)
	}
	if res.Reachable != 2 || res.AssetsNew != 2 {
		t.Fatalf("reachable=%d new=%d, want 2/2", res.Reachable, res.AssetsNew)
	}
	if got := h.auditCount(t, ws, "discovery.agent_sweep"); got != 1 {
		t.Fatalf("audit events = %d, want 1", got)
	}
	// Scan row recorded completed.
	var scan models.DiscoveryScan
	h.db.Where("workspace_id = ?", ws).Take(&scan)
	if scan.Status != models.DiscoveryScanCompleted {
		t.Fatalf("scan status = %q, want completed", scan.Status)
	}
}

func TestAgentSweepValidation(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	ws := seedWorkspace(t, h.db, "acme")

	if _, err := h.engine.AgentSweep(ctx, ws, AgentSweepRequest{Hosts: []string{"10.0.0.1"}}); !errors.Is(err, ErrValidation) {
		t.Errorf("missing agent: err = %v, want ErrValidation", err)
	}
	// Fan-out cap.
	h.engine.cfg.MaxProbeTargets = 4
	if _, err := h.engine.AgentSweep(ctx, ws, AgentSweepRequest{AgentID: uuid.New(), CIDRs: []string{"10.0.0.0/29"}, Ports: []int{22, 3389}}); !errors.Is(err, ErrValidation) {
		t.Errorf("fan-out cap: err = %v, want ErrValidation", err)
	}
}

func TestAgentSweepNoDialer(t *testing.T) {
	h := newHarness(t)
	h.engine.dialer = nil
	ctx := context.Background()
	ws := seedWorkspace(t, h.db, "acme")
	if _, err := h.engine.AgentSweep(ctx, ws, AgentSweepRequest{AgentID: uuid.New(), Hosts: []string{"10.0.0.1"}}); !errors.Is(err, ErrUnsupported) {
		t.Errorf("no dialer: err = %v, want ErrUnsupported", err)
	}
}

// --- agent self-report import ----------------------------------------------

func TestImportAgentReachable(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	ws := seedWorkspace(t, h.db, "acme")
	agentID := uuid.New()
	for _, r := range []models.AgentReachableTarget{
		{WorkspaceID: ws, AgentID: agentID, Pattern: "10.0.0.5:22", Kind: models.AgentReachKindHost},
		{WorkspaceID: ws, AgentID: agentID, Pattern: "db.internal", Kind: models.AgentReachKindHostname},
	} {
		if err := h.db.Create(&r).Error; err != nil {
			t.Fatalf("seed reachable: %v", err)
		}
	}
	res, err := h.engine.ImportAgentReachable(ctx, ws, agentID, "tester")
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if res.AssetsNew != 2 {
		t.Fatalf("new = %d, want 2", res.AssetsNew)
	}
	var hostPort models.DiscoveredAsset
	h.db.Where("workspace_id = ? AND external_id = ?", ws, "agent-reach:"+agentID.String()+":10.0.0.5:22").Take(&hostPort)
	if hostPort.Protocol != "ssh" {
		t.Fatalf("host:port import protocol = %q, want ssh", hostPort.Protocol)
	}
}

// --- DB account enumeration ------------------------------------------------

func TestEnumerateAccountsClassify(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	ws := seedWorkspace(t, h.db, "acme")
	requireMFA := true
	// The DB target itself (admin credential) plus a managed grant target for
	// user "appsvc" at the same address.
	target, err := h.vault.CreateTarget(ctx, pam.CreateTargetInput{
		WorkspaceID: ws, Name: "pg-prod", Protocol: "postgres", Address: "db.acme:5432",
		Username: "postgres", RequireMFA: &requireMFA, Secret: pam.Secret{Password: "pw"}, Actor: "tester",
	})
	if err != nil {
		t.Fatalf("create db target: %v", err)
	}
	if _, err := h.vault.CreateTarget(ctx, pam.CreateTargetInput{
		WorkspaceID: ws, Name: "pg-appsvc", Protocol: "postgres", Address: "db.acme:5432",
		Username: "appsvc", RequireMFA: &requireMFA, Secret: pam.Secret{Password: "pw"}, Actor: "tester",
	}); err != nil {
		t.Fatalf("create managed grant target: %v", err)
	}

	h.dbEnum.accounts = []EnumeratedAccount{
		{Username: "appsvc", CanLogin: true},             // managed (matches a target username)
		{Username: "analyst", CanLogin: true},            // orphan (login, no grant)
		{Username: "pg_signal_backend", CanLogin: false}, // unmanaged (no login)
	}
	res, err := h.engine.EnumerateAccounts(ctx, ws, target.ID, "tester", models.DiscoveryTriggerManual)
	if err != nil {
		t.Fatalf("enumerate: %v", err)
	}
	if res.AccountsFound != 3 {
		t.Fatalf("found = %d, want 3", res.AccountsFound)
	}
	statusOf := func(u string) string {
		var a models.DiscoveredAccount
		h.db.Where("workspace_id = ? AND target_id = ? AND username = ?", ws, target.ID, u).Take(&a)
		return a.Status
	}
	if s := statusOf("appsvc"); s != models.DiscoveryStatusManaged {
		t.Errorf("appsvc = %q, want managed", s)
	}
	if s := statusOf("analyst"); s != models.DiscoveryStatusOrphan {
		t.Errorf("analyst = %q, want orphan", s)
	}
	if s := statusOf("pg_signal_backend"); s != models.DiscoveryStatusUnmanaged {
		t.Errorf("pg_signal_backend = %q, want unmanaged", s)
	}
}

func TestEnumerateAccountsNonDatabase(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	ws := seedWorkspace(t, h.db, "acme")
	requireMFA := true
	target, err := h.vault.CreateTarget(ctx, pam.CreateTargetInput{
		WorkspaceID: ws, Name: "ssh-box", Protocol: "ssh", Address: "10.0.0.5:22",
		Username: "root", RequireMFA: &requireMFA, Secret: pam.Secret{Password: "pw"}, Actor: "tester",
	})
	if err != nil {
		t.Fatalf("create target: %v", err)
	}
	if _, err := h.engine.EnumerateAccounts(ctx, ws, target.ID, "tester", ""); !errors.Is(err, ErrUnsupported) {
		t.Errorf("ssh target: err = %v, want ErrUnsupported", err)
	}
}

// --- onboarding ------------------------------------------------------------

func TestOnboardAsset(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	ws := seedWorkspace(t, h.db, "acme")
	asset := h.seedAsset(t, ws, models.DiscoverySourceAgentSweep, "host:10.0.0.5:22", "ssh", "10.0.0.5:22", models.DiscoveryStatusUnmanaged)
	agentID := uuid.New()

	target, err := h.engine.OnboardAsset(ctx, ws, asset.ID, OnboardAssetInput{
		Username: "root", Secret: pam.Secret{Password: "hunter2"}, AgentID: &agentID, RequireMFA: true, Actor: "tester",
	})
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}
	if target.Address != "10.0.0.5:22" || target.Protocol != "ssh" {
		t.Fatalf("target prefilled wrong: %+v", target)
	}
	if h.binder.calls != 1 {
		t.Fatalf("binder calls = %d, want 1", h.binder.calls)
	}
	var got models.DiscoveredAsset
	h.db.Where("id = ?", asset.ID).Take(&got)
	if got.Status != models.DiscoveryStatusManaged || got.TargetID == nil || *got.TargetID != target.ID {
		t.Fatalf("asset not marked managed: %+v", got)
	}
	if c := h.auditCount(t, ws, "discovery.onboard"); c != 1 {
		t.Fatalf("onboard audit = %d, want 1", c)
	}

	// Re-onboard is a conflict.
	if _, err := h.engine.OnboardAsset(ctx, ws, asset.ID, OnboardAssetInput{Username: "root", Secret: pam.Secret{Password: "x"}, Actor: "tester"}); !errors.Is(err, ErrConflict) {
		t.Errorf("re-onboard: err = %v, want ErrConflict", err)
	}
}

// TestOnboardAssetBindFailureStillLinksTarget locks in the fix for the
// BindTarget-strands-asset bug: when the agent bind fails AFTER the target is
// created, the asset must still be linked to the target (status=managed,
// target_id set) so it is neither un-onboardable nor invisible to the sweep —
// while the bind failure is still surfaced to the caller.
func TestOnboardAssetBindFailureStillLinksTarget(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	ws := seedWorkspace(t, h.db, "acme")
	asset := h.seedAsset(t, ws, models.DiscoverySourceAgentSweep, "host:10.0.0.7:22", "ssh", "10.0.0.7:22", models.DiscoveryStatusUnmanaged)
	agentID := uuid.New()
	h.binder.err = errors.New("agent offline")

	target, err := h.engine.OnboardAsset(ctx, ws, asset.ID, OnboardAssetInput{
		Username: "root", Secret: pam.Secret{Password: "hunter2"}, AgentID: &agentID, RequireMFA: true, Actor: "tester",
	})
	// The bind failure must be surfaced...
	if err == nil || !strings.Contains(err.Error(), "agent offline") {
		t.Fatalf("expected surfaced bind error, got %v", err)
	}
	// ...but the target must exist and the asset must be linked to it (not stuck).
	if target == nil {
		t.Fatalf("target should still be created on bind failure")
	}
	var got models.DiscoveredAsset
	h.db.Where("id = ?", asset.ID).Take(&got)
	if got.Status != models.DiscoveryStatusManaged || got.TargetID == nil || *got.TargetID != target.ID {
		t.Fatalf("asset not linked after bind failure (stuck managed/NULL): %+v", got)
	}
	// The onboard link audit event must still have been appended.
	if c := h.auditCount(t, ws, "discovery.onboard"); c != 1 {
		t.Fatalf("onboard audit = %d, want 1", c)
	}
	// The asset is fully onboarded, so a retry is a conflict (not a stuck loop).
	if _, err := h.engine.OnboardAsset(ctx, ws, asset.ID, OnboardAssetInput{Username: "root", Secret: pam.Secret{Password: "x"}, Actor: "tester"}); !errors.Is(err, ErrConflict) {
		t.Errorf("re-onboard after bind failure: err = %v, want ErrConflict", err)
	}
}

// TestOnboardAssetClaimBlocksConcurrentOnboard locks in the TOCTOU fix: the
// asset is claimed (unmanaged -> managed) atomically BEFORE the target is
// created, so a second onboarder that raced through the same status check loses
// the claim with ErrConflict and never creates an orphan PAM target. The
// in-memory SQLite harness can't share one DB across goroutines, so this drives
// the exact interleave deterministically through the claim CAS rather than with
// real concurrency.
func TestOnboardAssetClaimBlocksConcurrentOnboard(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	ws := seedWorkspace(t, h.db, "acme")
	asset := h.seedAsset(t, ws, models.DiscoverySourceAgentSweep, "host:10.0.0.9:22", "ssh", "10.0.0.9:22", models.DiscoveryStatusUnmanaged)

	// Caller A wins the claim and is mid-onboard (its target is not created yet).
	if err := h.engine.claimAssetForOnboard(ctx, ws, asset.ID); err != nil {
		t.Fatalf("first claim: %v", err)
	}

	// Caller B raced through the same unmanaged status check; its full onboard
	// must now lose the claim with ErrConflict and create NO PAM target.
	if _, err := h.engine.OnboardAsset(ctx, ws, asset.ID, OnboardAssetInput{
		Username: "root", Secret: pam.Secret{Password: "x"}, Actor: "tester",
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("racing onboard: err = %v, want ErrConflict", err)
	}
	if n := h.targetCount(t, ws); n != 0 {
		t.Fatalf("orphan target created by losing onboarder: count = %d, want 0", n)
	}

	// Releasing A's claim (e.g. its own target creation failed) returns the
	// asset to the candidate list so it can be retried cleanly.
	h.engine.releaseAssetClaim(ctx, ws, asset.ID)
	var reverted models.DiscoveredAsset
	h.db.Where("id = ?", asset.ID).Take(&reverted)
	if reverted.Status != models.DiscoveryStatusUnmanaged || reverted.TargetID != nil {
		t.Fatalf("release did not revert claim: %+v", reverted)
	}

	target, err := h.engine.OnboardAsset(ctx, ws, asset.ID, OnboardAssetInput{
		Username: "root", Secret: pam.Secret{Password: "hunter2"}, Actor: "tester",
	})
	if err != nil {
		t.Fatalf("retry onboard: %v", err)
	}
	if n := h.targetCount(t, ws); n != 1 {
		t.Fatalf("target count after retry = %d, want 1", n)
	}
	var got models.DiscoveredAsset
	h.db.Where("id = ?", asset.ID).Take(&got)
	if got.Status != models.DiscoveryStatusManaged || got.TargetID == nil || *got.TargetID != target.ID {
		t.Fatalf("asset not linked after retry: %+v", got)
	}
}

func TestIgnoreAsset(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	ws := seedWorkspace(t, h.db, "acme")
	asset := h.seedAsset(t, ws, models.DiscoverySourceAgentSweep, "host:10.0.0.5:22", "ssh", "10.0.0.5:22", models.DiscoveryStatusUnmanaged)
	if err := h.engine.IgnoreAsset(ctx, ws, asset.ID, "tester"); err != nil {
		t.Fatalf("ignore: %v", err)
	}
	var got models.DiscoveredAsset
	h.db.Where("id = ?", asset.ID).Take(&got)
	if got.Status != models.DiscoveryStatusIgnored {
		t.Fatalf("status = %q, want ignored", got.Status)
	}

	managed := h.seedAsset(t, ws, models.DiscoverySourceConnector, "ec2:i-1", "ssh", "1.2.3.4:22", models.DiscoveryStatusManaged)
	if err := h.engine.IgnoreAsset(ctx, ws, managed.ID, "tester"); !errors.Is(err, ErrConflict) {
		t.Errorf("ignore managed: err = %v, want ErrConflict", err)
	}
}

func TestDispositionAccount(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	ws := seedWorkspace(t, h.db, "acme")
	acct := models.DiscoveredAccount{WorkspaceID: ws, TargetID: uuid.New(), Username: "analyst", Source: models.DiscoverySourceDBAccounts, Status: models.DiscoveryStatusOrphan, CanLogin: true, FirstSeenAt: fixedNow, LastSeenAt: fixedNow}
	if err := h.db.Create(&acct).Error; err != nil {
		t.Fatalf("seed account: %v", err)
	}
	if err := h.engine.DispositionAccount(ctx, ws, acct.ID, models.DiscoveryStatusIgnored, "tester"); err != nil {
		t.Fatalf("disposition: %v", err)
	}
	var got models.DiscoveredAccount
	h.db.Where("id = ?", acct.ID).Take(&got)
	if got.Status != models.DiscoveryStatusIgnored {
		t.Fatalf("status = %q, want ignored", got.Status)
	}
	if err := h.engine.DispositionAccount(ctx, ws, acct.ID, "bogus", "tester"); !errors.Is(err, ErrValidation) {
		t.Errorf("bad disposition: err = %v, want ErrValidation", err)
	}
}

// --- policy ----------------------------------------------------------------

func TestPolicyDefaultAndSave(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	ws := seedWorkspace(t, h.db, "acme")

	// Default view: disabled, require-lease pinned true.
	view, err := h.engine.GetPolicy(ctx, ws)
	if err != nil {
		t.Fatalf("get default policy: %v", err)
	}
	if view.Enabled || !view.RequireLease {
		t.Fatalf("default policy = %+v, want disabled + require_lease", view)
	}

	// Save flag-only policy (no credential, create_targets false).
	view, err = h.engine.SavePolicy(ctx, ws, PolicyInput{
		Enabled: true, Rules: []AutoOnboardRule{{Name: "ssh", Protocols: []string{"ssh"}}}, Actor: "tester",
	})
	if err != nil {
		t.Fatalf("save flag-only: %v", err)
	}
	if !view.Enabled || view.HasCredential || !view.RequireLease {
		t.Fatalf("flag-only view = %+v", view)
	}

	// create_targets without a credential is a validation error.
	if _, err := h.engine.SavePolicy(ctx, ws, PolicyInput{Enabled: true, CreateTargets: true, Rules: []AutoOnboardRule{{Name: "ssh", Protocols: []string{"ssh"}}}, Actor: "tester"}); !errors.Is(err, ErrValidation) {
		t.Fatalf("create_targets no cred: err = %v, want ErrValidation", err)
	}

	// Save with a sealed credential.
	view, err = h.engine.SavePolicy(ctx, ws, PolicyInput{
		Enabled: true, CreateTargets: true,
		Rules:      []AutoOnboardRule{{Name: "ssh", Protocols: []string{"ssh"}}},
		Credential: &pam.Secret{Username: "root", Password: "s3cret"}, Actor: "tester",
	})
	if err != nil {
		t.Fatalf("save with cred: %v", err)
	}
	if !view.HasCredential || view.CredentialUser != "root" {
		t.Fatalf("cred view = %+v", view)
	}

	// The plaintext password must never be persisted in the policy row.
	var raw models.AutoOnboardingPolicy
	h.db.Where("workspace_id = ?", ws).Take(&raw)
	if raw.CredentialEnvelope == "" || raw.CredentialEnvelope == "s3cret" {
		t.Fatalf("credential not sealed: %q", raw.CredentialEnvelope)
	}
	if c := h.auditCount(t, ws, "discovery.policy_update"); c < 1 {
		t.Fatalf("policy audit = %d, want >=1", c)
	}
}

// TestSavePolicyCredentialPreservation locks in the credential lifecycle so a
// username-only edit never silently wipes the sealed secret, while an explicit
// empty-username + empty-secret save still reverts the policy to flag-only.
func TestSavePolicyCredentialPreservation(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	ws := seedWorkspace(t, h.db, "acme")

	base := func(cred *pam.Secret) PolicyInput {
		return PolicyInput{
			Enabled:    true,
			Rules:      []AutoOnboardRule{{Name: "ssh", Protocols: []string{"ssh"}}},
			Credential: cred,
			Actor:      "tester",
		}
	}

	// Seal an initial credential and capture the envelope.
	if _, err := h.engine.SavePolicy(ctx, ws, base(&pam.Secret{Username: "root", Password: "s3cret"})); err != nil {
		t.Fatalf("seal initial: %v", err)
	}
	var sealed models.AutoOnboardingPolicy
	h.db.Where("workspace_id = ?", ws).Take(&sealed)
	if sealed.CredentialEnvelope == "" {
		t.Fatalf("expected sealed envelope after initial save")
	}

	// Username-only edit (no secret) must KEEP the sealed envelope unchanged
	// and only update the non-secret username.
	view, err := h.engine.SavePolicy(ctx, ws, base(&pam.Secret{Username: "svc-onboard"}))
	if err != nil {
		t.Fatalf("username-only edit: %v", err)
	}
	if !view.HasCredential || view.CredentialUser != "svc-onboard" {
		t.Fatalf("username-only view = %+v, want has_credential + renamed user", view)
	}
	var afterRename models.AutoOnboardingPolicy
	h.db.Where("workspace_id = ?", ws).Take(&afterRename)
	if afterRename.CredentialEnvelope != sealed.CredentialEnvelope || afterRename.CredentialKeyVer != sealed.CredentialKeyVer {
		t.Fatalf("username-only edit changed the sealed secret: env %q->%q ver %d->%d",
			sealed.CredentialEnvelope, afterRename.CredentialEnvelope, sealed.CredentialKeyVer, afterRename.CredentialKeyVer)
	}

	// A new password reseals: the envelope must change.
	if _, err := h.engine.SavePolicy(ctx, ws, base(&pam.Secret{Username: "svc-onboard", Password: "rotated"})); err != nil {
		t.Fatalf("reseal: %v", err)
	}
	var resealed models.AutoOnboardingPolicy
	h.db.Where("workspace_id = ?", ws).Take(&resealed)
	if resealed.CredentialEnvelope == afterRename.CredentialEnvelope {
		t.Fatalf("reseal did not change the envelope")
	}

	// Explicit clear: empty username + empty secret reverts to flag-only.
	view, err = h.engine.SavePolicy(ctx, ws, base(&pam.Secret{}))
	if err != nil {
		t.Fatalf("clear: %v", err)
	}
	if view.HasCredential {
		t.Fatalf("explicit clear left a credential: %+v", view)
	}
	var cleared models.AutoOnboardingPolicy
	h.db.Where("workspace_id = ?", ws).Take(&cleared)
	if cleared.CredentialEnvelope != "" || cleared.CredentialUsername != "" || cleared.CredentialKeyVer != 0 {
		t.Fatalf("clear left residue: %+v", cleared)
	}
}

// --- scheduled sweep / policy evaluation -----------------------------------

func TestRunScheduledSweepFlagOnly(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	ws := seedWorkspace(t, h.db, "acme")
	// Two unmanaged ssh assets; one rdp asset that must NOT match.
	h.seedAsset(t, ws, models.DiscoverySourceAgentSweep, "host:10.0.0.1:22", "ssh", "10.0.0.1:22", models.DiscoveryStatusUnmanaged)
	h.seedAsset(t, ws, models.DiscoverySourceAgentSweep, "host:10.0.0.2:22", "ssh", "10.0.0.2:22", models.DiscoveryStatusUnmanaged)
	h.seedAsset(t, ws, models.DiscoverySourceAgentSweep, "host:10.0.0.3:3389", "rdp", "10.0.0.3:3389", models.DiscoveryStatusUnmanaged)
	if _, err := h.engine.SavePolicy(ctx, ws, PolicyInput{Enabled: true, Rules: []AutoOnboardRule{{Name: "ssh", Protocols: []string{"ssh"}}}, Actor: "tester"}); err != nil {
		t.Fatalf("save policy: %v", err)
	}

	res, err := h.engine.RunScheduledSweep(ctx, ws)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if res.PolicyMatched != 2 || res.Onboarded != 0 {
		t.Fatalf("matched=%d onboarded=%d, want 2/0", res.PolicyMatched, res.Onboarded)
	}
	var flagged int64
	h.db.Model(&models.DiscoveredAsset{}).Where("workspace_id = ? AND policy_matched = ?", ws, true).Count(&flagged)
	if flagged != 2 {
		t.Fatalf("flagged = %d, want 2", flagged)
	}
}

// TestRunScheduledSweepPaginatesUnmanaged seeds more unmanaged assets than a
// single keyset page (evalAssetBatchSize) so the policy evaluation must cross a
// page boundary. Every matching asset must be flagged exactly once — proving the
// bounded iteration covers the whole inventory and never loops.
func TestRunScheduledSweepPaginatesUnmanaged(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	ws := seedWorkspace(t, h.db, "acme")
	const total = evalAssetBatchSize + 37
	for i := 0; i < total; i++ {
		ext := fmt.Sprintf("host:10.1.%d.%d:22", i/256, i%256)
		h.seedAsset(t, ws, models.DiscoverySourceAgentSweep, ext, "ssh", fmt.Sprintf("10.1.%d.%d:22", i/256, i%256), models.DiscoveryStatusUnmanaged)
	}
	if _, err := h.engine.SavePolicy(ctx, ws, PolicyInput{Enabled: true, Rules: []AutoOnboardRule{{Name: "ssh", Protocols: []string{"ssh"}}}, Actor: "tester"}); err != nil {
		t.Fatalf("save policy: %v", err)
	}

	res, err := h.engine.RunScheduledSweep(ctx, ws)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if res.PolicyMatched != total {
		t.Fatalf("matched = %d, want %d", res.PolicyMatched, total)
	}
	var flagged int64
	h.db.Model(&models.DiscoveredAsset{}).Where("workspace_id = ? AND policy_matched = ?", ws, true).Count(&flagged)
	if flagged != int64(total) {
		t.Fatalf("flagged = %d, want %d", flagged, total)
	}
}

func TestRunScheduledSweepCreateMode(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	ws := seedWorkspace(t, h.db, "acme")
	h.seedAsset(t, ws, models.DiscoverySourceAgentSweep, "host:10.0.0.1:22", "ssh", "10.0.0.1:22", models.DiscoveryStatusUnmanaged)
	if _, err := h.engine.SavePolicy(ctx, ws, PolicyInput{
		Enabled: true, CreateTargets: true,
		Rules:      []AutoOnboardRule{{Name: "ssh", Protocols: []string{"ssh"}}},
		Credential: &pam.Secret{Username: "root", Password: "pw"}, Actor: "tester",
	}); err != nil {
		t.Fatalf("save policy: %v", err)
	}

	res, err := h.engine.RunScheduledSweep(ctx, ws)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if res.Onboarded != 1 {
		t.Fatalf("onboarded = %d, want 1", res.Onboarded)
	}
	// Auto-created target requires a lease (no standing access) — verify via the
	// managed asset now linking to a target.
	var a models.DiscoveredAsset
	h.db.Where("workspace_id = ? AND external_id = ?", ws, "host:10.0.0.1:22").Take(&a)
	if a.Status != models.DiscoveryStatusManaged || a.TargetID == nil {
		t.Fatalf("asset not onboarded: %+v", a)
	}
}

func TestRunScheduledSweepNoPolicyIsNoop(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	ws := seedWorkspace(t, h.db, "acme")
	res, err := h.engine.RunScheduledSweep(ctx, ws)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if res != (ScheduledSweepResult{}) {
		t.Fatalf("no-policy sweep = %+v, want zero", res)
	}
}

// --- connector inventory ---------------------------------------------------

func TestConnectorInventory(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	ws := seedWorkspace(t, h.db, "acme")
	h.res.impl = &fakeConn{specs: []access.DiscoveredAssetSpec{
		{ExternalID: "ec2:i-123", Kind: access.AssetKindHost, Name: "web", Protocol: "ssh", Address: "10.1.0.4:22"},
		{ExternalID: "rds:db-1", Kind: access.AssetKindDatabase, Name: "orders", Protocol: "postgres", Address: "orders.rds:5432"},
	}}
	res, err := h.engine.ConnectorInventory(ctx, ws, uuid.New(), "tester", models.DiscoveryTriggerManual)
	if err != nil {
		t.Fatalf("inventory: %v", err)
	}
	if res.AssetsNew != 2 {
		t.Fatalf("new = %d, want 2", res.AssetsNew)
	}
	if c := h.auditCount(t, ws, "discovery.connector_inventory"); c != 1 {
		t.Fatalf("audit = %d, want 1", c)
	}
}

func TestConnectorInventoryUnsupported(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	ws := seedWorkspace(t, h.db, "acme")
	// A connector with no AssetDiscoverer capability.
	h.res.impl = nil
	if _, err := h.engine.ConnectorInventory(ctx, ws, uuid.New(), "tester", ""); !errors.Is(err, ErrUnsupported) {
		t.Errorf("no capability: err = %v, want ErrUnsupported", err)
	}
}

// --- summary ---------------------------------------------------------------

func TestSummary(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	ws := seedWorkspace(t, h.db, "acme")
	h.seedAsset(t, ws, models.DiscoverySourceAgentSweep, "a1", "ssh", "10.0.0.1:22", models.DiscoveryStatusUnmanaged)
	h.seedAsset(t, ws, models.DiscoverySourceAgentSweep, "a2", "ssh", "10.0.0.2:22", models.DiscoveryStatusManaged)
	h.db.Create(&models.DiscoveredAccount{WorkspaceID: ws, TargetID: uuid.New(), Username: "analyst", Source: models.DiscoverySourceDBAccounts, Status: models.DiscoveryStatusOrphan, FirstSeenAt: fixedNow, LastSeenAt: fixedNow})

	s, err := h.engine.Summary(ctx, ws)
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	if s.TotalAssets != 2 || s.UnmanagedAssets != 1 || s.ManagedAssets != 1 || s.OrphanAccounts != 1 {
		t.Fatalf("summary = %+v", s)
	}
}
