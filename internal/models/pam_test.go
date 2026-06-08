package models

import "testing"

// TestPAMProtocolsSourceOfTruth pins the canonical protocol set so the gateway
// listeners (cmd/pam-gateway), the vault's validProtocol gate, and the
// 0011_pam_protocol_expansion.sql CHECK constraint stay in agreement: a change
// to the supported set must be a deliberate edit here.
func TestPAMProtocolsSourceOfTruth(t *testing.T) {
	want := []string{"ssh", "postgres", "mysql", "k8s-exec", "rdp", "vnc", "mongodb", "redis", "mssql", "http"}
	got := PAMProtocols()
	if len(got) != len(want) {
		t.Fatalf("PAMProtocols() = %v (len %d), want %v", got, len(got), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("PAMProtocols()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	// The returned slice must be a copy: mutating it cannot corrupt the
	// package-level source of truth.
	got[0] = "tampered"
	if PAMProtocols()[0] != "ssh" {
		t.Fatal("PAMProtocols() leaked a mutable reference to the source of truth")
	}
}

func TestIsValidPAMProtocol(t *testing.T) {
	for _, p := range PAMProtocols() {
		if !IsValidPAMProtocol(p) {
			t.Errorf("IsValidPAMProtocol(%q) = false, want true", p)
		}
	}
	for _, p := range []string{"", "telnet", "RDP", "ssh ", "https"} {
		if IsValidPAMProtocol(p) {
			t.Errorf("IsValidPAMProtocol(%q) = true, want false", p)
		}
	}
}
