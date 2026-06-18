package broker

import (
	"context"
	"crypto/tls"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

// lookupDirectory is a SessionDirectory whose Lookup returns canned values. It
// embeds the interface so only Lookup is implemented — the forward-only dialer
// never calls Claim/Refresh/Release/OnlineCount/IsOnline, so leaving them nil is
// safe and keeps the fake minimal.
type lookupDirectory struct {
	SessionDirectory
	entry *OwnerEntry
	fresh bool
	err   error
}

func (d lookupDirectory) Lookup(context.Context, uuid.UUID, uuid.UUID) (*OwnerEntry, bool, error) {
	return d.entry, d.fresh, d.err
}

// TestForwardOnlyDialerFailsClosed proves every non-live path through the
// forward-only dialer returns ErrAgentUnavailable — never a direct dial, never a
// nil-but-no-error conn — preserving the broker's agent-only, fail-closed
// guarantee for the workflow engine's scheduled active sweep.
func TestForwardOnlyDialerFailsClosed(t *testing.T) {
	ctx := context.Background()
	ws, agent := uuid.New(), uuid.New()
	// A non-nil forward client with a tight timeout for the "owner unreachable"
	// case. It carries a non-nil (empty) client TLS config so the dial fails
	// closed deterministically regardless of whether the dead port refuses the
	// TCP connect (the common case) or — in an unusual sandbox where the port is
	// open — the TLS handshake fails: never a nil-pointer panic. For the
	// directory-only cases it is never dialed at all.
	fwd := NewForwardClient(&ForwardTLS{client: &tls.Config{}}, 200*time.Millisecond)

	cases := []struct {
		name string
		dir  SessionDirectory
		fwd  *ForwardClient
		ws   uuid.UUID
		ag   uuid.UUID
	}{
		{"nil directory", nil, fwd, ws, agent},
		{"nil forward client", lookupDirectory{fresh: true, entry: &OwnerEntry{NodeID: "n2", ForwardAddr: "127.0.0.1:1"}}, nil, ws, agent},
		{"nil workspace id", lookupDirectory{fresh: true, entry: &OwnerEntry{NodeID: "n2", ForwardAddr: "127.0.0.1:1"}}, fwd, uuid.Nil, agent},
		{"nil agent id", lookupDirectory{fresh: true, entry: &OwnerEntry{NodeID: "n2", ForwardAddr: "127.0.0.1:1"}}, fwd, ws, uuid.Nil},
		{"lookup error", lookupDirectory{err: errors.New("db down")}, fwd, ws, agent},
		{"owner unknown", lookupDirectory{entry: nil, fresh: false}, fwd, ws, agent},
		{"owner stale", lookupDirectory{fresh: false, entry: &OwnerEntry{NodeID: "n2", ForwardAddr: "127.0.0.1:1"}}, fwd, ws, agent},
		{"owner missing forward addr", lookupDirectory{fresh: true, entry: &OwnerEntry{NodeID: "n2", ForwardAddr: ""}}, fwd, ws, agent},
		{"owner unreachable", lookupDirectory{fresh: true, entry: &OwnerEntry{NodeID: "n2", ForwardAddr: "127.0.0.1:1"}}, fwd, ws, agent},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := NewForwardOnlyDialer(tc.dir, tc.fwd)
			conn, err := d.DialThroughAgent(ctx, tc.ws, tc.ag, "10.0.0.1:22")
			if !errors.Is(err, ErrAgentUnavailable) {
				t.Fatalf("err = %v, want ErrAgentUnavailable", err)
			}
			if conn != nil {
				_ = conn.Close()
				t.Fatalf("expected nil conn on fail-closed path")
			}
		})
	}
}

// TestForwardOnlyDialerNilReceiver guards the zero-value/nil receiver path so a
// mis-wired dialer fails closed rather than panicking.
func TestForwardOnlyDialerNilReceiver(t *testing.T) {
	var d *ForwardOnlyDialer
	conn, err := d.DialThroughAgent(context.Background(), uuid.New(), uuid.New(), "10.0.0.1:22")
	if !errors.Is(err, ErrAgentUnavailable) {
		t.Fatalf("err = %v, want ErrAgentUnavailable", err)
	}
	if conn != nil {
		_ = conn.Close()
		t.Fatalf("expected nil conn from nil receiver")
	}
}

// TestForwardOnlyDialerDialBudget proves the dialer advertises the forward
// client's dial timeout as its DialBudget (so discovery's probeOne widens the
// outer deadline to ForwardTimeout instead of the tight ProbeTimeout), and
// reports 0 — letting probeOne fall back to ProbeTimeout — when no forward
// client is wired or the receiver is nil.
func TestForwardOnlyDialerDialBudget(t *testing.T) {
	dir := lookupDirectory{fresh: true, entry: &OwnerEntry{NodeID: "n2", ForwardAddr: "127.0.0.1:1"}}

	if got := NewForwardOnlyDialer(dir, NewForwardClient(&ForwardTLS{client: &tls.Config{}}, 15*time.Second)).DialBudget(); got != 15*time.Second {
		t.Fatalf("DialBudget() = %s, want 15s", got)
	}
	// A zero/negative dialTO is defaulted to 15s by NewForwardClient, so the
	// advertised budget mirrors that default rather than reporting 0.
	if got := NewForwardOnlyDialer(dir, NewForwardClient(&ForwardTLS{client: &tls.Config{}}, 0)).DialBudget(); got != 15*time.Second {
		t.Fatalf("DialBudget() with defaulted timeout = %s, want 15s", got)
	}
	if got := NewForwardOnlyDialer(dir, nil).DialBudget(); got != 0 {
		t.Fatalf("DialBudget() with nil forward client = %s, want 0", got)
	}
	var nilDialer *ForwardOnlyDialer
	if got := nilDialer.DialBudget(); got != 0 {
		t.Fatalf("DialBudget() on nil receiver = %s, want 0", got)
	}
}
