package discovery

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
)

// deadlineCapturingDialer records the deadline of the context passed to
// DialThroughAgent so a test can assert which budget probeOne imposed. It always
// fails the dial (probeOne only needs the deadline, not a live conn).
type deadlineCapturingDialer struct {
	gotDeadline time.Time
	hadDeadline bool
}

func (d *deadlineCapturingDialer) DialThroughAgent(ctx context.Context, _, _ uuid.UUID, _ string) (net.Conn, error) {
	d.gotDeadline, d.hadDeadline = ctx.Deadline()
	return nil, errors.New("capture only")
}

// budgetCapturingDialer is a deadlineCapturingDialer that also advertises a dial
// budget via DialBudgeter — modelling the cross-replica forward-only dialer.
type budgetCapturingDialer struct {
	deadlineCapturingDialer
	budget time.Duration
}

func (d *budgetCapturingDialer) DialBudget() time.Duration { return d.budget }

// TestProbeOneUsesAdvertisedDialBudget proves the forward-path regression is
// fixed: when the dialer advertises a wider DialBudget than ProbeTimeout,
// probeOne imposes that wider budget as the outer dial deadline (so the
// forward client's own dial timeout is no longer capped to the 3s probe).
func TestProbeOneUsesAdvertisedDialBudget(t *testing.T) {
	d := &budgetCapturingDialer{budget: 30 * time.Second}
	e := &Engine{dialer: d, cfg: Config{ProbeTimeout: 3 * time.Second}.withDefaults()}

	start := time.Now()
	if e.probeOne(context.Background(), uuid.New(), uuid.New(), "10.0.0.1", 22) {
		t.Fatal("probeOne returned reachable for a failing dial")
	}
	if !d.hadDeadline {
		t.Fatal("dial context had no deadline")
	}
	remaining := time.Until(d.gotDeadline)
	// The outer deadline must reflect the 30s budget, not the 3s ProbeTimeout.
	if remaining <= 10*time.Second {
		t.Fatalf("outer dial budget = %s (from start %s), want ~30s (the advertised budget, not ProbeTimeout)", remaining, time.Since(start))
	}
}

// TestProbeOneFallsBackToProbeTimeout proves a plain dialer that does NOT
// advertise a budget keeps the tight direct-probe ProbeTimeout.
func TestProbeOneFallsBackToProbeTimeout(t *testing.T) {
	d := &deadlineCapturingDialer{}
	e := &Engine{dialer: d, cfg: Config{ProbeTimeout: 3 * time.Second}.withDefaults()}

	if e.probeOne(context.Background(), uuid.New(), uuid.New(), "10.0.0.1", 22) {
		t.Fatal("probeOne returned reachable for a failing dial")
	}
	if !d.hadDeadline {
		t.Fatal("dial context had no deadline")
	}
	remaining := time.Until(d.gotDeadline)
	if remaining > 5*time.Second {
		t.Fatalf("outer dial budget = %s, want ~3s ProbeTimeout (no budgeter advertised)", remaining)
	}
}

// TestEngineDialBudget covers the budget-selection rule directly: advertised
// positive budget wins; a non-positive advertised value or a non-budgeter
// dialer falls back to ProbeTimeout.
func TestEngineDialBudget(t *testing.T) {
	cfg := Config{ProbeTimeout: 3 * time.Second}.withDefaults()
	cases := []struct {
		name   string
		dialer AgentDialer
		want   time.Duration
	}{
		{"advertised wider budget", &budgetCapturingDialer{budget: 15 * time.Second}, 15 * time.Second},
		{"advertised tighter budget", &budgetCapturingDialer{budget: time.Second}, time.Second},
		{"advertised zero falls back", &budgetCapturingDialer{budget: 0}, 3 * time.Second},
		{"no budgeter falls back", &deadlineCapturingDialer{}, 3 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := &Engine{dialer: tc.dialer, cfg: cfg}
			if got := e.dialBudget(); got != tc.want {
				t.Fatalf("dialBudget() = %s, want %s", got, tc.want)
			}
		})
	}
}
