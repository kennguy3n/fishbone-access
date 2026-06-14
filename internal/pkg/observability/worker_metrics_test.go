package observability

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestServeMetricsEmptyAddrIsNoOp proves an empty addr disables the server and
// returns a join that does not block, so a worker can wire it unconditionally.
func TestServeMetricsEmptyAddrIsNoOp(t *testing.T) {
	join := NewMetrics().ServeMetrics(context.Background(), "")
	done := make(chan struct{})
	go func() { join(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("no-op join blocked, want immediate return")
	}
}

// TestServeMetricsServesAndShutsDown proves the worker server exposes the
// scrape endpoint and /healthz, and that cancelling the context shuts it down
// (join returns).
func TestServeMetricsServesAndShutsDown(t *testing.T) {
	// Bind an ephemeral port to avoid clashing with anything on the box.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	m := NewMetrics()
	m.IncWakeEvents() // ensure the hibernation series is present in the scrape
	ctx, cancel := context.WithCancel(context.Background())
	join := m.ServeMetrics(ctx, addr)

	base := "http://" + addr
	waitReady(t, base+"/healthz")

	body := get(t, base+"/metrics")
	if !strings.Contains(body, "shieldnet_hibernation_wake_events_total") {
		t.Errorf("scrape missing hibernation series\n%s", body)
	}

	cancel()
	done := make(chan struct{})
	go func() { join(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("join did not return after context cancel")
	}
}

func waitReady(t *testing.T, url string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("server at %s never became ready", url)
}

func get(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}
