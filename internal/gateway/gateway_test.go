package gateway

import (
	"bufio"
	"context"
	"net"
	"testing"
	"time"
)

// echoHandler writes back whatever it reads — a stand-in for a real protocol
// proxy, sufficient to prove the supervisor's accept/drain lifecycle.
func echoHandler(_ context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()
	sc := bufio.NewScanner(conn)
	for sc.Scan() {
		_, _ = conn.Write(append(sc.Bytes(), '\n'))
	}
}

func TestSupervisorAcceptsAndServes(t *testing.T) {
	sup := NewSupervisor([]Listener{
		{Name: "echo", Addr: "127.0.0.1:0", Handler: ConnHandlerFunc(echoHandler)},
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sup.Run(ctx) }()

	// Wait for the bound address.
	var addr string
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if a, ok := sup.Addrs()["echo"]; ok && a != "" {
			addr = a
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if addr == "" {
		t.Fatal("listener never bound")
	}

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write([]byte("hello\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	got, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got != "hello\n" {
		t.Fatalf("echo = %q, want %q", got, "hello\n")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v, want nil on clean shutdown", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

func TestSupervisorRejectsHandlerlessListener(t *testing.T) {
	sup := NewSupervisor([]Listener{{Name: "bad", Addr: "127.0.0.1:0"}})
	if err := sup.Run(context.Background()); err == nil {
		t.Fatal("expected error for listener without handler")
	}
}

func TestSupervisorBindError(t *testing.T) {
	// Bind a port, then ask the supervisor to bind the same address.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pre-bind: %v", err)
	}
	defer func() { _ = ln.Close() }()

	sup := NewSupervisor([]Listener{
		{Name: "dup", Addr: ln.Addr().String(), Handler: ConnHandlerFunc(echoHandler)},
	})
	if err := sup.Run(context.Background()); err == nil {
		t.Fatal("expected bind error for in-use address")
	}
}
