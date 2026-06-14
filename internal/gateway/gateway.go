// Package gateway is the PAM (Privileged Access Management) proxy core behind
// the pam-gateway binary. It supervises a set of named protocol listeners
// (SSH, PostgreSQL, MySQL, Kubernetes-exec) over TCP: it binds each address,
// accepts connections, and hands each connection to that protocol's
// ConnHandler.
//
// The listener supervisor handles connection lifecycle, concurrency
// tracking, and graceful drain. The per-protocol ConnHandlers (wire-protocol
// parsing, CA-signed cert injection, session recording, the audit hash chain)
// plug into this supervisor unchanged.
package gateway

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
)

// ConnHandler handles a single accepted connection for one protocol. It must
// return when ctx is cancelled (gateway shutdown) and is responsible for
// closing conn.
type ConnHandler interface {
	Handle(ctx context.Context, conn net.Conn)
}

// ConnHandlerFunc adapts a function to ConnHandler.
type ConnHandlerFunc func(ctx context.Context, conn net.Conn)

// Handle implements ConnHandler.
func (f ConnHandlerFunc) Handle(ctx context.Context, conn net.Conn) { f(ctx, conn) }

// Listener describes one protocol proxy endpoint.
type Listener struct {
	// Name is a human label ("ssh", "postgres", "mysql", "k8s-exec").
	Name string
	// Addr is the bind address (e.g. ":2222").
	Addr string
	// Handler processes accepted connections.
	Handler ConnHandler
}

// Supervisor binds and serves a set of protocol listeners and drains them on
// shutdown.
type Supervisor struct {
	listeners []Listener

	mu      sync.Mutex
	active  []boundListener
	conns   map[net.Conn]struct{}
	closing bool
	wg      sync.WaitGroup
}

// boundListener pairs a bound net.Listener with its protocol name so callers
// (Addrs, closeAll) never have to correlate it back to s.listeners by index.
type boundListener struct {
	name string
	ln   net.Listener
}

// NewSupervisor builds a Supervisor for the given listeners.
func NewSupervisor(listeners []Listener) *Supervisor {
	return &Supervisor{listeners: listeners, conns: make(map[net.Conn]struct{})}
}

// Run binds every listener and serves until ctx is cancelled, then drains
// in-flight connections. It returns the first bind error, or nil on clean
// shutdown.
func (s *Supervisor) Run(ctx context.Context) error {
	// Validate the whole listener set before binding anything, so a
	// misconfigured listener cannot leave earlier listeners bound and their
	// serve goroutines running.
	for _, l := range s.listeners {
		if l.Handler == nil {
			return fmt.Errorf("gateway: listener %q has no handler", l.Name)
		}
	}

	var lc net.ListenConfig
	for _, l := range s.listeners {
		ln, err := lc.Listen(ctx, "tcp", l.Addr)
		if err != nil {
			// Drain any listeners/goroutines already started before failing,
			// so callers can assume all resources are released on return.
			s.closeAll()
			s.wg.Wait()
			return fmt.Errorf("gateway: bind %s (%s): %w", l.Name, l.Addr, err)
		}
		s.track(l.Name, ln)
		s.wg.Add(1)
		go s.serve(ctx, l, ln)
	}

	<-ctx.Done()
	s.closeAll()
	s.wg.Wait()
	return nil
}

// Addrs returns the actual bound addresses keyed by listener name. Useful for
// tests that bind to :0 and need the OS-assigned port. The name travels with
// each bound listener (boundListener), so this does not depend on s.active and
// s.listeners staying index-aligned.
func (s *Supervisor) Addrs() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]string, len(s.active))
	for _, b := range s.active {
		out[b.name] = b.ln.Addr().String()
	}
	return out
}

func (s *Supervisor) serve(ctx context.Context, l Listener, ln net.Listener) {
	defer s.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			// A closed listener (shutdown) surfaces as ErrClosed: exit quietly.
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if ctx.Err() != nil {
				return
			}
			logger.Warnf(ctx, "gateway: %s accept error: %v", l.Name, err)
			continue
		}
		if !s.trackConn(conn) {
			// Already shutting down: refuse the late connection.
			_ = conn.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.untrackConn(conn)
			l.Handler.Handle(ctx, conn)
		}()
	}
}

// trackConn registers an accepted connection, returning false if the
// supervisor is already shutting down (so the caller refuses it).
func (s *Supervisor) trackConn(conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return false
	}
	s.conns[conn] = struct{}{}
	return true
}

func (s *Supervisor) untrackConn(conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conns, conn)
}

func (s *Supervisor) track(name string, ln net.Listener) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active = append(s.active, boundListener{name: name, ln: ln})
}

// closeAll stops accepting (closes listeners) and force-closes in-flight
// connections so their ConnHandlers unblock and Run can return. Real protocol
// handlers also observe ctx cancellation; closing the socket is the backstop
// that guarantees drain completes.
func (s *Supervisor) closeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closing = true
	for _, b := range s.active {
		_ = b.ln.Close()
	}
	for conn := range s.conns {
		_ = conn.Close()
	}
}
