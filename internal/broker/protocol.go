// Package broker is the control-plane side of the outbound connector-agent
// tunnel. An agent (cmd/access-target-agent) runs inside a customer's private
// network and dials OUT to the Relay over mTLS; the Relay multiplexes many
// session streams over that single outbound connection with yamux, tracks which
// agents are online per workspace, and exposes DialThroughAgent so the PAM
// gateway can reach a private target through the agent's tunnel without the
// customer opening any inbound port.
//
// Why yamux: the tunnel must carry many concurrent privileged sessions over one
// outbound connection, with each session looking like an ordinary net.Conn to
// the existing protocol proxies (SSH, Postgres, ...). yamux gives bidirectional
// stream multiplexing, per-stream flow control, and built-in keepalives over a
// single net.Conn, and its *yamux.Stream already implements net.Conn — so the
// gateway's handlers consume a brokered stream unchanged. It is the same proven
// multiplexer HashiCorp Boundary/Consul use for exactly this worker-tunnel
// shape, which is why it is preferred here over a bespoke websocket subprotocol.
package broker

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Control-stream message types. The agent opens exactly one control stream when
// the tunnel comes up and sends newline-delimited JSON ControlMessages on it:
// one register on connect, then a heartbeat on a fixed interval. The relay only
// reads this stream.
const (
	ControlTypeRegister  = "register"
	ControlTypeHeartbeat = "heartbeat"
)

// ControlMessage is one message on the agent→relay control stream.
type ControlMessage struct {
	Type     string           `json:"type"`
	Register *RegisterPayload `json:"register,omitempty"`
}

// RegisterPayload is the agent's self-description sent on connect: its build and
// host platform (health/inventory) and the network destinations it can reach,
// which the relay unions with operator-created bindings to route dials.
type RegisterPayload struct {
	AgentVersion string          `json:"agent_version"`
	Platform     string          `json:"platform"`
	Reachable    []ReachableSpec `json:"reachable"`
}

// ReachableSpec is one self-reported reachable destination (a CIDR, host, or
// hostname pattern). Kind is one of models.AgentReachKind*.
type ReachableSpec struct {
	Pattern string `json:"pattern"`
	Kind    string `json:"kind"`
}

// DialRequest is written by the relay on a freshly opened dial stream to ask the
// agent to connect to Target (host:port) on its side of the tunnel.
type DialRequest struct {
	Target string `json:"target"`
}

// DialResponse is the agent's reply on the dial stream. When OK is true the rest
// of the stream is the raw, bidirectional byte tunnel to the upstream target;
// otherwise Error explains why the agent could not reach it and the stream is
// closed.
type DialResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// maxLineBytes bounds a single control/handshake JSON line so a misbehaving or
// hostile peer cannot drive the relay to read an unbounded line into memory.
const maxLineBytes = 64 * 1024

// writeJSONLine marshals v and writes it followed by a newline. It is used for
// both the control messages and the dial handshake.
func writeJSONLine(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > maxLineBytes {
		return fmt.Errorf("broker: message too large (%d bytes)", len(b))
	}
	b = append(b, '\n')
	_, err = w.Write(b)
	return err
}

// readJSONLine reads bytes one at a time up to and including the first newline
// and unmarshals the line into v. Reading byte-by-byte is deliberate: the dial
// handshake is immediately followed by the raw byte tunnel on the SAME stream,
// so the reader must not buffer past the newline or it would swallow the first
// bytes of the tunnel. The lines exchanged here are tiny and one-shot per
// stream, so the per-byte read cost is irrelevant.
func readJSONLine(r io.Reader, v any) error {
	buf := make([]byte, 0, 256)
	one := make([]byte, 1)
	for {
		n, err := r.Read(one)
		if n > 0 {
			if one[0] == '\n' {
				break
			}
			buf = append(buf, one[0])
			if len(buf) > maxLineBytes {
				return errors.New("broker: handshake line exceeded limit")
			}
			continue
		}
		if err != nil {
			if errors.Is(err, io.EOF) && len(buf) == 0 {
				return io.EOF
			}
			return err
		}
	}
	return json.Unmarshal(buf, v)
}

// scanControl returns a bufio.Scanner configured to read newline-delimited
// ControlMessages from the dedicated control stream (which carries no raw tunnel
// after it, so buffering ahead is safe and efficient here).
func scanControl(r io.Reader) *bufio.Scanner {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, 4096), maxLineBytes)
	return s
}
