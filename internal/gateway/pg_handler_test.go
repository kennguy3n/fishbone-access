package gateway

import (
	"bytes"
	"testing"

	"github.com/jackc/pgx/v5/pgproto3"
)

// encodeFrontend serialises a sequence of frontend (client→server) messages
// into the wire bytes a Backend would read, so the extended-query drain logic
// can be exercised without a socket.
func encodeFrontend(t *testing.T, msgs ...pgproto3.FrontendMessage) []byte {
	t.Helper()
	var buf []byte
	for _, m := range msgs {
		b, err := m.Encode(buf)
		if err != nil {
			t.Fatalf("encode %T: %v", m, err)
		}
		buf = b
	}
	return buf
}

func TestDrainUntilSyncStopsAtSync(t *testing.T) {
	// A denied Parse leaves Bind/Describe/Execute/Sync pipelined behind it.
	// drainUntilSync must consume exactly up to and including Sync, leaving the
	// next message (a fresh Query) unread for the main loop.
	wire := encodeFrontend(t,
		&pgproto3.Bind{},
		&pgproto3.Describe{ObjectType: 'P'},
		&pgproto3.Execute{},
		&pgproto3.Sync{},
		&pgproto3.Query{String: "SELECT 1"},
	)
	backend := pgproto3.NewBackend(bytes.NewReader(wire), &bytes.Buffer{})

	if ok := drainUntilSync(backend); !ok {
		t.Fatal("drainUntilSync returned false, want true (Sync seen)")
	}

	// The Query after Sync must still be readable — drain stopped at the
	// synchronisation point and did not over-consume.
	msg, err := backend.Receive()
	if err != nil {
		t.Fatalf("receive after drain: %v", err)
	}
	q, ok := msg.(*pgproto3.Query)
	if !ok {
		t.Fatalf("after drain got %T, want *pgproto3.Query", msg)
	}
	if q.String != "SELECT 1" {
		t.Fatalf("query after drain = %q, want %q", q.String, "SELECT 1")
	}
}

func TestDrainUntilSyncTerminateBeforeSync(t *testing.T) {
	// If the client terminates before sending Sync, the drain must report
	// failure so the handler tears the connection down rather than hanging.
	wire := encodeFrontend(t,
		&pgproto3.Bind{},
		&pgproto3.Terminate{},
	)
	backend := pgproto3.NewBackend(bytes.NewReader(wire), &bytes.Buffer{})

	if ok := drainUntilSync(backend); ok {
		t.Fatal("drainUntilSync returned true on Terminate, want false")
	}
}

func TestDrainUntilSyncEOF(t *testing.T) {
	// A truncated stream (connection dropped mid-pipeline) must not block.
	wire := encodeFrontend(t, &pgproto3.Bind{})
	backend := pgproto3.NewBackend(bytes.NewReader(wire), &bytes.Buffer{})

	if ok := drainUntilSync(backend); ok {
		t.Fatal("drainUntilSync returned true on EOF, want false")
	}
}

func TestPgSpliceStateTracksTxStatus(t *testing.T) {
	s := &pgSpliceState{txStatus: 'I'}
	if got := s.currentTxStatus(); got != 'I' {
		t.Fatalf("initial tx status = %q, want 'I'", got)
	}
	s.setTxStatus('T')
	if got := s.currentTxStatus(); got != 'T' {
		t.Fatalf("tx status after BEGIN = %q, want 'T'", got)
	}
	s.setTxStatus('E')
	if got := s.currentTxStatus(); got != 'E' {
		t.Fatalf("tx status after error = %q, want 'E'", got)
	}
}
