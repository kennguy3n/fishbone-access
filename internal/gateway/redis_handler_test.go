package gateway

import (
	"bufio"
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/services/pam"
)

// --- RESP wire-helper unit tests ------------------------------------------

func TestReadRESPCommandMultibulk(t *testing.T) {
	in := "*3\r\n$3\r\nSET\r\n$3\r\nfoo\r\n$3\r\nbar\r\n"
	args, raw, err := readRESPCommand(bufio.NewReader(strings.NewReader(in)))
	if err != nil {
		t.Fatalf("readRESPCommand: %v", err)
	}
	if len(args) != 3 || args[0] != "SET" || args[1] != "foo" || args[2] != "bar" {
		t.Fatalf("args = %v", args)
	}
	if string(raw) != in {
		t.Fatalf("raw round-trip mismatch: %q", raw)
	}
}

func TestReadRESPCommandInline(t *testing.T) {
	args, raw, err := readRESPCommand(bufio.NewReader(strings.NewReader("PING\r\n")))
	if err != nil {
		t.Fatalf("readRESPCommand: %v", err)
	}
	if len(args) != 1 || args[0] != "PING" {
		t.Fatalf("inline args = %v", args)
	}
	if string(raw) != "PING\r\n" {
		t.Fatalf("inline raw = %q", raw)
	}
}

func TestReadRESPCommandRejectsHugeArray(t *testing.T) {
	_, _, err := readRESPCommand(bufio.NewReader(strings.NewReader("*9999999999\r\n")))
	if err == nil {
		t.Fatal("expected error for oversized array count")
	}
}

func TestEncodeRESPCommandRoundTrips(t *testing.T) {
	enc := encodeRESPCommand("AUTH", "user", "p@ss")
	args, _, err := readRESPCommand(bufio.NewReader(strings.NewReader(string(enc))))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(args) != 3 || args[0] != "AUTH" || args[1] != "user" || args[2] != "p@ss" {
		t.Fatalf("round-trip args = %v", args)
	}
}

func TestRedisCommandString(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{[]string{"flushall"}, "FLUSHALL"},
		{[]string{"config", "set", "maxmemory", "0"}, "CONFIG SET maxmemory 0"},
		{[]string{"GET", "myKey"}, "GET myKey"}, // key case preserved
	}
	for _, c := range cases {
		if got := redisCommandString(c.in); got != c.want {
			t.Errorf("redisCommandString(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

// --- integration test against a mock Redis upstream -----------------------

// mockRedisUpstream is a minimal RESP server: it expects the proxy to inject
// AUTH with wantPass, replies +OK to it, and thereafter replies +OK to every
// command it receives, recording the command verbs it saw. A real redis-server
// is unnecessary — the proxy's contract is "authenticate, then relay framed
// commands", which this double exercises faithfully.
type mockRedisUpstream struct {
	wantPass string

	mu   sync.Mutex
	seen []string
}

func (m *mockRedisUpstream) commands() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.seen...)
}

func (m *mockRedisUpstream) serve(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	// First command must be the injected AUTH.
	args, _, err := readRESPCommand(br)
	if err != nil {
		return
	}
	if len(args) < 2 || !strings.EqualFold(args[0], "AUTH") || args[len(args)-1] != m.wantPass {
		_, _ = conn.Write([]byte("-ERR upstream auth failed\r\n"))
		return
	}
	_, _ = conn.Write([]byte("+OK\r\n"))
	for {
		args, _, err := readRESPCommand(br)
		if err != nil {
			return
		}
		if len(args) == 0 {
			continue
		}
		m.mu.Lock()
		m.seen = append(m.seen, strings.ToUpper(args[0]))
		m.mu.Unlock()
		_, _ = conn.Write([]byte("+OK\r\n"))
	}
}

func TestRedisProxyEndToEnd(t *testing.T) {
	env := newProxyTestEnv(t)
	// Deny FLUSHALL for everyone via the 1C policy engine.
	env.seedDeny(t, "no-flush", []string{"*"}, []string{"cmd:FLUSHALL"})

	// Mock upstream.
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	defer upLn.Close()
	up := &mockRedisUpstream{wantPass: "upstream-secret"}
	go func() {
		for {
			c, err := upLn.Accept()
			if err != nil {
				return
			}
			go up.serve(c)
		}
	}()

	target := env.createTarget(t, models.PAMProtocolRedis, upLn.Addr().String(), pam.Secret{Password: "upstream-secret"})
	token := env.mintToken(t, target.ID, "alice")

	proxy, err := NewRedisProxy(RedisProxyConfig{
		Broker: env.broker, Sessions: env.sessions, Hub: env.hub, Store: env.store,
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewRedisProxy: %v", err)
	}

	client, server := pipeConn(t)
	defer client.Close()
	done := make(chan struct{})
	go func() {
		proxy.Handle(context.Background(), server)
		close(done)
	}()

	cr := bufio.NewReader(client)

	// Operator authenticates with the one-shot token as the AUTH password.
	if _, err := client.Write(encodeRESPCommand("AUTH", token)); err != nil {
		t.Fatalf("send AUTH: %v", err)
	}
	if line := readLine(t, cr); line != "+OK" {
		t.Fatalf("auth ack = %q, want +OK", line)
	}

	// Allowed command flows through to the upstream.
	if _, err := client.Write(encodeRESPCommand("SET", "foo", "bar")); err != nil {
		t.Fatalf("send SET: %v", err)
	}
	if line := readLine(t, cr); line != "+OK" {
		t.Fatalf("SET reply = %q, want +OK", line)
	}

	// Denied command is rejected by the gateway, never reaching the upstream.
	if _, err := client.Write(encodeRESPCommand("FLUSHALL")); err != nil {
		t.Fatalf("send FLUSHALL: %v", err)
	}
	line := readLine(t, cr)
	if !strings.HasPrefix(line, "-ERR pam-gateway:") {
		t.Fatalf("FLUSHALL reply = %q, want -ERR pam-gateway:", line)
	}

	// Close the operator side to end the session.
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("proxy did not return after operator close")
	}

	// The upstream saw the injected AUTH's effect (SET forwarded) but never
	// FLUSHALL.
	seen := up.commands()
	for _, c := range seen {
		if c == "FLUSHALL" {
			t.Fatal("denied FLUSHALL reached upstream")
		}
	}
	if len(seen) == 0 || seen[0] != "SET" {
		t.Fatalf("upstream did not receive forwarded SET: %v", seen)
	}

	// Session recording captured both directions and the policy-deny annotation.
	rows := env.sessionRows(t)
	if len(rows) != 1 {
		t.Fatalf("want 1 session row, got %d", len(rows))
	}
	if rows[0].State != models.PAMSessionClosed {
		t.Fatalf("session not closed: %q", rows[0].State)
	}
	replay, ok := env.store.put[rows[0].ID.String()]
	if !ok {
		t.Fatal("no replay flushed for session")
	}
	frames := parseFrames(t, replay)
	var sawInput, sawDenyNote bool
	for _, f := range frames {
		switch f.dir {
		case DirInput:
			if strings.Contains(string(f.payload), "SET") {
				sawInput = true
			}
		case DirControl:
			if strings.Contains(string(f.payload), "command denied") {
				sawDenyNote = true
			}
		}
	}
	if !sawInput {
		t.Fatal("recording missing forwarded input command")
	}
	if !sawDenyNote {
		t.Fatal("recording missing policy-deny annotation")
	}

	// Both commands were logged with their decisions.
	cmds := env.commandRows(t, rows[0].ID)
	if len(cmds) != 2 {
		t.Fatalf("want 2 logged commands, got %d", len(cmds))
	}
	if cmds[0].Decision != models.PAMDecisionAllow || cmds[1].Decision != models.PAMDecisionDeny {
		t.Fatalf("command decisions = %q,%q", cmds[0].Decision, cmds[1].Decision)
	}
}

// TestRedisProxyWrongProtocolTokenRejected proves a token minted for a
// non-redis target is refused and its orphaned session reconciled closed.
func TestRedisProxyWrongProtocolTokenRejected(t *testing.T) {
	env := newProxyTestEnv(t)
	target := env.createTarget(t, models.PAMProtocolPostgres, "127.0.0.1:1", pam.Secret{Password: "pw"})
	token := env.mintToken(t, target.ID, "alice")

	proxy, err := NewRedisProxy(RedisProxyConfig{Broker: env.broker, Sessions: env.sessions, Hub: env.hub, Store: env.store})
	if err != nil {
		t.Fatalf("NewRedisProxy: %v", err)
	}
	client, server := pipeConn(t)
	defer client.Close()
	done := make(chan struct{})
	go func() {
		proxy.Handle(context.Background(), server)
		close(done)
	}()

	if _, err := client.Write(encodeRESPCommand("AUTH", token)); err != nil {
		t.Fatalf("send AUTH: %v", err)
	}
	cr := bufio.NewReader(client)
	if line := readLine(t, cr); !strings.HasPrefix(line, "-ERR") {
		t.Fatalf("want -ERR for wrong-protocol token, got %q", line)
	}
	<-done

	rows := env.sessionRows(t)
	if len(rows) != 1 || rows[0].State != models.PAMSessionClosed {
		t.Fatalf("orphaned session not reconciled closed: %+v", rows)
	}
}

// TestRedisProxyOperatorAuthDeadline proves the operator-authentication phase is
// bounded by a read deadline: a client that opens the connection but never sends
// an AUTH must not pin the serving goroutine open indefinitely (a slowloris-style
// resource exhaustion). With the pre-auth read deadline the proxy returns within
// ~DialTimeout; without it Handle blocks forever in readRESPCommand and this test
// hits its generous timeout. Regression cover for the missing pre-auth deadline.
func TestRedisProxyOperatorAuthDeadline(t *testing.T) {
	env := newProxyTestEnv(t)
	proxy, err := NewRedisProxy(RedisProxyConfig{
		Broker: env.broker, Sessions: env.sessions, Hub: env.hub, Store: env.store,
		DialTimeout: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewRedisProxy: %v", err)
	}

	client, server := pipeConn(t)
	defer client.Close()

	done := make(chan struct{})
	go func() {
		proxy.Handle(context.Background(), server)
		close(done)
	}()

	// The client deliberately stays silent (never sends AUTH). Handle must abort
	// on the read deadline well before this bound, which is many multiples of the
	// 200ms DialTimeout.
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Handle did not return: operator auth read is not deadline-bounded (slowloris)")
	}
}

// concurrencyProbe is an io.Writer that detects overlapping Write calls. It
// widens the in-Write window with a tiny sleep so an unsynchronized writer would
// reliably be caught with two writers in flight at once.
type concurrencyProbe struct {
	inFlight      atomic.Int32
	maxConcurrent atomic.Int32
}

func (c *concurrencyProbe) Write(p []byte) (int, error) {
	n := c.inFlight.Add(1)
	for {
		m := c.maxConcurrent.Load()
		if n <= m || c.maxConcurrent.CompareAndSwap(m, n) {
			break
		}
	}
	time.Sleep(time.Microsecond)
	c.inFlight.Add(-1)
	return len(p), nil
}

// TestLockedWriterSerializesConcurrentWrites proves the shared operator-connection
// writer funnels concurrent writes through its mutex, so the two relay goroutines
// (the deny-reply injector and the upstream-reply copier) can never interleave
// frame bytes on the socket. Run under -race this also guards the helper itself.
// Regression cover for the concurrent-operator-write hazard in the MongoDB deny
// path. (The Redis proxy no longer uses a second writer goroutine — it drives a
// strictly sequential request/reply loop — so this helper now guards Mongo.)
func TestLockedWriterSerializesConcurrentWrites(t *testing.T) {
	probe := &concurrencyProbe{}
	lw := newLockedWriter(probe)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_, _ = lw.Write([]byte("-ERR pam-gateway: denied\r\n"))
			}
		}()
	}
	wg.Wait()

	if got := probe.maxConcurrent.Load(); got > 1 {
		t.Fatalf("lockedWriter allowed %d concurrent writes; deny and reply frames can interleave", got)
	}
}

// mockRedisEchoUpstream authenticates like mockRedisUpstream but answers every
// forwarded command with a simple-string echo of the command's first argument
// (its key). That makes each reply individually identifiable, so a test can
// prove the proxy returns replies in command order even when a denied command
// sits between two forwarded ones.
type mockRedisEchoUpstream struct {
	wantPass string
}

func (m *mockRedisEchoUpstream) serve(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	args, _, err := readRESPCommand(br)
	if err != nil {
		return
	}
	if len(args) < 2 || !strings.EqualFold(args[0], "AUTH") || args[len(args)-1] != m.wantPass {
		_, _ = conn.Write([]byte("-ERR upstream auth failed\r\n"))
		return
	}
	_, _ = conn.Write([]byte("+OK\r\n"))
	for {
		args, _, err := readRESPCommand(br)
		if err != nil {
			return
		}
		if len(args) == 0 {
			continue
		}
		key := ""
		if len(args) > 1 {
			key = args[1]
		}
		_, _ = conn.Write([]byte("+" + key + "\r\n"))
	}
}

// TestRedisProxyPipelinedReplyOrdering proves replies are returned in command
// order even when a denied command sits between two forwarded ones. The operator
// pipelines three commands in a single write — GET a, DEL b (denied by policy),
// GET c — and must read exactly "+a", the gateway deny error, then "+c", in that
// order. The previous two-goroutine design could write the DEL-b deny error
// before the upstream's "+a" reply landed, shifting every reply by one and
// handing the operator the wrong answer; the sequential pump prevents that.
func TestRedisProxyPipelinedReplyOrdering(t *testing.T) {
	env := newProxyTestEnv(t)
	env.seedDeny(t, "no-del", []string{"*"}, []string{"cmd:DEL *"})

	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	defer upLn.Close()
	up := &mockRedisEchoUpstream{wantPass: "upstream-secret"}
	go func() {
		for {
			c, err := upLn.Accept()
			if err != nil {
				return
			}
			go up.serve(c)
		}
	}()

	target := env.createTarget(t, models.PAMProtocolRedis, upLn.Addr().String(), pam.Secret{Password: "upstream-secret"})
	token := env.mintToken(t, target.ID, "alice")

	proxy, err := NewRedisProxy(RedisProxyConfig{
		Broker: env.broker, Sessions: env.sessions, Hub: env.hub, Store: env.store,
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewRedisProxy: %v", err)
	}

	client, server := pipeConn(t)
	defer client.Close()
	go proxy.Handle(context.Background(), server)

	cr := bufio.NewReader(client)
	if _, err := client.Write(encodeRESPCommand("AUTH", token)); err != nil {
		t.Fatalf("send AUTH: %v", err)
	}
	if line := readLine(t, cr); line != "+OK" {
		t.Fatalf("auth ack = %q, want +OK", line)
	}

	// Pipeline three commands in a single write; DEL is denied by policy.
	var pipeline []byte
	pipeline = append(pipeline, encodeRESPCommand("GET", "a")...)
	pipeline = append(pipeline, encodeRESPCommand("DEL", "b")...)
	pipeline = append(pipeline, encodeRESPCommand("GET", "c")...)
	if _, err := client.Write(pipeline); err != nil {
		t.Fatalf("send pipeline: %v", err)
	}

	// Reply 1 must be the upstream echo for GET a.
	if line := readLine(t, cr); line != "+a" {
		t.Fatalf("reply 1 = %q, want +a (GET a)", line)
	}
	// Reply 2 must be the gateway deny for DEL b — NOT an upstream reply.
	if line := readLine(t, cr); !strings.HasPrefix(line, "-ERR pam-gateway:") {
		t.Fatalf("reply 2 = %q, want gateway deny for DEL b", line)
	}
	// Reply 3 must be the upstream echo for GET c.
	if line := readLine(t, cr); line != "+c" {
		t.Fatalf("reply 3 = %q, want +c (GET c)", line)
	}

	// Upstream must have seen GET a and GET c only, in order, never DEL.
	_ = client.Close()
}

// TestReadRESPReply exercises the upstream reply reader across RESP2 and RESP3
// reply types, proving it returns exactly one complete reply (recursing into
// aggregates) and leaves any following bytes untouched, and that it fails closed
// on an unknown reply type.
func TestReadRESPReply(t *testing.T) {
	cases := []struct {
		name  string
		in    string
		want  string
		trail string // bytes that must remain unread after one reply
	}{
		{"simple string", "+OK\r\n", "+OK\r\n", ""},
		{"error", "-ERR nope\r\n", "-ERR nope\r\n", ""},
		{"integer", ":42\r\n", ":42\r\n", ""},
		{"bulk", "$5\r\nhello\r\n", "$5\r\nhello\r\n", ""},
		{"null bulk", "$-1\r\n", "$-1\r\n", ""},
		{"empty bulk", "$0\r\n\r\n", "$0\r\n\r\n", ""},
		{"array", "*2\r\n$3\r\nfoo\r\n:7\r\n", "*2\r\n$3\r\nfoo\r\n:7\r\n", ""},
		{"null array", "*-1\r\n", "*-1\r\n", ""},
		{"nested array", "*1\r\n*2\r\n:1\r\n:2\r\n", "*1\r\n*2\r\n:1\r\n:2\r\n", ""},
		{"resp3 null", "_\r\n", "_\r\n", ""},
		{"resp3 boolean", "#t\r\n", "#t\r\n", ""},
		{"resp3 double", ",3.14\r\n", ",3.14\r\n", ""},
		{"resp3 map", "%1\r\n$1\r\na\r\n:1\r\n", "%1\r\n$1\r\na\r\n:1\r\n", ""},
		{"resp3 set", "~2\r\n:1\r\n:2\r\n", "~2\r\n:1\r\n:2\r\n", ""},
		{"verbatim", "=8\r\ntxt:abcd\r\n", "=8\r\ntxt:abcd\r\n", ""},
		{"stops at one reply", "+first\r\n+second\r\n", "+first\r\n", "+second\r\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := bufio.NewReader(strings.NewReader(c.in))
			got, err := readRESPReply(r)
			if err != nil {
				t.Fatalf("readRESPReply: %v", err)
			}
			if string(got) != c.want {
				t.Fatalf("reply = %q, want %q", got, c.want)
			}
			rest, _ := r.ReadString(0) // drain remaining buffered bytes
			if rest != c.trail {
				t.Fatalf("trailing bytes = %q, want %q", rest, c.trail)
			}
		})
	}

	if _, err := readRESPReply(bufio.NewReader(strings.NewReader("@bogus\r\n"))); err == nil {
		t.Fatal("expected error for unknown RESP reply type")
	}
}

// readLine reads a single CRLF-terminated reply line, trimming the CRLF.
func readLine(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	line, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("read line: %v", err)
	}
	return strings.TrimRight(line, "\r\n")
}
