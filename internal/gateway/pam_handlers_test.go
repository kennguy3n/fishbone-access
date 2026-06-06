package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

// frame is one decoded recording frame.
type frame struct {
	dir     Direction
	at      time.Time
	payload []byte
}

// parseFrames decodes the recorder's framed byte stream so tests can assert on
// direction ordering and payload content.
func parseFrames(t *testing.T, b []byte) []frame {
	t.Helper()
	var out []frame
	for len(b) > 0 {
		if len(b) < frameHeaderLen {
			t.Fatalf("truncated frame header: %d bytes left", len(b))
		}
		dir := Direction(b[0])
		nanos := binary.BigEndian.Uint64(b[1:9])
		n := binary.BigEndian.Uint32(b[9:13])
		b = b[frameHeaderLen:]
		if uint32(len(b)) < n {
			t.Fatalf("truncated frame payload: want %d, have %d", n, len(b))
		}
		out = append(out, frame{dir: dir, at: time.Unix(0, int64(nanos)), payload: append([]byte(nil), b[:n]...)})
		b = b[n:]
	}
	return out
}

// --- recorder tests -------------------------------------------------------

func TestRecorderFramesBothDirections(t *testing.T) {
	rec := NewIORecorder("sess-1", 0)
	rec.Record(DirInput, []byte("whoami\n"))
	rec.Record(DirOutput, []byte("root\n"))
	rec.Annotate("policy: allow")
	rec.Record(DirInput, nil) // ignored

	frames := parseFrames(t, rec.Bytes())
	if len(frames) != 3 {
		t.Fatalf("want 3 frames, got %d", len(frames))
	}
	if frames[0].dir != DirInput || string(frames[0].payload) != "whoami\n" {
		t.Fatalf("frame0 bad: %c %q", frames[0].dir, frames[0].payload)
	}
	if frames[1].dir != DirOutput || string(frames[1].payload) != "root\n" {
		t.Fatalf("frame1 bad: %c %q", frames[1].dir, frames[1].payload)
	}
	if frames[2].dir != DirControl || string(frames[2].payload) != "policy: allow" {
		t.Fatalf("frame2 bad: %c %q", frames[2].dir, frames[2].payload)
	}
}

func TestRecorderTeeReaderPassesThrough(t *testing.T) {
	rec := NewIORecorder("sess-tee", 0)
	src := bytes.NewReader([]byte("hello world"))
	tee := rec.TeeReader(DirInput, src)
	got := make([]byte, 11)
	n, _ := tee.Read(got)
	if string(got[:n]) != "hello world" {
		t.Fatalf("tee altered bytes: %q", got[:n])
	}
	frames := parseFrames(t, rec.Bytes())
	if len(frames) != 1 || string(frames[0].payload) != "hello world" {
		t.Fatalf("tee did not record passthrough: %+v", frames)
	}
}

func TestRecorderTruncationCap(t *testing.T) {
	// Cap small so the second write trips truncation.
	rec := NewIORecorder("sess-trunc", frameHeaderLen+4)
	rec.Record(DirOutput, []byte("aaaa"))
	rec.Record(DirOutput, []byte("bbbb")) // exceeds cap
	if !rec.Truncated() {
		t.Fatal("expected recorder to mark truncated")
	}
	frames := parseFrames(t, rec.Bytes())
	// First payload + a control truncation note.
	if len(frames) != 2 || frames[1].dir != DirControl {
		t.Fatalf("unexpected frames after truncation: %+v", frames)
	}
}

func TestRecorderLiveMonitorFanOut(t *testing.T) {
	rec := NewIORecorder("sess-mon", 0)
	mon := &captureMonitor{}
	remove := rec.AddMonitor(mon)
	rec.Record(DirOutput, []byte("first"))
	remove()
	rec.Record(DirOutput, []byte("second")) // after detach, not seen

	mon.mu.Lock()
	defer mon.mu.Unlock()
	if len(mon.frames) != 1 || string(mon.frames[0]) != "first" {
		t.Fatalf("monitor saw %d frames: %v", len(mon.frames), mon.frames)
	}
}

func TestRecorderFlushToStore(t *testing.T) {
	rec := NewIORecorder("sess-flush", 0)
	rec.Record(DirInput, []byte("data"))
	store := &memStore{put: map[string][]byte{}}
	if err := rec.Flush(context.Background(), store); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	// Flush is idempotent and subsequent records are ignored.
	rec.Record(DirInput, []byte("after-close"))
	if err := rec.Flush(context.Background(), store); err != nil {
		t.Fatalf("second Flush: %v", err)
	}
	if _, ok := store.put["sess-flush"]; !ok {
		t.Fatal("store did not receive the recording")
	}
}

type captureMonitor struct {
	mu     sync.Mutex
	frames [][]byte
}

func (m *captureMonitor) OnFrame(_ Direction, _ time.Time, payload []byte) {
	m.mu.Lock()
	m.frames = append(m.frames, append([]byte(nil), payload...))
	m.mu.Unlock()
}

type memStore struct {
	mu  sync.Mutex
	put map[string][]byte
}

func (s *memStore) PutReplay(_ context.Context, sessionID string, r io.Reader) error {
	buf := new(bytes.Buffer)
	if _, err := io.Copy(buf, r); err != nil {
		return err
	}
	s.mu.Lock()
	s.put[sessionID] = buf.Bytes()
	s.mu.Unlock()
	return nil
}

// --- session hub tests ----------------------------------------------------

func TestSessionHubTerminateAndMonitor(t *testing.T) {
	hub := NewSessionHub()
	sessionID := uuid.New()
	ws := uuid.New()
	rec := NewIORecorder(sessionID.String(), 0)

	terminated := false
	deregister := hub.Register(sessionID, ws, "alice", rec, func() { terminated = true })

	// Monitor attaches to the live recorder.
	mon := &captureMonitor{}
	detach, ok := hub.Monitor(sessionID, mon)
	if !ok {
		t.Fatal("Monitor did not find live session")
	}
	rec.Record(DirOutput, []byte("live"))
	detach()

	// Active listing is workspace-scoped.
	if got := hub.ActiveInWorkspace(ws); len(got) != 1 || got[0].SessionID != sessionID {
		t.Fatalf("ActiveInWorkspace wrong: %+v", got)
	}
	if got := hub.ActiveInWorkspace(uuid.New()); len(got) != 0 {
		t.Fatalf("cross-workspace listing leaked %d sessions", len(got))
	}

	// Terminate invokes the cancel func.
	if !hub.Terminate(sessionID) {
		t.Fatal("Terminate returned false for active session")
	}
	if !terminated {
		t.Fatal("cancel func not invoked on terminate")
	}

	deregister()
	if hub.Terminate(sessionID) {
		t.Fatal("Terminate should return false after deregister")
	}

	mon.mu.Lock()
	defer mon.mu.Unlock()
	if len(mon.frames) != 1 || string(mon.frames[0]) != "live" {
		t.Fatalf("monitor frames: %v", mon.frames)
	}
}

// --- filesystem replay store tests ---------------------------------------

func TestFilesystemReplayStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFilesystemReplayStore(dir)
	if err != nil {
		t.Fatalf("NewFilesystemReplayStore: %v", err)
	}
	payload := []byte("recorded-bytes")
	if err := store.PutReplay(context.Background(), "sess-fs", bytes.NewReader(payload)); err != nil {
		t.Fatalf("PutReplay: %v", err)
	}
	want := filepath.Join(dir, ReplayKey("sess-fs"))
	got, err := os.ReadFile(want)
	if err != nil {
		t.Fatalf("read replay file: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("replay file mismatch: %q", got)
	}
}

// --- SSH CA tests ---------------------------------------------------------

func TestSSHCAMintsValidCert(t *testing.T) {
	_, caPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("gen ca key: %v", err)
	}
	caSigner, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatalf("ca signer: %v", err)
	}
	ca := NewSSHCertificateAuthority(caSigner, 5*time.Minute)
	if ca.Fingerprint() == "" {
		t.Fatal("empty CA fingerprint")
	}

	signer, err := ca.MintEphemeralCert("alice")
	if err != nil {
		t.Fatalf("MintEphemeralCert: %v", err)
	}
	cert, ok := signer.PublicKey().(*ssh.Certificate)
	if !ok {
		t.Fatalf("minted key is not a certificate: %T", signer.PublicKey())
	}
	if cert.CertType != ssh.UserCert {
		t.Fatalf("want user cert, got type %d", cert.CertType)
	}
	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "alice" {
		t.Fatalf("principals wrong: %v", cert.ValidPrincipals)
	}
	if _, ok := cert.Extensions["permit-pty"]; !ok {
		t.Fatal("expected permit-pty extension")
	}
	// Validity window is bounded (not a static key).
	window := time.Unix(int64(cert.ValidBefore), 0).Sub(time.Unix(int64(cert.ValidAfter), 0))
	if window <= 0 || window > 10*time.Minute {
		t.Fatalf("unexpected validity window: %s", window)
	}

	// Cert verifies against the CA via a checker.
	checker := &ssh.CertChecker{IsUserAuthority: func(k ssh.PublicKey) bool {
		return bytes.Equal(k.Marshal(), caSigner.PublicKey().Marshal())
	}}
	if err := checker.CheckCert("alice", cert); err != nil {
		t.Fatalf("cert failed CA verification: %v", err)
	}
}

func TestSSHCAEmptyPrincipalRejected(t *testing.T) {
	_, caPriv, _ := ed25519.GenerateKey(nil)
	caSigner, _ := ssh.NewSignerFromKey(caPriv)
	ca := NewSSHCertificateAuthority(caSigner, time.Minute)
	if _, err := ca.MintEphemeralCert(""); err == nil {
		t.Fatal("expected error for empty principal")
	}
}

// --- MySQL wire-protocol helper tests -------------------------------------

func TestMySQLScrambleInvariants(t *testing.T) {
	salt := bytes.Repeat([]byte{0x42}, 20)
	if got := scrambleNativePassword(nil, salt); got != nil {
		t.Fatalf("empty password must scramble to nil, got %v", got)
	}
	s1 := scrambleNativePassword([]byte("hunter2"), salt)
	if len(s1) != 20 {
		t.Fatalf("scramble must be 20 bytes, got %d", len(s1))
	}
	// Deterministic for the same inputs.
	if !bytes.Equal(s1, scrambleNativePassword([]byte("hunter2"), salt)) {
		t.Fatal("scramble not deterministic")
	}
	// Different salt → different scramble (no static reuse).
	salt2 := bytes.Repeat([]byte{0x43}, 20)
	if bytes.Equal(s1, scrambleNativePassword([]byte("hunter2"), salt2)) {
		t.Fatal("scramble must depend on salt")
	}
}

func TestMySQLHandshakeRoundTrip(t *testing.T) {
	salt := make([]byte, 20)
	for i := range salt {
		salt[i] = byte(i + 1)
	}
	greeting := buildHandshakeV10(salt)
	gotSalt, plugin, err := parseHandshakeV10(greeting)
	if err != nil {
		t.Fatalf("parseHandshakeV10: %v", err)
	}
	if plugin != "mysql_native_password" {
		t.Fatalf("plugin = %q", plugin)
	}
	if !bytes.Equal(gotSalt, salt) {
		t.Fatalf("salt round-trip mismatch: got %v want %v", gotSalt, salt)
	}
}

// --- k8s helper tests -----------------------------------------------------

func TestK8sBearerTokenExtraction(t *testing.T) {
	cases := map[string]string{
		"Bearer abc.def":  "abc.def",
		"bearer xyz":      "xyz",
		"Basic abc":       "",
		"":                "",
		"Bearer   spaced": "spaced",
	}
	for header, want := range cases {
		if got := bearerToken(header); got != want {
			t.Errorf("bearerToken(%q) = %q, want %q", header, got, want)
		}
	}
}

func TestK8sBasicAuthEncoding(t *testing.T) {
	got := basicAuth("user", "pass")
	want := base64.StdEncoding.EncodeToString([]byte("user:pass"))
	if got != want {
		t.Fatalf("basicAuth = %q, want %q", got, want)
	}
}

func TestK8sEphemeralTLSCertUsable(t *testing.T) {
	cert, err := ephemeralTLSCert()
	if err != nil {
		t.Fatalf("ephemeralTLSCert: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("no certificate bytes")
	}
	// Cert is usable in a tls.Config without panic.
	_ = &tls.Config{Certificates: []tls.Certificate{cert}} //nolint:gosec
}
