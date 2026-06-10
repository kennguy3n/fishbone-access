package gateway

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"
	"go.mongodb.org/mongo-driver/v2/x/mongo/driver/wiremessage"
	"golang.org/x/crypto/pbkdf2"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
	"github.com/kennguy3n/fishbone-access/internal/services/pam"
)

// maxMongoMessageSize bounds a single wire message the proxy will buffer. The
// MongoDB server default maxMessageSizeBytes is 48MB; anything larger is
// rejected to stop a malicious peer from forcing an unbounded allocation.
const maxMongoMessageSize = 48 * 1024 * 1024

// mongoHeaderLen is the fixed wire-message header size (messageLength,
// requestID, responseTo, opCode — four int32s).
const mongoHeaderLen = 16

// mongoGatedCommands are the destructive MongoDB commands gated against the 1C
// policy engine. They mirror the SQL DROP/DELETE/UPDATE gating the Postgres and
// MySQL proxies apply: a deny policy with a resource like "cmd:drop *" or
// "cmd:delete users*" blocks them live.
var mongoGatedCommands = map[string]struct{}{
	"drop":             {},
	"dropdatabase":     {},
	"delete":           {},
	"update":           {},
	"findandmodify":    {},
	"dropindexes":      {},
	"renamecollection": {},
}

// MongoProxy is the gateway.ConnHandler for the MongoDB listener (:27017). It
// terminates the operator's MongoDB connection, authenticates the operator with
// the one-shot connect token presented as a SASL PLAIN password (the mechanism
// the gateway advertises in its hello reply), redeems it, then dials the
// upstream and authenticates as the gateway using SCRAM-SHA-256 with the vault
// credential. Thereafter it relays wire messages in both directions, parsing
// each operator command to gate destructive operations (drop/delete/update/…)
// against the 1C policy engine and recording every command for replay. Session
// open/close lands in the workspace audit hash chain via the session manager.
type MongoProxy struct {
	broker      *pam.Broker
	sessions    *pam.SessionManager
	hub         *SessionHub
	store       ReplayStore
	dialTimeout time.Duration
	recMaxBytes int
}

// MongoProxyConfig configures a MongoProxy.
type MongoProxyConfig struct {
	Broker      *pam.Broker
	Sessions    *pam.SessionManager
	Hub         *SessionHub
	Store       ReplayStore
	DialTimeout time.Duration
	RecMaxBytes int
}

// NewMongoProxy builds a MongoProxy. broker and sessions are required.
func NewMongoProxy(cfg MongoProxyConfig) (*MongoProxy, error) {
	if cfg.Broker == nil || cfg.Sessions == nil {
		return nil, errors.New("gateway: MongoProxy requires broker and session manager")
	}
	dt := cfg.DialTimeout
	if dt <= 0 {
		dt = 15 * time.Second
	}
	return &MongoProxy{
		broker:      cfg.Broker,
		sessions:    cfg.Sessions,
		hub:         cfg.Hub,
		store:       cfg.Store,
		dialTimeout: dt,
		recMaxBytes: cfg.RecMaxBytes,
	}, nil
}

// Handle implements gateway.ConnHandler.
func (p *MongoProxy) Handle(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()
	clientAddr := conn.RemoteAddr().String()

	br := bufio.NewReaderSize(conn, 32*1024)
	token, err := p.authenticateOperator(ctx, conn, br)
	if err != nil {
		logger.Warnf(ctx, "mongo-proxy: operator auth from %s: %v", clientAddr, err)
		return
	}

	leased, err := p.broker.RedeemConnectToken(ctx, token, clientAddr)
	if err != nil {
		logger.Warnf(ctx, "mongo-proxy: redeem from %s failed: %v", clientAddr, err)
		return
	}
	if leased.Target.Protocol != models.PAMProtocolMongoDB {
		reconcileOrphanSession(ctx, p.sessions, leased.Session, "mongo-proxy")
		return
	}
	session := leased.Session
	logger.Infof(ctx, "mongo-proxy: session %s opened for %s → %s", session.ID, session.Subject, leased.Target.Address)

	sessCtx, cancel := context.WithCancel(ctx)
	rec := NewIORecorder(sessCtx, session.ID.String(), p.recMaxBytes)
	defer cancel()
	if p.hub != nil {
		defer p.hub.Register(session.ID, session.WorkspaceID, session.Subject, rec, cancel)()
	}
	defer func() {
		flushCtx, fcancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer fcancel()
		if err := rec.Flush(flushCtx, p.store); err != nil {
			logger.Warnf(ctx, "mongo-proxy: flush replay %s: %v", session.ID, err)
		}
		if err := p.sessions.CloseSession(flushCtx, session.WorkspaceID, session.ID); err != nil {
			logger.Warnf(ctx, "mongo-proxy: close session %s: %v", session.ID, err)
		}
	}()

	upstream, err := p.dialUpstream(sessCtx, leased)
	if err != nil {
		rec.Annotate(fmt.Sprintf("[upstream connect failed: %v]", err))
		logger.Warnf(ctx, "mongo-proxy: upstream %s: %v", leased.Target.Address, err)
		return
	}
	defer func() { _ = upstream.Close() }()

	p.splice(sessCtx, conn, br, upstream, session, rec, cancel)
}

// authenticateOperator runs the gateway's server side of the MongoDB handshake:
// it answers hello/isMaster by advertising SASL PLAIN, then reads the
// saslStart{PLAIN} message and extracts the connect token from its
// "\x00user\x00token" payload. The token is returned for redemption; the
// gateway replies with a successful, completed conversation so the operator's
// driver proceeds to issue commands.
func (p *MongoProxy) authenticateOperator(ctx context.Context, conn net.Conn, br *bufio.Reader) (string, error) {
	deadline := time.Now().Add(p.dialTimeout)
	_ = conn.SetReadDeadline(deadline)
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	const maxHandshakeMessages = 16
	for i := 0; i < maxHandshakeMessages; i++ {
		msg, err := readWireMessage(br)
		if err != nil {
			return "", fmt.Errorf("read handshake message: %w", err)
		}
		name, body, _, reqID, _, ok := parseCommand(msg)
		if !ok {
			return "", errors.New("malformed handshake message")
		}
		switch strings.ToLower(name) {
		case "ismaster", "hello":
			if _, err := conn.Write(buildHelloReply(reqID)); err != nil {
				return "", err
			}
		case "saslstart":
			token, err := tokenFromSaslStart(body)
			if err != nil {
				_, _ = conn.Write(buildAuthErrorReply(reqID, err.Error()))
				return "", err
			}
			if _, err := conn.Write(buildSaslDoneReply(reqID)); err != nil {
				return "", err
			}
			return token, nil
		case "saslcontinue":
			// PLAIN is single-step; a continue here means the client expected a
			// multi-step mechanism. Answer done so the client does not hang, but
			// there is nothing further to do.
			if _, err := conn.Write(buildSaslDoneReply(reqID)); err != nil {
				return "", err
			}
		default:
			// Any pre-auth command other than the handshake/auth set is refused.
			if _, err := conn.Write(buildAuthErrorReply(reqID, "authentication required")); err != nil {
				return "", err
			}
		}
	}
	return "", errors.New("handshake did not complete within bound")
}

// dialUpstream opens a TCP connection to the upstream mongod and authenticates
// as the gateway using SCRAM-SHA-256 with the vault credential.
func (p *MongoProxy) dialUpstream(ctx context.Context, leased *pam.LeasedSession) (net.Conn, error) {
	d := net.Dialer{Timeout: p.dialTimeout}
	conn, err := d.DialContext(ctx, "tcp", leased.Target.Address)
	if err != nil {
		return nil, fmt.Errorf("dial mongod: %w", err)
	}
	user := credUser(leased)
	// A target with no credential proxies unauthenticated (e.g. a mongod with no
	// auth enabled on a trusted segment); only run SCRAM when a password is set.
	if leased.Secret.Password == "" {
		return conn, nil
	}
	authSource := decodeTargetConfig(leased.Target.Config)["auth_source"]
	if authSource == "" {
		authSource = "admin"
	}
	if err := scramSHA256Auth(conn, p.dialTimeout, authSource, user, leased.Secret.Password); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("upstream SCRAM-SHA-256: %w", err)
	}
	return conn, nil
}

// splice relays wire messages in both directions. Operator→upstream messages
// are parsed so destructive commands can be gated and every command recorded;
// upstream→operator messages are relayed one complete wire message at a time so
// a deny reply written by the command loop can never be spliced into the middle
// of an upstream message on the shared operator socket.
func (p *MongoProxy) splice(ctx context.Context, operator net.Conn, operatorBuf *bufio.Reader, upstream net.Conn, session *models.PAMSession, rec *IORecorder, cancel context.CancelFunc) {
	var wg sync.WaitGroup

	// Both relay directions write to the operator connection: the command loop
	// injects deny replies, the reply loop streams upstream replies. Drivers
	// correlate replies by responseTo so ordering is safe, but a raw net.Conn
	// still does not serialize concurrent Writes — funnel both through one
	// lockedWriter so the bytes of a deny frame and a reply frame cannot
	// interleave on the socket.
	operatorOut := newLockedWriter(operator)

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		p.forwardOperatorCommands(ctx, operatorOut, operatorBuf, upstream, session, rec)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		p.relayUpstreamReplies(operatorOut, upstream, rec)
	}()

	go func() {
		<-ctx.Done()
		_ = operator.Close()
		_ = upstream.Close()
	}()

	wg.Wait()
}

// forwardOperatorCommands reads operator wire messages, gates destructive
// commands, and forwards the allowed ones verbatim to the upstream. A denied
// command is answered locally with a MongoDB command error and never reaches
// the upstream, keeping the stream framed and in sync.
func (p *MongoProxy) forwardOperatorCommands(ctx context.Context, operator io.Writer, operatorBuf *bufio.Reader, upstream net.Conn, session *models.PAMSession, rec *IORecorder) {
	for {
		// Honour the live soft-pause gate before reading the next operator
		// message: while an admin has frozen the session no further wire
		// message is pulled or forwarded to the upstream server.
		rec.WaitWhilePaused()
		msg, err := readWireMessage(operatorBuf)
		if err != nil {
			return
		}
		name, _, ns, reqID, _, ok := parseCommand(msg)
		if !ok {
			// Unparseable as a command (e.g. OP_COMPRESSED or a getMore reply
			// shape) — record and forward without gating so the proxy stays
			// transparent to protocol features it does not interpret.
			rec.Record(DirInput, msg)
			if _, err := upstream.Write(msg); err != nil {
				return
			}
			continue
		}

		cmd := mongoCommandString(name, ns)
		rec.Record(DirInput, []byte(cmd+"\n"))

		if _, gated := mongoGatedCommands[strings.ToLower(name)]; gated {
			decision, derr := p.sessions.LogCommand(ctx, session, cmd)
			if derr != nil || !decision.Allowed() {
				reason := decision.Reason
				if reason == "" {
					reason = "denied by command policy"
				}
				rec.Annotate(fmt.Sprintf("[command denied: %s]", reason))
				if _, err := operator.Write(buildCommandErrorReply(reqID, "pam-gateway: "+reason)); err != nil {
					return
				}
				continue
			}
		} else {
			// Non-destructive commands are still logged (audited) but always
			// allowed; logging failures must not drop the command.
			_, _ = p.sessions.LogCommand(ctx, session, cmd)
		}

		if _, err := upstream.Write(msg); err != nil {
			return
		}
	}
}

// relayUpstreamReplies reads complete wire messages from the upstream and writes
// each as a single Write through the shared lockedWriter. Relaying whole
// messages (rather than an io.Copy that flushes arbitrary 32KB chunks) is what
// makes the lockedWriter sufficient: a deny reply from the command loop can only
// land between two upstream messages, never inside one, so the operator's driver
// always reads a contiguous, correctly length-prefixed wire message.
func (p *MongoProxy) relayUpstreamReplies(operator io.Writer, upstream io.Reader, rec *IORecorder) {
	upstreamBuf := bufio.NewReaderSize(upstream, 32*1024)
	for {
		msg, err := readWireMessage(upstreamBuf)
		if err != nil {
			return
		}
		rec.Record(DirOutput, msg)
		if _, err := operator.Write(msg); err != nil {
			return
		}
	}
}

// --- wire helpers ---------------------------------------------------------

// readWireMessage reads one full MongoDB wire message: a 4-byte little-endian
// messageLength prefix followed by the remainder of the message.
func readWireMessage(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	msgLen := int32(uint32(lenBuf[0]) | uint32(lenBuf[1])<<8 | uint32(lenBuf[2])<<16 | uint32(lenBuf[3])<<24)
	if msgLen < mongoHeaderLen || int64(msgLen) > maxMongoMessageSize {
		return nil, fmt.Errorf("invalid mongo message length %d", msgLen)
	}
	buf := make([]byte, msgLen)
	copy(buf, lenBuf[:])
	if _, err := io.ReadFull(r, buf[4:]); err != nil {
		return nil, err
	}
	return buf, nil
}

// parseCommand extracts the command name, body document, namespace, and request
// id from an OP_MSG or OP_QUERY wire message. ok is false for opcodes the proxy
// does not interpret (e.g. OP_COMPRESSED), which are forwarded transparently.
func parseCommand(msg []byte) (name string, body bsoncore.Document, namespace string, requestID int32, opcode wiremessage.OpCode, ok bool) {
	length, reqID, _, code, rem, hok := wiremessage.ReadHeader(msg)
	if !hok || int(length) != len(msg) {
		return "", nil, "", 0, 0, false
	}
	// Opcodes the proxy does not interpret (OP_REPLY, OP_COMPRESSED, …) fall to
	// the default case and are forwarded transparently, so the switch is
	// intentionally not exhaustive over wiremessage.OpCode.
	switch code { //nolint:exhaustive // unhandled opcodes are forwarded via default
	case wiremessage.OpMsg:
		flags, rem2, fok := wiremessage.ReadMsgFlags(rem)
		if !fok {
			return "", nil, "", reqID, code, false
		}
		_ = flags
		// Walk sections until the body (single document, the command) is found.
		// The body section is the command document; the OP_MSG spec and every
		// driver emit it first, so this loop returns at the body and any optional
		// trailing CRC32C checksum (checksumPresent) is never examined. A message
		// with no body section yields ok=false regardless — and carries no
		// command to gate — so checksum handling does not affect gating.
		for len(rem2) > 0 {
			st, after, sok := wiremessage.ReadMsgSectionType(rem2)
			if !sok {
				return "", nil, "", reqID, code, false
			}
			switch st {
			case wiremessage.SingleDocument:
				doc, _, dok := wiremessage.ReadMsgSectionSingleDocument(after)
				if !dok {
					return "", nil, "", reqID, code, false
				}
				cmdName, nsVal := commandNameAndNS(doc)
				return cmdName, doc, nsVal, reqID, code, true
			case wiremessage.DocumentSequence:
				_, _, after2, dsok := wiremessage.ReadMsgSectionRawDocumentSequence(after)
				if !dsok {
					return "", nil, "", reqID, code, false
				}
				rem2 = after2
			default:
				return "", nil, "", reqID, code, false
			}
		}
		return "", nil, "", reqID, code, false
	case wiremessage.OpQuery: //nolint:staticcheck // OP_QUERY is legacy but still emitted by real clients; a proxy must handle it
		return parseLegacyQueryCommand(rem, reqID, code)
	default:
		return "", nil, "", reqID, code, false
	}
}

// parseLegacyQueryCommand parses an OP_QUERY message's command document and
// collection. OP_QUERY and its wiremessage readers are deprecated in favour of
// OP_MSG, but legacy Mongo drivers (and the wire-protocol handshake against
// admin.$cmd) still issue OP_QUERY, so the proxy must parse it to gate and
// record those commands. The staticcheck deprecation warnings are suppressed at
// the function scope for exactly this reason.
//
//nolint:staticcheck // OP_QUERY is legacy but still emitted by real clients; a proxy must handle it
func parseLegacyQueryCommand(rem []byte, reqID int32, code wiremessage.OpCode) (string, bsoncore.Document, string, int32, wiremessage.OpCode, bool) {
	_, rem2, fok := wiremessage.ReadQueryFlags(rem)
	if !fok {
		return "", nil, "", reqID, code, false
	}
	fullColl, rem3, cok := wiremessage.ReadQueryFullCollectionName(rem2)
	if !cok {
		return "", nil, "", reqID, code, false
	}
	_, rem4, sok := wiremessage.ReadQueryNumberToSkip(rem3)
	if !sok {
		return "", nil, "", reqID, code, false
	}
	_, rem5, rok := wiremessage.ReadQueryNumberToReturn(rem4)
	if !rok {
		return "", nil, "", reqID, code, false
	}
	doc, _, dok := wiremessage.ReadQueryQuery(rem5)
	if !dok {
		return "", nil, "", reqID, code, false
	}
	cmdName, _ := commandNameAndNS(doc)
	return cmdName, doc, fullColl, reqID, code, true
}

// commandNameAndNS returns the command verb (the first element key of the
// command document) and a best-effort namespace (the command's string value,
// which is the collection for collection commands, plus "$db" when present).
func commandNameAndNS(doc bsoncore.Document) (name, namespace string) {
	elem, err := doc.IndexErr(0)
	if err != nil {
		return "", ""
	}
	name = elem.Key()
	if coll, ok := elem.Value().StringValueOK(); ok {
		namespace = coll
	}
	if db, ok := doc.Lookup("$db").StringValueOK(); ok {
		if namespace != "" {
			namespace = db + "." + namespace
		} else {
			namespace = db
		}
	}
	return name, namespace
}

// mongoCommandString renders a command for policy evaluation and recording,
// e.g. "drop mydb.sessions". The verb is lower-cased (commands are
// case-insensitive); the namespace is preserved for pattern matching.
func mongoCommandString(name, namespace string) string {
	v := strings.ToLower(name)
	if namespace == "" {
		return v
	}
	return v + " " + namespace
}

// buildHelloReply builds an OP_MSG hello/isMaster reply advertising SASL PLAIN
// as the supported mechanism so the operator's driver authenticates by sending
// its connect token as the PLAIN password.
func buildHelloReply(responseTo int32) []byte {
	var doc []byte
	idx, doc := bsoncore.AppendDocumentStart(doc)
	doc = bsoncore.AppendBooleanElement(doc, "ismaster", true)
	doc = bsoncore.AppendBooleanElement(doc, "isWritablePrimary", true)
	doc = bsoncore.AppendInt32Element(doc, "maxBsonObjectSize", 16*1024*1024)
	doc = bsoncore.AppendInt32Element(doc, "maxMessageSizeBytes", maxMongoMessageSize)
	doc = bsoncore.AppendInt32Element(doc, "maxWriteBatchSize", 100000)
	doc = bsoncore.AppendInt32Element(doc, "maxWireVersion", 17)
	doc = bsoncore.AppendInt32Element(doc, "minWireVersion", 0)
	doc = appendStringArray(doc, "saslSupportedMechs", []string{"PLAIN"})
	doc = bsoncore.AppendDoubleElement(doc, "ok", 1)
	doc, _ = bsoncore.AppendDocumentEnd(doc, idx)
	return buildMsgReply(responseTo, doc)
}

// buildSaslDoneReply builds a successful, completed SASL conversation reply.
func buildSaslDoneReply(responseTo int32) []byte {
	var doc []byte
	idx, doc := bsoncore.AppendDocumentStart(doc)
	doc = bsoncore.AppendInt32Element(doc, "conversationId", 1)
	doc = bsoncore.AppendBooleanElement(doc, "done", true)
	doc = bsoncore.AppendBinaryElement(doc, "payload", 0x00, []byte{})
	doc = bsoncore.AppendDoubleElement(doc, "ok", 1)
	doc, _ = bsoncore.AppendDocumentEnd(doc, idx)
	return buildMsgReply(responseTo, doc)
}

// buildAuthErrorReply builds an OP_MSG authentication-failure reply (code 18,
// AuthenticationFailed).
func buildAuthErrorReply(responseTo int32, msg string) []byte {
	return buildErrorReply(responseTo, 18, "AuthenticationFailed", msg)
}

// buildCommandErrorReply builds an OP_MSG command-failure reply (code 13,
// Unauthorized) used to refuse a policy-denied command.
func buildCommandErrorReply(responseTo int32, msg string) []byte {
	return buildErrorReply(responseTo, 13, "Unauthorized", msg)
}

// buildErrorReply builds an OP_MSG {ok:0, code, codeName, errmsg} reply.
func buildErrorReply(responseTo, code int32, codeName, msg string) []byte {
	var doc []byte
	idx, doc := bsoncore.AppendDocumentStart(doc)
	doc = bsoncore.AppendDoubleElement(doc, "ok", 0)
	doc = bsoncore.AppendStringElement(doc, "errmsg", msg)
	doc = bsoncore.AppendInt32Element(doc, "code", code)
	doc = bsoncore.AppendStringElement(doc, "codeName", codeName)
	doc, _ = bsoncore.AppendDocumentEnd(doc, idx)
	return buildMsgReply(responseTo, doc)
}

// buildMsgReply frames a single-document OP_MSG reply.
func buildMsgReply(responseTo int32, doc []byte) []byte {
	idx, b := wiremessage.AppendHeaderStart(nil, wiremessage.NextRequestID(), responseTo, wiremessage.OpMsg)
	b = wiremessage.AppendMsgFlags(b, 0)
	b = wiremessage.AppendMsgSectionType(b, wiremessage.SingleDocument)
	b = append(b, doc...)
	return bsoncore.UpdateLength(b, idx, int32(len(b)-int(idx)))
}

// appendStringArray appends a BSON array of strings as an element.
func appendStringArray(dst []byte, key string, vals []string) []byte {
	aidx, dst := bsoncore.AppendArrayElementStart(dst, key)
	for i, v := range vals {
		dst = bsoncore.AppendStringElement(dst, strconv.Itoa(i), v)
	}
	dst, _ = bsoncore.AppendArrayEnd(dst, aidx)
	return dst
}

// tokenFromSaslStart extracts the connect token from a saslStart command. The
// gateway only accepts the PLAIN mechanism (whose payload is
// "authzid\x00authcid\x00password"); the token is the password field.
func tokenFromSaslStart(body bsoncore.Document) (string, error) {
	mech, ok := body.Lookup("mechanism").StringValueOK()
	if !ok {
		return "", errors.New("saslStart missing mechanism")
	}
	if !strings.EqualFold(mech, "PLAIN") {
		return "", fmt.Errorf("unsupported SASL mechanism %q (gateway requires PLAIN for token auth)", mech)
	}
	_, payload, ok := body.Lookup("payload").BinaryOK()
	if !ok {
		return "", errors.New("saslStart missing payload")
	}
	parts := strings.SplitN(string(payload), "\x00", 3)
	if len(parts) != 3 || parts[2] == "" {
		return "", errors.New("malformed PLAIN payload")
	}
	return parts[2], nil
}

// --- SCRAM-SHA-256 client (RFC 5802 / 7677) -------------------------------

// scramSHA256Auth performs a SCRAM-SHA-256 authentication conversation with an
// upstream mongod over conn, using the saslStart/saslContinue command pair
// wrapped in OP_MSG. It implements the client side of RFC 5802 with the
// SHA-256 hash (RFC 7677) so the gateway can inject the vault credential
// without a third-party SCRAM dependency.
func scramSHA256Auth(conn net.Conn, timeout time.Duration, authSource, user, password string) error {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	clientNonce, err := randomNonce()
	if err != nil {
		return err
	}
	gs2 := "n,,"
	clientFirstBare := "n=" + scramEscapeUsername(user) + ",r=" + clientNonce
	clientFirst := gs2 + clientFirstBare

	serverFirstPayload, convID, err := scramSend(conn, buildSaslStartSCRAM(authSource, clientFirst))
	if err != nil {
		return err
	}
	sf, err := parseScramServerFirst(serverFirstPayload)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(sf.nonce, clientNonce) {
		return errors.New("server nonce does not extend client nonce")
	}

	// RFC 5802: only the username in client-first-bare is comma/equals escaped.
	// The password fed to PBKDF2 is the SASLprep'd value, which is identity for
	// ASCII; it must NOT be escaped or a password containing '=' or ',' would
	// derive the wrong salted key and the upstream would reject the proof.
	saltedPassword := pbkdf2.Key([]byte(password), sf.salt, sf.iterations, sha256.Size, sha256.New)
	clientKey := scramHMAC(saltedPassword, []byte("Client Key"))
	storedKey := sha256.Sum256(clientKey)
	channelBinding := base64.StdEncoding.EncodeToString([]byte(gs2))
	clientFinalWithoutProof := "c=" + channelBinding + ",r=" + sf.nonce
	authMessage := clientFirstBare + "," + serverFirstPayload + "," + clientFinalWithoutProof
	clientSignature := scramHMAC(storedKey[:], []byte(authMessage))
	clientProof := xorBytes(clientKey, clientSignature)
	clientFinal := clientFinalWithoutProof + ",p=" + base64.StdEncoding.EncodeToString(clientProof)

	serverFinalPayload, _, err := scramSend(conn, buildSaslContinueSCRAM(authSource, convID, clientFinal))
	if err != nil {
		return err
	}
	// Verify the server signature so a man-in-the-middle upstream cannot spoof a
	// successful auth.
	serverKey := scramHMAC(saltedPassword, []byte("Server Key"))
	serverSignature := scramHMAC(serverKey, []byte(authMessage))
	gotSig, err := scramServerSignature(serverFinalPayload)
	if err != nil {
		return err
	}
	if !hmac.Equal(gotSig, serverSignature) {
		return errors.New("server signature verification failed")
	}
	return nil
}

// scramSend writes one SASL command and reads the reply, returning the decoded
// payload string and the conversationId.
func scramSend(conn net.Conn, msg []byte) (payload string, convID int32, err error) {
	if _, err := conn.Write(msg); err != nil {
		return "", 0, err
	}
	// Read directly from conn (not a fresh bufio.Reader): readWireMessage uses
	// io.ReadFull to consume exactly one message, so no bytes are over-read into
	// a buffer that a subsequent call would discard.
	reply, err := readWireMessage(conn)
	if err != nil {
		return "", 0, err
	}
	_, body, _, _, _, ok := parseCommand(reply)
	if !ok {
		return "", 0, errors.New("malformed SASL reply")
	}
	if okVal, ok := body.Lookup("ok").AsFloat64OK(); !ok || okVal != 1 {
		errmsg, _ := body.Lookup("errmsg").StringValueOK()
		return "", 0, fmt.Errorf("upstream rejected SASL: %s", errmsg)
	}
	convID, _ = body.Lookup("conversationId").AsInt32OK()
	_, p, _ := body.Lookup("payload").BinaryOK()
	return string(p), convID, nil
}

// buildSaslStartSCRAM frames a saslStart{SCRAM-SHA-256} OP_MSG command.
func buildSaslStartSCRAM(db, clientFirst string) []byte {
	var doc []byte
	idx, doc := bsoncore.AppendDocumentStart(doc)
	doc = bsoncore.AppendInt32Element(doc, "saslStart", 1)
	doc = bsoncore.AppendStringElement(doc, "mechanism", "SCRAM-SHA-256")
	doc = bsoncore.AppendBinaryElement(doc, "payload", 0x00, []byte(clientFirst))
	doc = bsoncore.AppendStringElement(doc, "$db", db)
	doc, _ = bsoncore.AppendDocumentEnd(doc, idx)
	return buildMsgRequest(doc)
}

// buildSaslContinueSCRAM frames a saslContinue OP_MSG command.
func buildSaslContinueSCRAM(db string, convID int32, clientFinal string) []byte {
	var doc []byte
	idx, doc := bsoncore.AppendDocumentStart(doc)
	doc = bsoncore.AppendInt32Element(doc, "saslContinue", 1)
	doc = bsoncore.AppendInt32Element(doc, "conversationId", convID)
	doc = bsoncore.AppendBinaryElement(doc, "payload", 0x00, []byte(clientFinal))
	doc = bsoncore.AppendStringElement(doc, "$db", db)
	doc, _ = bsoncore.AppendDocumentEnd(doc, idx)
	return buildMsgRequest(doc)
}

// buildMsgRequest frames a single-document OP_MSG request (responseTo 0).
func buildMsgRequest(doc []byte) []byte {
	idx, b := wiremessage.AppendHeaderStart(nil, wiremessage.NextRequestID(), 0, wiremessage.OpMsg)
	b = wiremessage.AppendMsgFlags(b, 0)
	b = wiremessage.AppendMsgSectionType(b, wiremessage.SingleDocument)
	b = append(b, doc...)
	return bsoncore.UpdateLength(b, idx, int32(len(b)-int(idx)))
}

// scramServerFirst holds the parsed server-first SCRAM message.
type scramServerFirst struct {
	nonce      string
	salt       []byte
	iterations int
}

// parseScramServerFirst parses "r=<nonce>,s=<salt-b64>,i=<iter>".
func parseScramServerFirst(payload string) (scramServerFirst, error) {
	var sf scramServerFirst
	for _, field := range strings.Split(payload, ",") {
		if len(field) < 2 {
			continue
		}
		val := field[2:]
		switch field[:2] {
		case "r=":
			sf.nonce = val
		case "s=":
			salt, err := base64.StdEncoding.DecodeString(val)
			if err != nil {
				return sf, fmt.Errorf("decode salt: %w", err)
			}
			sf.salt = salt
		case "i=":
			n, err := strconv.Atoi(val)
			if err != nil {
				return sf, fmt.Errorf("parse iterations: %w", err)
			}
			sf.iterations = n
		}
	}
	if sf.nonce == "" || len(sf.salt) == 0 || sf.iterations <= 0 {
		return sf, errors.New("incomplete server-first message")
	}
	return sf, nil
}

// scramServerSignature extracts and decodes the ServerSignature from a
// server-final message ("v=<base64>", optionally with extension attributes).
// Parsing the v= attribute and comparing the decoded bytes with hmac.Equal is
// stricter than a substring check: it rejects a payload that merely contains
// the expected value elsewhere, and it fails closed when the server returns an
// error attribute ("e=...") instead of a verifier.
func scramServerSignature(payload string) ([]byte, error) {
	for _, field := range strings.Split(payload, ",") {
		if len(field) < 2 {
			continue
		}
		if field[:2] == "v=" {
			sig, err := base64.StdEncoding.DecodeString(field[2:])
			if err != nil {
				return nil, fmt.Errorf("decode server signature: %w", err)
			}
			return sig, nil
		}
	}
	return nil, errors.New("server-final message missing verifier")
}

// randomNonce returns a base64 client nonce.
func randomNonce() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// scramHMAC computes HMAC-SHA-256(key, msg).
func scramHMAC(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return h.Sum(nil)
}

// xorBytes returns a XOR b (equal length).
func xorBytes(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// scramEscapeUsername applies the comma/equals escaping RFC 5802 §5.1 mandates
// for the username in the client-first-bare message ('=' → "=3D", ',' → "=2C").
// This is purely the n= field encoding — it is NOT SASLprep and must never be
// applied to the password (the password is SASLprep'd, identity for ASCII, and
// fed raw to PBKDF2). MongoDB usernames in practice are ASCII.
func scramEscapeUsername(s string) string {
	s = strings.ReplaceAll(s, "=", "=3D")
	s = strings.ReplaceAll(s, ",", "=2C")
	return s
}
