package webaccess

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kennguy3n/fishbone-access/internal/gateway"
	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
	"github.com/kennguy3n/fishbone-access/internal/services/pam"
)

// dbConsole is the protocol-specific half of the web database console: it runs
// one already-authorised statement against the upstream and returns a result
// the bridge serialises to the browser. Postgres and MySQL implementations sit
// behind it so the read/gate/audit loop in runDB is protocol-agnostic.
type dbConsole interface {
	// run executes sql and returns either a row set or a write summary.
	run(ctx context.Context, sql string) (resultMessage, error)
	// close releases the upstream connection.
	close()
}

// runDB drives the interactive database console: each operator statement is
// recorded, gated by command policy (and audited) before execution, then run
// against the upstream with the result streamed back as a clean table or a
// write summary. A policy deny refuses that one statement and keeps the console
// open (matching the native Postgres/MySQL proxies, which answer a denied query
// with an error and a fresh ReadyForQuery rather than tearing the connection
// down). It blocks until the operator disconnects or the session is cancelled.
func (b *Bridge) runDB(ctx context.Context, cancel context.CancelFunc, conn wsConn, sender *wsSender, leased *pam.LeasedSession, rec *gateway.IORecorder, activity *activityClock) {
	console, err := b.openConsole(ctx, leased)
	if err != nil {
		rec.Annotate(fmt.Sprintf("[upstream connect failed: %v]", err))
		_ = sender.json(errorMessage{Type: msgError, Message: "cannot reach database: " + sanitizeDialError(err)})
		logger.Warnf(ctx, "webaccess: connect upstream db %s: %v", leased.Target.Address, err)
		return
	}
	defer console.close()

	// Unblock the blocking read when the session is cancelled (admin terminate
	// / idle timeout) by closing the connection.
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		var msg clientMessage
		if json.Unmarshal(data, &msg) != nil {
			continue
		}
		if msg.Type == msgPing {
			// Heartbeat: echo the client timestamp for an RTT reading without
			// touching the idle clock.
			_ = sender.json(pongMessage{Type: msgPong, TS: msg.TS})
			continue
		}
		if msg.Type != msgQuery {
			continue
		}
		statement := strings.TrimSpace(msg.SQL)
		if statement == "" {
			continue
		}
		activity.touch()
		// Soft-pause gate: hold the statement until an admin resumes. Output
		// (the result) only flows after execution, so pausing simply defers the
		// next statement.
		rec.WaitWhilePaused()
		if ctx.Err() != nil {
			return
		}
		b.runStatement(ctx, console, sender, leased.Session, rec, statement)
		activity.touch()
	}
}

// runStatement gates one statement against policy (recording + audit), executes
// it on a pass, and streams the result. A deny or an execution error is
// surfaced as a non-fatal error frame so the console stays usable.
func (b *Bridge) runStatement(ctx context.Context, console dbConsole, sender *wsSender, session *models.PAMSession, rec *gateway.IORecorder, statement string) {
	rec.Record(gateway.DirInput, []byte(statement+"\n"))
	decision, err := b.sessions.LogCommand(ctx, session, statement)
	if err != nil || !decision.Allowed() {
		reason := decision.Reason
		if reason == "" {
			reason = "denied by command policy"
		}
		if err != nil {
			reason = "command policy unavailable"
		}
		rec.Annotate(fmt.Sprintf("[query %s: %s]", models.PAMDecisionDeny, reason))
		_ = sender.json(errorMessage{Type: msgError, Message: reason, Denied: true})
		return
	}

	result, err := console.run(ctx, statement)
	if err != nil {
		rec.Record(gateway.DirOutput, []byte("ERROR: "+err.Error()+"\n"))
		_ = sender.json(errorMessage{Type: msgError, Message: sanitizeDialError(err)})
		return
	}
	rec.Record(gateway.DirOutput, []byte(summariseResult(result)))
	_ = sender.json(result)
}

// openConsole dials the upstream database matching the target protocol.
func (b *Bridge) openConsole(ctx context.Context, leased *pam.LeasedSession) (dbConsole, error) {
	switch leased.Target.Protocol {
	case models.PAMProtocolPostgres:
		conn, err := dialUpstreamPostgres(ctx, leased, b.dialTimeout)
		if err != nil {
			return nil, err
		}
		return &pgConsole{conn: conn, maxRows: b.maxResultRows}, nil
	case models.PAMProtocolMySQL:
		db, err := dialUpstreamMySQL(ctx, leased, b.dialTimeout)
		if err != nil {
			return nil, err
		}
		return &mysqlConsole{db: db, maxRows: b.maxResultRows}, nil
	default:
		return nil, fmt.Errorf("webaccess: unsupported database protocol %q", leased.Target.Protocol)
	}
}

// summariseResult renders a compact, replay-friendly line describing a result
// for the recording transcript (the recording stores the operator-visible
// outcome, not every cell, keeping the transcript readable and small).
func summariseResult(r resultMessage) string {
	if len(r.Columns) > 0 {
		n := len(r.Rows)
		suffix := ""
		if r.Truncated {
			suffix = "+ (truncated)"
		}
		return fmt.Sprintf("[%d row(s)%s in %dms]\n", n, suffix, r.ElapsedMs)
	}
	cmd := r.Command
	if cmd == "" {
		cmd = "OK"
	}
	return fmt.Sprintf("[%s: %d row(s) affected in %dms]\n", cmd, r.RowsAffected, r.ElapsedMs)
}

// pgConsole runs statements over a pgx connection. pgx.Query handles both row
// sets and commands uniformly: a non-SELECT yields no field descriptions and a
// CommandTag carrying the verb and affected-row count.
type pgConsole struct {
	conn    *pgx.Conn
	maxRows int
}

func (c *pgConsole) close() {
	closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = c.conn.Close(closeCtx)
}

func (c *pgConsole) run(ctx context.Context, statement string) (resultMessage, error) {
	start := time.Now()
	rows, err := c.conn.Query(ctx, statement)
	if err != nil {
		return resultMessage{}, err
	}
	defer rows.Close()

	fields := rows.FieldDescriptions()
	if len(fields) == 0 {
		// Drain to completion so the CommandTag is populated, then report the
		// write summary.
		for rows.Next() { //nolint:revive // intentional drain of an empty result
		}
		if err := rows.Err(); err != nil {
			return resultMessage{}, err
		}
		tag := rows.CommandTag()
		return resultMessage{
			Type:         msgResult,
			Command:      commandVerb(statement, tag.String()),
			RowsAffected: tag.RowsAffected(),
			ElapsedMs:    time.Since(start).Milliseconds(),
		}, nil
	}

	cols := make([]queryColumn, len(fields))
	for i, f := range fields {
		cols[i] = queryColumn{Name: f.Name}
	}
	var out [][]*string
	truncated := false
	for rows.Next() {
		if len(out) >= c.maxRows {
			truncated = true
			break
		}
		vals, verr := rows.Values()
		if verr != nil {
			return resultMessage{}, verr
		}
		out = append(out, toStringRow(vals))
	}
	if err := rows.Err(); err != nil && !truncated {
		return resultMessage{}, err
	}
	return resultMessage{
		Type:      msgResult,
		Columns:   cols,
		Rows:      out,
		ElapsedMs: time.Since(start).Milliseconds(),
		Truncated: truncated,
	}, nil
}

// mysqlConsole runs statements over a single-connection *sql.DB. Unlike pgx,
// the database/sql MySQL driver distinguishes row-returning statements from
// writes, so the verb is inspected to pick Query vs. Exec.
type mysqlConsole struct {
	db      *sql.DB
	maxRows int
}

func (c *mysqlConsole) close() { _ = c.db.Close() }

func (c *mysqlConsole) run(ctx context.Context, statement string) (resultMessage, error) {
	start := time.Now()
	if returnsRows(statement) {
		rows, err := c.db.QueryContext(ctx, statement)
		if err != nil {
			return resultMessage{}, err
		}
		defer func() { _ = rows.Close() }()
		colNames, err := rows.Columns()
		if err != nil {
			return resultMessage{}, err
		}
		cols := make([]queryColumn, len(colNames))
		for i, n := range colNames {
			cols[i] = queryColumn{Name: n}
		}
		var out [][]*string
		truncated := false
		for rows.Next() {
			if len(out) >= c.maxRows {
				truncated = true
				break
			}
			raw := make([]sql.NullString, len(colNames))
			scanTargets := make([]any, len(colNames))
			for i := range raw {
				scanTargets[i] = &raw[i]
			}
			if err := rows.Scan(scanTargets...); err != nil {
				return resultMessage{}, err
			}
			row := make([]*string, len(raw))
			for i, ns := range raw {
				if ns.Valid {
					v := ns.String
					row[i] = &v
				}
			}
			out = append(out, row)
		}
		if err := rows.Err(); err != nil && !truncated {
			return resultMessage{}, err
		}
		return resultMessage{
			Type:      msgResult,
			Columns:   cols,
			Rows:      out,
			ElapsedMs: time.Since(start).Milliseconds(),
			Truncated: truncated,
		}, nil
	}

	res, err := c.db.ExecContext(ctx, statement)
	if err != nil {
		return resultMessage{}, err
	}
	affected, _ := res.RowsAffected()
	return resultMessage{
		Type:         msgResult,
		Command:      commandVerb(statement, ""),
		RowsAffected: affected,
		ElapsedMs:    time.Since(start).Milliseconds(),
	}, nil
}

// returnsRows reports whether a SQL statement is expected to return a row set,
// from its leading keyword. Used only for the MySQL path (pgx is uniform).
func returnsRows(statement string) bool {
	switch firstKeyword(statement) {
	case "select", "show", "describe", "desc", "explain", "with", "table", "values", "call":
		return true
	default:
		return false
	}
}

// commandVerb derives a short command label for a write summary: the upstream's
// own tag when present (Postgres), else the statement's leading keyword
// upper-cased.
func commandVerb(statement, tag string) string {
	if tag != "" {
		if i := strings.IndexByte(tag, ' '); i > 0 {
			return tag[:i]
		}
		return tag
	}
	kw := firstKeyword(statement)
	if kw == "" {
		return "OK"
	}
	return strings.ToUpper(kw)
}

// firstKeyword returns the lower-cased leading SQL keyword of a statement,
// skipping leading whitespace and a leading line comment.
func firstKeyword(statement string) string {
	s := strings.TrimSpace(statement)
	for strings.HasPrefix(s, "--") {
		if nl := strings.IndexByte(s, '\n'); nl >= 0 {
			s = strings.TrimSpace(s[nl+1:])
		} else {
			return ""
		}
	}
	i := strings.IndexFunc(s, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '(' || r == ';'
	})
	if i < 0 {
		i = len(s)
	}
	return strings.ToLower(s[:i])
}

// toStringRow converts a pgx value row to the nullable-string wire form.
func toStringRow(vals []any) []*string {
	row := make([]*string, len(vals))
	for i, v := range vals {
		if v == nil {
			continue
		}
		s := stringifyValue(v)
		row[i] = &s
	}
	return row
}

// stringifyValue renders a Postgres-decoded value as text for the result grid.
func stringifyValue(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []byte:
		return string(t)
	case time.Time:
		return t.Format(time.RFC3339Nano)
	case fmt.Stringer:
		return t.String()
	default:
		// json.Marshal renders composite types (arrays, json/jsonb, numerics)
		// faithfully; fall back to %v if it cannot.
		if b, err := json.Marshal(v); err == nil {
			return string(b)
		}
		return fmt.Sprintf("%v", v)
	}
}
