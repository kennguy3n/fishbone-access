package webaccess

import (
	"testing"
	"time"
)

func TestFirstKeyword(t *testing.T) {
	cases := map[string]string{
		"SELECT * FROM t":                       "select",
		"  select 1":                            "select",
		"\n\tUPDATE t SET x=1":                  "update",
		"INSERT INTO t VALUES (1)":              "insert",
		"WITH a AS (SELECT 1) SELECT":           "with",
		"(SELECT 1)":                            "",
		"-- a comment\nSELECT 1":                "select",
		"":                                      "",
		"VACUUM;":                               "vacuum",
		"/*+ MAX_EXECUTION_TIME(1) */ SELECT 1": "select",
		"/* leading block */ UPDATE t SET x=1":  "update",
		"-- line\n/* block */\nselect 2":        "select",
		"/* unterminated select":                "",
	}
	for in, want := range cases {
		if got := firstKeyword(in); got != want {
			t.Errorf("firstKeyword(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSanitizeCommandText(t *testing.T) {
	cases := map[string]string{
		// Well-formed input is returned byte-for-byte.
		"SELECT * FROM payments": "SELECT * FROM payments",
		"ls -la /etc":            "ls -la /etc",
		"echo café — déjà":       "echo café — déjà",
		"":                       "",
		// NUL (0x00) is dropped: Postgres TEXT cannot store it, so a stray NUL
		// must not fail the audit write and tear the session down.
		"echo \x00hi": "echo hi",
		"\x00\x00":    "",
		"a\x00b\x00c": "abc",
		// A torn multibyte sequence (lone UTF-8 continuation/lead bytes) is
		// coerced away rather than left to trip "invalid byte sequence".
		"echo \xe2\x80hi": "echo hi",
		"\xff\xfe":        "",
		"good\x80tail":    "goodtail",
	}
	for in, want := range cases {
		if got := sanitizeCommandText(in); got != want {
			t.Errorf("sanitizeCommandText(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestReturnsRows(t *testing.T) {
	rowReturning := []string{"SELECT 1", "show tables", "DESCRIBE t", "explain analyze select 1", "WITH a AS (select 1) select * from a", "TABLE t", "VALUES (1)", "CALL p()",
		"ANALYZE TABLE t", "OPTIMIZE TABLE t", "CHECK TABLE t", "CHECKSUM TABLE t", "HANDLER t READ FIRST",
		"/*+ hint */ SELECT 1"}
	for _, s := range rowReturning {
		if !returnsRows(s) {
			t.Errorf("returnsRows(%q) = false, want true", s)
		}
	}
	writes := []string{"INSERT INTO t VALUES (1)", "update t set x=1", "DELETE FROM t", "create table t(x int)", "drop table t", "begin", "commit"}
	for _, s := range writes {
		if returnsRows(s) {
			t.Errorf("returnsRows(%q) = true, want false", s)
		}
	}
}

func TestCommandVerb(t *testing.T) {
	if got := commandVerb("insert into t values(1)", "INSERT 0 1"); got != "INSERT" {
		t.Errorf("commandVerb with tag = %q, want INSERT", got)
	}
	if got := commandVerb("update t set x=1", ""); got != "UPDATE" {
		t.Errorf("commandVerb no tag = %q, want UPDATE", got)
	}
	if got := commandVerb("   ", ""); got != "OK" {
		t.Errorf("commandVerb empty = %q, want OK", got)
	}
}

func TestToStringRow(t *testing.T) {
	ts := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	row := toStringRow([]any{nil, "abc", int64(42), ts, []byte("bin"), map[string]any{"k": "v"}})
	if row[0] != nil {
		t.Errorf("nil value should map to nil pointer, got %v", *row[0])
	}
	if row[1] == nil || *row[1] != "abc" {
		t.Errorf("string value mismatch: %v", row[1])
	}
	if row[2] == nil || *row[2] != "42" {
		t.Errorf("int value mismatch: %v", row[2])
	}
	if row[3] == nil || *row[3] != ts.Format(time.RFC3339Nano) {
		t.Errorf("time value mismatch: %v", row[3])
	}
	if row[4] == nil || *row[4] != "bin" {
		t.Errorf("[]byte value mismatch: %v", row[4])
	}
	if row[5] == nil || *row[5] != `{"k":"v"}` {
		t.Errorf("map value mismatch: %v", row[5])
	}
}

func TestSummariseResult(t *testing.T) {
	rowSet := resultMessage{Columns: []queryColumn{{Name: "id"}}, Rows: [][]*string{{nil}, {nil}}, ElapsedMs: 3}
	if got := summariseResult(rowSet); got != "[2 row(s) in 3ms]\n" {
		t.Errorf("summariseResult rowset = %q", got)
	}
	truncated := resultMessage{Columns: []queryColumn{{Name: "id"}}, Rows: [][]*string{{nil}}, Truncated: true, ElapsedMs: 1}
	if got := summariseResult(truncated); got != "[1 row(s)+ (truncated) in 1ms]\n" {
		t.Errorf("summariseResult truncated = %q", got)
	}
	write := resultMessage{Command: "UPDATE", RowsAffected: 5, ElapsedMs: 2}
	if got := summariseResult(write); got != "[UPDATE: 5 row(s) affected in 2ms]\n" {
		t.Errorf("summariseResult write = %q", got)
	}
}

func TestSanitizeDialError(t *testing.T) {
	if got := sanitizeDialError(errStr("webaccess: ssh dial 10.0.0.1:22: connection refused")); got != "connection refused" {
		t.Errorf("sanitizeDialError = %q", got)
	}
	if got := sanitizeDialError(errStr("plain")); got != "plain" {
		t.Errorf("sanitizeDialError plain = %q", got)
	}
}

// errStr is a tiny error helper for table tests.
type errStr string

func (e errStr) Error() string { return string(e) }
