package migrations

import (
	"strings"
	"testing"
)

// TestLintEmbeddedMigrationsPass is the gate that backs `make migrate-check`:
// the migrations that actually ship must pass every rule. If a future migration
// introduces a duplicate version, an undeclared gap, or a lock-unsafe statement,
// this test (and the CLI) fail.
func TestLintEmbeddedMigrationsPass(t *testing.T) {
	result, err := Lint()
	if err != nil {
		t.Fatalf("Lint: %v", err)
	}
	if !result.OK() {
		t.Fatalf("embedded migrations have lint violations:\n%v", result.Err())
	}
}

func TestCheckVersions(t *testing.T) {
	tests := []struct {
		name      string
		filenames []string
		wantRules []string // rules expected at least once; empty means "no violations"
	}{
		{
			name:      "clean contiguous",
			filenames: []string{"0001_init.sql", "0002_next.sql", "0003_more.sql"},
		},
		{
			name:      "reserved gap is allowed",
			filenames: []string{"0005_pam_gateway.sql", "0010_workflow_approvals.sql"},
		},
		{
			name:      "undeclared gap flagged",
			filenames: []string{"0001_init.sql", "0003_skip.sql"},
			wantRules: []string{RuleVersionGap},
		},
		{
			name:      "duplicate version flagged",
			filenames: []string{"0001_init.sql", "0001_dup.sql"},
			wantRules: []string{RuleDuplicateVersion},
		},
		{
			name:      "bad filename flagged",
			filenames: []string{"1_init.sql", "0002_Bad_Name.sql", "0002_trailing_.sql"},
			wantRules: []string{RuleFilename},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := checkVersions(tc.filenames)
			assertRules(t, got, tc.wantRules)
		})
	}
}

func TestLockSafety(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		wantRules []string
	}{
		{
			name: "plain create index is allowed (transactional runner)",
			sql:  `CREATE INDEX idx_audit_ws ON audit_events (workspace_id);`,
		},
		{
			name: "add column not null with default is allowed",
			sql:  `ALTER TABLE t ADD COLUMN IF NOT EXISTS c INT NOT NULL DEFAULT 0;`,
		},
		{
			name: "numeric type comma does not split clause",
			sql:  `ALTER TABLE t ADD COLUMN price NUMERIC(10,2) NOT NULL DEFAULT 0;`,
		},
		{
			name:      "create index concurrently flagged",
			sql:       `CREATE INDEX CONCURRENTLY idx ON t (a);`,
			wantRules: []string{RuleConcurrently},
		},
		{
			name:      "add column not null without default flagged",
			sql:       `ALTER TABLE t ADD COLUMN c TEXT NOT NULL;`,
			wantRules: []string{RuleAddColumnNotNull},
		},
		{
			name:      "second clause not null without default flagged",
			sql:       `ALTER TABLE t ADD COLUMN a INT NOT NULL DEFAULT 1, ADD COLUMN b TEXT NOT NULL;`,
			wantRules: []string{RuleAddColumnNotNull},
		},
		{
			name:      "alter column type flagged",
			sql:       `ALTER TABLE t ALTER COLUMN c TYPE BIGINT;`,
			wantRules: []string{RuleAlterColumnType},
		},
		{
			name:      "alter column set data type flagged",
			sql:       `ALTER TABLE t ALTER COLUMN c SET DATA TYPE BIGINT;`,
			wantRules: []string{RuleAlterColumnType},
		},
		{
			name:      "drop column flagged",
			sql:       `ALTER TABLE t DROP COLUMN c;`,
			wantRules: []string{RuleDropColumn},
		},
		{
			name:      "lock table flagged",
			sql:       `LOCK TABLE t IN ACCESS EXCLUSIVE MODE;`,
			wantRules: []string{RuleLockTable},
		},
		{
			name: "keyword inside comment is ignored",
			sql:  "-- this migration avoids CONCURRENTLY on purpose\nCREATE INDEX idx ON t (a);",
		},
		{
			name: "keyword inside string literal is ignored",
			sql:  `INSERT INTO notes (body) VALUES ('we must DROP COLUMN later');`,
		},
		{
			name: "set not null alone is allowed (no type rewrite, no add)",
			sql:  `ALTER TABLE t ALTER COLUMN c SET NOT NULL;`,
		},
		{
			name: "keyword inside dollar-quoted body is ignored",
			sql: "CREATE FUNCTION f() RETURNS void AS $$\n" +
				"BEGIN\n  LOCK TABLE t; -- DROP COLUMN x;\nEND;\n$$ LANGUAGE plpgsql;",
		},
		{
			name: "keyword inside tagged dollar-quoted body is ignored",
			sql:  "CREATE FUNCTION f() RETURNS void AS $body$ ALTER TABLE t DROP COLUMN c; $body$ LANGUAGE plpgsql;",
		},
		{
			name:      "real violation outside dollar-quoted body is still flagged",
			sql:       "CREATE FUNCTION f() RETURNS void AS $$ SELECT 1; $$ LANGUAGE sql;\nALTER TABLE t DROP COLUMN c;",
			wantRules: []string{RuleDropColumn},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := lockSafety("test.sql", tc.sql)
			assertRules(t, got, tc.wantRules)
		})
	}
}

func TestSplitTopLevelCommas(t *testing.T) {
	parts := splitTopLevelCommas("ADD COLUMN a NUMERIC(10,2), ADD COLUMN b INT")
	if len(parts) != 2 {
		t.Fatalf("got %d parts, want 2: %q", len(parts), parts)
	}
	if !strings.Contains(parts[0], "NUMERIC(10,2)") {
		t.Errorf("first clause lost its parenthesised type: %q", parts[0])
	}
}

func TestMaskSQLDollarQuoting(t *testing.T) {
	// A dollar-quoted body is fully blanked (so its keywords/semicolons never
	// reach the scanner) while a positional parameter like $1 is left intact.
	in := "DO $$ DROP COLUMN x; $$; SELECT $1;"
	masked := maskSQL(in)
	if len(masked) != len(in) {
		t.Fatalf("mask changed length: got %d want %d", len(masked), len(in))
	}
	if strings.Contains(masked, "DROP COLUMN") {
		t.Errorf("dollar-quoted body not masked: %q", masked)
	}
	if !strings.Contains(masked, "$1") {
		t.Errorf("positional parameter $1 should be left intact: %q", masked)
	}
	// Two semicolons survive: the one ending the DO statement and the trailing
	// SELECT terminator; the one inside the body is masked.
	if strings.Count(masked, ";") != 2 {
		t.Errorf("expected 2 surviving semicolons, got %q", masked)
	}
}

func TestMaskSQLPreservesLength(t *testing.T) {
	in := "SELECT 'a;b' /* c;d */ -- e;f\nFROM t;"
	masked := maskSQL(in)
	if len(masked) != len(in) {
		t.Fatalf("mask changed length: got %d want %d", len(masked), len(in))
	}
	// The semicolons inside the literal and comments must be masked so statement
	// splitting does not treat them as boundaries.
	if strings.Count(masked, ";") != 1 {
		t.Errorf("masked SQL should retain only the real statement terminator, got %q", masked)
	}
}

// assertRules checks that got contains exactly the set of rules in want (by
// presence). An empty want asserts no violations.
func assertRules(t *testing.T, got []Violation, want []string) {
	t.Helper()
	if len(want) == 0 {
		if len(got) != 0 {
			t.Fatalf("expected no violations, got: %v", got)
		}
		return
	}
	seen := map[string]bool{}
	for _, v := range got {
		seen[v.Rule] = true
	}
	for _, r := range want {
		if !seen[r] {
			t.Errorf("expected violation rule %q, got: %v", r, got)
		}
	}
}
