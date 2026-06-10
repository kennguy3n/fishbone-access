package migrations

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// This file implements the migration linter that backs `make migrate-check`,
// matching the intent of visible-fishbone's `sng-migrate validate --strict`
// (version integrity + lock-safety) adapted to this repo's runner.
//
// Two families of rules are enforced:
//
//   - Version integrity: filenames are well-formed (NNNN_name.sql), version
//     numbers are unique, and the sequence is contiguous apart from an
//     explicitly declared reserved range. A duplicate or an undeclared gap is a
//     real bug — the runner records applied versions by their string version in
//     schema_migrations, so a duplicate would make two files race the same
//     primary key and a silent gap usually means a migration was lost in a merge.
//
//   - Lock-safety: each statement is checked for patterns that take a heavy lock
//     (or are outright illegal) under THIS repo's migration runner, which wraps
//     every file in a single transaction (see Run). Because of that transaction,
//     the rules are the mirror image of an out-of-transaction runner's:
//     CONCURRENTLY is forbidden (Postgres rejects CREATE/DROP INDEX CONCURRENTLY
//     inside a transaction, so such a migration fails at apply time), while a
//     plain CREATE INDEX is allowed. The remaining rules flag operations that
//     hold ACCESS EXCLUSIVE for a table rewrite (ADD COLUMN NOT NULL without a
//     DEFAULT, ALTER COLUMN ... TYPE), an explicit LOCK TABLE, or a destructive
//     DROP COLUMN.
//
// The linter reads the same embedded files the runner applies, so it lints
// exactly what ships.

// reservedVersions records version numbers that are intentionally absent from
// the sequence so the contiguity check does not flag the gap they leave. The
// 0006–0009 range was reserved while several workstreams were in flight and
// their schema ultimately landed under later versions; the numbers were never
// reused, so the gap is by design rather than a lost migration. Any gap NOT
// listed here is treated as a real bug. New migrations must continue the
// sequence contiguously from the current maximum (0018, 0019, …).
var reservedVersions = map[int]bool{6: true, 7: true, 8: true, 9: true}

// filenamePattern is the required migration filename shape: a 4-digit
// zero-padded version, an underscore, then a lower-snake-case name.
var filenamePattern = regexp.MustCompile(`^[0-9]{4}_[a-z0-9]+(?:_[a-z0-9]+)*\.sql$`)

// Lock-safety matchers run over masked, whitespace-collapsed SQL (see maskSQL).
var (
	reConcurrently   = regexp.MustCompile(`(?i)\bCONCURRENTLY\b`)
	reAlterColumnTyp = regexp.MustCompile(`(?i)\bALTER\s+COLUMN\s+\S+\s+(?:SET\s+DATA\s+)?TYPE\b`)
	reDropColumn     = regexp.MustCompile(`(?i)\bDROP\s+COLUMN\b`)
	reLockTable      = regexp.MustCompile(`(?i)\bLOCK\s+(?:TABLE\b|\w)`)
	reAddColumn      = regexp.MustCompile(`(?i)\bADD\s+COLUMN\b`)
	reNotNull        = regexp.MustCompile(`(?i)\bNOT\s+NULL\b`)
	reDefault        = regexp.MustCompile(`(?i)\bDEFAULT\b`)
)

// Rule names are stable identifiers so a violation can be grepped/suppressed by
// a precise key rather than prose.
const (
	RuleFilename         = "filename-format"
	RuleDuplicateVersion = "duplicate-version"
	RuleVersionGap       = "version-gap"
	RuleConcurrently     = "concurrently-in-transaction"
	RuleAddColumnNotNull = "add-column-not-null-no-default"
	RuleAlterColumnType  = "alter-column-type"
	RuleDropColumn       = "drop-column"
	RuleLockTable        = "lock-table"
)

// Violation is one rule failure, naming the file, the rule, and a human detail.
type Violation struct {
	File   string
	Rule   string
	Detail string
}

func (v Violation) String() string {
	if v.File == "" {
		return fmt.Sprintf("[%s] %s", v.Rule, v.Detail)
	}
	return fmt.Sprintf("%s: [%s] %s", v.File, v.Rule, v.Detail)
}

// LintResult is the outcome of a Lint run.
type LintResult struct {
	Violations []Violation
}

// OK reports whether the lint passed (no violations).
func (r LintResult) OK() bool { return len(r.Violations) == 0 }

// Err returns a single aggregated error describing every violation, or nil when
// the lint passed, so a caller can `if err := r.Err(); err != nil`.
func (r LintResult) Err() error {
	if r.OK() {
		return nil
	}
	lines := make([]string, len(r.Violations))
	for i, v := range r.Violations {
		lines[i] = v.String()
	}
	return fmt.Errorf("migration lint failed (%d violation(s)):\n%s",
		len(r.Violations), strings.Join(lines, "\n"))
}

// Lint loads the embedded migrations and runs every rule, returning all
// violations found. It returns an error only when the migrations cannot be read.
func Lint() (LintResult, error) {
	entries, err := files.ReadDir(".")
	if err != nil {
		return LintResult{}, err
	}

	var (
		result    LintResult
		filenames []string
	)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		filenames = append(filenames, e.Name())
	}
	sort.Strings(filenames)

	result.Violations = append(result.Violations, checkVersions(filenames)...)

	for _, name := range filenames {
		// Only lint the SQL of well-formed files; a malformed filename is already
		// reported by checkVersions and its body has no reliable version to key on.
		if !filenamePattern.MatchString(name) {
			continue
		}
		b, err := files.ReadFile(name)
		if err != nil {
			return LintResult{}, err
		}
		result.Violations = append(result.Violations, lockSafety(name, string(b))...)
	}
	return result, nil
}

// checkVersions enforces filename format, version uniqueness, and contiguity
// (ignoring the declared reserved range).
func checkVersions(filenames []string) []Violation {
	var violations []Violation
	seen := map[int][]string{}
	var versions []int

	for _, name := range filenames {
		if !filenamePattern.MatchString(name) {
			violations = append(violations, Violation{
				File:   name,
				Rule:   RuleFilename,
				Detail: "filename must match NNNN_name.sql (4-digit version, lower-snake-case name)",
			})
			continue
		}
		v, _ := strconv.Atoi(name[:4]) // safe: pattern guarantees 4 digits
		if _, ok := seen[v]; !ok {
			versions = append(versions, v)
		}
		seen[v] = append(seen[v], name)
	}

	// Duplicate versions: two files claiming the same NNNN.
	for _, v := range versions {
		if names := seen[v]; len(names) > 1 {
			violations = append(violations, Violation{
				Rule:   RuleDuplicateVersion,
				Detail: fmt.Sprintf("version %04d is used by multiple files: %s", v, strings.Join(names, ", ")),
			})
		}
	}

	// Contiguity: every integer between the min and max present version must be
	// either present or declared reserved.
	if len(versions) > 0 {
		sort.Ints(versions)
		min, max := versions[0], versions[len(versions)-1]
		present := map[int]bool{}
		for _, v := range versions {
			present[v] = true
		}
		for v := min; v <= max; v++ {
			if present[v] || reservedVersions[v] {
				continue
			}
			violations = append(violations, Violation{
				Rule:   RuleVersionGap,
				Detail: fmt.Sprintf("missing version %04d (sequence has a gap that is not declared reserved)", v),
			})
		}
	}
	return violations
}

// lockSafety runs the per-statement lock-safety rules over one migration file.
func lockSafety(name, sql string) []Violation {
	var violations []Violation
	for _, stmt := range splitStatements(maskSQL(sql)) {
		s := collapseWS(stmt)
		if s == "" {
			continue
		}
		if reConcurrently.MatchString(s) {
			violations = append(violations, Violation{
				File:   name,
				Rule:   RuleConcurrently,
				Detail: "CONCURRENTLY is illegal inside the per-migration transaction this runner uses; use a plain (transactional) index build",
			})
		}
		if reAlterColumnTyp.MatchString(s) {
			violations = append(violations, Violation{
				File:   name,
				Rule:   RuleAlterColumnType,
				Detail: "ALTER COLUMN ... TYPE rewrites the table under ACCESS EXCLUSIVE; migrate via a new column + backfill instead",
			})
		}
		if reDropColumn.MatchString(s) {
			violations = append(violations, Violation{
				File:   name,
				Rule:   RuleDropColumn,
				Detail: "DROP COLUMN is destructive and rewrites the table; drop in a dedicated, reviewed migration after the column is unused",
			})
		}
		if reLockTable.MatchString(s) {
			violations = append(violations, Violation{
				File:   name,
				Rule:   RuleLockTable,
				Detail: "explicit LOCK TABLE blocks all access for the migration's duration",
			})
		}
		// ADD COLUMN ... NOT NULL without DEFAULT: evaluate each top-level clause
		// (commas at paren-depth 0 separate ALTER TABLE actions) so a type like
		// NUMERIC(10,2) does not split a clause and so multiple ADD COLUMNs in one
		// statement are each judged on their own.
		for _, clause := range splitTopLevelCommas(s) {
			if reAddColumn.MatchString(clause) && reNotNull.MatchString(clause) && !reDefault.MatchString(clause) {
				violations = append(violations, Violation{
					File:   name,
					Rule:   RuleAddColumnNotNull,
					Detail: "ADD COLUMN ... NOT NULL without DEFAULT fails on a populated table; add a DEFAULT (or backfill then SET NOT NULL)",
				})
			}
		}
	}
	return violations
}

// maskSQL blanks out content the lock-safety scanner must not match inside:
// line comments (-- … EOL), block comments (/* … */), and single-quoted string
// literals (including ” escapes). Masked spans are replaced with spaces so byte
// offsets and statement boundaries are preserved.
func maskSQL(sql string) string {
	out := []byte(sql)
	n := len(out)
	for i := 0; i < n; {
		switch {
		case out[i] == '-' && i+1 < n && out[i+1] == '-':
			for i < n && out[i] != '\n' {
				out[i] = ' '
				i++
			}
		case out[i] == '/' && i+1 < n && out[i+1] == '*':
			for i < n && !(out[i] == '*' && i+1 < n && out[i+1] == '/') {
				if out[i] != '\n' {
					out[i] = ' '
				}
				i++
			}
			// Blank the closing */ too.
			for j := 0; j < 2 && i < n; j++ {
				out[i] = ' '
				i++
			}
		case out[i] == '\'':
			out[i] = ' '
			i++
			for i < n {
				if out[i] == '\'' {
					// Doubled '' is an escaped quote inside the literal.
					if i+1 < n && out[i+1] == '\'' {
						out[i], out[i+1] = ' ', ' '
						i += 2
						continue
					}
					out[i] = ' '
					i++
					break
				}
				if out[i] != '\n' {
					out[i] = ' '
				}
				i++
			}
		default:
			i++
		}
	}
	return string(out)
}

// splitStatements splits masked SQL into statements on semicolons. The masker
// has already removed quoted/commented semicolons, so a plain split is safe for
// the DDL these migrations contain (no PL/pgSQL bodies are used).
func splitStatements(masked string) []string {
	return strings.Split(masked, ";")
}

// splitTopLevelCommas splits s on commas that sit at parenthesis depth 0, so
// ALTER TABLE clauses separate while a parenthesised type list (e.g.
// NUMERIC(10,2)) stays intact.
func splitTopLevelCommas(s string) []string {
	var (
		parts []string
		depth int
		start int
	)
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				parts = append(parts, s[start:i])
				start = i + 1
			}
		}
	}
	parts = append(parts, s[start:])
	return parts
}

// collapseWS trims s and collapses internal runs of whitespace to single spaces
// so the token regexes match across original newlines and indentation.
func collapseWS(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
