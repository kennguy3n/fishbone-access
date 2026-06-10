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
// A lock-safety rule is a judgment call, not an absolute: the destructive or
// heavy operation it flags is occasionally the correct thing to do in a
// dedicated, reviewed migration. Such a migration opts out with an explicit
// `-- migrate-lint:allow <rule>` directive (see reSuppress), which keeps the
// waiver visible in the diff and grep-able by rule name. Version-integrity
// rules cannot be suppressed — a duplicate or undeclared gap is always a defect.
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

// Rule names are stable identifiers so a violation can be grepped or suppressed
// by a precise key rather than prose (see the migrate-lint:allow directive).
const (
	RuleFilename         = "filename-format"
	RuleDuplicateVersion = "duplicate-version"
	RuleVersionGap       = "version-gap"
	RuleConcurrently     = "concurrently-in-transaction"
	RuleAddColumnNotNull = "add-column-not-null-no-default"
	RuleAlterColumnType  = "alter-column-type"
	RuleDropColumn       = "drop-column"
	RuleLockTable        = "lock-table"

	// RuleUnknownSuppression flags a migrate-lint:allow directive that names a
	// rule which is not a suppressible lock-safety rule (a typo, or an attempt to
	// silence a version-integrity rule). The directive is then a no-op, so we
	// surface it rather than let the author believe a check was waived.
	RuleUnknownSuppression = "unknown-suppression"
)

// suppressibleRules are the lock-safety rules a migration may explicitly opt out
// of with a `-- migrate-lint:allow <rule>` directive. These are judgment calls:
// a heavy lock or a destructive change is usually wrong, but is legitimate in a
// dedicated, reviewed migration (e.g. dropping a column that is already unused).
// Version-integrity rules are intentionally absent — a duplicate version or an
// undeclared gap is a structural defect, never a reviewed exception.
var suppressibleRules = map[string]bool{
	RuleConcurrently:     true,
	RuleAddColumnNotNull: true,
	RuleAlterColumnType:  true,
	RuleDropColumn:       true,
	RuleLockTable:        true,
}

// reSuppress matches a suppression directive and captures its comma-separated
// rule list. The directive lives in a SQL comment, e.g.
//
//	-- migrate-lint:allow drop-column   (column X unused since 0014, see TICKET-123)
//	-- migrate-lint:allow lock-table,alter-column-type
//
// Anything after the rule list (a free-text reason, which reviewers should
// include) is ignored by the parser.
var reSuppress = regexp.MustCompile(`(?i)\bmigrate-lint:allow\s+([a-z0-9\-]+(?:\s*,\s*[a-z0-9\-]+)*)`)

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
// A `-- migrate-lint:allow <rule>` directive anywhere in the file waives that
// (suppressible) rule for the whole file; a directive naming an unknown or
// non-suppressible rule is itself reported.
func lockSafety(name, sql string) []Violation {
	allowed, violations := parseSuppressions(name, sql)
	// add records a violation unless the file has opted out of that rule.
	add := func(rule, detail string) {
		if allowed[rule] {
			return
		}
		violations = append(violations, Violation{File: name, Rule: rule, Detail: detail})
	}
	for _, stmt := range splitStatements(maskSQL(sql)) {
		s := collapseWS(stmt)
		if s == "" {
			continue
		}
		if reConcurrently.MatchString(s) {
			add(RuleConcurrently, "CONCURRENTLY is illegal inside the per-migration transaction this runner uses; use a plain (transactional) index build")
		}
		if reAlterColumnTyp.MatchString(s) {
			add(RuleAlterColumnType, "ALTER COLUMN ... TYPE rewrites the table under ACCESS EXCLUSIVE; migrate via a new column + backfill instead")
		}
		if reDropColumn.MatchString(s) {
			add(RuleDropColumn, "DROP COLUMN is destructive and rewrites the table; drop in a dedicated, reviewed migration after the column is unused, then add `-- migrate-lint:allow drop-column <reason>`")
		}
		if reLockTable.MatchString(s) {
			add(RuleLockTable, "explicit LOCK TABLE blocks all access for the migration's duration")
		}
		// ADD COLUMN ... NOT NULL without DEFAULT: evaluate each top-level clause
		// (commas at paren-depth 0 separate ALTER TABLE actions) so a type like
		// NUMERIC(10,2) does not split a clause and so multiple ADD COLUMNs in one
		// statement are each judged on their own.
		for _, clause := range splitTopLevelCommas(s) {
			if reAddColumn.MatchString(clause) && reNotNull.MatchString(clause) && !reDefault.MatchString(clause) {
				add(RuleAddColumnNotNull, "ADD COLUMN ... NOT NULL without DEFAULT fails on a populated table; add a DEFAULT (or backfill then SET NOT NULL)")
			}
		}
	}
	return violations
}

// parseSuppressions reads every `-- migrate-lint:allow <rule>[,<rule>…]`
// directive in the file's comments and returns the set of lock-safety rules the
// file waives. A directive that names a rule which is not in suppressibleRules
// is returned as a RuleUnknownSuppression violation so a typo or a misguided
// attempt to silence a structural check is loud, not silent.
//
// Directives are matched against commentText(sql), not the raw bytes, so a
// directive is honoured only when it genuinely lives in a SQL comment. A string
// such as INSERT INTO t VALUES ('-- migrate-lint:allow drop-column') can no
// longer smuggle a suppression past a real violation through data.
func parseSuppressions(name, sql string) (map[string]bool, []Violation) {
	allowed := map[string]bool{}
	var violations []Violation
	for _, m := range reSuppress.FindAllStringSubmatch(commentText(sql), -1) {
		for _, tok := range strings.Split(m[1], ",") {
			rule := strings.ToLower(strings.TrimSpace(tok))
			if rule == "" {
				continue
			}
			if !suppressibleRules[rule] {
				violations = append(violations, Violation{
					File:   name,
					Rule:   RuleUnknownSuppression,
					Detail: fmt.Sprintf("migrate-lint:allow names %q, which is not a suppressible lock-safety rule", rule),
				})
				continue
			}
			allowed[rule] = true
		}
	}
	return allowed, violations
}

// maskSQL blanks out content the lock-safety scanner must not match inside:
// line comments (-- … EOL), block comments (/* … */, which PostgreSQL allows to
// nest), single-quoted string literals (with ” escapes), escape strings
// (E'…', where a backslash escapes the next byte so \' does not close), and
// dollar-quoted strings ($$…$$ or $tag$…$tag$, e.g. PL/pgSQL bodies). Masked
// spans are replaced with spaces so byte offsets and statement boundaries are
// preserved.
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
			// PostgreSQL block comments nest, so track depth rather than stopping at
			// the first */ (which would leave the tail of an outer comment exposed to
			// the scanner).
			depth := 0
			for i < n {
				if out[i] == '/' && i+1 < n && out[i+1] == '*' {
					out[i], out[i+1] = ' ', ' '
					i += 2
					depth++
					continue
				}
				if out[i] == '*' && i+1 < n && out[i+1] == '/' {
					out[i], out[i+1] = ' ', ' '
					i += 2
					depth--
					if depth == 0 {
						break
					}
					continue
				}
				if out[i] != '\n' {
					out[i] = ' '
				}
				i++
			}
		case (out[i] == 'E' || out[i] == 'e') && i+1 < n && out[i+1] == '\'' &&
			(i == 0 || !isWordChar(out[i-1])):
			// PostgreSQL escape string E'…': unlike a standard literal, a backslash
			// escapes the next byte, so \' and \\ do NOT end the string. Mask the E
			// prefix, the quotes, and the body. The leading-word guard keeps the tail
			// of an identifier (e.g. a column named foo_e) from being read as a prefix.
			out[i] = ' ' // E/e prefix
			i++
			out[i] = ' ' // opening quote
			i++
			for i < n {
				if out[i] == '\\' && i+1 < n {
					out[i] = ' '
					i++
					if out[i] != '\n' {
						out[i] = ' '
					}
					i++
					continue
				}
				if out[i] == '\'' {
					// A doubled '' is an escaped quote in an E-string too.
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
		case out[i] == '$':
			// PostgreSQL dollar-quoted string ($$...$$ or $tag$...$tag$), used for
			// PL/pgSQL bodies. Mask the whole span — including any LOCK TABLE / DROP
			// COLUMN keywords or semicolons it contains — so a function body is never
			// scanned as DDL. A bare '$' or a positional parameter like $1 is not a
			// delimiter (dollarTag returns ""), so it is left intact.
			if delim := dollarTag(out, i); delim != "" {
				end := i + len(delim)
				for k := i; k < end; k++ {
					out[k] = ' '
				}
				i = end
				for i < n {
					if hasDelimAt(out, i, delim) {
						for k := i; k < i+len(delim); k++ {
							out[k] = ' '
						}
						i += len(delim)
						break
					}
					if out[i] != '\n' {
						out[i] = ' '
					}
					i++
				}
			} else {
				i++
			}
		default:
			i++
		}
	}
	return string(out)
}

// commentText is the inverse of maskSQL: it returns sql with everything EXCEPT
// line- and block-comment bodies blanked to spaces (length and newlines
// preserved). It shares maskSQL's lexical rules — string literals, E'…' escape
// strings, and dollar-quoted bodies are skipped wholesale so a -- or /* that
// appears inside one is never mistaken for the start of a comment. This is what
// lets parseSuppressions trust that a matched directive really sits in a
// comment rather than in data.
func commentText(sql string) string {
	src := []byte(sql)
	n := len(src)
	out := make([]byte, n)
	for i := range out {
		if src[i] == '\n' {
			out[i] = '\n'
		} else {
			out[i] = ' '
		}
	}
	for i := 0; i < n; {
		switch {
		case src[i] == '-' && i+1 < n && src[i+1] == '-':
			for i < n && src[i] != '\n' {
				out[i] = src[i]
				i++
			}
		case src[i] == '/' && i+1 < n && src[i+1] == '*':
			depth := 0
			for i < n {
				if src[i] == '/' && i+1 < n && src[i+1] == '*' {
					out[i], out[i+1] = src[i], src[i+1]
					i += 2
					depth++
					continue
				}
				if src[i] == '*' && i+1 < n && src[i+1] == '/' {
					out[i], out[i+1] = src[i], src[i+1]
					i += 2
					depth--
					if depth == 0 {
						break
					}
					continue
				}
				out[i] = src[i]
				i++
			}
		case (src[i] == 'E' || src[i] == 'e') && i+1 < n && src[i+1] == '\'' &&
			(i == 0 || !isWordChar(src[i-1])):
			i += 2
			for i < n {
				if src[i] == '\\' && i+1 < n {
					i += 2
					continue
				}
				if src[i] == '\'' {
					if i+1 < n && src[i+1] == '\'' {
						i += 2
						continue
					}
					i++
					break
				}
				i++
			}
		case src[i] == '\'':
			i++
			for i < n {
				if src[i] == '\'' {
					if i+1 < n && src[i+1] == '\'' {
						i += 2
						continue
					}
					i++
					break
				}
				i++
			}
		case src[i] == '$':
			if delim := dollarTag(src, i); delim != "" {
				i += len(delim)
				for i < n {
					if hasDelimAt(src, i, delim) {
						i += len(delim)
						break
					}
					i++
				}
			} else {
				i++
			}
		default:
			i++
		}
	}
	return string(out)
}

// dollarTag reports the dollar-quote opening delimiter starting at b[i] (which
// must be '$'), e.g. "$$" or "$body$", or "" if b[i] does not open a
// dollar-quoted string. The tag (between the dollar signs) may be empty or an
// identifier that starts with a letter/underscore and continues with
// letters/digits/underscores; this is what distinguishes a real delimiter from
// a positional parameter such as $1.
func dollarTag(b []byte, i int) string {
	j := i + 1
	if j < len(b) && (isLetter(b[j]) || b[j] == '_') {
		j++
		for j < len(b) && (isLetter(b[j]) || isDigit(b[j]) || b[j] == '_') {
			j++
		}
	}
	if j < len(b) && b[j] == '$' {
		return string(b[i : j+1])
	}
	return ""
}

// hasDelimAt reports whether delim occurs in b starting at index i.
func hasDelimAt(b []byte, i int, delim string) bool {
	return i+len(delim) <= len(b) && string(b[i:i+len(delim)]) == delim
}

func isLetter(c byte) bool   { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isDigit(c byte) bool    { return c >= '0' && c <= '9' }
func isWordChar(c byte) bool { return isLetter(c) || isDigit(c) || c == '_' }

// splitStatements splits masked SQL into statements on semicolons. The masker
// has already blanked semicolons inside comments, string literals, and
// dollar-quoted bodies, so a plain split is safe even for migrations that embed
// a PL/pgSQL function body.
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
