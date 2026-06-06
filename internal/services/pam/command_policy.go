// Package pam implements the Session 1D Privileged Access Management domain
// services that sit behind the pam-gateway proxy: the credential vault
// (per-target sealed secrets), one-shot connect tokens with leasing and
// rotation, live command-policy evaluation against the 1C policy engine, the
// step-up MFA gate, session lifecycle + admin takeover, and appending every
// command/decision to the per-workspace audit hash chain.
//
// These services hold no wire-protocol logic — the SSH/Postgres/MySQL/k8s
// ConnHandlers in internal/gateway call into them — so they are unit-testable
// without opening a socket.
package pam

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
)

// commandResourcePrefix marks a 1C policy resource ref that targets the PAM
// command plane rather than a connector resource. A deny policy whose
// definition lists resources like "cmd:rm -rf*" or "cmd:DROP *" is evaluated
// live against every command/statement the gateway proxies. Reusing the
// existing models.Policy storage and its draft→active→archived state machine
// (only active policies bind) keeps PAM on the 1C policy engine instead of a
// parallel rule store.
const commandResourcePrefix = "cmd:"

// Decision is the outcome of evaluating one command/statement against policy.
type Decision struct {
	// Effect is one of models.PAMDecisionAllow / PAMDecisionDeny.
	Effect string
	// Reason is a short human-readable explanation (the matching policy name and
	// pattern) recorded in the audit chain and surfaced to the operator on deny.
	Reason string
}

// Allowed reports whether the command may be forwarded to the target.
func (d Decision) Allowed() bool { return d.Effect == models.PAMDecisionAllow }

// commandRule is one compiled deny rule extracted from an active policy.
type commandRule struct {
	policyName string
	subjects   map[string]struct{} // empty/"*" ⇒ all subjects
	patterns   []string            // command globs (lower-cased)
	allSubject bool
}

// CommandPolicyEvaluator decides allow/deny for SSH commands and SQL statements
// by consulting the workspace's active 1C policies. It caches the compiled deny
// rules per workspace for a short TTL so per-command evaluation does not hit the
// database on every keystroke-delimited command, while still picking up policy
// promotions within one TTL window. Deny wins; the default is allow because the
// session itself is already gated by a redeemed connect token.
type CommandPolicyEvaluator struct {
	db  *gorm.DB
	ttl time.Duration
	now func() time.Time

	mu    sync.Mutex
	cache map[uuid.UUID]cachedRules
}

type cachedRules struct {
	rules     []commandRule
	expiresAt time.Time
}

// NewCommandPolicyEvaluator wires an evaluator. ttl <= 0 selects 5s, short
// enough that a newly promoted deny policy takes effect almost immediately.
func NewCommandPolicyEvaluator(db *gorm.DB, ttl time.Duration) *CommandPolicyEvaluator {
	if ttl <= 0 {
		ttl = 5 * time.Second
	}
	return &CommandPolicyEvaluator{
		db:    db,
		ttl:   ttl,
		now:   time.Now,
		cache: make(map[uuid.UUID]cachedRules),
	}
}

// SetClock overrides the time source (tests).
func (e *CommandPolicyEvaluator) SetClock(now func() time.Time) {
	if now != nil {
		e.now = now
	}
}

// Evaluate returns the policy decision for subject running command in
// workspaceID. An empty command is allowed (nothing to gate). A database error
// fails closed: the command is denied rather than silently permitted, because a
// privileged command plane must not lose its gate when policy is unreadable.
func (e *CommandPolicyEvaluator) Evaluate(ctx context.Context, workspaceID uuid.UUID, subject, command string) (Decision, error) {
	cmd := strings.TrimSpace(command)
	if cmd == "" {
		return Decision{Effect: models.PAMDecisionAllow}, nil
	}
	rules, err := e.rulesFor(ctx, workspaceID)
	if err != nil {
		return Decision{Effect: models.PAMDecisionDeny, Reason: "policy unavailable (fail-closed)"}, err
	}

	lc := strings.ToLower(cmd)
	for i := range rules {
		r := &rules[i]
		if !r.allSubject {
			if _, ok := r.subjects[subject]; !ok {
				continue
			}
		}
		for _, pat := range r.patterns {
			if globMatch(pat, lc) {
				return Decision{
					Effect: models.PAMDecisionDeny,
					Reason: fmt.Sprintf("denied by policy %q (pattern %q)", r.policyName, pat),
				}, nil
			}
		}
	}
	return Decision{Effect: models.PAMDecisionAllow}, nil
}

// rulesFor returns the compiled deny rules for a workspace, loading and caching
// them on a miss or after TTL expiry.
func (e *CommandPolicyEvaluator) rulesFor(ctx context.Context, workspaceID uuid.UUID) ([]commandRule, error) {
	now := e.now()
	e.mu.Lock()
	if c, ok := e.cache[workspaceID]; ok && now.Before(c.expiresAt) {
		e.mu.Unlock()
		return c.rules, nil
	}
	e.mu.Unlock()

	rules, err := e.loadRules(ctx, workspaceID)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	// Drop expired entries before inserting so the map is bounded by the number
	// of workspaces actively evaluated within one TTL window, not by every
	// workspace ever seen for the lifetime of the gateway process.
	for id, c := range e.cache {
		if !now.Before(c.expiresAt) {
			delete(e.cache, id)
		}
	}
	e.cache[workspaceID] = cachedRules{rules: rules, expiresAt: now.Add(e.ttl)}
	e.mu.Unlock()
	return rules, nil
}

// loadRules reads the workspace's active policies and compiles those carrying
// command-plane deny resources into commandRules.
func (e *CommandPolicyEvaluator) loadRules(ctx context.Context, workspaceID uuid.UUID) ([]commandRule, error) {
	var policies []models.Policy
	if err := e.db.WithContext(ctx).
		Where("workspace_id = ? AND state = ?", workspaceID, lifecycle.PolicyStateActive).
		Find(&policies).Error; err != nil {
		return nil, fmt.Errorf("pam: load active policies: %w", err)
	}

	rules := make([]commandRule, 0, len(policies))
	for i := range policies {
		def, err := lifecycle.ParsePolicyDefinition(policies[i].Definition)
		if err != nil {
			// A stored active policy that no longer parses is a data-integrity
			// problem, not a per-command failure; skip it so one bad row cannot
			// disable the whole command gate, but it is intentionally not fatal.
			continue
		}
		if def.Action != lifecycle.PolicyActionDeny {
			continue
		}
		patterns := make([]string, 0, len(def.Resources))
		for _, res := range def.Resources {
			if !strings.HasPrefix(res, commandResourcePrefix) {
				continue
			}
			pat := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(res, commandResourcePrefix)))
			if pat != "" {
				patterns = append(patterns, pat)
			}
		}
		if len(patterns) == 0 {
			continue
		}
		rule := commandRule{
			policyName: policies[i].Name,
			subjects:   make(map[string]struct{}, len(def.Subjects)),
			patterns:   patterns,
		}
		for _, s := range def.Subjects {
			if s == "*" {
				rule.allSubject = true
			}
			rule.subjects[s] = struct{}{}
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// globMatch reports whether pattern (with '*' wildcards matching any run of
// characters, including across path separators) matches s. Both are expected
// lower-cased by the caller. A pattern with no '*' must match the whole string
// exactly. This is a deliberately simple matcher: command policy uses
// substring-style globs ("*drop table*"), not full shell globbing.
func globMatch(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == s
	}
	// Anchor the first and last segments; the middle segments must appear in
	// order. An empty leading/trailing part means the pattern starts/ends with
	// '*' and is unanchored on that side.
	if parts[0] != "" {
		if !strings.HasPrefix(s, parts[0]) {
			return false
		}
		s = s[len(parts[0]):]
	}
	last := parts[len(parts)-1]
	if last != "" {
		if !strings.HasSuffix(s, last) {
			return false
		}
		s = s[:len(s)-len(last)]
	}
	for _, mid := range parts[1 : len(parts)-1] {
		if mid == "" {
			continue
		}
		idx := strings.Index(s, mid)
		if idx < 0 {
			return false
		}
		s = s[idx+len(mid):]
	}
	return true
}
