package compliance

// EvidenceKind is the control-relevant classification of an audit-chain event.
// It is derived purely from the audit Action string (see classify), so the
// evidence stream never stores its own copy of an event — it re-labels the
// chain.
type EvidenceKind string

const (
	KindAccessRequested      EvidenceKind = "access_requested"
	KindAccessGranted        EvidenceKind = "access_granted"
	KindAccessRevoked        EvidenceKind = "access_revoked"
	KindAccessExpired        EvidenceKind = "access_expired"
	KindPolicyCreated        EvidenceKind = "policy_created"
	KindPolicyPromoted       EvidenceKind = "policy_promoted"
	KindPolicyArchived       EvidenceKind = "policy_archived"
	KindReviewStarted        EvidenceKind = "review_started"
	KindReviewDecision       EvidenceKind = "review_decision"
	KindReviewCompleted      EvidenceKind = "review_completed"
	KindCertificationStarted EvidenceKind = "certification_started"
	KindCertificationDecided EvidenceKind = "certification_decision"
	KindCertificationClosed  EvidenceKind = "certification_closed"
	KindCertificationOverdue EvidenceKind = "certification_overdue"
	KindJoinerProvisioned    EvidenceKind = "joiner_provisioned"
	KindMoverRecorded        EvidenceKind = "mover_recorded"
	KindKillSwitchFired      EvidenceKind = "kill_switch_fired"
	KindOrphanDetected       EvidenceKind = "orphan_detected"
	KindOrphanDisposition    EvidenceKind = "orphan_disposition"
	KindPrivilegedCommand    EvidenceKind = "privileged_command"
	// KindPrivilegedSession marks the lifecycle of a proxied privileged session
	// (opened / closed / admin-terminated). A monitored privileged session is
	// itself the primary evidence that privileged access is supervised, so the
	// session-level events count toward CC6.7 / A.8.2 alongside the per-command
	// rows — a session that ran but logged no command still demonstrates the
	// monitoring control fired.
	KindPrivilegedSession EvidenceKind = "privileged_session"
	// KindPrivilegedRecording marks the tamper-evident reference to a session's
	// recording (replay key + SHA-256), anchored in the chain at teardown. It is
	// the evidence that ties a monitored session to a replayable, integrity-
	// verifiable artifact, which is what an auditor needs to substantiate CC6.7 /
	// A.8.2 beyond a bare "a session happened" log line.
	KindPrivilegedRecording EvidenceKind = "privileged_recording"
	KindEvidenceExported    EvidenceKind = "evidence_exported"
	// KindOther is the catch-all for audit actions that are recorded for
	// integrity but carry no direct control mapping. They still appear in the
	// raw stream so the chain stays complete and verifiable.
	KindOther EvidenceKind = "other"
)

// Framework is a compliance framework the evidence pack can be mapped to. The
// names align with the #39 policy-pack catalog framework taxonomy so the two
// surfaces speak the same vocabulary.
type Framework string

const (
	FrameworkSOC2     Framework = "SOC 2"
	FrameworkISO27001 Framework = "ISO 27001"
	FrameworkPCIDSS   Framework = "PCI-DSS"
)

// Frameworks is the ordered set of frameworks an evidence pack can target.
func Frameworks() []Framework {
	return []Framework{FrameworkSOC2, FrameworkISO27001, FrameworkPCIDSS}
}

// ValidFramework reports whether name is a known framework (case-sensitive
// against the catalog names) and returns the canonical value.
func ValidFramework(name string) (Framework, bool) {
	for _, f := range Frameworks() {
		if string(f) == name {
			return f, true
		}
	}
	return "", false
}

// Control is one framework control point and the evidence kinds that satisfy
// it. Coverage is computed by counting stream records whose kind is in Kinds.
type Control struct {
	ID    string         `json:"id"`
	Title string         `json:"title"`
	Kinds []EvidenceKind `json:"-"`
}

// controlsByFramework maps each framework to its control points and the
// evidence kinds that demonstrate each control. The mappings are deliberately
// conservative — a control is only credited to evidence that genuinely shows it
// — and mirror the same control references the policy-pack templates cite.
var controlsByFramework = map[Framework][]Control{
	FrameworkSOC2: {
		{ID: "CC6.1", Title: "Logical access security — least-privilege policy enforced", Kinds: []EvidenceKind{KindPolicyPromoted, KindPolicyCreated, KindAccessGranted}},
		{ID: "CC6.2", Title: "Access provisioned on authorization", Kinds: []EvidenceKind{KindAccessRequested, KindAccessGranted, KindJoinerProvisioned}},
		{ID: "CC6.3", Title: "Access modified/removed when no longer required", Kinds: []EvidenceKind{KindAccessRevoked, KindAccessExpired, KindKillSwitchFired, KindMoverRecorded}},
		{ID: "CC6.7", Title: "Privileged access monitored", Kinds: []EvidenceKind{KindPrivilegedSession, KindPrivilegedCommand, KindPrivilegedRecording}},
		{ID: "CC7.2", Title: "Access reviewed/certified periodically", Kinds: []EvidenceKind{KindReviewStarted, KindReviewDecision, KindReviewCompleted, KindCertificationStarted, KindCertificationDecided, KindCertificationClosed}},
		{ID: "CC7.3", Title: "Orphan / anomalous access detected and dispositioned", Kinds: []EvidenceKind{KindOrphanDetected, KindOrphanDisposition}},
	},
	FrameworkISO27001: {
		{ID: "A.5.15", Title: "Access control policy", Kinds: []EvidenceKind{KindPolicyPromoted, KindPolicyCreated, KindPolicyArchived}},
		{ID: "A.5.16", Title: "Identity lifecycle management", Kinds: []EvidenceKind{KindJoinerProvisioned, KindMoverRecorded, KindKillSwitchFired}},
		{ID: "A.5.18", Title: "Access rights provisioned, reviewed and removed", Kinds: []EvidenceKind{KindAccessRequested, KindAccessGranted, KindAccessRevoked, KindAccessExpired, KindReviewDecision, KindReviewCompleted, KindCertificationDecided, KindCertificationClosed}},
		{ID: "A.8.2", Title: "Privileged access rights monitored", Kinds: []EvidenceKind{KindPrivilegedSession, KindPrivilegedCommand, KindPrivilegedRecording}},
		{ID: "A.8.15", Title: "Tamper-evident logging", Kinds: []EvidenceKind{KindEvidenceExported}},
	},
	FrameworkPCIDSS: {
		{ID: "7.2", Title: "Least-privilege access control system", Kinds: []EvidenceKind{KindPolicyPromoted, KindPolicyCreated, KindAccessGranted}},
		{ID: "7.2.4", Title: "Access reviewed at least every 6 months", Kinds: []EvidenceKind{KindReviewStarted, KindReviewCompleted, KindCertificationStarted, KindCertificationDecided, KindCertificationClosed}},
		{ID: "8.1.3", Title: "Access for terminated users revoked promptly", Kinds: []EvidenceKind{KindAccessRevoked, KindAccessExpired, KindKillSwitchFired}},
		{ID: "8.2", Title: "Access provisioned on authorization", Kinds: []EvidenceKind{KindAccessRequested, KindAccessGranted, KindJoinerProvisioned}},
		{ID: "10.2", Title: "Audit trail of access to system components", Kinds: []EvidenceKind{KindPrivilegedSession, KindPrivilegedCommand, KindPrivilegedRecording, KindEvidenceExported}},
	},
}

// Controls returns the control points defined for a framework, or nil for an
// unknown framework.
func Controls(f Framework) []Control {
	return controlsByFramework[f]
}

// classify maps an audit Action string to an EvidenceKind. It matches on the
// stable action prefixes the lifecycle/PAM/compliance services emit (see
// internal/services/*/*.go appendAudit call sites). Unknown actions classify as
// KindOther so the raw stream stays complete and chain-verifiable even as new
// action types are added.
func classify(action string) EvidenceKind {
	switch {
	case action == "access_request.created":
		return KindAccessRequested
	case action == "access_grant.created":
		return KindAccessGranted
	case action == "access_grant.revoked":
		return KindAccessRevoked
	case action == "access_grant.expired":
		return KindAccessExpired
	case action == "policy.created":
		return KindPolicyCreated
	case action == "policy.promoted" || action == "policy.promoted_with_override":
		return KindPolicyPromoted
	case action == "policy.archived":
		return KindPolicyArchived
	case action == "policy.draft_updated":
		return KindOther
	case action == "access_review.started":
		return KindReviewStarted
	case action == "access_review.completed":
		return KindReviewCompleted
	case hasPrefix(action, "access_review.decision."):
		return KindReviewDecision
	case action == "certification.campaign.started":
		return KindCertificationStarted
	case action == "certification.campaign.closed":
		return KindCertificationClosed
	case action == "certification.campaign.overdue":
		return KindCertificationOverdue
	case hasPrefix(action, "certification.item.decision."):
		return KindCertificationDecided
	case hasPrefix(action, "jml.joiner."):
		return KindJoinerProvisioned
	case hasPrefix(action, "jml.mover."):
		return KindMoverRecorded
	case hasPrefix(action, "jml.leaver."):
		return KindKillSwitchFired
	case action == "orphan.detected":
		return KindOrphanDetected
	case hasPrefix(action, "orphan.disposition."):
		return KindOrphanDisposition
	case action == "pam.command":
		return KindPrivilegedCommand
	case action == "pam.session.opened" || action == "pam.session.closed" || action == "pam.session.terminated" ||
		action == "pam.session.paused" || action == "pam.session.resumed":
		// The full privileged-session lifecycle, including operator-initiated
		// soft-pause/resume — an admin actively supervising a live session is
		// itself CC6.7 / A.8.2 monitoring evidence, so it must not fall to
		// KindOther and drop out of coverage.
		return KindPrivilegedSession
	case action == "pam.session.recording":
		return KindPrivilegedRecording
	case action == "compliance.export":
		return KindEvidenceExported
	default:
		return KindOther
	}
}

// controlledKinds is the set of kinds that map to at least one control in at
// least one framework — used by coverage so "control evidence" excludes the
// KindOther integrity-only rows.
var controlledKinds = func() map[EvidenceKind]struct{} {
	set := map[EvidenceKind]struct{}{}
	for _, controls := range controlsByFramework {
		for _, c := range controls {
			for _, k := range c.Kinds {
				set[k] = struct{}{}
			}
		}
	}
	return set
}()

// isControlled reports whether a kind maps to any framework control.
func isControlled(k EvidenceKind) bool {
	_, ok := controlledKinds[k]
	return ok
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
