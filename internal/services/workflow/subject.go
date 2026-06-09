package workflow

import "strings"

// Subject is the identity a workflow run targets. For a live run it is the real
// joiner/mover/leaver; for a dry-run it is a sample identity the admin types
// into the "simulate for sample user" panel. Conditions are evaluated against
// these fields.
type Subject struct {
	ExternalID  string            `json:"external_id"`
	Email       string            `json:"email,omitempty"`
	DisplayName string            `json:"display_name,omitempty"`
	Department  string            `json:"department,omitempty"`
	Groups      []string          `json:"groups,omitempty"`
	Attributes  map[string]string `json:"attributes,omitempty"`
}

// attribute resolves a single-valued attribute by name. department and the
// common identity fields are first-class; anything else is looked up in the
// free-form Attributes map (case-insensitive on the key).
func (s Subject) attribute(name string) string {
	switch strings.ToLower(name) {
	case "department", "dept":
		return s.Department
	case "email":
		return s.Email
	case "display_name", "name":
		return s.DisplayName
	case "external_id", "user", "user_id":
		return s.ExternalID
	case "group", "groups":
		// A single-valued operator (eq/neq/in) against "groups" matches when the
		// subject has exactly one group; multi-valued matching uses multi().
		if len(s.Groups) == 1 {
			return s.Groups[0]
		}
		return ""
	default:
		return s.lookupAttr(name)
	}
}

// multi resolves a multi-valued attribute (used by contains/not_contains).
// "groups" is the canonical multi-valued attribute; a free-form attribute is
// treated as a single-element set.
func (s Subject) multi(name string) []string {
	switch strings.ToLower(name) {
	case "group", "groups":
		return s.Groups
	default:
		if v := s.lookupAttr(name); v != "" {
			return []string{v}
		}
		return nil
	}
}

func (s Subject) lookupAttr(name string) string {
	if s.Attributes == nil {
		return ""
	}
	if v, ok := s.Attributes[name]; ok {
		return v
	}
	// Case-insensitive fallback so a condition on "Department" matches an
	// attribute key stored as "department".
	for k, v := range s.Attributes {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}
