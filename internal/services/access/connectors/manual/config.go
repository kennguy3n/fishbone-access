package manual

import (
	"fmt"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// Config is the optional, free-form descriptor of a manual target. Every field
// is optional: a manual connector is valid with no configuration at all. The
// fields exist so the catalogue and evidence record carry a human-readable
// description of what is being governed.
type Config struct {
	// SystemName is the operator-facing name of the governed system
	// (e.g. "Datacentre badge access", "Legacy AS/400 payroll").
	SystemName string `json:"system_name"`
	// ResourceKind is an optional classification of what is granted
	// (e.g. "physical", "application-role", "shared-account").
	ResourceKind string `json:"resource_kind"`
	// FulfilmentContact is an optional pointer to who performs the
	// out-of-band change (a team name or queue), recorded for the audit trail.
	FulfilmentContact string `json:"fulfilment_contact"`
}

// decodeConfig converts the untyped config map into a Config, rejecting any
// supplied field whose type is not a string. Pure-local; never touches the
// network.
func decodeConfig(raw map[string]interface{}) (Config, error) {
	var c Config
	for key, dst := range map[string]*string{
		"system_name":        &c.SystemName,
		"resource_kind":      &c.ResourceKind,
		"fulfilment_contact": &c.FulfilmentContact,
	} {
		v, ok := raw[key]
		if !ok || v == nil {
			continue
		}
		s, ok := v.(string)
		if !ok {
			return Config{}, fmt.Errorf("%w: manual: %s must be a string", access.ErrValidation, key)
		}
		*dst = s
	}
	return c, nil
}
