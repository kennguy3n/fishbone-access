package discovery

import (
	"encoding/json"

	"gorm.io/datatypes"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// probePort pairs a TCP port with the PAM protocol it implies, used by the
// agent network sweep. Only well-known privileged-service ports are probed —
// discovery is a targeted reachability check, not a full port scan.
type probePort struct {
	Port     int
	Protocol string
}

// defaultProbePorts is the fixed set the agent sweep probes per host: the
// common privileged-service ports an SME environment exposes. Kept small and
// well-known on purpose (bounded fan-out, no speculative scanning).
var defaultProbePorts = []probePort{
	{22, "ssh"},
	{3389, "rdp"},
	{5432, "postgres"},
	{3306, "mysql"},
	{1433, "mssql"},
	{27017, "mongodb"},
	{6379, "redis"},
}

// protocolForPort returns the inferred protocol for a well-known port, or "" if
// the port is not one discovery probes.
func protocolForPort(port int) string {
	for _, p := range defaultProbePorts {
		if p.Port == port {
			return p.Protocol
		}
	}
	return ""
}

// defaultProtocolForKind picks a sensible PAM protocol when a connector could
// not infer one, so an onboard form is never left blank.
func defaultProtocolForKind(kind string) string {
	switch kind {
	case access.AssetKindDatabase:
		return "postgres"
	default:
		return "ssh"
	}
}

// mustAuditMeta marshals an audit metadata map to datatypes.JSON. A marshal
// failure (impossible for these flat string/number maps) degrades to nil rather
// than failing the surrounding mutation.
func mustAuditMeta(m map[string]any) datatypes.JSON {
	if len(m) == 0 {
		return nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil
	}
	return datatypes.JSON(b)
}

// jsonMap marshals a string map to datatypes.JSON for an asset/account's
// metadata column.
func jsonMap(m map[string]string) datatypes.JSON {
	if len(m) == 0 {
		return nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil
	}
	return datatypes.JSON(b)
}

// kindForProtocol infers an asset kind from a PAM protocol so the onboard form
// can fall back sensibly when a discovered asset has no inferred protocol.
func kindForProtocol(protocol string) string {
	switch protocol {
	case models.PAMProtocolPostgres, models.PAMProtocolMySQL, "mssql", "mongodb", "redis":
		return access.AssetKindDatabase
	default:
		return access.AssetKindHost
	}
}
