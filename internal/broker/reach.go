package broker

import (
	"net"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

// ClassifyPattern infers the binding kind for a free-form reachable pattern so
// callers (the bind API, the agent config) need not specify it explicitly:
// a parseable CIDR is "cidr", a "*."-prefixed or non-IP dotted name is
// "hostname", and anything else (an IP or host[:port]) is "host".
func ClassifyPattern(pattern string) string {
	pattern = strings.TrimSpace(pattern)
	if _, _, err := net.ParseCIDR(pattern); err == nil {
		return models.AgentReachKindCIDR
	}
	if strings.HasPrefix(pattern, "*.") {
		return models.AgentReachKindHostname
	}
	host, _ := splitHostPort(pattern)
	if net.ParseIP(host) != nil {
		return models.AgentReachKindHost
	}
	if strings.Contains(host, ".") {
		return models.AgentReachKindHostname
	}
	return models.AgentReachKindHost
}

// splitHostPort tolerates a bare host (no port) and IPv6 literals, returning the
// host and the port (empty when absent).
func splitHostPort(addr string) (host, port string) {
	if h, p, err := net.SplitHostPort(addr); err == nil {
		return h, p
	}
	return strings.Trim(addr, "[]"), ""
}
