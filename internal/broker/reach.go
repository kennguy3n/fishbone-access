package broker

import (
	"net"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

// reachableSet is an agent's union of reachable destinations, evaluated to
// decide whether the agent can serve a DialThroughAgent for a given address.
// It is built from the agent's self-reported specs and the operator-created
// bindings; matching is deliberately conservative (fail closed) so the relay
// never routes a dial to an agent that has not advertised a path to it.
type reachableSet struct {
	cidrs     []*net.IPNet
	hosts     []hostPort // exact host (optionally host:port)
	hostnames []string   // hostname or "*.suffix"
}

type hostPort struct {
	host string
	port string // empty = any port
}

func newReachableSet(specs []ReachableSpec) reachableSet {
	var rs reachableSet
	for _, s := range specs {
		rs.add(s.Pattern, s.Kind)
	}
	return rs
}

func (rs *reachableSet) add(pattern, kind string) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return
	}
	if kind == "" {
		kind = ClassifyPattern(pattern)
	}
	switch kind {
	case models.AgentReachKindCIDR:
		if _, ipnet, err := net.ParseCIDR(pattern); err == nil {
			rs.cidrs = append(rs.cidrs, ipnet)
		}
	case models.AgentReachKindHostname:
		rs.hostnames = append(rs.hostnames, strings.ToLower(pattern))
	default: // host
		h, p := splitHostPort(pattern)
		rs.hosts = append(rs.hosts, hostPort{host: strings.ToLower(h), port: p})
	}
}

// allows reports whether addr (host:port, or a bare host) is covered by the
// set. An IP literal is checked against CIDRs and host entries; a hostname is
// checked against host and hostname entries (including "*.suffix" wildcards).
func (rs *reachableSet) allows(addr string) bool {
	host, port := splitHostPort(addr)
	host = strings.ToLower(host)
	if host == "" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		for _, c := range rs.cidrs {
			if c.Contains(ip) {
				return true
			}
		}
	}
	for _, h := range rs.hosts {
		if h.host == host && (h.port == "" || h.port == port) {
			return true
		}
	}
	for _, pattern := range rs.hostnames {
		if matchHostname(pattern, host) {
			return true
		}
	}
	return false
}

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

func matchHostname(pattern, host string) bool {
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		return strings.HasSuffix(host, suffix) && len(host) > len(suffix)
	}
	return pattern == host
}

// splitHostPort tolerates a bare host (no port) and IPv6 literals, returning the
// host and the port (empty when absent).
func splitHostPort(addr string) (host, port string) {
	if h, p, err := net.SplitHostPort(addr); err == nil {
		return h, p
	}
	return strings.Trim(addr, "[]"), ""
}
