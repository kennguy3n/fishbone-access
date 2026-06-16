package discovery

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// AgentSweepRequest parameterises an operator-initiated network sweep. Either
// Hosts or CIDRs (or both) must be supplied; the engine expands them to a
// bounded host list and probes the well-known privileged-service ports through
// the named agent. Ports, when empty, defaults to defaultProbePorts.
type AgentSweepRequest struct {
	AgentID uuid.UUID
	Hosts   []string
	CIDRs   []string
	Ports   []int
	Actor   string
	Trigger string
}

// SweepResult summarises a completed agent sweep.
type SweepResult struct {
	ScanID      uuid.UUID `json:"scan_id"`
	Probed      int       `json:"probed"`
	Reachable   int       `json:"reachable"`
	AssetsFound int       `json:"assets_found"`
	AssetsNew   int       `json:"assets_new"`
}

// AgentSweep runs an operator-initiated reachability sweep: it expands the
// requested hosts/CIDRs, probes each (host, port) THROUGH the bound agent with
// strict per-probe timeouts and bounded concurrency, and reconciles every open
// port into a DiscoveredAsset. It is never an unbounded internet scan — only the
// operator-specified hosts are probed, only through an agent in the workspace,
// and the total fan-out is capped by Config.MaxProbeTargets.
func (e *Engine) AgentSweep(ctx context.Context, workspaceID uuid.UUID, req AgentSweepRequest) (SweepResult, error) {
	if workspaceID == uuid.Nil {
		return SweepResult{}, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	if req.AgentID == uuid.Nil {
		return SweepResult{}, fmt.Errorf("%w: agent_id is required — discovery only sweeps through an agent", ErrValidation)
	}
	if e.dialer == nil {
		return SweepResult{}, fmt.Errorf("%w: agent dial seam not configured", ErrUnsupported)
	}
	hosts, err := expandHosts(req.Hosts, req.CIDRs)
	if err != nil {
		return SweepResult{}, err
	}
	if len(hosts) == 0 {
		return SweepResult{}, fmt.Errorf("%w: no hosts or cidrs to sweep", ErrValidation)
	}
	ports := req.Ports
	if len(ports) == 0 {
		for _, p := range defaultProbePorts {
			ports = append(ports, p.Port)
		}
	}
	if len(hosts)*len(ports) > e.cfg.MaxProbeTargets {
		return SweepResult{}, fmt.Errorf("%w: sweep fan-out %d exceeds cap %d; narrow the host/cidr list",
			ErrValidation, len(hosts)*len(ports), e.cfg.MaxProbeTargets)
	}

	trigger := req.Trigger
	if trigger == "" {
		trigger = models.DiscoveryTriggerManual
	}
	scan, err := e.startScan(ctx, workspaceID, models.DiscoverySourceAgentSweep, trigger, req.Actor, map[string]any{
		"agent_id": req.AgentID.String(),
		"hosts":    req.Hosts,
		"cidrs":    req.CIDRs,
		"ports":    ports,
	})
	if err != nil {
		return SweepResult{}, err
	}

	result := SweepResult{ScanID: scan.ID}
	specs, probed, reachable := e.probeHosts(ctx, workspaceID, req.AgentID, hosts, ports)
	result.Probed = probed
	result.Reachable = reachable

	found, fresh, recErr := e.reconcileAssets(ctx, workspaceID, models.DiscoverySourceAgentSweep, specs, &req.AgentID, nil)
	result.AssetsFound = found
	result.AssetsNew = fresh
	scan.AssetsFound = found
	scan.AssetsNew = fresh
	e.finishScan(ctx, scan, recErr)
	if recErr != nil {
		return result, recErr
	}
	if err := e.appendAudit(ctx, workspaceID, req.Actor, "discovery.agent_sweep", req.AgentID.String(), map[string]any{
		"reachable":  reachable,
		"assets_new": fresh,
		"scan_id":    scan.ID.String(),
	}); err != nil {
		return result, err
	}
	return result, nil
}

// probeHosts probes every (host, port) pair through the agent with bounded
// concurrency, returning the reachable ones as asset specs plus probe counts.
func (e *Engine) probeHosts(ctx context.Context, workspaceID, agentID uuid.UUID, hosts []string, ports []int) (specs []access.DiscoveredAssetSpec, probed, reachable int) {
	type job struct {
		host string
		port int
	}
	jobs := make(chan job)
	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	workers := e.cfg.ProbeConcurrency
	if workers < 1 {
		workers = 1
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				mu.Lock()
				probed++
				mu.Unlock()
				if ctx.Err() != nil {
					continue
				}
				if e.probeOne(ctx, workspaceID, agentID, j.host, j.port) {
					addr := net.JoinHostPort(j.host, strconv.Itoa(j.port))
					protocol := protocolForPort(j.port)
					mu.Lock()
					reachable++
					specs = append(specs, access.DiscoveredAssetSpec{
						ExternalID: "host:" + addr,
						Kind:       access.AssetKindHost,
						Name:       j.host,
						Protocol:   protocol,
						Address:    addr,
						Metadata: map[string]string{
							"port":     strconv.Itoa(j.port),
							"via_port": protocol,
						},
					})
					mu.Unlock()
				}
			}
		}()
	}
	for _, h := range hosts {
		for _, p := range ports {
			select {
			case <-ctx.Done():
				goto drain
			case jobs <- job{host: h, port: p}:
			}
		}
	}
drain:
	close(jobs)
	wg.Wait()
	// Deterministic order for stable scan output and tests.
	sort.Slice(specs, func(i, j int) bool { return specs[i].ExternalID < specs[j].ExternalID })
	return specs, probed, reachable
}

// probeOne dials one host:port through the agent within ProbeTimeout and
// reports whether the port accepted a connection. The connection is closed
// immediately — discovery only checks reachability, never sends a payload.
func (e *Engine) probeOne(ctx context.Context, workspaceID, agentID uuid.UUID, host string, port int) bool {
	dialCtx, cancel := context.WithTimeout(ctx, e.cfg.ProbeTimeout)
	defer cancel()
	conn, err := e.dialer.DialThroughAgent(dialCtx, workspaceID, agentID, net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// expandHosts turns the request's hosts + CIDRs into a de-duplicated host list.
// A /24-or-smaller CIDR is fully enumerated (network and broadcast addresses
// dropped); a larger IPv4 CIDR or any IPv6 CIDR is refused so a sweep can never
// fan out to an unbounded address space.
func expandHosts(hosts, cidrs []string) ([]string, error) {
	seen := map[string]struct{}{}
	var out []string
	add := func(h string) {
		h = trimHost(h)
		if h == "" {
			return
		}
		if _, ok := seen[h]; ok {
			return
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}
	for _, h := range hosts {
		add(h)
	}
	for _, c := range cidrs {
		ip, ipnet, err := net.ParseCIDR(trimHost(c))
		if err != nil {
			return nil, fmt.Errorf("%w: invalid cidr %q", ErrValidation, c)
		}
		if ip.To4() == nil {
			return nil, fmt.Errorf("%w: IPv6 cidr %q is not supported for sweeps", ErrValidation, c)
		}
		ones, bits := ipnet.Mask.Size()
		if bits-ones > 8 {
			return nil, fmt.Errorf("%w: cidr %q is larger than /24; narrow it", ErrValidation, c)
		}
		for cur := cloneIP(ipnet.IP); ipnet.Contains(cur); incIP(cur) {
			// Skip network/broadcast for a true subnet.
			if isNetworkOrBroadcast(cur, ipnet) {
				continue
			}
			add(cur.String())
		}
	}
	return out, nil
}

func trimHost(h string) string {
	return strings.TrimSpace(h)
}

func cloneIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func isNetworkOrBroadcast(ip net.IP, ipnet *net.IPNet) bool {
	ones, bits := ipnet.Mask.Size()
	if bits-ones == 0 {
		return false // /32: the single host is usable
	}
	network := ip.Mask(ipnet.Mask)
	if ip.Equal(network) {
		return true
	}
	// Broadcast = network | ^mask.
	bcast := cloneIP(network.To4())
	for i := range bcast {
		bcast[i] |= ^ipnet.Mask[i]
	}
	return ip.Equal(bcast)
}
