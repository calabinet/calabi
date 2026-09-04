package mesh

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// Service self-check (F3b).
//
// The confusion this exists to end: a rule names a service, an admin confirms
// it, and it still does not work. The usual cause is an application bound to
// 127.0.0.1 only. Opening the port in the packet filter changes nothing then,
// because a peer's packet arrives on the tun interface addressed to this node's
// OVERLAY address and finds no socket there — the app is listening somewhere
// else entirely, on an address peers can't name.
//
// Nothing outside this machine can tell that apart from "the app is down", so
// the node dials BOTH:
//
//	target  — where this machine reaches the app (127.0.0.1:<port> by default)
//	overlay — <own overlay>:<port>, the way a peer would
//
//	target ok, overlay ok      → fine
//	target ok, overlay NOT ok  → bound to loopback (or a local firewall)
//	neither ok                 → the app isn't running
//
// This is OBSERVATION, not discovery: every address dialed comes from a service
// the operator declared. rejected scanning a node's listening ports, and
// this doesn't — it checks the ones already written down, which is the same
// thing the tunnel upstream prober has always done (internal/probe/health.go).
//
// TCP only. A udp "dial" is connectionless and succeeds against a port nothing
// is listening on, so reporting its result would be worse than reporting
// nothing — hence Checked, and hence the coordinator dropping unchecked entries
// rather than storing them as failures.

// serviceHealthInterval is how often the node re-checks and re-reports. The
// coordinator keeps only the current value in memory, so this is also how long
// a restarted coordinator shows nothing for this node.
const serviceHealthInterval = time.Minute

// serviceDialTimeout bounds one probe. Short: both addresses are local or on
// this machine's own overlay, so anything slow is already a failure.
const serviceDialTimeout = 2 * time.Second

// overlayWaitPoll is how often the loop looks for its overlay address before its
// first check. Short: it is waiting on the first netmap, not on a timer.
const overlayWaitPoll = 250 * time.Millisecond

// ServiceHealthReport is one service as this node sees it.
type ServiceHealthReport struct {
	Name     string
	TargetOK bool
	MeshOK   bool
	// Checked is false when the node could not test at all (udp, or no overlay
	// address yet). The booleans above are then meaningless.
	Checked bool
}

// setOverlay records this node's own overlay address from the netmap, so the
// self-check can dial the address peers use.
func (c *Controller) setOverlay(a netip.Addr) {
	c.selfMu.Lock()
	c.overlay = a
	c.selfMu.Unlock()
}

func (c *Controller) getOverlay() netip.Addr {
	c.selfMu.Lock()
	defer c.selfMu.Unlock()
	return c.overlay
}

// setSelfServices records the coordinator's registry of THIS node's services,
// which arrives on the netmap. See resolveServices for what it is for.
func (c *Controller) setSelfServices(in []DeclaredService) {
	c.selfMu.Lock()
	c.selfServices = in
	c.selfMu.Unlock()
}

func (c *Controller) getSelfServices() []DeclaredService {
	c.selfMu.Lock()
	defer c.selfMu.Unlock()
	return c.selfServices
}

// resolveServices is everything this node should self-check: what its own config
// declares, plus what the coordinator says is registered on it.
//
// The second half is the whole reason this exists. A manager can enter a service
// in the console (F4a) and the machine never hears about it any other way — so
// before the netmap carried them, a console-authored service showed "not
// observed" forever. That is the kind most in need of a check: nobody was
// standing at the machine when its address was typed in.
//
// The local entry wins on a name collision. In practice there is none — a name
// is unique per node across both sources — but if the two ever disagreed, the
// machine's own config is what its operator set, and this check is about what
// this machine sees.
func (c *Controller) resolveServices() []DeclaredService {
	out, _ := c.resolveServicesWithSource()
	return out
}

// resolveServicesWithSource is resolveServices plus, for each entry, whether it
// came from the coordinator rather than this machine's config.
func (c *Controller) resolveServicesWithSource() ([]DeclaredService, []bool) {
	local := c.Params.Services
	extra := c.getSelfServices()
	out := append([]DeclaredService(nil), local...)
	src := make([]bool, len(out))
	seen := make(map[string]bool, len(out))
	for _, s := range out {
		seen[s.Name] = true
	}
	for _, s := range extra {
		if seen[s.Name] {
			continue
		}
		out = append(out, s)
		src = append(src, true)
	}
	return out, src
}

// waitForOverlay blocks until this node's overlay address arrives on a netmap,
// or ctx ends. Reports whether it arrived.
//
// Polls a mutex-guarded field rather than adding a channel to the Controller:
// it runs once per session and the address normally lands within a second of
// the stream opening.
func (c *Controller) waitForOverlay(ctx context.Context) bool {
	if c.getOverlay().IsValid() {
		return true
	}
	t := time.NewTicker(overlayWaitPoll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-t.C:
			if c.getOverlay().IsValid() {
				return true
			}
		}
	}
}

// checkServices probes every declared service once. Pure-ish: it dials, it does
// not report.
func (c *Controller) checkServices(ctx context.Context) []ServiceHealthReport {
	return c.checkServicesOf(ctx, c.resolveServices())
}

// checkServicesOf probes a specific set. Split out so the loop can hold on to
// the set it checked: the machine's own :7400 console shows what each service IS
// next to what the check found, and re-resolving would let the two drift.
func (c *Controller) checkServicesOf(ctx context.Context, services []DeclaredService) []ServiceHealthReport {
	overlay := c.getOverlay()
	out := make([]ServiceHealthReport, 0, len(services))
	for _, s := range services {
		r := ServiceHealthReport{Name: s.Name}
		if s.Proto == "udp" || !overlay.IsValid() {
			out = append(out, r) // Checked stays false
			continue
		}
		r.Checked = true
		r.TargetOK = dialOK(ctx, serviceTargetAddr(s))
		r.MeshOK = dialOK(ctx, net.JoinHostPort(overlay.String(), strconv.Itoa(s.Port)))
		out = append(out, r)
	}
	return out
}

// serviceTargetAddr is where THIS machine reaches the app: the declared target,
// or loopback on the service's own port.
func serviceTargetAddr(s DeclaredService) string {
	if s.Target != "" {
		return s.Target
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(s.Port))
}

func dialOK(ctx context.Context, addr string) bool {
	d := net.Dialer{Timeout: serviceDialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// serviceHealthLoop checks and reports until ctx is done. Best-effort
// throughout: a failed report costs one interval's freshness, and the console
// shows "not observed" rather than a wrong verdict.
func (c *Controller) serviceHealthLoop(ctx context.Context, nodeID int64) {
	// Wait for the overlay address before the first check, rather than burning a
	// cycle on it. The netmap that carries it is delivered by the caller AFTER
	// this goroutine starts, so an immediate check finds nothing checkable — and
	// a report with no checked entries REPLACES whatever the coordinator held
	// for this node. Every reconnect used to blank the column for a full
	// interval because of that race.
	//
	// It also can't return early on "no services declared" any more: the set is
	// no longer known until the netmap arrives, since a manager may have
	// registered one in the console.
	if !c.waitForOverlay(ctx) {
		return
	}
	t := time.NewTicker(serviceHealthInterval)
	defer t.Stop()
	sent := 0
	for {
		services, fromNetmap := c.resolveServicesWithSource()
		reports := c.checkServicesOf(ctx, services)
		c.setObservations(services, fromNetmap, reports)
		checked := 0
		for _, r := range reports {
			if r.Checked {
				checked++
			}
		}
		// Nothing observable and nothing outstanding: skip the call entirely,
		// so a node with no services (or only udp ones, which prove nothing)
		// doesn't spend an RPC a minute saying so. The ONE report after the last
		// observable service disappears still goes out — that is what clears the
		// coordinator's stale entries.
		if checked > 0 || sent > 0 {
			if err := c.Coord.ReportServiceHealth(ctx, nodeID, reports); err != nil {
				if c.Logger != nil {
					c.Logger.Debug("mesh: service health report failed", "err", err)
				}
			} else {
				sent = checked // only a delivered report changes what is outstanding
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// ServiceObservation is one service as this machine currently sees it: what the
// service IS, and what the last self-check found. Served to the machine's OWN
// :7400 console — the operator standing at the machine is the one who can act on
// "bound to loopback", and making them open the web console to learn it is
// backwards.
type ServiceObservation struct {
	Service DeclaredService
	Health  ServiceHealthReport
	// FromNetmap marks one the COORDINATOR reported (a manager registered it in
	// the web console) rather than one this machine's own config declares.
	//
	// Recorded rather than inferred. The local console works out which rows it
	// may edit by subtracting its declarations from this list, and "not declared
	// locally" is only the same thing as "came from the console" while the two
	// lists are in step — the moment a local service is removed it stops being
	// declared, and the leftover observation would come back labelled as
	// somebody else's.
	FromNetmap bool
}

// setObservations records the last check. Current value only, same posture as
// the coordinator's tracker: a history of which port answered when is the kind
// of record says not to accumulate, and it is no more welcome on the machine
// than in the control plane.
func (c *Controller) setObservations(services []DeclaredService, fromNetmap []bool, reports []ServiceHealthReport) {
	byName := make(map[string]ServiceHealthReport, len(reports))
	for _, r := range reports {
		byName[r.Name] = r
	}
	out := make([]ServiceObservation, 0, len(services))
	for i, s := range services {
		o := ServiceObservation{Service: s, Health: byName[s.Name]}
		if i < len(fromNetmap) {
			o.FromNetmap = fromNetmap[i]
		}
		out = append(out, o)
	}
	c.healthMu.Lock()
	c.observations = out
	c.healthMu.Unlock()
}

// ServiceObservations is the last self-check, for the local status API. Empty
// until the first check completes — which is NOT "nothing is offered", the same
// distinction Checked draws inside one entry.
func (c *Controller) ServiceObservations() []ServiceObservation {
	c.healthMu.Lock()
	defer c.healthMu.Unlock()
	return append([]ServiceObservation(nil), c.observations...)
}

// healthGuard is embedded in Controller, declared here with its only users.
type healthGuard struct {
	healthMu     sync.Mutex
	observations []ServiceObservation
}

// netmapSelf is what the last netmap said about THIS node. Embedded in
// Controller, declared here so the fields and their only users live together.
type netmapSelf struct {
	selfMu       sync.Mutex
	overlay      netip.Addr
	selfServices []DeclaredService
}
