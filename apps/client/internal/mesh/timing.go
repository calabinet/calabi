package mesh

import "time"

// Timing is how often a mesh session does its periodic work.
//
// Every loop here exists because, without it, some change would go unnoticed
// for too long: a roam nobody announced, a relay that got slower, a NAT binding
// about to expire. On a desktop each tick costs next to nothing. On a phone each
// one can wake the cellular radio, and a phone is also the one device whose
// platform DOES announce network changes (Controller.NetworkChanged), so several
// of these loops can be slowed or dropped there without losing what they
// guarded.
//
// A zero duration turns that loop off. The event-driven path it backs up keeps
// running regardless: a fresh netmap still probes peers, a changed home still
// reports endpoints, NetworkChanged still runs the full repair.
//
// The relay link's own liveness ping is not here: it is the datapath's, and its
// phone setting waits on measurements.
type Timing struct {
	// DiscoProbe re-pings every peer's candidate endpoints, to find direct paths
	// and to keep the ones found from going stale.
	DiscoProbe time.Duration
	// EndpointReport re-reports candidate endpoints so peers learn of a roam
	// this node was not told about.
	EndpointReport time.Duration
	// HomeProbe re-measures the relay regions and re-homes on the closest.
	HomeProbe time.Duration
	// ConnReport uploads who this node exchanged traffic with.
	ConnReport time.Duration
	// ServiceHealth re-checks the services this node declares.
	ServiceHealth time.Duration
	// WakeDetect watches the clock for a suspend the OS did not announce.
	WakeDetect bool
	// PersistentKeepalive is WireGuard's per-peer keepalive. It holds NAT
	// bindings open so a peer can START a connection to this node over a direct
	// path; the relay stays reachable without it.
	PersistentKeepalive time.Duration
}

// DesktopTiming is the timing a session runs with unless told otherwise.
func DesktopTiming() Timing {
	return Timing{
		DiscoProbe:          probeInterval,
		EndpointReport:      endpointReportInterval,
		HomeProbe:           homeProbeInterval,
		ConnReport:          connReportInterval,
		ServiceHealth:       serviceHealthInterval,
		WakeDetect:          true,
		PersistentKeepalive: meshKeepalive,
	}
}

// timing is the session's effective Timing: c.Timing, or DesktopTiming.
func (c *Controller) timing() Timing {
	if c.Timing != nil {
		return *c.Timing
	}
	return DesktopTiming()
}
