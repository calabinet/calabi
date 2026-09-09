package mesh

import (
	"context"
	"fmt"
	"github.com/calabi/calabi/apps/client/internal/mesh/derp"
)

// Probe drives one leg of the relay path — this node to a relay and back — on
// the link the pool already holds.
//
// addr names the relay; empty means this node's home relay. It does NOT dial:
// a probe that opened its own connection would either need a second identity
// the coordinator has not granted, or reuse this node's key and evict the very
// link it was measuring (the hub gives a key to the newest connection claiming
// it). Measuring the live link is also the more honest measurement, since that
// is the connection actually carrying the node's traffic.
func (p *relayPool) Probe(ctx context.Context, addr string, opts derp.ProbeOpts) (*derp.ProbeResult, string, error) {
	p.mu.Lock()
	if addr == "" {
		addr = p.home
	}
	c := p.clients[addr]
	p.mu.Unlock()

	if addr == "" {
		return nil, "", fmt.Errorf("this node has no home relay yet")
	}
	if c == nil {
		return nil, addr, fmt.Errorf("no live link to relay %s (it is dialed on demand; send traffic through it first, or name a relay this node is connected to)", addr)
	}
	res, err := c.Probe(ctx, opts)
	return res, addr, err
}

// Relays lists the relay addresses this pool currently holds links to, so a
// caller can say which legs are measurable rather than guessing at one.
func (p *relayPool) Relays() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, 0, len(p.clients))
	for addr := range p.clients {
		out = append(out, addr)
	}
	return out
}

// ProbeRelay exposes the pool's leg probe on the datapath, which is what the
// daemon holds. A datapath that is down has no pool and says so.
func (d *WGDatapath) ProbeRelay(ctx context.Context, addr string, opts derp.ProbeOpts) (*derp.ProbeResult, string, error) {
	if d == nil || d.relays == nil {
		return nil, "", fmt.Errorf("mesh datapath is not running")
	}
	return d.relays.Probe(ctx, addr, opts)
}
