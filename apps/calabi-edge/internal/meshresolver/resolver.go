// Package meshresolver maintains the two small caches an edge needs to relay
// a visitor connection to the same-region peer that owns a tunnel:
//
//   - owner cache: host → owning edge_node_id, polled from
//     tunnel-svc.ResolveOwners(base_domain). Because same-region edges share
//     a base_domain, one call returns the whole region's owner registry.
//   - address book: edge_node_id → VPC-internal forward addr, polled from
//     identity-svc.ListEdges(region), filtered to healthy, same-region,
//     internal_addr-bearing peers.
//
// ResolveOwner combines the two for the listener relay path. It is
// the concrete implementation of listener.OwnerResolver.
//
// Design note (deviation from the original sketch): owner changes are
// low-frequency (only on tunnel create/delete or failover), so we poll on a
// short interval rather than subscribe to NATS owner events. Polling works
// identically in cluster mode and (future) bff-edge mode without extending
// the NATS→gRPC bridge. A dial failure additionally kicks an immediate
// refresh so a moved/dead owner is re-discovered within one round trip rather
// than waiting for the next tick.
package meshresolver

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// Owner is one host→owning-edge mapping (from tunnel-svc.ResolveOwners).
type Owner struct {
	Domain     string
	EdgeNodeID int64
}

// Edge is one same-region directory entry (from identity-svc.ListEdges).
type Edge struct {
	EdgeNodeID   int64
	Region       string
	InternalAddr string
	Healthy      bool
}

// OwnerSource fetches the host→owner map for a base domain. Implemented by
// the tunnelstore client adapter in main.
//
// Conditional poll: knownGen is the generation token from the previous
// successful call (empty on the first). When the source reports unchanged=true
// the owner set is identical to that generation — owners is nil and the
// caller keeps its cache. gen is the source's current generation, echoed back
// as knownGen on the next call.
type OwnerSource interface {
	ResolveOwners(ctx context.Context, baseDomain, knownGen string) (owners []Owner, gen string, unchanged bool, err error)
}

// EdgeDirectory fetches the region's edge directory. Implemented by the
// identity client adapter in main.
type EdgeDirectory interface {
	ListEdges(ctx context.Context, region string) ([]Edge, error)
}

// Config parameterizes a Resolver.
type Config struct {
	SelfEdgeID int64         // this edge's numeric id; owners equal to it are local misses
	Region     string        // region scope for the address book
	BaseDomain string        // shared regional base domain for the owner cache
	Interval   time.Duration // poll cadence; <=0 defaults to 3s, clamped to >=1s
	Owners     OwnerSource
	Dir        EdgeDirectory
	Logger     *slog.Logger
}

// Resolver holds the two caches and serves ResolveOwner lookups.
type Resolver struct {
	cfg      Config
	interval time.Duration
	logger   *slog.Logger

	mu          sync.RWMutex
	ownerByHost map[string]int64 // lowercased host (no port) → owner edge id
	addrByEdge  map[int64]string // edge id → internal_addr (healthy, same-region)

	// lastOwnerGen is the generation token of the owner snapshot currently
	// applied to ownerByHost, fed back as known_generation on the next poll
	// for the ETag-style conditional fetch. Touched only from the Run
	// goroutine (refresh is never called concurrently), so it needs no lock.
	lastOwnerGen string

	kick chan struct{} // buffered(1); RefreshSoon triggers an off-cycle refresh
	// onceUnsupported makes the "owner source unsupported" warning fire once.
	loggedOwnerUnsupported bool
	loggedDirUnsupported   bool
}

const (
	defaultInterval = 3 * time.Second
	minInterval     = 1 * time.Second
	refreshTimeout  = 5 * time.Second
)

// New builds a Resolver with empty caches. Call Run to start polling.
func New(cfg Config) *Resolver {
	iv := cfg.Interval
	if iv <= 0 {
		iv = defaultInterval
	}
	if iv < minInterval {
		iv = minInterval
	}
	lg := cfg.Logger
	if lg == nil {
		lg = slog.Default()
	}
	return &Resolver{
		cfg:         cfg,
		interval:    iv,
		logger:      lg.With("component", "mesh-resolver"),
		ownerByHost: map[string]int64{},
		addrByEdge:  map[int64]string{},
		kick:        make(chan struct{}, 1),
	}
}

// ResolveOwner implements listener.OwnerResolver. Returns ok=false (caller
// falls back to a local miss) when there is no known owner, the owner is THIS
// edge, or the owner has no reachable internal_addr in the address book.
func (r *Resolver) ResolveOwner(host string) (string, int64, bool) {
	h := normalizeHost(host)
	if h == "" {
		return "", 0, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	ownerID, ok := r.ownerByHost[h]
	if !ok || ownerID == 0 || ownerID == r.cfg.SelfEdgeID {
		return "", 0, false
	}
	addr, ok := r.addrByEdge[ownerID]
	if !ok || addr == "" {
		return "", 0, false
	}
	return addr, ownerID, true
}

// RefreshSoon requests an off-cycle refresh (non-blocking). The listener
// relay calls this after a failed dial so a moved/dead owner is re-resolved
// without waiting for the next tick. Implements the listener's optional
// refresher capability.
func (r *Resolver) RefreshSoon() {
	select {
	case r.kick <- struct{}{}:
	default: // a refresh is already queued
	}
}

// Run blocks until ctx is done, refreshing both caches immediately and then
// every interval (or whenever RefreshSoon kicks).
func (r *Resolver) Run(ctx context.Context) error {
	r.logger.Info("mesh resolver started",
		"region", r.cfg.Region, "base_domain", r.cfg.BaseDomain,
		"self_edge", r.cfg.SelfEdgeID, "interval", r.interval)
	r.refresh(ctx)
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			r.refresh(ctx)
		case <-r.kick:
			r.refresh(ctx)
		}
	}
}

func (r *Resolver) refresh(ctx context.Context) {
	cctx, cancel := context.WithTimeout(ctx, refreshTimeout)
	defer cancel()
	r.refreshOwners(cctx)
	r.refreshDir(cctx)
}

func (r *Resolver) refreshOwners(ctx context.Context) {
	if r.cfg.Owners == nil {
		return
	}
	owners, gen, unchanged, err := r.cfg.Owners.ResolveOwners(ctx, r.cfg.BaseDomain, r.lastOwnerGen)
	if err != nil {
		// Keep the stale cache on error so a transient blip doesn't blank
		// out all forwarding. Warn once for the "unsupported transport"
		// case (bff-edge mode), debug for transient failures.
		if isUnsupported(err) {
			if !r.loggedOwnerUnsupported {
				r.loggedOwnerUnsupported = true
				r.logger.Warn("owner source unsupported on this transport; peer forwarding disabled", "err", err)
			}
		} else {
			r.logger.Debug("refresh owners failed; keeping stale cache", "err", err)
		}
		return
	}
	if unchanged {
		// Server's generation matches what we already hold — the common case
		// at steady state and the whole point of the conditional poll: no
		// item list crossed the wire. Keep the cache untouched.
		if gen != "" {
			r.lastOwnerGen = gen
		}
		return
	}
	m := make(map[string]int64, len(owners))
	for _, o := range owners {
		h := normalizeHost(o.Domain)
		if h != "" && o.EdgeNodeID != 0 {
			m[h] = o.EdgeNodeID
		}
	}
	r.mu.Lock()
	r.ownerByHost = m
	r.mu.Unlock()
	r.lastOwnerGen = gen
}

func (r *Resolver) refreshDir(ctx context.Context) {
	if r.cfg.Dir == nil {
		return
	}
	edges, err := r.cfg.Dir.ListEdges(ctx, r.cfg.Region)
	if err != nil {
		if isUnsupported(err) {
			if !r.loggedDirUnsupported {
				r.loggedDirUnsupported = true
				r.logger.Warn("edge directory unsupported on this transport; peer forwarding disabled", "err", err)
			}
		} else {
			r.logger.Debug("refresh directory failed; keeping stale cache", "err", err)
		}
		return
	}
	m := make(map[int64]string)
	for _, e := range edges {
		if e.EdgeNodeID == 0 || e.EdgeNodeID == r.cfg.SelfEdgeID {
			continue // skip self — we never forward to ourselves
		}
		if !e.Healthy || e.InternalAddr == "" {
			continue // dead peer or not mesh-capable
		}
		// Region guard: ListEdges(region) already filters, but if a caller
		// passed an empty region we still refuse cross-region peers.
		if r.cfg.Region != "" && e.Region != "" && !strings.EqualFold(e.Region, r.cfg.Region) {
			continue
		}
		m[e.EdgeNodeID] = e.InternalAddr
	}
	r.mu.Lock()
	r.addrByEdge = m
	r.mu.Unlock()
}

// Stats returns current cache sizes (for /metrics or debug logging).
func (r *Resolver) Stats() (owners, peers int) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.ownerByHost), len(r.addrByEdge)
}

// normalizeHost lowercases and strips any :port suffix so cache keys match
// however the listener passed the host (HTTP Host may carry a port; SNI does
// not). Mirrors router.LookupHTTP's normalization.
func normalizeHost(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	if i := strings.LastIndex(h, ":"); i > 0 {
		// Only strip when what follows looks like a port (all digits) so we
		// don't truncate IPv6 literals. Hosts here are domains, but be safe.
		if isAllDigits(h[i+1:]) {
			h = h[:i]
		}
	}
	return h
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// isUnsupported reports whether err is one of the "transport doesn't proxy
// this RPC" sentinels. We compare on the message suffix to avoid importing
// the tunnelstore / identity packages here (which would invert the
// dependency — those packages provide the adapters that call us).
func isUnsupported(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "not supported by this transport")
}
