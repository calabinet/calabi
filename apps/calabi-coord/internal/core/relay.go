package core

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Self-hosted relays (R2) — an org registering a calabi-derp it runs itself.
//
// Three constraints shape everything here, and none is negotiable:
//
//  1. An org's relay appears ONLY in that org's map. A relay never sees
//     plaintext, but it does see the metadata — who talks to whom, how much,
//     when. Putting org A's relay in org B's map hands A a picture of B's
//     traffic.
//  2. The platform's regions are always there too. Self-hosting adds a nearer
//     road, it does not replace the road; a user's VPS going down must not
//     leave a meshnet with nothing but direct paths.
//  3. Region codes are namespaced. The code is the key nodes report a home
//     under, the relay pool dials by, and the coordinator validates against —
//     so a user naming their relay "lax" must not collide with the platform's.
//
// Registration is DECLARATIVE: the user tells the console an address, and
// nothing about calabi-derp changes. It has no idea a coordinator exists and is
// not going to learn — that ignorance is the entire reason the same binary is
// safe to hand out. Which is also why there is no "verify the relay is up" step
// here: probing a user's VPS from the control plane is how a user's outage
// becomes the control plane's outage.

// SelfHostedRegionPrefix namespaces a self-hosted relay's region code.
const SelfHostedRegionPrefix = "self-"

// maxRelaysPerMeshnet caps registrations. Not a product limit — a guard against
// a runaway script, since each entry costs a region in every one of that org's
// netmaps.
const maxRelaysPerMeshnet = 16

// defaultRelaySTUNPort is what a registration without one gets. A region with no
// STUN endpoint cannot be latency-measured, and a region that cannot be measured
// is never chosen as anyone's home — i.e. a relay registered without it would
// quietly do nothing. Defaulting beats rejecting: 3478 is what the relay listens
// on unless the operator changed it.
const defaultRelaySTUNPort = 3478

// Relay is one calabi-derp an org runs itself.
type Relay struct {
	ID      int64     `json:"id"`
	Meshnet MeshnetID `json:"meshnet"`
	// Label is a DNS label chosen by the user; the region code is derived from
	// it, never stored separately, so the two can't drift.
	Label string `json:"label"`
	// HostName is the address MESH NODES dial — public, and reachable from
	// wherever this org's devices are.
	HostName string `json:"host_name"`
	DERPPort int    `json:"derp_port"`
	STUNPort int    `json:"stun_port"`
	// Enabled false keeps the row but drops the region from the map, so an
	// operator can park a relay for maintenance without losing its registration.
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}

// RegionCode is how this relay appears in a netmap.
func (r Relay) RegionCode() string { return SelfHostedRegionPrefix + r.Label }

var (
	// ErrInvalidRelay is returned for a registration that isn't usable.
	ErrInvalidRelay = errors.New("core: invalid relay")
	// ErrRelayExists is returned when the meshnet already has that label.
	ErrRelayExists = errors.New("core: a relay with this label already exists")
	// ErrRelayNotFound is returned for an unknown relay id.
	ErrRelayNotFound = errors.New("core: relay not found")
	// ErrTooManyRelays is returned at the per-meshnet cap.
	ErrTooManyRelays = errors.New("core: too many relays registered")
)

// RelayStore persists self-hosted relay registrations. Optional: a coordinator
// without one simply has no self-hosted relays.
type RelayStore interface {
	ListRelays(ctx context.Context, t MeshnetID) ([]Relay, error)
	CreateRelay(ctx context.Context, r Relay) (*Relay, error)
	// UpdateRelay rewrites the mutable fields (host / ports / enabled) by id.
	UpdateRelay(ctx context.Context, r Relay) error
	DeleteRelay(ctx context.Context, id int64) error
}

// ValidateRelay checks a registration. Expects a normalized label. Pure.
func ValidateRelay(label, host string, derpPort, stunPort int) error {
	if err := ValidateNodeName(label); err != nil {
		return fmt.Errorf("%w: label: %s", ErrInvalidRelay,
			strings.TrimPrefix(err.Error(), "core: invalid node name: "))
	}
	if strings.TrimSpace(host) == "" {
		return fmt.Errorf("%w: host is empty", ErrInvalidRelay)
	}
	if derpPort < 1 || derpPort > 65535 {
		return fmt.Errorf("%w: derp port %d out of range (1-65535)", ErrInvalidRelay, derpPort)
	}
	if stunPort < 0 || stunPort > 65535 {
		return fmt.Errorf("%w: stun port %d out of range (0-65535)", ErrInvalidRelay, stunPort)
	}
	return nil
}

// RelaysFor lists a meshnet's registered relays (empty when the build has no
// registry).
func (c *Coordinator) RelaysFor(ctx context.Context, t MeshnetID) ([]Relay, error) {
	if c.Relays == nil {
		return nil, nil
	}
	return c.Relays.ListRelays(ctx, t)
}

// RegisterRelay stores a new self-hosted relay for a meshnet.
//
// The meshnet comes from the CALLER's authenticated context, never from the
// request body — constraint ① is only worth as much as the weakest place the
// org id is decided.
func (c *Coordinator) RegisterRelay(ctx context.Context, t MeshnetID, in Relay) (*Relay, error) {
	if c.Relays == nil {
		return nil, fmt.Errorf("core: relay registry not supported")
	}
	label := NormalizeNodeName(in.Label)
	host := strings.TrimSpace(in.HostName)
	if in.STUNPort == 0 {
		in.STUNPort = defaultRelaySTUNPort
	}
	if err := ValidateRelay(label, host, in.DERPPort, in.STUNPort); err != nil {
		return nil, err
	}
	existing, err := c.Relays.ListRelays(ctx, t)
	if err != nil {
		return nil, fmt.Errorf("core: list relays: %w", err)
	}
	// Duplicate BEFORE the shadow check below, and that order is load-bearing.
	// c.DERP is the COMPOSITE map, so this org's own relays are already in it;
	// checking the code first would report a plain duplicate label as "the
	// platform already publishes that region", which is both wrong and baffling.
	// Once a duplicate is ruled out, any remaining hit can only be a platform
	// region — which is exactly what that check means to catch.
	for _, r := range existing {
		if r.Label == label {
			return nil, ErrRelayExists
		}
	}
	if len(existing) >= maxRelaysPerMeshnet {
		return nil, fmt.Errorf("%w: %d registered (max %d)", ErrTooManyRelays, len(existing), maxRelaysPerMeshnet)
	}
	// A registration must not be able to shadow a platform region: nodes would
	// then be steered at the user's machine for traffic the platform is meant to
	// carry, and the map builder would have to pick a winner.
	published, err := c.DERP.DERPMap(ctx, t)
	if err != nil {
		return nil, fmt.Errorf("core: derp map: %w", err)
	}
	code := SelfHostedRegionPrefix + label
	if published.HasRegion(code) {
		return nil, fmt.Errorf("%w: region %q is already published by the platform", ErrInvalidRelay, code)
	}
	out, err := c.Relays.CreateRelay(ctx, Relay{
		Meshnet: t, Label: label, HostName: host,
		DERPPort: in.DERPPort, STUNPort: in.STUNPort, Enabled: true,
	})
	if err != nil {
		return nil, fmt.Errorf("core: create relay: %w", err)
	}
	if c.Logger != nil {
		c.Logger.Info("self-hosted relay registered", "meshnet", t, "relay_id", out.ID,
			"region", out.RegionCode(), "host", out.HostName)
	}
	return out, nil
}

// UpsertRelay is the idempotent form of RegisterRelay for a merged edge/relay
// node that self-registers on every heartbeat (edge/derp merge — it mirrors the
// edge's RegisterEdgeNode, which upserts). A re-registration under the same label
// rewrites the mutable fields (host/ports, re-enable) instead of returning
// ErrRelayExists, and reports whether anything actually moved so the caller can
// skip a needless netmap push. RegisterRelay (console path) keeps its strict
// "error on duplicate" contract; only the node self-registration uses this.
func (c *Coordinator) UpsertRelay(ctx context.Context, t MeshnetID, in Relay) (*Relay, bool, error) {
	if c.Relays == nil {
		return nil, false, fmt.Errorf("core: relay registry not supported")
	}
	label := NormalizeNodeName(in.Label)
	host := strings.TrimSpace(in.HostName)
	if in.STUNPort == 0 {
		in.STUNPort = defaultRelaySTUNPort
	}
	if err := ValidateRelay(label, host, in.DERPPort, in.STUNPort); err != nil {
		return nil, false, err
	}
	existing, err := c.Relays.ListRelays(ctx, t)
	if err != nil {
		return nil, false, fmt.Errorf("core: list relays: %w", err)
	}
	// One machine (host) runs one relay. If this host already carries a relay
	// under a DIFFERENT label — the operator renamed the region, so the node now
	// self-registers a new label — retire the stale row instead of leaving an
	// orphan region pointing at the same box. Only self-registration (this
	// method) does this; the console RegisterRelay path stays strict. `retired`
	// feeds the changed flag so even a steady-state target still forces the
	// netmap push that drops the removed region.
	retired := false
	if host != "" {
		kept := existing[:0]
		for _, r := range existing {
			if r.HostName == host && r.Label != label {
				if delErr := c.Relays.DeleteRelay(ctx, r.ID); delErr == nil {
					retired = true
					if c.Logger != nil {
						c.Logger.Info("self-hosted relay retired: host re-registered under a new label",
							"meshnet", t, "relay_id", r.ID, "old_region", r.RegionCode(),
							"new_label", label, "host", host)
					}
					continue
				}
			}
			kept = append(kept, r)
		}
		existing = kept
	}
	for _, r := range existing {
		if r.Label != label {
			continue
		}
		// Same label = same relay (the label IS the region code). Nothing moved →
		// changed=false so a 30s heartbeat doesn't churn every node's netmap
		// (unless we just retired a stale sibling — then the map did change).
		if r.HostName == host && r.DERPPort == in.DERPPort && r.STUNPort == in.STUNPort && r.Enabled {
			out := r
			return &out, retired, nil
		}
		r.HostName, r.DERPPort, r.STUNPort, r.Enabled = host, in.DERPPort, in.STUNPort, true
		if err := c.Relays.UpdateRelay(ctx, r); err != nil {
			return nil, false, fmt.Errorf("core: update relay: %w", err)
		}
		if c.Logger != nil {
			c.Logger.Info("self-hosted relay re-registered", "meshnet", t, "relay_id", r.ID,
				"region", r.RegionCode(), "host", host)
		}
		out := r
		return &out, true, nil
	}
	// New relay: same cap + platform-shadow guard as RegisterRelay, then create.
	if len(existing) >= maxRelaysPerMeshnet {
		return nil, false, fmt.Errorf("%w: %d registered (max %d)", ErrTooManyRelays, len(existing), maxRelaysPerMeshnet)
	}
	published, err := c.DERP.DERPMap(ctx, t)
	if err != nil {
		return nil, false, fmt.Errorf("core: derp map: %w", err)
	}
	code := SelfHostedRegionPrefix + label
	if published.HasRegion(code) {
		return nil, false, fmt.Errorf("%w: region %q is already published by the platform", ErrInvalidRelay, code)
	}
	out, err := c.Relays.CreateRelay(ctx, Relay{
		Meshnet: t, Label: label, HostName: host,
		DERPPort: in.DERPPort, STUNPort: in.STUNPort, Enabled: true,
	})
	if err != nil {
		return nil, false, fmt.Errorf("core: create relay: %w", err)
	}
	if c.Logger != nil {
		c.Logger.Info("self-hosted relay registered (auto)", "meshnet", t, "relay_id", out.ID,
			"region", out.RegionCode(), "host", out.HostName)
	}
	return out, true, nil
}

// SetRelayEnabled parks or un-parks a relay. Scoped to the caller's meshnet: an
// id from another tenant is not found, never someone else's row.
func (c *Coordinator) SetRelayEnabled(ctx context.Context, t MeshnetID, id int64, enabled bool) (*Relay, error) {
	r, err := c.relayInMeshnet(ctx, t, id)
	if err != nil {
		return nil, err
	}
	if r.Enabled == enabled {
		return r, nil
	}
	r.Enabled = enabled
	if err := c.Relays.UpdateRelay(ctx, *r); err != nil {
		return nil, fmt.Errorf("core: update relay: %w", err)
	}
	if c.Logger != nil {
		c.Logger.Info("self-hosted relay enabled changed", "meshnet", t, "relay_id", id,
			"region", r.RegionCode(), "enabled", enabled)
	}
	return r, nil
}

// DeleteRelay removes a registration. Scoped to the caller's meshnet.
func (c *Coordinator) DeleteRelay(ctx context.Context, t MeshnetID, id int64) error {
	if _, err := c.relayInMeshnet(ctx, t, id); err != nil {
		return err
	}
	if err := c.Relays.DeleteRelay(ctx, id); err != nil {
		return fmt.Errorf("core: delete relay: %w", err)
	}
	if c.Logger != nil {
		c.Logger.Info("self-hosted relay deleted", "meshnet", t, "relay_id", id)
	}
	return nil
}

// relayInMeshnet resolves an id WITHIN one meshnet. Every mutation goes through
// it, so "id from another tenant" is answered the same way everywhere: not
// found. Returning a different error would tell the caller the row exists.
func (c *Coordinator) relayInMeshnet(ctx context.Context, t MeshnetID, id int64) (*Relay, error) {
	if c.Relays == nil {
		return nil, fmt.Errorf("core: relay registry not supported")
	}
	all, err := c.Relays.ListRelays(ctx, t)
	if err != nil {
		return nil, fmt.Errorf("core: list relays: %w", err)
	}
	for i := range all {
		if all[i].ID == id {
			return &all[i], nil
		}
	}
	return nil, ErrRelayNotFound
}

// CompositeDERP is the map an org actually receives: the platform's regions plus
// the relays that org runs itself.
//
// Platform regions come FIRST and are never dropped. Two things depend on it:
// Coordinator.DefaultDERPHome names a platform region and must stay resolvable,
// and a self-hosted region must never be a new node's default home — it hasn't
// measured anything yet, and defaulting to the org's own VPS bets its first
// connectivity on a machine nobody has checked.
type CompositeDERP struct {
	// Platform is the fleet map from config, identical for every org. Used when
	// PlatformFn is nil — community, dev, and static-config deployments.
	Platform DERPMap
	// PlatformFn, when set, supplies the platform regions LIVE on every call and
	// takes precedence over Platform. The platform build derives them from the
	// edge directory (edge/derp merge), so a merged relay coming online or moving
	// is reflected without a restart or a hand-kept map file.
	PlatformFn func() DERPMap
	// Relays supplies each org's own. Nil = platform only, i.e. exactly the
	// behaviour of StaticDERP.
	Relays RelayStore
}

// DERPMap implements DERPMapSource.
func (c CompositeDERP) DERPMap(ctx context.Context, t MeshnetID) (DERPMap, error) {
	platform := c.Platform
	if c.PlatformFn != nil {
		platform = c.PlatformFn()
	}
	out := DERPMap{Regions: append([]DERPRegion(nil), platform.Regions...)}
	if c.Relays == nil {
		return out, nil
	}
	mine, err := c.Relays.ListRelays(ctx, t)
	if err != nil {
		// A registry hiccup must not cost this org the platform's relays too —
		// that would turn "your own relay is unreachable" into "your mesh has no
		// fallback at all". Degrade to the platform map.
		return out, nil
	}
	sort.Slice(mine, func(i, j int) bool { return mine[i].ID < mine[j].ID })
	for _, r := range mine {
		if !r.Enabled {
			continue
		}
		code := r.RegionCode()
		if out.HasRegion(code) {
			// Defence in depth: registration already rejects a shadowing label,
			// so this can only be a row that predates a platform region gaining
			// that code. The platform's entry wins — it is the one every other
			// org is also using.
			continue
		}
		out.Regions = append(out.Regions, DERPRegion{
			Code:  code,
			Nodes: []DERPNode{{HostName: r.HostName, DERPPort: r.DERPPort, STUNPort: r.STUNPort}},
		})
	}
	return out, nil
}

// MemRelayStore is an in-memory RelayStore (dev / tests / community).
type MemRelayStore struct {
	mu   sync.Mutex
	next int64
	m    map[int64]Relay
}

func NewMemRelayStore() *MemRelayStore { return &MemRelayStore{m: map[int64]Relay{}} }

func (s *MemRelayStore) ListRelays(_ context.Context, t MeshnetID) ([]Relay, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Relay, 0, len(s.m))
	for _, v := range s.m {
		if v.Meshnet == t {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *MemRelayStore) CreateRelay(_ context.Context, in Relay) (*Relay, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	in.ID = s.next
	in.CreatedAt = time.Now()
	s.m[in.ID] = in
	out := in
	return &out, nil
}

func (s *MemRelayStore) UpdateRelay(_ context.Context, in Relay) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.m[in.ID]
	if !ok {
		return ErrRelayNotFound
	}
	cur.HostName, cur.DERPPort, cur.STUNPort, cur.Enabled = in.HostName, in.DERPPort, in.STUNPort, in.Enabled
	s.m[in.ID] = cur
	return nil
}

func (s *MemRelayStore) DeleteRelay(_ context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[id]; !ok {
		return ErrRelayNotFound
	}
	delete(s.m, id)
	return nil
}
