package core

import (
	"context"
	"net/netip"
	"sync"
	"time"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

// MemNodeStore is an in-memory NodeStore for the self-hosted coordinator and for
// tests/dev. The platform build swaps in a DB-backed store (MESH.1/MESH.8).
type MemNodeStore struct {
	mu     sync.Mutex
	nextID int64
	nodes  map[int64]*Node
}

// NewMemNodeStore returns an empty in-memory store.
func NewMemNodeStore() *MemNodeStore {
	return &MemNodeStore{nodes: make(map[int64]*Node)}
}

func (s *MemNodeStore) Upsert(_ context.Context, n *Node) (*Node, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *n
	if cp.ID == 0 {
		s.nextID++
		cp.ID = s.nextID
		if cp.CreatedAt.IsZero() {
			cp.CreatedAt = time.Now()
		}
	}
	cp.LastSeen = time.Now()
	stored := cp
	s.nodes[cp.ID] = &stored
	out := stored
	return &out, nil
}

func (s *MemNodeStore) Get(_ context.Context, id int64) (*Node, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.nodes[id]
	if !ok {
		return nil, ErrNodeNotFound
	}
	out := *n
	return &out, nil
}

// ResolveNodeKey implements NodeKeyResolver: find a node by key across every
// meshnet. Used only to attribute relay usage — see the interface's comment on
// why this one lookup is allowed to cross the tenant boundary.
func (s *MemNodeStore) ResolveNodeKey(_ context.Context, key meshproto.NodeKey) (*Node, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var found *Node
	for _, n := range s.nodes {
		if !n.NodeKey.Equal(key) {
			continue
		}
		if found != nil {
			return nil, ErrAmbiguousNodeKey
		}
		cp := *n
		found = &cp
	}
	if found == nil {
		return nil, ErrNodeNotFound
	}
	return found, nil
}

func (s *MemNodeStore) FindByKey(_ context.Context, t MeshnetID, key meshproto.NodeKey) (*Node, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, n := range s.nodes {
		if n.Meshnet == t && n.NodeKey == key {
			out := *n
			return &out, nil
		}
	}
	return nil, ErrNodeNotFound
}

func (s *MemNodeStore) ListMeshnet(_ context.Context, t MeshnetID) ([]*Node, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*Node
	for _, n := range s.nodes {
		if n.Meshnet == t {
			cp := *n
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (s *MemNodeStore) UpdateEndpoints(_ context.Context, id int64, eps []netip.AddrPort) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.nodes[id]
	if !ok {
		return ErrNodeNotFound
	}
	n.Endpoints = append([]netip.AddrPort(nil), eps...)
	n.LastSeen = time.Now()
	return nil
}

func (s *MemNodeStore) UpdateApprovedRoutes(_ context.Context, id int64, routes []netip.Prefix) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.nodes[id]
	if !ok {
		return ErrNodeNotFound
	}
	n.ApprovedRoutes = append([]netip.Prefix(nil), routes...)
	n.RoutesReviewed = true
	return nil
}

func (s *MemNodeStore) UpdateName(_ context.Context, id int64, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.nodes[id]
	if !ok {
		return ErrNodeNotFound
	}
	n.Name = name
	n.NamePinned = true
	return nil
}

func (s *MemNodeStore) UpdateDERPHome(_ context.Context, id int64, region string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.nodes[id]
	if !ok {
		return ErrNodeNotFound
	}
	n.DERPHome = region
	return nil
}

func (s *MemNodeStore) Delete(_ context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.nodes[id]; !ok {
		return ErrNodeNotFound
	}
	delete(s.nodes, id)
	return nil
}

func (s *MemNodeStore) SetTags(_ context.Context, id int64, tags []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.nodes[id]
	if !ok {
		return ErrNodeNotFound
	}
	n.Tags = append([]string(nil), tags...)
	n.TagsPinned = true
	return nil
}

func (s *MemNodeStore) SetApproved(_ context.Context, id int64, approved bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.nodes[id]
	if !ok {
		return ErrNodeNotFound
	}
	n.Approved = approved
	return nil
}

func (s *MemNodeStore) SetDisabled(_ context.Context, id int64, disabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.nodes[id]
	if !ok {
		return ErrNodeNotFound
	}
	n.Disabled = disabled
	return nil
}

// AllowAllPolicy is the v0 PolicyStore: every node may reach every other node in
// its meshnet. MESH.5 replaces this with the real ACL engine.
type AllowAllPolicy struct{}

func (AllowAllPolicy) Filter(_ context.Context, _ MeshnetID, _ *Node, candidates []*Node) ([]*Node, error) {
	return candidates, nil
}

// StaticDERP is a fixed DERPMapSource — used by the self-hosted coordinator (reads
// a file) and dev. The platform build sources the map from the live fleet.
type StaticDERP struct{ Map DERPMap }

// DERPMap ignores the meshnet: a static map has no per-org relays to add. This
// is the self-hosted coordinator's behaviour and the platform's until self-hosted
// relays land (R2).
func (s StaticDERP) DERPMap(_ context.Context, _ MeshnetID) (DERPMap, error) { return s.Map, nil }
