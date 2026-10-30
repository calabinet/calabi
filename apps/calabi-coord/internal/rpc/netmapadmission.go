package rpc

import (
	"context"
	"sync"

	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
	meshpb "github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Admission bounds long-lived delta baselines as well as legacy streams. Two
// streams per device allow the usual reconnect overlap in one session. A new
// registration cancels streams under superseded tokens. Counts are independent
// of build/send concurrency and remain charged until actual RPC exit.
type netMapAdmissions struct {
	mu                        sync.Mutex
	nodes                     map[int64]int
	groups                    map[core.MeshnetID]int
	total                     int
	perNode, perGroup, global int
	leases                    map[int64]map[uint64]netMapLease
	nextLease                 uint64
}

type netMapLease struct {
	token  string
	cancel context.CancelFunc
}
type netMapContextStream struct {
	meshpb.Coordinator_PullNetMapServer
	ctx context.Context
}

func (s *netMapContextStream) Context() context.Context { return s.ctx }

func newNetMapAdmissions() *netMapAdmissions {
	return &netMapAdmissions{nodes: make(map[int64]int), groups: make(map[core.MeshnetID]int), leases: make(map[int64]map[uint64]netMapLease), perNode: 2, perGroup: 2048, global: 8192}
}

func (a *netMapAdmissions) acquire(t core.MeshnetID, id int64) (func(), error) {
	return a.acquireSession(t, id, "", nil)
}

func (a *netMapAdmissions) cancelOtherSessions(id int64, token string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, lease := range a.leases[id] {
		if lease.token != token && lease.cancel != nil {
			lease.cancel()
		}
	}
}

func (a *netMapAdmissions) acquireSession(t core.MeshnetID, id int64, token string, cancel context.CancelFunc) (func(), error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var scope string
	switch {
	case a.nodes[id] >= a.perNode:
		scope = "device"
	case a.groups[t] >= a.perGroup:
		scope = "meshnet"
	case a.total >= a.global:
		scope = "coordinator"
	}
	if scope != "" {
		return nil, status.Errorf(codes.ResourceExhausted, "%s netmap subscription limit reached", scope)
	}
	a.nodes[id]++
	a.groups[t]++
	a.total++
	a.nextLease++
	leaseID := a.nextLease
	if a.leases[id] == nil {
		a.leases[id] = make(map[uint64]netMapLease)
	}
	a.leases[id][leaseID] = netMapLease{token: token, cancel: cancel}
	var once sync.Once
	return func() {
		once.Do(func() {
			a.mu.Lock()
			defer a.mu.Unlock()
			a.nodes[id]--
			a.groups[t]--
			a.total--
			delete(a.leases[id], leaseID)
			if a.nodes[id] == 0 {
				delete(a.nodes, id)
				delete(a.leases, id)
			}
			if a.groups[t] == 0 {
				delete(a.groups, t)
			}
		})
	}, nil
}
