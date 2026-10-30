package mesh

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

func TestProbePhoneSleepsUntilDue(t *testing.T) {
	base, peers := schedulerFixture(1)
	s := newProbeScheduler(base.p, 20)
	s.update(peers)
	now := time.Now()
	sp := s.peers[peers[0].DiscoKey]
	sp.active.Store(now.UnixNano())
	sp.lastActive = now
	sp.lastSend = now
	for i := range sp.candidates {
		sp.candidates[i].next = now.Add(time.Minute)
		sp.candidates[i].attempt = 5
	}
	sp.candidates[0].next = now.Add(probeInterval)
	s.p.paths[sp.key] = peerPath{ep: sp.candidates[0].ep, confirmed: now}
	if got := s.nextDelay(now); got < probeInterval || got > probeInterval+time.Millisecond {
		t.Fatalf("phone timer=%s, want maintenance deadline", got)
	}
	sp.active.Store(now.Add(-2 * probeIdle).UnixNano())
	if got := s.nextDelay(now); got != time.Minute {
		t.Fatalf("idle timer=%s", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.run(ctx) }()
	time.Sleep(1500 * time.Millisecond)
	cancel()
	<-done
	if runs := s.runs.Load(); runs > 2 {
		t.Fatalf("idle phone kept polling: %d scheduler turns", runs)
	}
}

func TestProbeDiscoSourceCacheBounded(t *testing.T) {
	_, peers := schedulerFixture(1)
	key := peers[0].DiscoKey
	b := newMeshBind(meshproto.NodeKey{1}, nil, nil)
	b.srcOf = map[netip.AddrPort]meshproto.DiscoKey{}
	b.setPeers(WGConfig{Peers: []WGPeer{{PublicKey: meshproto.NodeKey{2}, DiscoKey: key}}})
	for i := 0; i < 1000; i++ {
		b.noteDiscoSource(key, loopback(uint16(10000+i)))
	}
	if len(b.srcOf) != probeCandidateLimit || len(b.sourceOrder[key]) != probeCandidateLimit {
		t.Fatal("source cache retained unbounded NAT history")
	}
	b.setPeers(WGConfig{})
	if len(b.srcOf) != 0 || len(b.sourceOrder) != 0 {
		t.Fatal("revoked source mappings survived")
	}
}

func TestProbePriorityReservesActivePaths(t *testing.T) {
	s, peers := schedulerFixture(1000)
	now := time.Unix(1_700_000_000, 0)
	start := now
	current := peers[0].DiscoKey
	primary := s.peers[current].candidates[0].ep
	for _, sp := range s.peers {
		sp.active.Store(now.UnixNano())
		sp.lastActive = now
		for i := range sp.candidates {
			sp.candidates[i].attempt = 10
			sp.candidates[i].next = now
		}
	}
	s.p.paths[current] = peerPath{ep: primary, confirmed: now}
	last := now
	maintained := 0
	s.send = func(key meshproto.DiscoKey, ep netip.AddrPort) error {
		if key == current && ep == primary {
			if now.Sub(last) > probeInterval+100*time.Millisecond {
				t.Fatal("low priority retries delayed live path")
			}
			last = now
			maintained++
			s.p.mu.Lock()
			s.p.paths[key] = peerPath{ep: ep, confirmed: now}
			s.p.mu.Unlock()
		}
		return nil
	}
	for ; now.Sub(start) < time.Minute; now = now.Add(20 * time.Millisecond) {
		for _, sp := range s.peers {
			sp.active.Store(now.UnixNano())
		}
		s.step(now)
		if float64(s.lowSent.Load()) > now.Sub(start).Seconds()*10+2.001 {
			t.Fatal("retry traffic exceeded its 20 percent budget")
		}
	}
	if maintained < 10 || s.lowSent.Load() == 0 {
		t.Fatalf("maintenance=%d low=%d", maintained, s.lowSent.Load())
	}
}

func TestProbePongBudgetsFairnessAndCoalescing(t *testing.T) {
	s, peers := schedulerFixture(1000)
	now := time.Unix(1_700_000_000, 0)
	start := now
	seen := map[meshproto.DiscoKey]bool{}
	s.reply = func(key meshproto.DiscoKey, _ discoTxID, _ netip.AddrPort) error { seen[key] = true; return nil }
	from := netip.MustParseAddrPort("192.168.1.20:41641")
	for _, p := range peers {
		s.queuePongAt(p.DiscoKey, discoTxID{1}, from, now)
	}
	for ; now.Sub(start) < 10*time.Second; now = now.Add(20 * time.Millisecond) {
		// An old client keeps probing while the global budget is saturated.
		s.queuePongAt(peers[0].DiscoKey, discoTxID{2}, from, now)
		s.step(now)
		if float64(s.replyStats.sent.Load()) > 100*now.Sub(start).Seconds()+20.001 {
			t.Fatal("global pong budget exceeded")
		}
	}
	if len(seen) != 1000 {
		t.Fatalf("pong starvation: %d/1000", len(seen))
	}
	if s.replyStats.coalesced.Load() == 0 || s.replyStats.limited.Load() == 0 {
		t.Fatal("missing queue diagnostics")
	}
	if len(s.peers[peers[0].DiscoKey].replies) > probeReplySlots {
		t.Fatal("unbounded reply state")
	}
}

func TestProbePongPerPeerAndRemoval(t *testing.T) {
	s, peers := schedulerFixture(3)
	now := time.Unix(1_700_000_000, 0)
	counts := map[meshproto.DiscoKey]int{}
	s.reply = func(k meshproto.DiscoKey, _ discoTxID, _ netip.AddrPort) error { counts[k]++; return nil }
	for i := 0; i < 50; i++ {
		s.queuePongAt(peers[0].DiscoKey, discoTxID{byte(i)}, netip.MustParseAddrPort(fmt.Sprintf("192.168.0.1:%d", 1000+i)), now)
	}
	for _, p := range peers[1:] {
		s.queuePongAt(p.DiscoKey, discoTxID{}, loopback(9000), now)
	}
	s.step(now)
	if counts[peers[0].DiscoKey] > 3 || counts[peers[1].DiscoKey] != 1 || counts[peers[2].DiscoKey] != 1 {
		t.Fatalf("bad per-peer fairness: %v", counts)
	}
	if s.replyStats.dropped.Load() != 46 {
		t.Fatal("per-peer queue was not bounded")
	}
	s.update(peers[1:])
	if s.replyPending != 0 {
		t.Fatal("removed peer retained replies")
	}
	before := s.replyPending
	s.queuePongAt(meshproto.DiscoKey{99}, discoTxID{}, loopback(9000), now)
	if s.replyPending != before {
		t.Fatal("unknown identity allocated queue state")
	}
}

// Fake time advances a full day with activity, topology refreshes, NAT-source
// churn, timeouts, and replies. Real short-run memory/CPU results are measured
// separately; advancing this clock does not claim a physical 24-hour soak.
func TestProbeVirtualDayBoundedState(t *testing.T) {
	if os.Getenv("CALABI_TEST_PROBE_DAY") != "1" || testing.Short() {
		t.Skip("set CALABI_TEST_PROBE_DAY=1")
	}
	s, peers := schedulerFixture(1000)
	s.p.scheduler = s
	now := time.Now()
	start := now
	var seq uint64
	s.send = func(k meshproto.DiscoKey, ep netip.AddrPort) error {
		seq++
		var tx discoTxID
		binary.LittleEndian.PutUint64(tx[:], seq)
		s.p.mu.Lock()
		defer s.p.mu.Unlock()
		if ep == peers[0].Endpoints[0] {
			s.p.paths[k] = peerPath{ep: ep, confirmed: now}
		} else {
			s.p.pending[tx] = pendingProbe{peer: k, ep: ep, sent: now}
		}
		return nil
	}
	s.reply = func(meshproto.DiscoKey, discoTxID, netip.AddrPort) error { return nil }
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	for tick := 0; tick < 86400; tick++ {
		now = start.Add(time.Duration(tick) * time.Second)
		for i := 0; i < 5; i++ {
			s.peers[peers[i].DiscoKey].active.Store(now.UnixNano())
		}
		if tick%900 == 0 {
			s.update(peers)
		}
		if tick%60 == 0 {
			k := peers[0].DiscoKey
			ep := netip.AddrPortFrom(netip.MustParseAddr("203.0.113.40"), uint16(10000+tick%50000))
			s.p.mu.Lock()
			if s.p.learned[k] == nil {
				s.p.learned[k] = map[netip.AddrPort]time.Time{}
			}
			s.p.learned[k][ep] = now
			s.p.mu.Unlock()
			s.queuePongAt(k, discoTxID{1}, ep, now)
		}
		s.step(now)
		if len(s.p.pending) > 510 || s.replyPending > probeReplyQueueLimit {
			t.Fatal("pending tasks grew without a bound")
		}
		for _, sp := range s.peers {
			if len(sp.candidates) > probeCandidateLimit || len(sp.replies) > probeReplySlots {
				t.Fatal("per-peer state grew without a bound")
			}
		}
	}
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	if after.HeapAlloc > before.HeapAlloc+8<<20 {
		t.Fatalf("retained heap grew: %d -> %d", before.HeapAlloc, after.HeapAlloc)
	}
	if s.timeouts.Load() == 0 || s.replyStats.sent.Load() == 0 {
		t.Fatal("soak did not exercise timeouts and replies")
	}
	t.Logf("virtual_hours=24 peers=1000 ping_attempts=%d high=%d low=%d timeouts=%d retained_heap_before=%d retained_heap_after=%d pending=%d replies=%d", s.sent.Load(), s.highSent.Load(), s.lowSent.Load(), s.timeouts.Load(), before.HeapAlloc, after.HeapAlloc, len(s.p.pending), s.replyPending)
}
