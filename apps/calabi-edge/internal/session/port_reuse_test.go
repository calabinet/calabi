// port_reuse_test.go — the edge must not hand out a remote port that a live
// tunnel row still holds.
//
// THE BUG, as the user's daemon logged it:
//
//	auto-claim NEW_PROXY failed  tunnel_id=28 name=test-udp01
//	err="calabi: code=3001 tunnelstore: remote port already bound on this
//	     edge: ... edge=1000400000 port=20000 already bound"
//
// and the tunnel then sat at 待接入 forever, because nothing retries.
//
// The port pool's model is "numbers I handed out". tunnel-svc's model is
// "numbers a live row is bound to". Those two drift apart in ordinary use, in
// two ways, and this file pins both:
//
//  1. A proxy closing does NOT delete its tunnel row — the row keeps its
//     remote_port. The session teardown released the port anyway, and Allocate
//     drains the free list LIFO, so the very next TCP/UDP tunnel was handed the
//     number a live row still held.
//
//  2. A CLAIM carries the port off its own row (req.RemotePort != 0), so it
//     never goes through Allocate at all. Every reconnect re-binds its port
//     without the pool ever hearing about it.
//
// The boot-time seed (ListEdgeClaimedPorts, 2fa72a08) closed the same hole for
// the restart case only. Neither of these needs a restart.
//
// Note that (edge_node_id, remote_port) is protocol-AGNOSTIC in tunnel-svc's
// unique check, while the edge's listeners are not: tcp/20000 and udp/20000
// register locally without complaint and collide only at the control plane.
// portLedger below models it exactly that way, which is why these tests
// reproduce the user's UDP-after-TCP shape.
//
// RUN: go test./apps/calabi-edge/internal/session/ -run TestPortReuse -v
package session

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"

	"github.com/hashicorp/yamux"

	"github.com/calabi/calabi/apps/calabi-edge/internal/router"
	proto "github.com/calabi/calabi/pkg/protocol"
)

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

// ctrlPipe stands in for the client's control stream. Writes (the edge's
// NEW_PROXY_RESP frames) are kept so a test can read back what the user was
// told; Read is already at EOF, which is exactly how Loop ends — the client
// going away — and that is what runs the teardown this file is about.
type ctrlPipe struct {
	mu  sync.Mutex
	out bytes.Buffer
}

func (c *ctrlPipe) Read([]byte) (int, error) { return 0, io.EOF }
func (c *ctrlPipe) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.out.Write(b)
}
func (c *ctrlPipe) Close() error { return nil }

// lastNewProxyResp decodes the frames written so far and returns the last
// NEW_PROXY_RESP — the answer the daemon acted on.
func (c *ctrlPipe) lastNewProxyResp(t *testing.T) proto.NewProxyResponse {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	r := bytes.NewReader(c.out.Bytes())
	var last proto.NewProxyResponse
	found := false
	for {
		f, err := proto.ReadFrame(r)
		if err != nil {
			break
		}
		if f.Type != proto.FrameNewProxyResp {
			continue
		}
		var resp proto.NewProxyResponse
		if err := proto.Unmarshal(f.Payload, &resp); err != nil {
			t.Fatalf("decode NEW_PROXY_RESP: %v", err)
		}
		last, found = resp, true
	}
	if !found {
		t.Fatal("no NEW_PROXY_RESP was written")
	}
	return last
}

// portRegistrar models the edge's listeners: TCP and UDP are separate address
// spaces, so tcp/20000 and udp/20000 both register fine. This is the half of
// the system that does NOT catch the collision.
type portRegistrar struct {
	tcp map[uint32]string
	udp map[uint32]string
}

func newPortRegistrar() *portRegistrar {
	return &portRegistrar{tcp: map[uint32]string{}, udp: map[uint32]string{}}
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

func (r *portRegistrar) RegisterHTTP(string, *Session, string) error { return nil }
func (r *portRegistrar) RegisterSNI(string, *Session, string) error  { return nil }
func (r *portRegistrar) RegisterTCP(port uint32, _ *Session, id string) (io.Closer, error) {
	if _, ok := r.tcp[port]; ok {
		return nil, fmt.Errorf("tcp port %d already registered", port)
	}
	r.tcp[port] = id
	return nopCloser{}, nil
}
func (r *portRegistrar) RegisterUDP(port uint32, _ *Session, id string) (io.Closer, error) {
	if _, ok := r.udp[port]; ok {
		return nil, fmt.Errorf("udp port %d already registered", port)
	}
	r.udp[port] = id
	return nopCloser{}, nil
}
func (r *portRegistrar) UnregisterByProxyID(id string) {
	for p, owner := range r.tcp {
		if owner == id {
			delete(r.tcp, p)
		}
	}
	for p, owner := range r.udp {
		if owner == id {
			delete(r.udp, p)
		}
	}
}

// portLedger models tunnel-svc: rows, and the (edge_node_id, remote_port)
// unique check over the live ones. Two things it does that a fake usually
// would not, both load-bearing:
//
//   - the key carries no protocol (store.checkUnique does not either);
//   - OnProxyClosed does NOT drop the row. A closed proxy leaves a live row
//     still bound to its port. That is the premise of this whole file.
type portLedger struct {
	bound  map[uint32]int64 // remote_port -> tunnel id
	nextID int64
}

func newPortLedger() *portLedger { return &portLedger{bound: map[uint32]int64{}, nextID: 100} }

func (l *portLedger) OnProxyOpened(_ *Session, p *Proxy) (int64, error) {
	if p.RemotePort != 0 {
		if owner, taken := l.bound[p.RemotePort]; taken && owner != p.ClaimTunnelID {
			return 0, fmt.Errorf("store: already exists: edge=1000400000 port=%d already bound",
				p.RemotePort)
		}
	}
	id := p.ClaimTunnelID
	if id == 0 {
		l.nextID++
		id = l.nextID
	}
	if p.RemotePort != 0 {
		l.bound[p.RemotePort] = id
	}
	return id, nil
}

func (l *portLedger) OnProxyClosed(*Session, *Proxy, string) {}

type stubDomains struct{}

func (stubDomains) Allocate(proto.ProxyKind) string { return "u000001.example.test" }

func newTestSession(t *testing.T) (*Session, *ctrlPipe) {
	t.Helper()
	// The teardown under test ends in Session.Close, which closes the yamux
	// mux, so the mux has to be real. net.Pipe is unbuffered: drain the far end
	// or yamux's goodbye blocks forever.
	local, remote := net.Pipe()
	go func() { _, _ = io.Copy(io.Discard, remote) }()
	t.Cleanup(func() { _ = remote.Close() })
	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = false
	cfg.LogOutput = io.Discard
	mux, err := yamux.Server(local, cfg)
	if err != nil {
		t.Fatalf("yamux: %v", err)
	}
	pipe := &ctrlPipe{}
	return New(slog.New(slog.NewTextHandler(io.Discard, nil)), mux, pipe), pipe
}

// newProxy drives the real NEW_PROXY handler and returns the response the
// client would have received.
func newProxy(t *testing.T, s *Session, pipe *ctrlPipe, reg ProxyRegistrar,
	pool PortAllocator, ledger ProxyPersister, req proto.NewProxyRequest) proto.NewProxyResponse {
	t.Helper()
	f, err := proto.EncodePayload(proto.FrameNewProxy, &req)
	if err != nil {
		t.Fatalf("encode NEW_PROXY: %v", err)
	}
	s.handleNewProxy(f, reg, stubDomains{}, pool, nil, ledger)
	return pipe.lastNewProxyResp(t)
}

// endSession runs Loop against a control stream that is already at EOF, which
// is how a client disconnect reaches this code: Loop returns at once and its
// deferred teardown tears down every proxy the session held.
func endSession(s *Session, reg ProxyRegistrar, pool PortAllocator, ledger ProxyPersister) {
	s.Loop(context.Background(), reg, stubDomains{}, pool, nil, ledger)
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

// (1) The client goes away and something else comes up. The row it left behind
// still holds port 20000, so the next tunnel must not be offered 20000.
func TestPortReuseAfterDisconnectDoesNotReissueABoundPort(t *testing.T) {
	pool := router.NewPortPool(20000, 20999)
	reg := newPortRegistrar()
	ledger := newPortLedger()

	s1, p1 := newTestSession(t)
	resp := newProxy(t, s1, p1, reg, pool, ledger, proto.NewProxyRequest{
		Name: "test-tcp01", Type: proto.ProxyKindTCP, LocalAddr: "192.168.1.222:5001",
	})
	if resp.Error != nil {
		t.Fatalf("first tcp proxy refused: %+v", resp.Error)
	}
	if resp.RemotePort != 20000 {
		t.Fatalf("first allocation = %d, want the bottom of the range (20000)", resp.RemotePort)
	}

	// The daemon restarts. The proxy is torn down; the tunnel ROW is not.
	endSession(s1, reg, pool, ledger)
	if ledger.bound[20000] == 0 {
		t.Fatal("precondition: the row must still hold 20000 after its proxy closed")
	}

	// A different tunnel now asks for a port.
	s2, p2 := newTestSession(t)
	resp = newProxy(t, s2, p2, reg, pool, ledger, proto.NewProxyRequest{
		Name: "test-udp01", Type: proto.ProxyKindUDP, LocalAddr: "192.168.1.222:5001",
	})
	if resp.Error != nil {
		t.Fatalf("the pool re-issued a port a live row still holds, and the claim was "+
			"refused exactly as the user saw it: %s", resp.Error.MessageEN)
	}
	if resp.RemotePort == 20000 {
		t.Fatal("the pool handed out 20000 again while a live row still held it")
	}
}

// (2) The reconnect path never goes through Allocate: a claim carries the port
// off its own row. The pool must still learn the number is spoken for.
func TestPortReuseClaimedPortIsTakenOutOfThePool(t *testing.T) {
	pool := router.NewPortPool(20000, 20999)
	reg := newPortRegistrar()
	ledger := newPortLedger()
	ledger.bound[20000] = 28 // test-tcp01's row, from a previous run

	// test-tcp01 reconnects and re-claims its own port. req.RemotePort != 0,
	// so this path does not touch the pool.
	s, pipe := newTestSession(t)
	resp := newProxy(t, s, pipe, reg, pool, ledger, proto.NewProxyRequest{
		Name: "test-tcp01", Type: proto.ProxyKindTCP, LocalAddr: "192.168.1.222:5001",
		RemotePort: 20000, ClaimTunnelID: 28,
	})
	if resp.Error != nil {
		t.Fatalf("re-claiming its own port must succeed: %+v", resp.Error)
	}

	// Now a brand-new UDP tunnel. tcp/20000 and udp/20000 do not collide on the
	// listener, so nothing local stops this; only tunnel-svc does.
	resp = newProxy(t, s, pipe, reg, pool, ledger, proto.NewProxyRequest{
		Name: "test-udp01", Type: proto.ProxyKindUDP, LocalAddr: "192.168.1.222:5001",
	})
	if resp.Error != nil {
		t.Fatalf("the pool offered a port that a claim had already bound: %s",
			resp.Error.MessageEN)
	}
	if resp.RemotePort == 20000 {
		t.Fatal("the pool handed out 20000 while a claimed row held it")
	}
}

// The control. A port that no row holds must still come back — otherwise an
// edge with no control plane (standalone / self-hosted) burns one port per CLI
// run and dies after a thousand of them.
func TestPortReuseUnpersistedPortStillReturnsToThePool(t *testing.T) {
	pool := router.NewPortPool(20000, 20999)
	reg := newPortRegistrar()

	s1, p1 := newTestSession(t)
	resp := newProxy(t, s1, p1, reg, pool, nil, proto.NewProxyRequest{
		Name: "cli-tcp", Type: proto.ProxyKindTCP, LocalAddr: "127.0.0.1:22",
	})
	if resp.Error != nil || resp.RemotePort != 20000 {
		t.Fatalf("first allocation: port=%d err=%+v", resp.RemotePort, resp.Error)
	}
	endSession(s1, reg, pool, nil)

	s2, p2 := newTestSession(t)
	resp = newProxy(t, s2, p2, reg, pool, nil, proto.NewProxyRequest{
		Name: "cli-tcp", Type: proto.ProxyKindTCP, LocalAddr: "127.0.0.1:22",
	})
	if resp.RemotePort != 20000 {
		t.Fatalf("an unpersisted port must be reusable; got %d, want 20000 back",
			resp.RemotePort)
	}
}

// newTestPool is the pool these tests hand to handleNewProxy when the port
// allocator is incidental to what they are checking.
func newTestPool() PortAllocator { return router.NewPortPool(20000, 20999) }
