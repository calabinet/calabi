package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
	meshpb "github.com/calabi/calabi/pkg/mesh-proto/meshpb"
	proto "github.com/calabi/calabi/pkg/protocol"
)

func testSelfSigned(t *testing.T, cn string) (*tls.Certificate, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, meshproto.CertPin(leaf)
}

// --- a self-hosted edge ------------------------------------------------------

// fakeEdge answers the control handshake on TLS with a self-signed certificate
// and holds the session open. A token edge (calabi.net's kind) accepts one
// token; a grant edge accepts its coordinator's devices, as a self-hosted edge
// does: a grant that coordinator signed, and the proof of the node key's
// private half against this connection's challenge. It ends a session whose
// grant runs out unrenewed.
type fakeEdge struct {
	addr  string
	pin   string
	token string
	coord ed25519.PublicKey
	cert  atomic.Pointer[tls.Certificate]

	mu        sync.Mutex
	conns     []net.Conn
	auths     int                 // sessions it authenticated
	nodes     []meshproto.NodeKey // grant edge: the node each of them proved
	refreshes int                 // grant edge: renewed grants it took
	expired   int                 // grant edge: sessions it ended for an expired grant
}

// startFakeEdge starts a token edge.
func startFakeEdge(t *testing.T, token string) *fakeEdge {
	return startEdge(t, &fakeEdge{token: token})
}

// startFakeGrantEdge starts an edge of the coordinator whose grant key's
// public half coord is.
func startFakeGrantEdge(t *testing.T, coord ed25519.PublicKey) *fakeEdge {
	return startEdge(t, &fakeEdge{coord: coord})
}

func startEdge(t *testing.T, e *fakeEdge) *fakeEdge {
	t.Helper()
	cert, pin := testSelfSigned(t, "calabi-edge")
	e.pin = pin
	e.cert.Store(cert)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return e.cert.Load(), nil },
		NextProtos:     []string{"calabi/1"},
		MinVersion:     tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	e.addr = ln.Addr().String()
	t.Cleanup(func() { ln.Close(); e.dropAll() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			e.mu.Lock()
			e.conns = append(e.conns, c)
			e.mu.Unlock()
			go e.serve(c)
		}
	}()
	return e
}

func (e *fakeEdge) serve(c net.Conn) {
	defer c.Close()
	sess, err := yamux.Server(c, nil)
	if err != nil {
		return
	}
	defer sess.Close()
	st, err := sess.AcceptStream()
	if err != nil {
		return
	}
	defer st.Close()
	if f, err := proto.ReadFrame(st); err != nil || f.Type != proto.FrameHello {
		return
	}
	hello := &proto.HelloAck{ProtocolMajor: uint32(proto.CurrentMajor), ServerID: "fake-edge"}
	var ch meshproto.EdgeChallenge
	var eph [meshproto.KeyLen]byte
	if e.coord != nil {
		if ch, eph, err = meshproto.NewEdgeChallenge(); err != nil {
			return
		}
		hello.AuthChallenge = ch.Encode()
	}
	ack, _ := proto.EncodePayload(proto.FrameHelloAck, hello)
	if _, err := proto.WriteFrame(st, ack); err != nil {
		return
	}
	f, err := proto.ReadFrame(st)
	if err != nil || f.Type != proto.FrameAuth {
		return
	}
	var ar proto.AuthRequest
	_ = proto.Unmarshal(f.Payload, &ar)
	var g meshproto.RelayGrant
	ok := ar.Token == e.token
	if e.coord != nil {
		g, err = meshproto.VerifyRelayGrant(e.coord, ar.Grant, time.Now())
		ok = err == nil && meshproto.OpenEdgeProof(ch, eph, g.Node, ar.Proof) == nil
	}
	resp := &proto.AuthResponse{TenantID: "1", ClientID: "c1", SessionID: "s1", BaseDomain: "tunnel.example.com"}
	if !ok {
		resp = &proto.AuthResponse{Error: &proto.ErrorPayload{Code: proto.CodeAuthInvalidToken, MessageEN: "invalid token"}}
	} else {
		e.mu.Lock()
		e.auths++
		e.nodes = append(e.nodes, g.Node)
		e.mu.Unlock()
	}
	out, _ := proto.EncodePayload(proto.FrameAuthResp, resp)
	if _, err := proto.WriteFrame(st, out); err != nil || resp.Error != nil {
		return
	}

	// Hold the session: take renewed grants, end it when its grant runs out.
	done := make(chan struct{})
	defer close(done)
	frames := make(chan proto.Frame)
	go func() {
		defer close(frames)
		for {
			f, err := proto.ReadFrame(st)
			if err != nil {
				return
			}
			select {
			case frames <- f:
			case <-done:
				return
			}
		}
	}()
	var expiry <-chan time.Time
	if e.coord != nil {
		expiry = time.After(time.Until(g.Expiry))
	}
	for {
		select {
		case f, ok := <-frames:
			if !ok {
				return
			}
			if f.Type != proto.FrameAuthRefresh || e.coord == nil {
				continue
			}
			var rr proto.AuthRefresh
			_ = proto.Unmarshal(f.Payload, &rr)
			ng, err := meshproto.VerifyRelayGrant(e.coord, rr.Grant, time.Now())
			if err != nil || ng.Node != g.Node {
				return
			}
			e.mu.Lock()
			e.refreshes++
			e.mu.Unlock()
			if ng.Expiry.After(g.Expiry) {
				g.Expiry = ng.Expiry
				expiry = time.After(time.Until(g.Expiry))
			}
		case <-expiry:
			e.mu.Lock()
			e.expired++
			e.mu.Unlock()
			return
		}
	}
}

func (e *fakeEdge) sessions() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.auths
}

// counts is what the edge has seen: sessions, renewals, expiries.
func (e *fakeEdge) counts() (auths, refreshes, expired int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.auths, e.refreshes, e.expired
}

func (e *fakeEdge) provedNodes() []meshproto.NodeKey {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]meshproto.NodeKey(nil), e.nodes...)
}

func (e *fakeEdge) dropAll() {
	e.mu.Lock()
	conns := e.conns
	e.conns = nil
	e.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
}

// rotateCert makes the edge present a new certificate and drops every session,
// so clients have to connect again; returns the new pin.
func (e *fakeEdge) rotateCert(t *testing.T) string {
	cert, pin := testSelfSigned(t, "calabi-edge")
	e.cert.Store(cert)
	e.dropAll()
	return pin
}

// --- a self-hosted coordinator -------------------------------------------------

// fakeSHCoord is a self-hosted coordinator on TLS with a self-signed
// certificate: it admits keys it knows, takes nodes back by proof alone when it
// offers node_reauth, lists what the lists need, counts sign-outs, and names
// its edge and signs grants for it (GetEdgeAccess).
type fakeSHCoord struct {
	meshpb.UnimplementedCoordinatorServer
	addr     string
	pin      string
	cert     atomic.Pointer[tls.Certificate]
	grantKey ed25519.PrivateKey

	mu        sync.Mutex
	keys      map[string]bool
	offer     bool
	pending   map[string]meshproto.RegisterChallenge
	ephs      map[string][meshproto.KeyLen]byte
	seq       int
	regs      []string
	signedOut int
	views     int
	usageTZ   string
	// Edge access: the edge it names (none until setEdge), how long its grants
	// last, whether the device waits for approval, and the node it signs for —
	// the last one that registered or opened a view session.
	edge       *meshpb.EdgeInfo
	grantTTL   time.Duration
	awaiting   bool
	node       meshproto.NodeKey
	edgeAccess int
	// Tunnel reports, and the session token each came with.
	reports      [][]*meshpb.TunnelReport
	reportTokens []string
}

func startFakeSHCoord(t *testing.T, offer bool, keys ...string) *fakeSHCoord {
	t.Helper()
	cert, pin := testSelfSigned(t, "calabi-coord")
	_, grantKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSHCoord{keys: map[string]bool{}, offer: offer, pin: pin, grantKey: grantKey, grantTTL: time.Hour,
		pending: map[string]meshproto.RegisterChallenge{}, ephs: map[string][meshproto.KeyLen]byte{}}
	f.cert.Store(cert)
	for _, k := range keys {
		f.keys[k] = true
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.addr = lis.Addr().String()
	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return f.cert.Load(), nil },
	})))
	meshpb.RegisterCoordinatorServer(gs, f)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	return f
}

// grantPub is the public half of the key it signs grants with: what its edge
// is configured with.
func (f *fakeSHCoord) grantPub() ed25519.PublicKey { return f.grantKey.Public().(ed25519.PublicKey) }

// setEdge makes it name the edge at addr, with the certificate pin.
func (f *fakeSHCoord) setEdge(addr, pin string) {
	f.mu.Lock()
	f.edge = &meshpb.EdgeInfo{Addr: addr, Pin: pin}
	f.mu.Unlock()
}

func (f *fakeSHCoord) rotateCert(t *testing.T) string {
	cert, pin := testSelfSigned(t, "calabi-coord")
	f.cert.Store(cert)
	return pin
}

func (f *fakeSHCoord) link(key string) string {
	return "calabi://join?" + url.Values{"v": {"1"}, "s": {f.addr}, "k": {key}, "fp": {f.pin}}.Encode()
}

func (f *fakeSHCoord) registrations() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.regs...)
}

func (f *fakeSHCoord) session(tok string) error {
	if tok != "sh-session" && !strings.HasPrefix(tok, "sh-view-") {
		return status.Error(codes.Unauthenticated, "no session")
	}
	return nil
}

func (f *fakeSHCoord) GetRegisterChallenge(_ context.Context, req *meshpb.GetRegisterChallengeRequest) (*meshpb.GetRegisterChallengeResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if req.GetAuthKey() != "" && !f.keys[req.GetAuthKey()] {
		return nil, status.Error(codes.Unauthenticated, "auth key denied")
	}
	ch, eph, err := meshproto.NewRegisterChallenge()
	if err != nil {
		return nil, err
	}
	f.seq++
	id := fmt.Sprintf("ch-%d", f.seq)
	f.pending[id], f.ephs[id] = ch, eph
	return &meshpb.GetRegisterChallengeResponse{ChallengeId: id, Challenge: ch.Encode()}, nil
}

func (f *fakeSHCoord) RegisterNode(_ context.Context, req *meshpb.RegisterNodeRequest) (*meshpb.RegisterNodeResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ch, ok := f.pending[req.GetChallengeId()]
	eph := f.ephs[req.GetChallengeId()]
	delete(f.pending, req.GetChallengeId())
	key, err := meshproto.ParseNodeKey(req.GetNodeKey())
	if !ok || err != nil || meshproto.OpenRegisterProof(ch, eph, key, req.GetRegisterProof()) != nil {
		return nil, status.Error(codes.Unauthenticated, "proof rejected")
	}
	if req.GetAuthKey() == "" {
		f.regs = append(f.regs, fmt.Sprintf("reauth:%d", req.GetNodeId()))
	} else {
		f.regs = append(f.regs, "key:"+req.GetAuthKey())
	}
	f.node = key
	resp := &meshpb.RegisterNodeResponse{NodeId: 21, OverlayAddr: "100.64.0.21", ProtocolVersion: meshproto.ProtocolVersion, SessionToken: "sh-session"}
	for _, c := range req.GetCapabilities() {
		if f.offer && c == string(meshproto.CapNodeReauth) {
			resp.Capabilities = append(resp.Capabilities, c)
		}
	}
	return resp, nil
}

func (f *fakeSHCoord) OpenViewSession(_ context.Context, req *meshpb.OpenViewSessionRequest) (*meshpb.OpenViewSessionResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ch, ok := f.pending[req.GetChallengeId()]
	eph := f.ephs[req.GetChallengeId()]
	delete(f.pending, req.GetChallengeId())
	key, err := meshproto.ParseNodeKey(req.GetNodeKey())
	if !ok || err != nil || meshproto.OpenRegisterProof(ch, eph, key, req.GetProof()) != nil {
		return nil, status.Error(codes.Unauthenticated, "proof rejected")
	}
	f.views++
	f.node = key
	return &meshpb.OpenViewSessionResponse{ViewToken: fmt.Sprintf("sh-view-%d", f.views), ExpiresUnix: time.Now().Add(10 * time.Minute).Unix()}, nil
}

func (f *fakeSHCoord) ListNodes(_ context.Context, req *meshpb.ListNodesRequest) (*meshpb.ListNodesResponse, error) {
	if err := f.session(req.GetSessionToken()); err != nil {
		return nil, err
	}
	return &meshpb.ListNodesResponse{Nodes: []*meshpb.NodeInfo{
		{Id: 21, Name: "desk", Os: "windows", OverlayAddr: "100.64.0.21", Online: true, Approved: true},
		{Id: 22, Name: "nas", Os: "linux", OverlayAddr: "100.64.0.22", Approved: true, Disabled: true},
	}}, nil
}

func (f *fakeSHCoord) ListTunnels(_ context.Context, req *meshpb.ListTunnelsRequest) (*meshpb.ListTunnelsResponse, error) {
	if err := f.session(req.GetSessionToken()); err != nil {
		return nil, err
	}
	seen := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC).Unix()
	return &meshpb.ListTunnelsResponse{Tunnels: []*meshpb.TunnelInfo{
		{Id: 3, NodeId: 22, NodeName: "nas", NodeOnline: true, Name: "photos", Type: "http", PublicAddr: "photos.example.com",
			LocalAddr: "127.0.0.1:8080", Status: "online", Traffic_30D: 5000, FirstSeenUnix: seen},
		{Id: 4, NodeId: 23, NodeName: "old-laptop", NodeOnline: false, Name: "ssh", Type: "tcp", PublicAddr: "edge.example.com:2222",
			LocalAddr: "127.0.0.1:22", Status: "online", FirstSeenUnix: seen},
	}}, nil
}

func (f *fakeSHCoord) GetUsage(_ context.Context, req *meshpb.GetUsageRequest) (*meshpb.GetUsageResponse, error) {
	if err := f.session(req.GetSessionToken()); err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.usageTZ = req.GetTimeZone()
	f.mu.Unlock()
	return &meshpb.GetUsageResponse{
		DevicesUsed: 3, DevicesDisabled: 1, DevicesLimit: -1,
		Month: &meshpb.UsageMonth{FromUnix: 1, ToUnix: 2, TunnelBytes: 700, RelayBytes: 300},
		Days:  []*meshpb.UsageDay{{StartUnix: 86400, Bytes: 10}, {StartUnix: 2 * 86400, Bytes: 990}},
	}, nil
}

func (f *fakeSHCoord) GetEdgeAccess(_ context.Context, req *meshpb.GetEdgeAccessRequest) (*meshpb.GetEdgeAccessResponse, error) {
	if err := f.session(req.GetSessionToken()); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.edgeAccess++
	if f.awaiting {
		return nil, status.Error(codes.FailedPrecondition, meshproto.AwaitingApproval)
	}
	exp := time.Now().Add(f.grantTTL)
	grant, err := meshproto.SignRelayGrant(f.grantKey, meshproto.RelayGrant{Node: f.node, Meshnet: 1, Scope: meshproto.RelayScopeAll, Expiry: exp})
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	out := &meshpb.GetEdgeAccessResponse{Grant: grant, GrantExpiresUnix: exp.Unix()}
	if f.edge != nil {
		out.Edges = []*meshpb.EdgeInfo{f.edge}
	}
	return out, nil
}

func (f *fakeSHCoord) ReportTunnels(_ context.Context, req *meshpb.ReportTunnelsRequest) (*meshpb.ReportTunnelsResponse, error) {
	if err := f.session(req.GetSessionToken()); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reports = append(f.reports, req.GetTunnels())
	f.reportTokens = append(f.reportTokens, req.GetSessionToken())
	return &meshpb.ReportTunnelsResponse{}, nil
}

func (f *fakeSHCoord) SignOut(context.Context, *meshpb.SignOutRequest) (*meshpb.SignOutResponse, error) {
	f.mu.Lock()
	f.signedOut++
	f.mu.Unlock()
	return &meshpb.SignOutResponse{}, nil
}
