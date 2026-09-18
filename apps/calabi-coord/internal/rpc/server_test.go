package rpc

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/calabi/calabi/apps/calabi-coord/internal/core"
	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
	meshpb "github.com/calabi/calabi/pkg/mesh-proto/meshpb"
)

const devKey = "k1"

func nodeKeyB64(b byte) string {
	var k meshproto.NodeKey
	for i := range k {
		k[i] = b
	}
	return k.String()
}

func startTestServer(t *testing.T) meshpb.CoordinatorClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	coord := &core.Coordinator{
		Nodes:  core.NewMemNodeStore(),
		Policy: core.AllowAllPolicy{},
		IPAM:   core.NewMemIPAM(),
		DERP:   core.StaticDERP{Map: core.DERPMap{Regions: []core.DERPRegion{{Code: "lax"}}}},
	}
	auth := core.StaticAuth{Keys: map[string]core.Identity{devKey: {Meshnet: 1}}}
	gs := grpc.NewServer()
	meshpb.RegisterCoordinatorServer(gs, New(coord, auth, core.NewNotifier(), slog.Default()))
	go func() { _ = gs.Serve(lis) }()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		gs.Stop()
		_ = lis.Close()
	})
	return meshpb.NewCoordinatorClient(conn)
}

// testNode is a node enrolled the way a real client does it: a real X25519 key
// pair, a challenge, a proof, and the session token that comes back.
type testNode struct {
	id      int64
	overlay string
	key     meshproto.NodeKey
	priv    [meshproto.KeyLen]byte
	token   string
}

func newKeyPair(t *testing.T) (meshproto.NodeKey, [meshproto.KeyLen]byte) {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate node key: %v", err)
	}
	var pub meshproto.NodeKey
	copy(pub[:], k.PublicKey().Bytes())
	var priv [meshproto.KeyLen]byte
	copy(priv[:], k.Bytes())
	return pub, priv
}

// enrollAs runs GetRegisterChallenge + RegisterNode claiming one key and sealing
// the proof with another, and returns the error: the impersonation tests claim a
// key they do not hold. mutate may edit the request before it is sent.
func enrollAs(ctx context.Context, c meshpb.CoordinatorClient, authKey, name string,
	claim meshproto.NodeKey, sealWith [meshproto.KeyLen]byte, mutate func(*meshpb.RegisterNodeRequest),
) (*meshpb.RegisterNodeResponse, error) {
	chr, err := c.GetRegisterChallenge(ctx, &meshpb.GetRegisterChallengeRequest{AuthKey: authKey})
	if err != nil {
		return nil, err
	}
	ch, err := meshproto.ParseRegisterChallenge(chr.GetChallenge())
	if err != nil {
		return nil, err
	}
	req := &meshpb.RegisterNodeRequest{
		AuthKey: authKey, NodeKey: claim.String(), Name: name, ProtocolVersion: meshproto.ProtocolVersion,
		ChallengeId: chr.GetChallengeId(), RegisterProof: meshproto.SealRegisterProof(ch, claim, sealWith),
	}
	if mutate != nil {
		mutate(req)
	}
	return c.RegisterNode(ctx, req)
}

// enroll registers a fresh node under authKey and fails the test on refusal.
func enroll(t *testing.T, c meshpb.CoordinatorClient, authKey, name string) testNode {
	t.Helper()
	key, priv := newKeyPair(t)
	resp, err := enrollAs(context.Background(), c, authKey, name, key, priv, nil)
	if err != nil {
		t.Fatalf("enroll %s: %v", name, err)
	}
	if resp.GetSessionToken() == "" {
		t.Fatalf("enroll %s: no session token", name)
	}
	return testNode{id: resp.GetNodeId(), overlay: resp.GetOverlayAddr(), key: key, priv: priv, token: resp.GetSessionToken()}
}

func register(t *testing.T, c meshpb.CoordinatorClient, name string) testNode {
	t.Helper()
	return enroll(t, c, devKey, name)
}

// pullFirst opens a netmap stream and returns its first message. A server stream
// reports a refusal on Recv, not on the call that opened it.
func pullFirst(ctx context.Context, c meshpb.CoordinatorClient, req *meshpb.PullNetMapRequest) (*meshpb.NetMap, error) {
	stream, err := c.PullNetMap(ctx, req)
	if err != nil {
		return nil, err
	}
	return stream.Recv()
}

func peerKeys(nm *meshpb.NetMap) map[string]string {
	m := map[string]string{} // node_key -> overlay_addr
	for _, p := range nm.GetPeers() {
		m[p.GetNodeKey()] = p.GetOverlayAddr()
	}
	return m
}

func TestRegisterAndNetMapPush(t *testing.T) {
	c := startTestServer(t)
	ctx := context.Background()

	a := register(t, c, "a")
	b := register(t, c, "b")
	if a.overlay != "100.64.0.1" {
		t.Fatalf("a overlay = %s, want 100.64.0.1", a.overlay)
	}

	// A opens its netmap stream; initial snapshot must show peer B with B's
	// node_key + overlay.
	stream, err := c.PullNetMap(ctx, &meshpb.PullNetMapRequest{NodeId: a.id, SessionToken: a.token})
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	nm1, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv initial: %v", err)
	}
	if nm1.GetSelf().GetNodeId() != a.id {
		t.Fatalf("self = %d, want %d", nm1.GetSelf().GetNodeId(), a.id)
	}
	pk := peerKeys(nm1)
	if got := pk[b.key.String()]; got != b.overlay {
		t.Fatalf("initial netmap: peer B overlay = %q, want %q (peers=%v)", got, b.overlay, pk)
	}
	if len(pk) != 1 {
		t.Fatalf("initial peers = %d, want 1", len(pk))
	}

	// Registering C must PUSH a fresh netmap to A's already-open stream.
	cc := register(t, c, "c")
	nm2, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv push: %v", err)
	}
	pk2 := peerKeys(nm2)
	if pk2[cc.key.String()] != cc.overlay {
		t.Fatalf("C overlay = %q, want %q (peers=%v)", pk2[cc.key.String()], cc.overlay, pk2)
	}
	if len(pk2) != 2 {
		t.Fatalf("pushed peers = %d, want 2 (b,c)", len(pk2))
	}
}

func TestRegisterAuthDenied(t *testing.T) {
	c := startTestServer(t)
	ctx := context.Background()
	if _, err := c.GetRegisterChallenge(ctx, &meshpb.GetRegisterChallengeRequest{AuthKey: "wrong"}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("challenge with a bad key: code = %v, want Unauthenticated", status.Code(err))
	}
	key, _ := newKeyPair(t)
	_, err := c.RegisterNode(ctx, &meshpb.RegisterNodeRequest{
		AuthKey: "wrong", NodeKey: key.String(), Name: "x", ProtocolVersion: meshproto.ProtocolVersion,
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want Unauthenticated", status.Code(err))
	}
}

// Mesh protocol v2: registering proves possession of the node private key. Each
// refusal below is one way of trying to enroll a key without holding it.
func TestRegisterRequiresProofOfPossession(t *testing.T) {
	c := startTestServer(t)
	ctx := context.Background()
	victim := register(t, c, "victim")
	_, mallory := newKeyPair(t)

	// 1. No challenge at all.
	if _, err := c.RegisterNode(ctx, &meshpb.RegisterNodeRequest{
		AuthKey: devKey, NodeKey: victim.key.String(), Name: "pwned", ProtocolVersion: meshproto.ProtocolVersion,
	}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no challenge: code = %v, want Unauthenticated", status.Code(err))
	}
	// 2. Claim the victim's key, seal with another.
	if _, err := enrollAs(ctx, c, devKey, "pwned", victim.key, mallory, nil); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("wrong private key: code = %v, want Unauthenticated", status.Code(err))
	}
	// 3. Replay a registration that already succeeded.
	var sent *meshpb.RegisterNodeRequest
	if _, err := enrollAs(ctx, c, devKey, "victim", victim.key, victim.priv, func(r *meshpb.RegisterNodeRequest) { sent = r }); err != nil {
		t.Fatalf("the genuine re-registration was refused: %v", err)
	}
	sent.Name = "pwned"
	if _, err := c.RegisterNode(ctx, sent); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("replayed challenge: code = %v, want Unauthenticated", status.Code(err))
	}
	// 4. A genuine proof, filed under a different challenge.
	one, _ := c.GetRegisterChallenge(ctx, &meshpb.GetRegisterChallengeRequest{AuthKey: devKey})
	two, _ := c.GetRegisterChallenge(ctx, &meshpb.GetRegisterChallengeRequest{AuthKey: devKey})
	ch1, _ := meshproto.ParseRegisterChallenge(one.GetChallenge())
	if _, err := c.RegisterNode(ctx, &meshpb.RegisterNodeRequest{
		AuthKey: devKey, NodeKey: victim.key.String(), Name: "victim", ProtocolVersion: meshproto.ProtocolVersion,
		ChallengeId: two.GetChallengeId(), RegisterProof: meshproto.SealRegisterProof(ch1, victim.key, victim.priv),
	}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("proof for another challenge: code = %v, want Unauthenticated", status.Code(err))
	}

	// None of it touched the device.
	observer := register(t, c, "observer")
	nm, err := pullFirst(ctx, c, &meshpb.PullNetMapRequest{NodeId: observer.id, SessionToken: observer.token})
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	for _, p := range nm.GetPeers() {
		if p.GetNodeKey() == victim.key.String() && p.GetName() != "victim" {
			t.Fatalf("the victim's device was renamed to %q", p.GetName())
		}
	}
}

// A challenge answers for the org that asked for it: one obtained with org A's
// key cannot be spent enrolling into org B.
func TestRegisterChallengeIsBoundToTheOrgThatAskedForIt(t *testing.T) {
	c := startTwoOrgServer(t)
	ctx := context.Background()
	key, priv := newKeyPair(t)
	chr, err := c.GetRegisterChallenge(ctx, &meshpb.GetRegisterChallengeRequest{AuthKey: "org-a-key"})
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}
	ch, _ := meshproto.ParseRegisterChallenge(chr.GetChallenge())
	if _, err := c.RegisterNode(ctx, &meshpb.RegisterNodeRequest{
		AuthKey: "org-b-key", NodeKey: key.String(), Name: "x", ProtocolVersion: meshproto.ProtocolVersion,
		ChallengeId: chr.GetChallengeId(), RegisterProof: meshproto.SealRegisterProof(ch, key, priv),
	}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want Unauthenticated", status.Code(err))
	}
}

func TestNodeScopedCallsNeedTheSessionOfThatNode(t *testing.T) {
	c := startTestServer(t)
	ctx := context.Background()
	a := register(t, c, "a")
	b := register(t, c, "b")

	pulls := []struct {
		name string
		req  *meshpb.PullNetMapRequest
		want codes.Code
	}{
		{"no session", &meshpb.PullNetMapRequest{NodeId: a.id}, codes.Unauthenticated},
		{"a made-up session", &meshpb.PullNetMapRequest{NodeId: a.id, SessionToken: "made-up"}, codes.Unauthenticated},
		{"the session of another node", &meshpb.PullNetMapRequest{NodeId: a.id, SessionToken: b.token}, codes.PermissionDenied},
		{"its own session", &meshpb.PullNetMapRequest{NodeId: a.id, SessionToken: a.token}, codes.OK},
	}
	for _, tc := range pulls {
		if _, err := pullFirst(ctx, c, tc.req); status.Code(err) != tc.want {
			t.Errorf("PullNetMap with %s: code = %v, want %v", tc.name, status.Code(err), tc.want)
		}
	}
	if _, err := c.ReportEndpoints(ctx, &meshpb.ReportEndpointsRequest{
		NodeId: a.id, SessionToken: b.token, Endpoints: []string{"203.0.113.7:41641"},
	}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("ReportEndpoints with another node's session: code = %v, want PermissionDenied", status.Code(err))
	}
	if _, err := c.ReportServiceHealth(ctx, &meshpb.ReportServiceHealthRequest{
		NodeId: a.id, Services: []*meshpb.ServiceHealth{{Name: "web", Checked: true}},
	}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("ReportServiceHealth with no session: code = %v, want Unauthenticated", status.Code(err))
	}
}

// Re-registering starts a new session and ends the old one: one live session
// per node, so a token cannot outlive the registration that minted it.
func TestReRegistrationSupersedesTheOldSession(t *testing.T) {
	c := startTestServer(t)
	ctx := context.Background()
	key, priv := newKeyPair(t)
	first, err := enrollAs(ctx, c, devKey, "a", key, priv, nil)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := enrollAs(ctx, c, devKey, "a", key, priv, nil)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if second.GetNodeId() != first.GetNodeId() {
		t.Fatalf("re-registration created node %d, want the same node %d", second.GetNodeId(), first.GetNodeId())
	}
	if _, err := pullFirst(ctx, c, &meshpb.PullNetMapRequest{NodeId: first.GetNodeId(), SessionToken: first.GetSessionToken()}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("superseded session: code = %v, want Unauthenticated", status.Code(err))
	}
	if _, err := pullFirst(ctx, c, &meshpb.PullNetMapRequest{NodeId: second.GetNodeId(), SessionToken: second.GetSessionToken()}); err != nil {
		t.Fatalf("current session refused: %v", err)
	}
}

func TestUpdateNodeDeclarationsUsesTheSession(t *testing.T) {
	c := startTestServer(t)
	ctx := context.Background()
	a := register(t, c, "a")
	b := register(t, c, "b")

	// What an org key plus a public node key used to be enough for.
	if _, err := c.UpdateNodeDeclarations(ctx, &meshpb.UpdateNodeDeclarationsRequest{
		AuthKey: devKey, NodeKey: a.key.String(), DeviceFingerprint: "fp-pwned",
	}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no session: code = %v, want Unauthenticated", status.Code(err))
	}
	if _, err := c.UpdateNodeDeclarations(ctx, &meshpb.UpdateNodeDeclarationsRequest{
		SessionToken: b.token, NodeKey: a.key.String(), DeviceFingerprint: "fp-pwned",
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("another node's session naming a's key: code = %v, want PermissionDenied", status.Code(err))
	}
	resp, err := c.UpdateNodeDeclarations(ctx, &meshpb.UpdateNodeDeclarationsRequest{
		SessionToken: a.token, DeviceFingerprint: "fp-a",
	})
	if err != nil {
		t.Fatalf("its own session: %v", err)
	}
	if resp.GetNodeId() != a.id {
		t.Fatalf("updated node %d, want %d", resp.GetNodeId(), a.id)
	}
}

// A node reports the relay region it measured as closest along with its
// endpoints (MESH.4 B2b); the coordinator records it and peers see it as that
// node's derp_home — which is where they will relay traffic to it.
func TestReportEndpointsSetsMeasuredHome(t *testing.T) {
	c := startTestServer(t)
	ctx := context.Background()
	a := register(t, c, "a")
	b := register(t, c, "b")

	if _, err := c.ReportEndpoints(ctx, &meshpb.ReportEndpointsRequest{
		NodeId:       a.id,
		SessionToken: a.token,
		Endpoints:    []string{"203.0.113.7:41641"},
		HomeRegion:   "lax",
	}); err != nil {
		t.Fatalf("report: %v", err)
	}

	nm, err := pullFirst(ctx, c, &meshpb.PullNetMapRequest{NodeId: b.id, SessionToken: b.token})
	if err != nil {
		t.Fatalf("pull netmap: %v", err)
	}
	var seen string
	for _, p := range nm.GetPeers() {
		if p.GetNodeKey() == a.key.String() {
			seen = p.GetDerpHome()
		}
	}
	if seen != "lax" {
		t.Fatalf("peer a's derp_home = %q, want the region it reported (lax)", seen)
	}
}

// Every node re-reports its endpoints each minute whether or not it roamed.
// Only a report that changes what peers see (the endpoint set, the home region)
// may push a netmap: each push re-sends the full map to every stream in the
// meshnet, which on a phone is a radio wake-up per push.
func TestReportEndpointsPushesOnlyOnChange(t *testing.T) {
	c := startTestServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := register(t, c, "a")
	b := register(t, c, "b")

	stream, err := c.PullNetMap(ctx, &meshpb.PullNetMapRequest{NodeId: a.id, SessionToken: a.token})
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("recv initial: %v", err)
	}
	pushes := make(chan *meshpb.NetMap, 16)
	go func() {
		for {
			nm, err := stream.Recv()
			if err != nil {
				close(pushes)
				return
			}
			pushes <- nm
		}
	}()
	report := func(home string, eps ...string) {
		t.Helper()
		if _, err := c.ReportEndpoints(ctx, &meshpb.ReportEndpointsRequest{
			NodeId: b.id, SessionToken: b.token, Endpoints: eps, HomeRegion: home,
		}); err != nil {
			t.Fatalf("report %v: %v", eps, err)
		}
	}
	// next returns B's endpoints and home as the next pushed netmap shows them.
	next := func() (map[string]bool, string) {
		t.Helper()
		select {
		case nm, ok := <-pushes:
			if !ok {
				t.Fatal("netmap stream ended")
			}
			for _, p := range nm.GetPeers() {
				if p.GetNodeKey() == b.key.String() {
					eps := map[string]bool{}
					for _, ep := range p.GetEndpoints() {
						eps[ep] = true
					}
					return eps, p.GetDerpHome()
				}
			}
			t.Fatal("pushed netmap has no peer b")
		case <-time.After(5 * time.Second):
			t.Fatal("no netmap pushed")
		}
		return nil, ""
	}
	// quiet asserts nothing is pushed for a while. Only used right before a
	// report that DOES push, whose content then tells which report it came from.
	quiet := func(what string) {
		t.Helper()
		select {
		case <-pushes:
			t.Fatalf("%s pushed a netmap", what)
		case <-time.After(300 * time.Millisecond):
		}
	}

	report("", "203.0.113.7:41641", "192.0.2.10:41641")
	if eps, _ := next(); !eps["203.0.113.7:41641"] || !eps["192.0.2.10:41641"] {
		t.Fatalf("first report: peer b endpoints = %v", eps)
	}

	report("", "192.0.2.10:41641", "203.0.113.7:41641") // same set, other order
	quiet("re-reporting the same endpoints")

	report("", "198.51.100.3:41641") // roamed
	if eps, _ := next(); !eps["198.51.100.3:41641"] || len(eps) != 1 {
		t.Fatalf("after roaming: peer b endpoints = %v, want just the new one", eps)
	}

	report("lax", "198.51.100.3:41641") // same endpoints, new home
	if _, home := next(); home != "lax" {
		t.Fatalf("after home change: peer b derp_home = %q, want lax", home)
	}

	report("lax", "198.51.100.3:41641")
	quiet("re-reporting the same endpoints and home")
}

func TestSameAddrPortSet(t *testing.T) {
	ap := netip.MustParseAddrPort
	x, y, z := ap("192.0.2.1:1"), ap("192.0.2.2:2"), ap("192.0.2.3:3")
	for _, tc := range []struct {
		a, b []netip.AddrPort
		want bool
	}{
		{nil, nil, true},
		{nil, []netip.AddrPort{x}, false},
		{[]netip.AddrPort{x}, nil, false},
		{[]netip.AddrPort{x, y}, []netip.AddrPort{y, x}, true},
		{[]netip.AddrPort{x, y}, []netip.AddrPort{x, y, y}, true},
		{[]netip.AddrPort{x, y}, []netip.AddrPort{x, z}, false},
		{[]netip.AddrPort{x, y}, []netip.AddrPort{x}, false},
		{[]netip.AddrPort{x}, []netip.AddrPort{x, y}, false},
	} {
		if got := sameAddrPortSet(tc.a, tc.b); got != tc.want {
			t.Errorf("sameAddrPortSet(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

// The coordinator publishes the relay map, so it also decides what a valid home
// is: a region it never published is refused rather than handed to peers.
func TestReportEndpointsRejectsUnknownHomeRegion(t *testing.T) {
	c := startTestServer(t)
	a := register(t, c, "a")

	_, err := c.ReportEndpoints(context.Background(), &meshpb.ReportEndpointsRequest{
		NodeId:       a.id,
		SessionToken: a.token,
		Endpoints:    []string{"203.0.113.7:41641"},
		HomeRegion:   "atlantis",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("err = %v (code %s), want InvalidArgument", err, status.Code(err))
	}
}

// A node below mesh protocol v2 cannot answer the registration challenge or
// carry a session, so it is refused AT registration with an error that says why -
// not half-enrolled and then refused on every call after.
func TestRegisterRefusesPreV2Protocol(t *testing.T) {
	c := startTestServer(t)
	key, _ := newKeyPair(t)
	for _, v := range []uint32{0, 1} {
		_, err := c.RegisterNode(context.Background(), &meshpb.RegisterNodeRequest{
			AuthKey: devKey, NodeKey: key.String(), Name: "old", ProtocolVersion: v,
		})
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("protocol v%d: code = %v, want FailedPrecondition", v, status.Code(err))
		}
	}
}
