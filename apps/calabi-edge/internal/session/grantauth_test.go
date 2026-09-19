package session

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	"golang.org/x/crypto/nacl/box"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
	proto "github.com/calabi/calabi/pkg/protocol"
)

// testGrants is the GrantAuth a standalone edge wires (cmd/calabi-edge coordGrants):
// the coordinator's signature, valid now, good for a self-hosted node.
type testGrants struct{ pub ed25519.PublicKey }

func (g testGrants) VerifyGrant(grant []byte, now time.Time) (meshproto.RelayGrant, error) {
	rg, err := meshproto.VerifyRelayGrant(g.pub, grant, now)
	if err != nil {
		return rg, err
	}
	if !rg.Scope.Permits(meshproto.RelayKindSelfHosted) {
		return rg, errors.New("scope")
	}
	return rg, nil
}

type testDevice struct {
	key  meshproto.NodeKey
	priv [meshproto.KeyLen]byte
}

func newTestDevice(t *testing.T) testDevice {
	t.Helper()
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testDevice{key: meshproto.NodeKey(*pub), priv: *priv}
}

type testCoord struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newTestCoord(t *testing.T) testCoord {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testCoord{pub: pub, priv: priv}
}

func (c testCoord) grant(t *testing.T, node meshproto.NodeKey, meshnet int64, expiry time.Time) []byte {
	t.Helper()
	g, err := meshproto.SignRelayGrant(c.priv, meshproto.RelayGrant{Node: node, Meshnet: meshnet, Scope: meshproto.RelayScopeAll, Expiry: expiry})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// edgeRig is an edge session on one end of an in-memory yamux connection and
// the device's control stream on the other.
type edgeRig struct {
	sess   *Session
	client io.ReadWriteCloser
}

func newEdgeRig(t *testing.T) edgeRig {
	t.Helper()
	a, b := net.Pipe()
	srv, err := yamux.Server(a, nil)
	if err != nil {
		t.Fatal(err)
	}
	cli, err := yamux.Client(b, nil)
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := srv.Accept()
		accepted <- c
	}()
	ctrl, err := cli.Open()
	if err != nil {
		t.Fatal(err)
	}
	s := New(slog.New(slog.NewTextHandler(io.Discard, nil)), srv, <-accepted)
	t.Cleanup(func() { _ = s.Close(); _ = cli.Close() })
	return edgeRig{sess: s, client: ctrl}
}

func (r edgeRig) send(t *testing.T, ft proto.FrameType, v any) {
	t.Helper()
	b, err := proto.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := proto.WriteFrame(r.client, proto.Frame{Version: proto.CurrentMajor, Type: ft, Payload: b}); err != nil {
		t.Fatal(err)
	}
}

func (r edgeRig) read(t *testing.T) proto.Frame {
	t.Helper()
	f, err := proto.ReadFrame(r.client)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	return f
}

// handshake runs the edge's side with grant auth and the device's side with
// makeAuth, which gets the challenge the edge sent.
func (r edgeRig) handshake(t *testing.T, grants GrantAuth, makeAuth func(ch meshproto.EdgeChallenge) proto.AuthRequest) (HandshakeResult, error, proto.AuthResponse) {
	t.Helper()
	type result struct {
		res HandshakeResult
		err error
	}
	done := make(chan result, 1)
	go func() {
		res, err := r.sess.PerformServerHandshake("edge-1", "test", "example.com", 0, 0, nil, grants)
		done <- result{res, err}
	}()
	r.send(t, proto.FrameHello, proto.HelloRequest{ProtocolMajor: uint32(proto.CurrentMajor)})
	var ack proto.HelloAck
	if err := proto.Unmarshal(r.read(t).Payload, &ack); err != nil {
		t.Fatal(err)
	}
	ch, err := meshproto.ParseEdgeChallenge(ack.AuthChallenge)
	if err != nil {
		t.Fatalf("HELLO_ACK carries no usable challenge: %v", err)
	}
	r.send(t, proto.FrameAuth, makeAuth(ch))
	var resp proto.AuthResponse
	if err := proto.Unmarshal(r.read(t).Payload, &resp); err != nil {
		t.Fatal(err)
	}
	out := <-done
	return out.res, out.err, resp
}

func TestGrantHandshakeAcceptsTheDeviceTheCoordinatorVouchesFor(t *testing.T) {
	coord, dev := newTestCoord(t), newTestDevice(t)
	r := newEdgeRig(t)
	res, err, resp := r.handshake(t, testGrants{coord.pub}, func(ch meshproto.EdgeChallenge) proto.AuthRequest {
		return proto.AuthRequest{Grant: coord.grant(t, dev.key, 7, time.Now().Add(time.Hour)), Proof: meshproto.SealEdgeProof(ch, dev.key, dev.priv)}
	})
	if err != nil || resp.Error != nil {
		t.Fatalf("refused: %v / %+v", err, resp.Error)
	}
	if res.TenantID != "7" || resp.TenantID != "7" {
		t.Fatalf("tenant = %q / %q, want the grant's meshnet 7", res.TenantID, resp.TenantID)
	}
	if res.ClientID != dev.key.String() {
		t.Fatalf("client = %q, want the device's node key", res.ClientID)
	}
}

func TestGrantHandshakeRefuses(t *testing.T) {
	coord, dev := newTestCoord(t), newTestDevice(t)
	other, stranger := newTestCoord(t), newTestDevice(t)
	for name, makeAuth := range map[string]func(t *testing.T, ch meshproto.EdgeChallenge) proto.AuthRequest{
		// Seeing a grant — any peer can see a node key — is not holding its key.
		"a proof by another key": func(t *testing.T, ch meshproto.EdgeChallenge) proto.AuthRequest {
			return proto.AuthRequest{Grant: coord.grant(t, dev.key, 7, time.Now().Add(time.Hour)), Proof: meshproto.SealEdgeProof(ch, dev.key, stranger.priv)}
		},
		"another coordinator's grant": func(t *testing.T, ch meshproto.EdgeChallenge) proto.AuthRequest {
			return proto.AuthRequest{Grant: other.grant(t, dev.key, 7, time.Now().Add(time.Hour)), Proof: meshproto.SealEdgeProof(ch, dev.key, dev.priv)}
		},
		"an expired grant": func(t *testing.T, ch meshproto.EdgeChallenge) proto.AuthRequest {
			return proto.AuthRequest{Grant: coord.grant(t, dev.key, 7, time.Now().Add(-time.Minute)), Proof: meshproto.SealEdgeProof(ch, dev.key, dev.priv)}
		},
		"a token instead": func(t *testing.T, _ meshproto.EdgeChallenge) proto.AuthRequest {
			return proto.AuthRequest{Token: "dev-token-please-change"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := newEdgeRig(t)
			_, err, resp := r.handshake(t, testGrants{coord.pub}, func(ch meshproto.EdgeChallenge) proto.AuthRequest { return makeAuth(t, ch) })
			if err == nil || resp.Error == nil {
				t.Fatal("accepted")
			}
			if resp.Error.Code != proto.CodeAuthInvalidToken {
				t.Fatalf("code = %d, want %d (the client reads it as a refused credential)", resp.Error.Code, proto.CodeAuthInvalidToken)
			}
		})
	}
}

// A session lives as long as its device keeps presenting fresh grants for the
// key it proved: a renewal extends it, and one for another device ends it.
func TestGrantRefresh(t *testing.T) {
	coord, dev, other := newTestCoord(t), newTestDevice(t), newTestDevice(t)
	r := newEdgeRig(t)
	first := time.Now().Add(time.Hour)
	if _, err, _ := r.handshake(t, testGrants{coord.pub}, func(ch meshproto.EdgeChallenge) proto.AuthRequest {
		return proto.AuthRequest{Grant: coord.grant(t, dev.key, 7, first), Proof: meshproto.SealEdgeProof(ch, dev.key, dev.priv)}
	}); err != nil {
		t.Fatal(err)
	}
	refresh := func(g []byte) proto.Frame {
		b, _ := proto.Marshal(proto.AuthRefresh{Grant: g})
		return proto.Frame{Type: proto.FrameAuthRefresh, Payload: b}
	}

	later := time.Now().Add(2 * time.Hour)
	r.sess.handleAuthRefresh(refresh(coord.grant(t, dev.key, 7, later)))
	r.sess.mu.Lock()
	got := r.sess.grantExpiry
	r.sess.mu.Unlock()
	// Grants carry whole seconds.
	if got.Before(later.Add(-time.Second)) {
		t.Fatalf("expiry %v after a renewal to %v", got, later)
	}

	errFrame := make(chan proto.Frame, 1)
	go func() {
		f, err := proto.ReadFrame(r.client)
		if err == nil {
			errFrame <- f
		}
	}()
	r.sess.handleAuthRefresh(refresh(coord.grant(t, other.key, 7, later)))
	select {
	case <-r.sess.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("a renewal for another device did not end the session")
	}
	select {
	case f := <-errFrame:
		if f.Type != proto.FrameError {
			t.Fatalf("got %s, want ERROR", f.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the device was not told why")
	}
}

// A grant that runs out unrenewed ends the session — how a device deleted or
// disabled on the coordinator loses its tunnels.
func TestGrantExpiryEndsTheSession(t *testing.T) {
	coord, dev := newTestCoord(t), newTestDevice(t)
	r := newEdgeRig(t)
	if _, err, _ := r.handshake(t, testGrants{coord.pub}, func(ch meshproto.EdgeChallenge) proto.AuthRequest {
		return proto.AuthRequest{Grant: coord.grant(t, dev.key, 7, time.Now().Add(1500*time.Millisecond)), Proof: meshproto.SealEdgeProof(ch, dev.key, dev.priv)}
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.sess.watchGrantExpiry(ctx)
	errFrame := make(chan proto.Frame, 1)
	go func() {
		f, err := proto.ReadFrame(r.client)
		if err == nil {
			errFrame <- f
		}
	}()
	select {
	case <-r.sess.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the session outlived its grant")
	}
	select {
	case f := <-errFrame:
		var e proto.ErrorPayload
		_ = proto.Unmarshal(f.Payload, &e)
		if f.Type != proto.FrameError || e.MessageKey != "calabi.err.auth.grant_expired" {
			t.Fatalf("got %s %+v, want ERROR grant_expired", f.Type, e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the device was not told why")
	}
}

// A token-verifier session has no grant and is not watched.
func TestTokenSessionIsNotWatchedForAGrant(t *testing.T) {
	r := newEdgeRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { r.sess.watchGrantExpiry(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("watchGrantExpiry waited on a session with no grant")
	}
	select {
	case <-r.sess.Done():
		t.Fatal("a token session was ended for having no grant")
	default:
	}
}
