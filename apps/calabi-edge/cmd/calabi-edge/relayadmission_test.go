package main

// A node's own relay on calabi.net (config.BYOIRelay) admits its organization's
// devices only, by grants checked against the key its registration returns
// (relayadmission.go). These drive runRelay over a real loopback listener, the
// way a device reaches it.

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/calabinet/calabi/apps/calabi-edge/internal/config"
	bffedge "github.com/calabinet/calabi/pkg/edge-proto/edgepb"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

const testOrg = 7

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

type testSigner struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newSigner(t *testing.T) testSigner {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testSigner{pub: pub, priv: priv}
}

func (s testSigner) grant(t *testing.T, d testDevice, meshnet int64) []byte {
	t.Helper()
	g, err := meshproto.SignRelayGrant(s.priv, meshproto.RelayGrant{
		Node: d.key, Meshnet: meshnet, Scope: meshproto.RelayScopeAll, Expiry: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

type testDevice struct {
	key  meshproto.NodeKey
	priv [meshproto.KeyLen]byte
}

func newDevice(t *testing.T) testDevice {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var d testDevice
	copy(d.key[:], k.PublicKey().Bytes())
	copy(d.priv[:], k.Bytes())
	return d
}

// dial connects the way a device does: ClientInfo, a ping, and an answer —
// sealed with its own key, carrying grant (possibly none) — to a challenge if
// the relay sends one. admitted means the relay answered the ping, which it does
// only for a registered link. The connection is returned open.
func (d testDevice) dial(t *testing.T, addr string, grant []byte) (challenged, admitted bool, conn net.Conn) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	challenged, admitted = d.speak(t, conn, func(ch meshproto.DERPAuthChallenge) ([]byte, error) {
		return meshproto.SealDERPAuthProof(ch, d.key, d.priv, grant)
	})
	return challenged, admitted, conn
}

// speak runs the device's side of the relay protocol over conn, answering a
// challenge with whatever seal makes of it. admitted means the relay answered
// the ping, which it does only for a registered link.
func (d testDevice) speak(t *testing.T, conn net.Conn, seal func(meshproto.DERPAuthChallenge) ([]byte, error)) (challenged, admitted bool) {
	t.Helper()
	probe := []byte("admitted?")
	if err := meshproto.WriteDERPFrame(conn, meshproto.DERPFrameClientInfo, d.key[:]); err != nil {
		t.Fatalf("client info: %v", err)
	}
	_ = meshproto.WriteDERPFrame(conn, meshproto.DERPFramePing, probe)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	for {
		typ, payload, err := meshproto.ReadDERPFrame(conn)
		if err != nil {
			return challenged, false
		}
		switch typ {
		case meshproto.DERPFrameAuthChallenge:
			challenged = true
			ch, err := meshproto.ParseDERPAuthChallenge(payload)
			if err != nil {
				t.Fatalf("parse challenge: %v", err)
			}
			proof, err := seal(ch)
			if err != nil {
				t.Fatalf("seal proof: %v", err)
			}
			_ = meshproto.WriteDERPFrame(conn, meshproto.DERPFrameAuthProof, proof)
			// The first ping was discarded: the relay drops everything before the proof.
			_ = meshproto.WriteDERPFrame(conn, meshproto.DERPFramePing, probe)
		case meshproto.DERPFramePong:
			return challenged, true
		}
	}
}

// waitClosed reports whether the relay closed conn within d.
func waitClosed(conn net.Conn, d time.Duration) bool {
	_ = conn.SetReadDeadline(time.Now().Add(d))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	for {
		if _, _, err := meshproto.ReadDERPFrame(conn); err != nil {
			var ne net.Error
			return !(errors.As(err, &ne) && ne.Timeout())
		}
	}
}

// startRelay runs runRelay for a node's own relay with a loopback listener, and
// returns a channel that yields the listener's address once runRelay asks for
// one — i.e. once it has decided how to admit devices.
func startRelay(t *testing.T, rc config.MeshService, w relayWiring) <-chan string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listening := make(chan string, 1)
	orig := relayListen
	relayListen = func(string) (net.Listener, error) {
		listening <- ln.Addr().String()
		return ln, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runRelay(ctx, rc, quietLog(), w) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("runRelay: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("runRelay did not return after shutdown")
		}
		relayListen = orig
		_ = ln.Close()
	})
	return listening
}

func listeningWithin(t *testing.T, listening <-chan string, d time.Duration) string {
	t.Helper()
	select {
	case addr := <-listening:
		return addr
	case <-time.After(d):
		t.Fatal("the relay never started listening")
		return ""
	}
}

// relayOnlyNoSTUN is a mesh block that binds nothing but the listener the test
// hands over.
var relayOnlyNoSTUN = config.MeshService{STUNPort: -1, Label: "tokyo"}

// THE regression. Until the platform answers the relay's registration it does
// not listen; once it has, it admits the organization's devices proving a grant,
// and nobody else: not a device with no grant, not a device of another
// organization with a grant the same coordinator genuinely signed.
func TestOwnRelayWaitsForItsRegistrationThenAdmitsOnlyItsOrganization(t *testing.T) {
	coord := newSigner(t)
	adm := newRelayAdmission("", quietLog())
	listening := startRelay(t, relayOnlyNoSTUN, relayWiring{admission: adm, org: testOrg})

	select {
	case <-listening:
		t.Fatal("the relay listened before it knew how to check devices")
	case <-time.After(300 * time.Millisecond):
	}
	if err := adm.learn(coord.pub); err != nil {
		t.Fatal(err)
	}
	addr := listeningWithin(t, listening, 2*time.Second)

	member, stranger, other := newDevice(t), newDevice(t), newDevice(t)
	if challenged, admitted, _ := member.dial(t, addr, coord.grant(t, member, testOrg)); !challenged || !admitted {
		t.Fatalf("organization's device: challenged=%v admitted=%v, want both", challenged, admitted)
	}
	if challenged, admitted, _ := stranger.dial(t, addr, nil); !challenged || admitted {
		t.Fatalf("device with no grant: challenged=%v admitted=%v, want challenged and refused", challenged, admitted)
	}
	if challenged, admitted, _ := other.dial(t, addr, coord.grant(t, other, testOrg+1)); !challenged || admitted {
		t.Fatalf("another organization's device: challenged=%v admitted=%v, want challenged and refused", challenged, admitted)
	}
}

// The control for the test above, and the rollout guarantee: a platform that
// signs no grants (or a gateway that predates the key) answers with none, and
// the relay then admits devices without one — they hold nothing to present, so
// demanding one would turn every device away.
func TestOwnRelayAdmitsWithoutGrantsWhenThePlatformSignsNone(t *testing.T) {
	adm := newRelayAdmission("", quietLog())
	if err := adm.learn(nil); err != nil {
		t.Fatal(err)
	}
	addr := listeningWithin(t, startRelay(t, relayOnlyNoSTUN, relayWiring{admission: adm, org: testOrg}), 2*time.Second)

	if challenged, admitted, _ := newDevice(t).dial(t, addr, nil); challenged || !admitted {
		t.Fatalf("challenged=%v admitted=%v, want admitted without a challenge", challenged, admitted)
	}
}

// When the key arrives later — the platform started signing grants, or its
// gateway was upgraded under a running relay — the relay checks from then on,
// and a link it admitted without a grant does not survive the change.
func TestOwnRelayStartsCheckingWhenTheKeyArrives(t *testing.T) {
	coord := newSigner(t)
	adm := newRelayAdmission("", quietLog())
	_ = adm.learn(nil)
	addr := listeningWithin(t, startRelay(t, relayOnlyNoSTUN, relayWiring{admission: adm, org: testOrg}), 2*time.Second)

	_, admitted, early := newDevice(t).dial(t, addr, nil)
	if !admitted {
		t.Fatal("setup: the relay should admit without grants before the key arrives")
	}
	if err := adm.learn(coord.pub); err != nil {
		t.Fatal(err)
	}
	if !waitClosed(early, 2*time.Second) {
		t.Fatal("a link admitted without a grant outlived the switch to checking grants")
	}

	member := newDevice(t)
	if challenged, admitted, _ := member.dial(t, addr, coord.grant(t, member, testOrg)); !challenged || !admitted {
		t.Fatalf("organization's device after the switch: challenged=%v admitted=%v", challenged, admitted)
	}
	if _, admitted, _ := newDevice(t).dial(t, addr, nil); admitted {
		t.Fatal("a device with no grant got in after the switch")
	}
}

// A new platform key is followed: grants signed with the old one stop working,
// grants signed with the new one work, and nobody has to restart the node.
func TestOwnRelayFollowsAKeyRotation(t *testing.T) {
	oldKey, newKey := newSigner(t), newSigner(t)
	adm := newRelayAdmission("", quietLog())
	_ = adm.learn(oldKey.pub)
	addr := listeningWithin(t, startRelay(t, relayOnlyNoSTUN, relayWiring{admission: adm, org: testOrg}), 2*time.Second)

	d := newDevice(t)
	_, admitted, before := d.dial(t, addr, oldKey.grant(t, d, testOrg))
	if !admitted {
		t.Fatal("setup: a grant under the current key was refused")
	}
	_ = adm.learn(newKey.pub)
	if !waitClosed(before, 2*time.Second) {
		t.Fatal("links checked under the old key survived the rotation")
	}
	if _, admitted, _ := d.dial(t, addr, oldKey.grant(t, d, testOrg)); admitted {
		t.Fatal("a grant under the old key still got in")
	}
	if _, admitted, _ := d.dial(t, addr, newKey.grant(t, d, testOrg)); !admitted {
		t.Fatal("a grant under the new key was refused")
	}
}

// A restart while the platform cannot be reached starts checking at once, with
// the key the last run heard, instead of staying down until the platform
// answers. A later answer with no key drops the kept one.
func TestOwnRelayStartsWithTheKeyKeptFromTheLastRun(t *testing.T) {
	coord := newSigner(t)
	dir := t.TempDir()
	if err := newRelayAdmission(dir, quietLog()).learn(coord.pub); err != nil {
		t.Fatal(err)
	}

	restarted := newRelayAdmission(dir, quietLog()) // nothing heard yet this run
	addr := listeningWithin(t, startRelay(t, relayOnlyNoSTUN, relayWiring{admission: restarted, org: testOrg}), 2*time.Second)
	member := newDevice(t)
	if challenged, admitted, _ := member.dial(t, addr, coord.grant(t, member, testOrg)); !challenged || !admitted {
		t.Fatalf("with the kept key: challenged=%v admitted=%v", challenged, admitted)
	}
	if _, admitted, _ := newDevice(t).dial(t, addr, nil); admitted {
		t.Fatal("with the kept key, a device with no grant got in")
	}

	_ = restarted.learn(nil)
	if _, err := os.Stat(filepath.Join(dir, relayGrantKeyFile)); !os.IsNotExist(err) {
		t.Fatalf("the kept key survived an answer with none (stat err %v)", err)
	}
}

// A node whose config names the key uses it as given: it listens at once, never
// waits for the platform, and still admits its organization's devices only.
func TestOwnRelayWithAConfiguredKeyDoesNotWait(t *testing.T) {
	coord := newSigner(t)
	rc := relayOnlyNoSTUN
	rc.CoordPubKey = base64.StdEncoding.EncodeToString(coord.pub)
	adm := newRelayAdmission("", quietLog()) // never answered
	addr := listeningWithin(t, startRelay(t, rc, relayWiring{admission: adm, org: testOrg}), 2*time.Second)

	member, other := newDevice(t), newDevice(t)
	if _, admitted, _ := member.dial(t, addr, coord.grant(t, member, testOrg)); !admitted {
		t.Fatal("organization's device was refused")
	}
	if _, admitted, _ := other.dial(t, addr, coord.grant(t, other, testOrg+1)); admitted {
		t.Fatal("another organization's device got in")
	}
}

// What the relay starts from. Only a node's own relay is changed: every other
// relay keeps its config's posture, including the refusal of require_auth with
// no key to check against.
func TestRelayStartAuth(t *testing.T) {
	coord := newSigner(t)
	adm := newRelayAdmission("", quietLog())

	auth, follow, err := relayStartAuth(config.MeshService{}, relayWiring{admission: adm, org: testOrg}, quietLog())
	if err != nil || !follow || !auth.Require || auth.Meshnet != testOrg || auth.Kind != meshproto.RelayKindSelfHosted {
		t.Fatalf("own relay, no key: auth=%+v follow=%v err=%v; want require, meshnet %d, self kind, follow", auth, follow, err, testOrg)
	}
	auth, follow, err = relayStartAuth(config.MeshService{CoordPubKey: base64.StdEncoding.EncodeToString(coord.pub)},
		relayWiring{admission: adm, org: testOrg}, quietLog())
	if err != nil || follow || !auth.Require || auth.CoordPub == nil || auth.Meshnet != testOrg {
		t.Fatalf("own relay, configured key: auth=%+v follow=%v err=%v; want require with that key, not following", auth, follow, err)
	}
	if _, _, err := relayStartAuth(config.MeshService{RequireAuth: true}, relayWiring{}, quietLog()); err == nil {
		t.Fatal("a relay that is not a node's own must still refuse require_auth with no key")
	}
	if auth, _, err := relayStartAuth(config.MeshService{}, relayWiring{}, quietLog()); err != nil || auth.Require || auth.Meshnet != 0 {
		t.Fatalf("a relay that is not a node's own changed: auth=%+v err=%v", auth, err)
	}
}

// fakeRegisterer answers RegisterRelay with resp or err.
type fakeRegisterer struct {
	resp *bffedge.RegisterRelayResponse
	err  error
}

func (f fakeRegisterer) RegisterRelay(context.Context, *bffedge.RegisterRelayRequest, ...grpc.CallOption) (*bffedge.RegisterRelayResponse, error) {
	return f.resp, f.err
}

// The registration heartbeat is what carries the key to the relay; a garbled
// one is a failed heartbeat and changes nothing about whom the relay admits.
func TestRegisterRelayOnceHandsTheKeyToTheRelay(t *testing.T) {
	coord := newSigner(t)
	req := &bffedge.RegisterRelayRequest{Label: "tokyo", Host: "relay.example", DerpPort: 3340}
	adm := newRelayAdmission("", quietLog())

	if err := registerRelayOnce(context.Background(), fakeRegisterer{err: errors.New("unavailable")}, req, adm); err == nil {
		t.Fatal("a failed registration reported success")
	}
	if heard, _, _ := adm.current(); heard {
		t.Fatal("a failed registration counted as an answer")
	}
	if err := registerRelayOnce(context.Background(),
		fakeRegisterer{resp: &bffedge.RegisterRelayResponse{CoordGrantPubkey: []byte("sixteen bytes!!!")}}, req, adm); err == nil {
		t.Fatal("a garbled key was accepted")
	}
	if heard, _, _ := adm.current(); heard {
		t.Fatal("a garbled key counted as an answer")
	}
	if err := registerRelayOnce(context.Background(),
		fakeRegisterer{resp: &bffedge.RegisterRelayResponse{CoordGrantPubkey: coord.pub}}, req, adm); err != nil {
		t.Fatalf("registration: %v", err)
	}
	if heard, key, _ := adm.current(); !heard || !key.Equal(coord.pub) {
		t.Fatalf("heard=%v key=%x, want the platform's key", heard, []byte(key))
	}
}

// A relay that cannot register waits for an answer that never comes — and
// shuts down cleanly when asked, rather than holding the edge up.
func TestOwnRelayThatCannotRegisterNeverListens(t *testing.T) {
	adm := newRelayAdmission("", quietLog())
	adm.cannotRegister("no public.host")
	listening := startRelay(t, relayOnlyNoSTUN, relayWiring{admission: adm, org: testOrg})
	select {
	case <-listening:
		t.Fatal("a relay that cannot learn its key listened anyway")
	case <-time.After(300 * time.Millisecond):
	}
}
