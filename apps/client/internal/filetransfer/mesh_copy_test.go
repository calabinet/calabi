package filetransfer

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"testing/iotest"
	"time"
)

func meshCopyPair(t *testing.T) (*Agent, *Agent) {
	return meshCopyPairPath(t, "relay")
}
func meshCopyPairPath(t *testing.T, path string) (*Agent, *Agent) {
	t.Helper()
	ips := []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2")}
	ids := make([]*Identity, 2)
	listeners := make([]net.Listener, 2)
	agents := make([]*Agent, 2)
	for i := range ids {
		var e error
		ids[i], e = NewIdentity()
		if e != nil {
			t.Fatal(e)
		}
		listeners[i], e = net.Listen("tcp", net.JoinHostPort(ips[i].String(), "0"))
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { listeners[i].Close() })
	}
	for i := range agents {
		peer := 1 - i
		port := listeners[i].Addr().(*net.TCPAddr).Port
		g := Grant{Path: path, Peer: Peer{IP: ips[peer], Fingerprint: ids[peer].Fingerprint}, Port: uint16(listeners[peer].Addr().(*net.TCPAddr).Port), DeviceKey: ips[peer].String()}
		var e error
		agents[i], e = NewAgent(AgentConfig{Directory: t.TempDir(), Scope: "copy-test", Identity: ids[i], LocalIP: ips[i], Port: uint16(port), Kbps: 100000, MaxBytes: ShellPasteLimit,
			Resolve: func(ip netip.Addr) (Grant, bool) { return g, ip == g.Peer.IP }, Incoming: func(netip.Addr, uint16) bool { return true }, ClipboardPeer: func(peer Grant) bool { return peer.DeviceKey == g.DeviceKey }})
		if e != nil {
			t.Fatal(e)
		}
		a := agents[i]
		done, e := a.Serve(listeners[i])
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { a.Close(); <-done })
	}
	return agents[0], agents[1]
}
func awaitCopy(t *testing.T, a *Agent, offer string, index int, offset int64, n int) []byte {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		b, pending, e := a.CopyRead(offer, index, offset, n)
		if e != nil {
			t.Fatal(e)
		}
		if !pending {
			return b
		}
		time.Sleep(time.Millisecond * 5)
	}
	t.Fatal("copy read timeout")
	return nil
}
func TestMeshCopyBidirectionalPullAndRevocation(t *testing.T) {
	a, b := meshCopyPair(t)
	ctx := context.Background()
	id, e := a.CopyStart(ctx, b.cfg.LocalIP)
	if e != nil {
		t.Fatal(e)
	}
	if a.Receiving() || b.Receiving() {
		t.Fatal("fixture must disable ordinary reception")
	}
	for _, pair := range [][2]*Agent{{a, b}, {b, a}} {
		src, dst := pair[0], pair[1]
		data := bytes.Repeat([]byte("中文-copy"), 8192)
		path := filepath.Join(t.TempDir(), "source.bin")
		if e = os.WriteFile(path, data, 0600); e != nil {
			t.Fatal(e)
		}
		if e = src.CopyOffer(ctx, id, []string{path}); e != nil {
			t.Fatal(e)
		}
		snap := dst.CopySnapshot()
		if snap.Offer == "" || len(snap.Manifest) != 596 {
			t.Fatal("missing offer")
		}
		if src.copySession.pending != nil || dst.copySession.pending != nil {
			t.Fatal("must not pull before paste")
		}
		if _, _, e = dst.CopyRead(snap.Offer, 1, 0, 1); e == nil {
			t.Fatal("invalid index accepted")
		}
		if _, _, e = dst.CopyRead(snap.Offer, 0, int64(len(data)), 1); e == nil {
			t.Fatal("past EOF accepted")
		}
		if got := awaitCopy(t, dst, snap.Offer, 0, 0, 65536); !bytes.Equal(got, data[:65536]) {
			t.Fatal("first block mismatch")
		}
		if got := awaitCopy(t, dst, snap.Offer, 0, 65536, len(data)-65536); !bytes.Equal(got, data[65536:]) {
			t.Fatal("tail mismatch")
		}
		dst.CopyCancel(snap.Offer)
		if _, _, e = dst.CopyRead(snap.Offer, 0, 0, 1); e == nil {
			t.Fatal("cancelled offer readable")
		}
	}
	if e = a.CopyRenew(ctx, id); e != nil {
		t.Fatal(e)
	}
	a.CopyClose(ctx, id)
	if a.CopySnapshot().Session != "" || b.CopySnapshot().Session != "" {
		t.Fatal("close did not revoke both ends")
	}
}
func TestMeshCopyLeaseAndStaleSession(t *testing.T) {
	a, b := meshCopyPair(t)
	ctx := context.Background()
	id, e := a.CopyStart(ctx, b.cfg.LocalIP)
	if e != nil {
		t.Fatal(e)
	}
	if e = a.CopyRenew(context.Background(), copyID()); e == nil {
		t.Fatal("wrong session renewed")
	}
	a.copyMu.Lock()
	a.copySession.until = time.Now().Add(-time.Second)
	a.copyMu.Unlock()
	if a.CopySnapshot().Session != "" {
		t.Fatal("expired session active")
	}
	if e = a.CopyRenew(context.Background(), id); e == nil {
		t.Fatal("expired session renewed")
	}
	if _, _, e = a.CopyRead(copyID(), 0, 0, 1); !errors.Is(e, ErrCopySessionEnded) {
		t.Fatalf("expired session returned %v", e)
	}
	if _, e := a.CopyStart(ctx, b.cfg.LocalIP); e == nil {
		t.Fatal("recovery displaced the live host lease")
	}
	b.copyMu.Lock()
	b.copySession.until = time.Now().Add(-time.Second)
	b.copyMu.Unlock()
	recovered, e := a.CopyStart(ctx, b.cfg.LocalIP)
	if e != nil || recovered == id || b.CopySnapshot().Session != recovered {
		t.Fatalf("file copy did not recover with a fresh lease: %v", e)
	}
	if e := a.CopyRenew(ctx, recovered); e != nil {
		t.Fatalf("recovered lease could not renew: %v", e)
	}
}

type copyResponseTimeoutTransport struct{}

func (copyResponseTimeoutTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(iotest.ErrReader(context.DeadlineExceeded)),
	}, nil
}

func TestMeshCopyResponseTimeout(t *testing.T) {
	ctx := context.Background()
	session := &meshCopySession{
		ctx: ctx,
		sender: &Sender{
			base:    "https://127.0.0.1/rdp-copy/v2",
			control: &http.Client{Transport: copyResponseTimeoutTransport{}},
		},
	}
	if _, err := copyCall(ctx, session, copyMessage{Op: "read", Count: 1}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("response body timeout returned %v", err)
	}
}
func TestMeshCopyManifestNames(t *testing.T) {
	for _, name := range []string{"../a", "a:b", "CON.txt", "LPT1", "a.", "a ", ""} {
		if validateCopyFiles([]copyFile{{name, 1}}) {
			t.Fatalf("accepted %q", name)
		}
	}
	if !validID(copyID()) {
		t.Fatal("invalid session ID")
	}
	if !validateCopyFiles([]copyFile{{"中文.pptx", 43 << 20}, {"empty", 0}}) {
		t.Fatal("valid files rejected")
	}
}

func TestMeshCopyDirectBlocks(t *testing.T) {
	a, b := meshCopyPairPath(t, "direct")
	ctx := context.Background()
	id, e := a.CopyStart(ctx, b.cfg.LocalIP)
	if e != nil {
		t.Fatal(e)
	}
	for _, pair := range [][2]*Agent{{a, b}, {b, a}} {
		src, dst := pair[0], pair[1]
		path := filepath.Join(t.TempDir(), "direct.bin")
		data := bytes.Repeat([]byte{42}, 65537)
		if e = os.WriteFile(path, data, 0600); e != nil {
			t.Fatal(e)
		}
		if e = src.CopyOffer(ctx, id, []string{path}); e != nil {
			t.Fatal(e)
		}
		offer := dst.CopySnapshot().Offer
		if !bytes.Equal(awaitCopy(t, dst, offer, 0, 0, 65536), data[:65536]) {
			t.Fatal("direct first block mismatch")
		}
		if !bytes.Equal(awaitCopy(t, dst, offer, 0, 65536, 1), data[65536:]) {
			t.Fatal("direct tail mismatch")
		}
	}
}
func TestMeshCopyChangedSourceAndNewOffer(t *testing.T) {
	a, b := meshCopyPair(t)
	ctx := context.Background()
	id, e := a.CopyStart(ctx, b.cfg.LocalIP)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "source.bin")
	if e = os.WriteFile(path, []byte("first"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = a.CopyOffer(ctx, id, []string{path}); e != nil {
		t.Fatal(e)
	}
	old := b.CopySnapshot().Offer
	if e = a.CopyOffer(ctx, id, []string{path}); e != nil {
		t.Fatal(e)
	}
	if _, _, e = b.CopyRead(old, 0, 0, 1); !errors.Is(e, ErrCopyOfferUnavailable) {
		t.Fatalf("old offer returned %v", e)
	}
	offer := b.CopySnapshot().Offer
	if e = os.Chtimes(path, time.Now(), time.Now().Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_, pending, e := b.CopyRead(offer, 0, 0, 5)
		if errors.Is(e, ErrCopySourceRead) {
			return
		}
		if e != nil {
			t.Fatalf("changed source returned %v", e)
		}
		if !pending {
			t.Fatal("changed source accepted")
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("changed source check timeout")
}
