package filetransfer

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func shellPair(t *testing.T, data []byte) (*Workspace, *Receiver, *Agent, string) {
	t.Helper()
	ip := netip.MustParseAddr("127.0.0.1")
	senderID, _ := NewIdentity()
	receiverID, _ := NewIdentity()
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	senderGrant := Grant{Path: "direct", Peer: Peer{IP: ip, Fingerprint: senderID.Fingerprint}, DeviceKey: "source", Port: 17401}
	receiverGrant := Grant{Path: "direct", Peer: Peer{IP: ip, Fingerprint: receiverID.Fingerprint}, DeviceKey: "remote", Port: port}
	a, e := NewAgent(AgentConfig{Identity: receiverID, Directory: t.TempDir(), Scope: "test", LocalIP: ip, Port: port, Kbps: 32768, MaxBytes: 16 << 20, Resolve: func(netip.Addr) (Grant, bool) { return senderGrant, true }, Incoming: func(netip.Addr, uint16) bool { return true }, ClipboardPeer: func(g Grant) bool { return g.DeviceKey == "source" }})
	if e != nil {
		t.Fatal(e)
	}
	if e = a.SetClipboardReceiving(true); e != nil {
		t.Fatal(e)
	}
	served, e := a.Serve(listener)
	if e != nil {
		t.Fatal(e)
	}
	w, e := NewWorkspace(AgentConfig{Identity: senderID, Directory: t.TempDir(), Scope: "test", LocalIP: ip, Port: 17401, Kbps: 32768, MaxBytes: 16 << 20, Resolve: func(netip.Addr) (Grant, bool) { return receiverGrant, true }, Incoming: func(netip.Addr, uint16) bool { return true }, ClipboardPeer: func(g Grant) bool { return g.DeviceKey == "remote" }})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { w.Close(); a.Close(); <-served })
	if a.Receiving() {
		t.Fatal("clipboard enabled ordinary reception")
	}
	if _, e = w.Agent.Sender(ip); e == nil {
		t.Fatal("ordinary sender bypassed receiving switch")
	}
	// Exercise the server gate directly, not only the public sender factory.
	raw, e := NewBatchSender(senderID, ip, receiverGrant.Peer, int(port), w.Agent.budget, func() bool { return true }, "test")
	if e != nil {
		t.Fatal(e)
	}
	e = raw.request(context.Background(), raw.client, "POST", "/offers", "", bytes.NewReader([]byte("{}")), 0, 0, nil)
	var denied *requestError
	if !errors.As(e, &denied) || denied.status != 403 {
		t.Fatalf("ordinary route with receiving off: %v", e)
	}
	raw.Close()
	if e = a.SetReceiving(false); e != nil {
		t.Fatal(e)
	}
	if !a.ClipboardReceiving() {
		t.Fatal("ordinary switch disabled clipboard")
	}
	senderGrant.ClipboardTransport = true
	ar, e := a.receiver(senderGrant, true)
	if e != nil {
		t.Fatal(e)
	}
	r := ar.receiver
	inbox := r.cfg.Directory
	src, err := w.Stage(context.Background(), bytes.NewReader(data), "中文粘贴.bin", int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.SendClipboard(netip.MustParseAddr("127.0.0.1"), []string{src.ID}); err != nil {
		t.Fatal(err)
	}
	syncUntil(t, func() bool { return len(r.List()) == 1 })
	if !r.List()[0].Clipboard || r.List()[0].State != "waiting" || r.List()[0].Offset != 0 {
		t.Fatal("clipboard offer must wait for paste")
	}
	syncUntil(t, func() bool { return ShellOfferReady(w.Jobs()[0].Progress) })

	return w, r, a, inbox
}
func TestShellPasteVerifiedTLSBatch(t *testing.T) {
	data := bytes.Repeat([]byte("real mutual TLS clipboard bytes"), 10000)
	_, r, a, _ := shellPair(t, data)
	batch := r.List()[0].Batch
	if _, err := a.NewShellPaste(context.Background(), t.TempDir(), "different-device", batch); err == nil {
		t.Fatal("cross-device batch accepted")
	}
	p, err := a.NewShellPaste(context.Background(), t.TempDir(), "source", batch)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	manifest := p.Manifest()
	if binary.LittleEndian.Uint32(manifest[4:])&0x4000 != 0 {
		t.Fatal("Calabi paste must not request Shell progress UI")
	}
	if len(manifest) != 596 || binary.LittleEndian.Uint32(manifest) != 1 || int(binary.LittleEndian.Uint32(manifest[4+68:])) != len(data) {
		t.Fatal("bad manifest")
	}
	if _, err = p.Read(0, 0, 10); err == nil {
		t.Fatal("read before paste accepted")
	}
	if err = p.Begin(); err != nil {
		t.Fatal(err)
	}
	syncUntil(t, func() bool {
		ready, _, _, err := p.Status(0)
		if err != nil {
			t.Fatal(err)
		}
		return ready
	})
	var got []byte
	for offset := 0; offset < len(data); {
		part, err := p.Read(0, int64(offset), 65536)
		if err != nil {
			t.Fatal(err)
		}
		if len(part) == 0 {
			t.Fatal("early EOF")
		}
		got = append(got, part...)
		offset += len(part)
	}
	if !bytes.Equal(data, got) {
		t.Fatal("pasted content mismatch")
	}
	if _, err = p.Read(0, 0, 65537); err == nil {
		t.Fatal("unbounded IPC read")
	}
	if _, err = p.Read(1, 0, 1); err == nil {
		t.Fatal("invalid file index")
	}
	if _, err = p.Read(0, -1, 1); err == nil {
		t.Fatal("negative offset")
	}
	a.clipboardReceiving.Store(false)
	if _, err = p.Read(0, 0, 1); err == nil {
		t.Fatal("receive switch ignored")
	}
	dir := p.directory
	p.Close()
	if _, err = os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("paste cache not cleaned", err)
	}
}
func TestShellPasteCancelStopsRealSenderAndRemovesPartial(t *testing.T) {
	w, r, a, inbox := shellPair(t, bytes.Repeat([]byte("x"), 8<<20))
	p, err := a.NewShellPaste(context.Background(), t.TempDir(), "source", r.List()[0].Batch)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if err = p.Begin(); err != nil {
		t.Fatal(err)
	}
	syncUntil(t, func() bool { return r.List()[0].Offset > 0 })
	p.Cancel()
	syncUntil(t, func() bool { state := w.Jobs()[0].State; return state == "cancelled" || state == "failed" })
	if r.List()[0].State != "cancelled" {
		t.Fatal("receiver not cancelled")
	}
	if _, err = os.Stat(filepath.Join(inbox, r.List()[0].ID+".part")); !os.IsNotExist(err) {
		t.Fatal("partial remains", err)
	}
	if _, err = p.Read(0, 0, 1); err == nil {
		t.Fatal("cancelled read succeeded")
	}
}
func TestShellPasteRejectsManifestMismatch(t *testing.T) {
	row := Received{DeviceKey: "a", Transfer: Transfer{Clipboard: true, ID: randomID(), Batch: randomID(), BatchCount: 1, Name: "test.bin", Size: 1, State: "waiting"}}
	if err := validateShellBatch([]Received{row}); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Received){
		func(r *Received) { r.Transfer.BatchCount = 2 }, func(r *Received) { r.Transfer.Name = "../x" },
		func(r *Received) { r.Transfer.Size = ShellPasteLimit + 1 }, func(r *Received) { r.Transfer.State = "cancelled" },
	} {
		bad := row
		mutate(&bad)
		if validateShellBatch([]Received{bad}) == nil {
			t.Fatal("invalid manifest accepted")
		}
	}
}

func TestShellOfferReadiness(t *testing.T) {
	p := BatchProgress{Batch: "b", Preparation: &PreparationProgress{Phase: "hashing"}}
	if ShellOfferReady(p) {
		t.Fatal("hashing advertised before offers")
	}
	p.Preparation = &PreparationProgress{Phase: "connecting"}
	if ShellOfferReady(p) {
		t.Fatal("incomplete offers advertised")
	}
	p.Preparation = nil
	if ShellOfferReady(p) {
		t.Fatal("missing remote acknowledgement")
	}
	p.Transfer = Transfer{ID: "id", Clipboard: true, State: "waiting"}
	if !ShellOfferReady(p) {
		t.Fatal("complete acknowledged offers not ready")
	}
	p.Transfer.Clipboard = false
	if ShellOfferReady(p) {
		t.Fatal("ordinary transfer treated as clipboard")
	}
}
