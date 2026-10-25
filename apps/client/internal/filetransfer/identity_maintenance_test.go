package filetransfer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

func TestLegacyIdentityAdoptsOriginalHistoryWithoutReplacingCertificate(t *testing.T) {
	base := t.TempDir()
	old, err := newIdentity(365 * 24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	key, err := x509.MarshalPKCS8PrivateKey(old.Certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeRecord(root, "file-identity.json", struct{ Certificate, Key []byte }{old.Certificate.Certificate[0], key}); err != nil {
		t.Fatal(err)
	}
	before, err := root.ReadFile("file-identity.json")
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadIdentity(base)
	if err != nil {
		t.Fatal(err)
	}
	after, err := root.ReadFile("file-identity.json")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.HistoryID() != old.Fingerprint || loaded.Fingerprint != old.Fingerprint || !bytes.Equal(before, after) {
		t.Fatal("legacy adoption changed certificate or private history scope")
	}
	renewed, err := MaintainIdentity(base, "renew")
	if err != nil {
		t.Fatal(err)
	}
	node := meshproto.NodeKey{1}
	info, err := renewed.Declaration(node, 17401, false)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := meshproto.VerifyFileTransfer(node, info, time.Now())
	if err != nil || pin != renewed.Fingerprint || pin == renewed.HistoryID() {
		t.Fatalf("network identity confused with retained history: %v", err)
	}
}

func TestIdentityMaintenanceKeepsCompletedFilesAndCancelsPending(t *testing.T) {
	base := t.TempDir()
	id, err := LoadIdentity(base)
	if err != nil {
		t.Fatal(err)
	}
	peerID, _ := NewIdentity()
	ip := netip.MustParseAddr("127.0.0.1")
	dir := filepath.Join(base, randomID())
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	grant := Grant{Path: "direct", Peer: Peer{IP: ip, Fingerprint: peerID.Fingerprint}, DeviceKey: "peer", Port: 17401, Receiving: true}
	cfg := AgentConfig{Identity: id, Directory: dir, Scope: "org7/" + id.HistoryID(), LocalIP: ip, Port: 17401, Kbps: 32768, MaxBytes: 8 << 20, Resolve: func(netip.Addr) (Grant, bool) { return grant, true }, Incoming: func(netip.Addr, uint16) bool { return true }}
	w, err := NewWorkspace(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	data := []byte("completed file survives maintenance")
	source, err := w.Stage(context.Background(), bytes.NewReader(data), "source.txt", int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	jobID := randomID()
	rec := outgoingRecord{Job: Job{ID: jobID, PeerIP: ip.String(), Sources: []string{source.ID}, State: "paused"}, Ticket: BatchTicket{ID: randomID(), Scope: cfg.Scope, Peer: grant.Peer}}
	if err := writeRecord(w.root, "job-"+jobID+".json", rec); err != nil {
		t.Fatal(err)
	}
	ar, err := w.Agent.receiver(grant, true)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(data)
	completed := Transfer{ID: randomID(), Batch: randomID(), BatchCount: 1, ClientID: randomID(), Name: "received.txt", Size: int64(len(data)), Offset: int64(len(data)), State: "completed", SHA256: hex.EncodeToString(h[:]), Kbps: 32768, MaxBlock: BlockSize}
	completed.StoredName = completed.ID + ".received"
	if err := ar.receiver.root.WriteFile(completed.StoredName, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeRecord(ar.receiver.root, completed.ID+".json", receiveRecord{Version: 1, Scope: cfg.Scope + "/peer", Peer: grant.Peer, Transfer: completed, Token: randomID(), Created: time.Now()}); err != nil {
		t.Fatal(err)
	}
	pending := completed
	pending.ID = randomID()
	pending.State = "receiving"
	pending.Offset = 0
	pending.StoredName = ""
	oldToken := randomID()
	if err := writeRecord(ar.receiver.root, pending.ID+".json", receiveRecord{Version: 1, Scope: cfg.Scope + "/peer", Peer: grant.Peer, Transfer: pending, Token: oldToken, Created: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if _, err := MaintainIdentity(base, "renew"); err == nil {
		t.Fatal("active agent identity replaced")
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	renewed, err := MaintainIdentity(base, "renew")
	if err != nil {
		t.Fatal(err)
	}
	if renewed.Fingerprint == id.Fingerprint || renewed.HistoryID() != id.HistoryID() {
		t.Fatal("renewal pin/history semantics wrong")
	}
	if !renewed.Certificate.PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey).Equal(id.Certificate.PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)) {
		t.Fatal("renewal unexpectedly reset key")
	}
	cfg.Identity = renewed
	reopened, err := NewWorkspace(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Agent.Receiving() || len(reopened.Staged()) != 1 || len(reopened.Jobs()) != 1 || reopened.Jobs()[0].State != "cancelled" {
		t.Fatal("history not preserved or pending task resumed")
	}
	var out bytes.Buffer
	if err := reopened.Agent.CopyCompleted(context.Background(), completed.ID, &out); err != nil || !bytes.Equal(out.Bytes(), data) {
		t.Fatalf("completed export after renewal: %v", err)
	}
	for _, row := range reopened.Agent.List() {
		if row.Transfer.ID == pending.ID && row.Transfer.State != "cancelled" {
			t.Fatal("pending inbox was not revoked")
		}
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	reset, err := MaintainIdentity(base, "reset")
	if err != nil {
		t.Fatal(err)
	}
	if reset.HistoryID() != id.HistoryID() || reset.Certificate.PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey).Equal(id.Certificate.PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)) {
		t.Fatal("reset did not preserve history or did not rotate key")
	}
	cfg.Identity = reset
	last, err := NewWorkspace(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer last.Close()
	out.Reset()
	if err := last.Agent.CopyCompleted(context.Background(), completed.ID, &out); err != nil || !bytes.Equal(out.Bytes(), data) {
		t.Fatalf("completed export after key reset: %v", err)
	}
}

func TestExpiredAndDamagedIdentityRequireExplicitMaintenance(t *testing.T) {
	base := t.TempDir()
	id, err := LoadIdentity(base)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	expired, err := identityWithKey(id.Certificate.PrivateKey.(ed25519.PrivateKey), -time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	expired.historyID = id.HistoryID()
	if err := storeIdentity(root, expired); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIdentity(base); err == nil {
		t.Fatal("expired certificate silently accepted")
	}
	if !ReadIdentityStatus(base).NeedsRenewal {
		t.Fatal("expired certificate not exposed for recovery")
	}
	if _, err := MaintainIdentity(base, "renew"); err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile("file-identity.json", []byte("damaged"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIdentity(base); err == nil {
		t.Fatal("damaged key silently reset")
	}
	if _, err := MaintainIdentity(base, "renew"); err == nil {
		t.Fatal("damaged key renewed without a valid key")
	}
	recovered, err := MaintainIdentity(base, "reset")
	if err != nil {
		t.Fatal(err)
	}
	if recovered.HistoryID() != id.HistoryID() {
		t.Fatal("recovery lost private history")
	}
	if err := root.Remove("file-identity.json"); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIdentity(base); err == nil {
		t.Fatal("missing established key silently replaced")
	}
	if !ReadIdentityStatus(base).Exists {
		t.Fatal("missing established key has no explicit UI recovery")
	}
	if _, err := MaintainIdentity(base, "reset"); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyWorkspaceLockAlsoBlocksMaintenance(t *testing.T) {
	base := t.TempDir()
	id, err := LoadIdentity(base)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(base, randomID())
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	l, err := identityLock(dir, "workspace.lock")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Unlock()
	if _, err := MaintainIdentity(base, "reset"); err == nil {
		t.Fatal("legacy active workspace key was replaced")
	}
	current, err := LoadIdentity(base)
	if err != nil || current.Fingerprint != id.Fingerprint {
		t.Fatal("refused maintenance changed identity")
	}
}
