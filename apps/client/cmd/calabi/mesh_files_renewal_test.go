package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/calabinet/calabi/apps/client/internal/filecontrol"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
	"github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
)

func TestDesktopAutomaticRenewalPreservesReceptionAndIdentity(t *testing.T) {
	for _, key := range []string{"HOME", "APPDATA", "XDG_CONFIG_HOME", "LOCALAPPDATA"} {
		t.Setenv(key, t.TempDir())
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	key := meshproto.NodeKey{1}
	ctl := &filecontrol.Control{Source: filecontrol.Source{
		View: func() (filecontrol.Snapshot, error) {
			return filecontrol.Snapshot{Ready: true, Registration: 1, Scope: "renew/example", NodeKey: key.String(), Overlay: "127.0.0.1"}, nil
		},
		Publish: func(_ context.Context, _ string, info *meshpb.FileTransferInfo) error {
			if info != nil {
				_, err := meshproto.VerifyFileTransfer(key, info, time.Now())
				return err
			}
			return nil
		},
	}}
	const console = "http://127.0.0.1:17547"
	done, err := filecontrol.Serve(ctx, ctl, console)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); <-done }()
	d, err := newDesktopFileAgent(ctx, console)
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	if _, err := d.handle(fileAction{Action: "receiving", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	d.opMu.Lock()
	old := d.identity
	cert, _ := x509.ParseCertificate(old.Certificate.Certificate[0])
	cert.NotAfter = time.Now().Add(time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, cert.PublicKey, old.Certificate.PrivateKey)
	if err != nil {
		d.opMu.Unlock()
		t.Fatal(err)
	}
	short := *old
	short.Certificate = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: old.Certificate.PrivateKey}
	hash := sha256.Sum256(der)
	short.Fingerprint = hex.EncodeToString(hash[:])
	encodedKey, err := x509.MarshalPKCS8PrivateKey(short.Certificate.PrivateKey)
	if err != nil {
		d.opMu.Unlock()
		t.Fatal(err)
	}
	data, _ := json.Marshal(struct {
		Certificate, Key []byte
		HistoryID        string
	}{der, encodedKey, old.HistoryID()})
	if err := os.WriteFile(filepath.Join(d.dir, "file-identity.json"), data, 0600); err != nil {
		d.opMu.Unlock()
		t.Fatal(err)
	}
	d.identity = &short
	d.renewAfter = time.Time{}
	d.opMu.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		d.renewIdentityWhenIdle()
		d.opMu.Lock()
		ready := d.identity != nil && d.identity.Fingerprint != short.Fingerprint
		d.opMu.Unlock()
		if ready {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	d.opMu.Lock()
	defer d.opMu.Unlock()
	if d.identity == nil || d.identity.Fingerprint == short.Fingerprint || d.identity.HistoryID() != old.HistoryID() {
		t.Fatal("automatic identity renewal did not retain history")
	}
	newKey, _ := x509.MarshalPKCS8PrivateKey(d.identity.Certificate.PrivateKey)
	if !bytes.Equal(newKey, encodedKey) {
		t.Fatal("automatic renewal replaced the key")
	}
	d.wMu.RLock()
	w := d.w
	d.wMu.RUnlock()
	if w == nil || !w.Agent.Receiving() {
		t.Fatal("reception was not restored after routine renewal")
	}
}
