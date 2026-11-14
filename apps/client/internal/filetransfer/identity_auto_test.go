package filetransfer

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func seedManagedCertificate(t *testing.T, dir string, old *Identity, lifetime time.Duration) *Identity {
	t.Helper()
	id, err := identityWithKey(old.Certificate.PrivateKey.(ed25519.PrivateKey), lifetime)
	if err != nil {
		t.Fatal(err)
	}
	id.historyID = old.HistoryID()
	r, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := storeIdentity(r, id); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestManagedRenewalPreservesKeyHistoryAndJournals(t *testing.T) {
	for _, lifetime := range []time.Duration{time.Hour, -time.Hour} {
		t.Run(lifetime.String(), func(t *testing.T) {
			dir := t.TempDir()
			old, err := LoadIdentity(dir)
			if err != nil {
				t.Fatal(err)
			}
			short := seedManagedCertificate(t, dir, old, lifetime)
			workspace := filepath.Join(dir, randomID())
			if err := os.Mkdir(workspace, 0700); err != nil {
				t.Fatal(err)
			}
			journal := []byte(`{"state":"paused","must_retain":"original"}`)
			p := filepath.Join(workspace, "job-"+randomID()+".json")
			if err := os.WriteFile(p, journal, 0600); err != nil {
				t.Fatal(err)
			}
			next, err := LoadManagedIdentity(dir)
			if err != nil {
				t.Fatal(err)
			}
			if next.Fingerprint == short.Fingerprint || next.HistoryID() != old.HistoryID() || !bytes.Equal(next.Certificate.PrivateKey.(ed25519.PrivateKey), old.Certificate.PrivateKey.(ed25519.PrivateKey)) || next.RenewalDue() {
				t.Fatal("renewal changed the key/history or failed to extend the certificate")
			}
			got, err := os.ReadFile(p)
			if err != nil || !bytes.Equal(got, journal) {
				t.Fatal("automatic renewal changed a transfer journal")
			}
			again, err := LoadManagedIdentity(dir)
			if err != nil || again.Fingerprint != next.Fingerprint {
				t.Fatal("healthy identity renewed again")
			}
		})
	}
}

func TestManagedRenewalDefersForIdentityAndWorkspaceLocks(t *testing.T) {
	for _, lockName := range []string{"file-identity-use.lock", "workspace.lock"} {
		t.Run(lockName, func(t *testing.T) {
			dir := t.TempDir()
			old, err := LoadIdentity(dir)
			if err != nil {
				t.Fatal(err)
			}
			short := seedManagedCertificate(t, dir, old, time.Hour)
			lockDir := dir
			if lockName == "workspace.lock" {
				lockDir = filepath.Join(dir, randomID())
				if err := os.Mkdir(lockDir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			lock, err := identityLock(lockDir, lockName)
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Unlock()
			loaded, err := LoadManagedIdentity(dir)
			if err != nil || loaded.Fingerprint != short.Fingerprint {
				t.Fatal("active identity was changed")
			}
			if err := lock.Unlock(); err != nil {
				t.Fatal(err)
			}
			renewed, err := LoadManagedIdentity(dir)
			if err != nil || renewed.Fingerprint == short.Fingerprint {
				t.Fatal("renewal was not retried after releasing the lock")
			}
		})
	}
}

func TestManagedRenewalDoesNotReplaceDamagedKeys(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadIdentity(dir); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "file-identity.json")
	if err := os.WriteFile(p, []byte("damaged"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadManagedIdentity(dir); err == nil {
		t.Fatal("damaged key was automatically replaced")
	}
	if got, _ := os.ReadFile(p); string(got) != "damaged" {
		t.Fatal("damaged key was overwritten")
	}
	if !ReadIdentityStatus(dir).NeedsRepair {
		t.Fatal("explicit recovery was not offered")
	}
}

func TestManagedRenewalDoesNotConcealFutureSystemClock(t *testing.T) {
	dir := t.TempDir()
	id, err := LoadIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(id.Certificate.Certificate[0])
	cert.NotBefore = time.Now().Add(24 * time.Hour)
	cert.NotAfter = time.Now().Add(365 * 24 * time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, id.Certificate.PrivateKey.(ed25519.PrivateKey).Public(), id.Certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	id.Certificate.Certificate[0] = der
	r, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := storeIdentity(r, id); err != nil {
		t.Fatal(err)
	}
	before, _ := r.ReadFile("file-identity.json")
	if _, err := LoadManagedIdentity(dir); err == nil {
		t.Fatal("future-dated identity was silently replaced")
	}
	after, _ := r.ReadFile("file-identity.json")
	if !bytes.Equal(before, after) || ReadIdentityStatus(dir).NeedsRepair {
		t.Fatal("clock issue was treated as key damage")
	}
}

func TestRenewalWaitsForRealHTTPHandlersAndStopsNewAdmissions(t *testing.T) {
	id, _ := NewIdentity()
	peer, _ := NewIdentity()
	cert, _ := x509.ParseCertificate(peer.Certificate.Certificate[0])
	ip := netip.MustParseAddr("127.0.0.1")
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	w, err := NewWorkspace(AgentConfig{Identity: id, Directory: t.TempDir(), Scope: "example", LocalIP: ip, Port: 17401, Kbps: 512, MaxBytes: 8 << 20,
		Resolve: func(netip.Addr) (Grant, bool) { close(entered); <-release; return Grant{}, false }, Incoming: func(netip.Addr, uint16) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	req := httptest.NewRequest("GET", "/file/v1/status", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	go func() { defer close(done); w.Agent.Handler().ServeHTTP(httptest.NewRecorder(), req) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not start")
	}
	if w.RetireForIdentityRenewal() {
		close(release)
		<-done
		t.Fatal("active HTTP request was interrupted")
	}
	close(release)
	<-done
	if !w.RetireForIdentityRenewal() {
		t.Fatal("idle workspace could not be retired")
	}
	r := httptest.NewRecorder()
	w.Agent.Handler().ServeHTTP(r, req)
	if r.Code != 403 {
		t.Fatalf("new request entered retired agent: %d", r.Code)
	}
}
