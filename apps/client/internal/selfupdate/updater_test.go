package selfupdate

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// testServer serves a manifest at /latest.json, its detached signature at
// /latest.json.sig, and the installer at /installer. The sha256 matches the
// served bytes unless shaOverride is set.
//
// manifestPriv signs the manifest; pass nil to serve an UNSIGNED manifest (the
// .sig then 404s), which is what a pre-UPD-1 release host looks like.
func testServer(t *testing.T, version string, installer []byte, sig, shaOverride string, manifestPriv ed25519.PrivateKey) *httptest.Server {
	t.Helper()
	sum := sha256.Sum256(installer)
	sha := hex.EncodeToString(sum[:])
	if shaOverride != "" {
		sha = shaOverride
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/installer", func(w http.ResponseWriter, _ *http.Request) { w.Write(installer) })

	// The manifest body has to be byte-identical between the copy we sign and
	// the copy we serve, so build it once — with a placeholder host that the
	// handler cannot know until the server is up.
	var body []byte
	mux.HandleFunc("/latest.json", func(w http.ResponseWriter, r *http.Request) {
		w.Write(manifestBody(t, version, sha, sig, "http://"+r.Host+"/installer", &body))
	})
	mux.HandleFunc("/latest.json.sig", func(w http.ResponseWriter, r *http.Request) {
		if manifestPriv == nil {
			http.NotFound(w, r)
			return
		}
		b := manifestBody(t, version, sha, sig, "http://"+r.Host+"/installer", &body)
		fmt.Fprintln(w, base64.StdEncoding.EncodeToString(ed25519.Sign(manifestPriv, b)))
	})
	return httptest.NewServer(mux)
}

// manifestBody renders (once) and caches the manifest bytes.
func manifestBody(t *testing.T, version, sha, sig, url string, cache *[]byte) []byte {
	t.Helper()
	if len(*cache) == 0 {
		*cache = []byte(fmt.Sprintf(`{"version":%q,"platforms":{%q:{"url":%q,"sha256":%q,"signature":%q}}}`,
			version, PlatformKey(), url, sha, sig))
	}
	return *cache
}

func TestUpdater_AppliesNewer(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	installer := []byte("fake calabi installer payload")
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, installer))
	srv := testServer(t, "1.7.0", installer, sig, "", priv)
	defer srv.Close()

	var appliedPath string
	u := &Updater{
		ManifestURL:    srv.URL + "/latest.json",
		CurrentVersion: "1.6.0",
		PubKey:         pub,
		DownloadDir:    t.TempDir(),
		Privileged:     true,
		Managed:        managedForTest,
		Apply:          func(_ context.Context, p string) error { appliedPath = p; return nil },
	}
	applied, err := u.CheckAndApply(context.Background())
	if err != nil || !applied {
		t.Fatalf("CheckAndApply=(%v,%v), want (true,nil)", applied, err)
	}
	if appliedPath == "" {
		t.Error("Apply was not called with the downloaded installer")
	}
}

func TestUpdater_UpToDate(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	installer := []byte("x")
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, installer))
	srv := testServer(t, "1.6.0", installer, sig, "", priv)
	defer srv.Close()

	called := false
	u := &Updater{
		ManifestURL:    srv.URL + "/latest.json",
		CurrentVersion: "1.6.0",
		PubKey:         pub,
		DownloadDir:    t.TempDir(),
		Privileged:     true,
		Managed:        managedForTest,
		Apply:          func(_ context.Context, _ string) error { called = true; return nil },
	}
	applied, err := u.CheckAndApply(context.Background())
	if err != nil || applied {
		t.Fatalf("CheckAndApply=(%v,%v), want (false,nil)", applied, err)
	}
	if called {
		t.Error("Apply must not run when already up to date")
	}
}

func TestUpdater_BadSHARefuses(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	installer := []byte("real payload")
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, installer))
	// manifest advertises a WRONG sha256 → verification must fail, apply must not run.
	srv := testServer(t, "1.7.0", installer, sig,
		"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", priv)
	defer srv.Close()

	called := false
	u := &Updater{
		ManifestURL:    srv.URL + "/latest.json",
		CurrentVersion: "1.6.0",
		PubKey:         pub,
		DownloadDir:    t.TempDir(),
		Privileged:     true,
		Managed:        managedForTest,
		Apply:          func(_ context.Context, _ string) error { called = true; return nil },
	}
	applied, err := u.CheckAndApply(context.Background())
	if err == nil || applied {
		t.Fatalf("CheckAndApply=(%v,%v), want (false, error)", applied, err)
	}
	if called {
		t.Error("Apply must not run when sha256 verification fails")
	}
}

func TestUpdater_BadSignatureRefuses(t *testing.T) {
	pub, manifestPriv, _ := ed25519.GenerateKey(nil)
	_, wrongPriv, _ := ed25519.GenerateKey(nil) // installer signed with a DIFFERENT key
	installer := []byte("real payload")
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(wrongPriv, installer))
	srv := testServer(t, "1.7.0", installer, sig, "", manifestPriv)
	defer srv.Close()

	called := false
	u := &Updater{
		ManifestURL:    srv.URL + "/latest.json",
		CurrentVersion: "1.6.0",
		PubKey:         pub,
		DownloadDir:    t.TempDir(),
		Privileged:     true,
		Managed:        managedForTest,
		Apply:          func(_ context.Context, _ string) error { called = true; return nil },
	}
	applied, err := u.CheckAndApply(context.Background())
	if err == nil || applied {
		t.Fatalf("CheckAndApply=(%v,%v), want (false, error)", applied, err)
	}
	if called {
		t.Error("Apply must not run when the signature is from the wrong key")
	}
}

// An unsigned manifest — every release host before UPD-1 — is refused outright.
// There is deliberately no "verify it if a signature happens to be there" mode:
// an attacker would simply not put one there.
func TestUpdater_UnsignedManifestRefused(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	installer := []byte("real payload")
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, installer))
	srv := testServer(t, "1.7.0", installer, sig, "", nil) // no.sig served
	defer srv.Close()

	called := false
	u := &Updater{
		ManifestURL:    srv.URL + "/latest.json",
		CurrentVersion: "1.6.0",
		PubKey:         pub,
		DownloadDir:    t.TempDir(),
		Privileged:     true,
		Managed:        managedForTest,
		Apply:          func(_ context.Context, _ string) error { called = true; return nil },
	}
	applied, err := u.CheckAndApply(context.Background())
	if err == nil || applied {
		t.Fatalf("CheckAndApply=(%v,%v), want (false, error)", applied, err)
	}
	if called {
		t.Error("Apply must not run for a manifest with no signature")
	}
}

// A manifest signed by someone else's key is refused even though every installer
// field inside it is internally consistent.
func TestUpdater_ForeignManifestSignatureRefused(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	_, attackerPriv, _ := ed25519.GenerateKey(nil)
	installer := []byte("real payload")
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, installer))
	srv := testServer(t, "1.7.0", installer, sig, "", attackerPriv)
	defer srv.Close()

	u := &Updater{
		ManifestURL:    srv.URL + "/latest.json",
		CurrentVersion: "1.6.0",
		PubKey:         pub,
		DownloadDir:    t.TempDir(),
		Privileged:     true,
		Managed:        managedForTest,
		Apply:          func(context.Context, string) error { t.Fatal("apply must not run"); return nil },
	}
	if _, err := u.CheckAndApply(context.Background()); err == nil {
		t.Fatal("a manifest signed by an unknown key was accepted")
	}
}
