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

// testServer serves a manifest at /latest.json and the installer at /installer,
// with a sha256 that matches the served bytes unless shaOverride is set.
func testServer(t *testing.T, version string, installer []byte, sig, shaOverride string) *httptest.Server {
	t.Helper()
	sum := sha256.Sum256(installer)
	sha := hex.EncodeToString(sum[:])
	if shaOverride != "" {
		sha = shaOverride
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/installer", func(w http.ResponseWriter, _ *http.Request) { w.Write(installer) })
	mux.HandleFunc("/latest.json", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"version":%q,"platforms":{%q:{"url":%q,"sha256":%q,"signature":%q}}}`,
			version, PlatformKey(), "http://"+r.Host+"/installer", sha, sig)
	})
	return httptest.NewServer(mux)
}

func TestUpdater_AppliesNewer(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	installer := []byte("fake calabi installer payload")
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, installer))
	srv := testServer(t, "1.7.0", installer, sig, "")
	defer srv.Close()

	var appliedPath string
	u := &Updater{
		ManifestURL:    srv.URL + "/latest.json",
		CurrentVersion: "1.6.0",
		PubKey:         pub,
		DownloadDir:    t.TempDir(),
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
	srv := testServer(t, "1.6.0", installer, sig, "")
	defer srv.Close()

	called := false
	u := &Updater{
		ManifestURL:    srv.URL + "/latest.json",
		CurrentVersion: "1.6.0",
		PubKey:         pub,
		DownloadDir:    t.TempDir(),
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
	srv := testServer(t, "1.7.0", installer, sig, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	defer srv.Close()

	called := false
	u := &Updater{
		ManifestURL:    srv.URL + "/latest.json",
		CurrentVersion: "1.6.0",
		PubKey:         pub,
		DownloadDir:    t.TempDir(),
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
	pub, _, _ := ed25519.GenerateKey(nil)
	_, wrongPriv, _ := ed25519.GenerateKey(nil) // sign with a DIFFERENT key
	installer := []byte("real payload")
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(wrongPriv, installer))
	srv := testServer(t, "1.7.0", installer, sig, "")
	defer srv.Close()

	called := false
	u := &Updater{
		ManifestURL:    srv.URL + "/latest.json",
		CurrentVersion: "1.6.0",
		PubKey:         pub,
		DownloadDir:    t.TempDir(),
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
