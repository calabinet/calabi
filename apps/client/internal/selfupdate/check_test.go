package selfupdate

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// foreignPlatformServer serves a SIGNED manifest whose only platform entry is
// for somebody else — exactly the shape download.calabi.net publishes today
// (desktop-only) as seen from a Linux or agent install.
func foreignPlatformServer(t *testing.T, version string, priv ed25519.PrivateKey) *httptest.Server {
	t.Helper()
	key := "solaris-sparc64" // never equal to PlatformKey() on any host we build for
	body := []byte(fmt.Sprintf(`{"version":%q,"platforms":{%q:{"url":"https://example.invalid/x","sha256":"aa","signature":"bb"}}}`,
		version, key))
	mux := http.NewServeMux()
	mux.HandleFunc("/latest.json", func(w http.ResponseWriter, _ *http.Request) { w.Write(body) })
	mux.HandleFunc("/latest.json.sig", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, base64.StdEncoding.EncodeToString(ed25519.Sign(priv, body)))
	})
	return httptest.NewServer(mux)
}

// A manifest with nothing for this platform is a STATE, not a failure.
//
// This is the Linux/agent bug: CheckAndApply used to return an error here, so
// every such daemon logged "no artifact for linux-x86_64" every 6 hours and NO
// surface anywhere ever learned a newer version existed. Revert the `if !ok`
// branch in check() to returning an error and this goes red.
func TestCheckNoArtifactForThisPlatformIsAStateNotAnError(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	srv := foreignPlatformServer(t, "1.11.0", priv)
	defer srv.Close()

	u := &Updater{
		ManifestURL:    srv.URL + "/latest.json",
		CurrentVersion: "1.10.0",
		PubKey:         pub,
		DownloadDir:    t.TempDir(),
		Privileged:     true,
		Managed:        managedForTest,
		Apply:          func(context.Context, string) error { t.Fatal("apply must not run"); return nil },
	}
	st, err := u.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !st.Available || st.Latest != "1.11.0" {
		t.Errorf("want the newer version reported: available=%v latest=%q", st.Available, st.Latest)
	}
	if st.HasArtifact || st.CanApply || st.Reason != ReasonNoArtifact {
		t.Errorf("want (no artifact, cannot apply, %q), got has=%v can=%v reason=%q",
			ReasonNoArtifact, st.HasArtifact, st.CanApply, st.Reason)
	}
	// And the periodic loop must treat it the same way: quiet, not an error.
	applied, err := u.CheckAndApply(context.Background())
	if applied || err != nil {
		t.Fatalf("CheckAndApply=(%v,%v), want (false,nil) — not an error", applied, err)
	}
}

// The other half of that line: an entry that EXISTS but is malformed or points
// at someone else's host stays a loud error. "Nothing published for me" and
// "what's published for me is wrong" must not collapse into one state.
func TestCheckUnsignedArtifactStaysAnError(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	installer := []byte("payload")
	srv := testServer(t, "1.11.0", installer, "", "", priv) // empty signature
	defer srv.Close()

	u := &Updater{
		ManifestURL:    srv.URL + "/latest.json",
		CurrentVersion: "1.10.0",
		PubKey:         pub,
		DownloadDir:    t.TempDir(),
		Privileged:     true,
		Managed:        managedForTest,
		Apply:          func(context.Context, string) error { t.Fatal("apply must not run"); return nil },
	}
	st, err := u.Check(context.Background())
	if err == nil {
		t.Fatal("an artifact with no signature was accepted")
	}
	if st.Reason != ReasonUnsigned {
		t.Errorf("Reason = %q, want %q", st.Reason, ReasonUnsigned)
	}
}

// A user-mode daemon checks — that is the whole point of splitting check from
// apply — but never installs. Drop `case !u.Privileged` from check() and the
// apply assertion fires.
func TestUnprivilegedDaemonChecksButNeverApplies(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	installer := []byte("fake calabi installer payload")
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, installer))
	srv := testServer(t, "1.11.0", installer, sig, "", priv)
	defer srv.Close()

	u := &Updater{
		ManifestURL:    srv.URL + "/latest.json",
		CurrentVersion: "1.10.0",
		PubKey:         pub,
		DownloadDir:    t.TempDir(),
		Privileged:     false, // a per-user daemon: cannot install, still wants to know
		Managed:        managedForTest,
		Apply:          func(context.Context, string) error { t.Fatal("apply must not run"); return nil },
	}
	st, err := u.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !st.Available || !st.HasArtifact {
		t.Fatalf("want the update seen: available=%v hasArtifact=%v", st.Available, st.HasArtifact)
	}
	if st.CanApply || st.Reason != ReasonNotPrivileged {
		t.Errorf("want (cannot apply, %q), got can=%v reason=%q", ReasonNotPrivileged, st.CanApply, st.Reason)
	}
	if applied, err := u.CheckAndApply(context.Background()); applied || err != nil {
		t.Fatalf("CheckAndApply=(%v,%v), want (false,nil)", applied, err)
	}
}

// The version floor is a ledger of what this machine has been OFFERED, so a
// daemon that only ever checks still has to write it. Otherwise a machine that
// later gains the ability to install (user daemon → system service) would start
// from an open floor and accept a replayed older manifest.
func TestCheckWritesTheVersionFloor(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	srv := foreignPlatformServer(t, "1.11.0", priv)
	defer srv.Close()

	dir := t.TempDir()
	u := &Updater{
		ManifestURL:    srv.URL + "/latest.json",
		CurrentVersion: "1.10.0",
		PubKey:         pub,
		DownloadDir:    dir,
		Privileged:     false,
		Managed:        managedForTest,
	}
	if _, err := u.Check(context.Background()); err != nil {
		t.Fatalf("Check: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, versionFloorFile))
	if err != nil {
		t.Fatalf("a check-only daemon did not record the floor: %v", err)
	}
	if got := readVersionFloor(dir); got != "1.11.0" {
		t.Errorf("floor = %q (file %q), want 1.11.0", got, b)
	}
}

// Check never downloads. The installer handler failing the test is the assertion.
func TestCheckDoesNotDownload(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	body := []byte(fmt.Sprintf(`{"version":"1.11.0","platforms":{%q:{"url":"%%s/installer","sha256":"aa","signature":"bb"}}}`, PlatformKey()))
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/installer", func(http.ResponseWriter, *http.Request) {
		t.Error("Check downloaded the installer")
	})
	mux.HandleFunc("/latest.json", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(fmt.Sprintf(string(body), "http://"+r.Host)))
	})
	mux.HandleFunc("/latest.json.sig", func(w http.ResponseWriter, r *http.Request) {
		b := []byte(fmt.Sprintf(string(body), "http://"+r.Host))
		fmt.Fprintln(w, base64.StdEncoding.EncodeToString(ed25519.Sign(priv, b)))
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	u := &Updater{
		ManifestURL:    srv.URL + "/latest.json",
		CurrentVersion: "1.10.0",
		PubKey:         pub,
		DownloadDir:    t.TempDir(),
		Privileged:     true,
		Managed:        managedForTest,
		Apply:          func(context.Context, string) error { t.Fatal("apply must not run"); return nil },
	}
	st, err := u.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !st.CanApply {
		t.Fatalf("want CanApply on a well-formed same-origin artifact, reason=%q", st.Reason)
	}
}
