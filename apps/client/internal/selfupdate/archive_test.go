package selfupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// tgz builds a.tar.gz from name→content pairs, in order.
func tgz(t *testing.T, entries ...[2]string) string {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		body := []byte(e[1])
		if err := tw.WriteHeader(&tar.Header{
			Name: e[0], Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "release.tar.gz")
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestExtractBinaryPullsCalabiOut(t *testing.T) {
	src := tgz(t, [2]string{"calabi", "ELF-ish payload"})
	dest := filepath.Join(t.TempDir(), "out")
	if err := extractBinary(src, dest); err != nil {
		t.Fatalf("extractBinary: %v", err)
	}
	b, err := os.ReadFile(dest)
	if err != nil || string(b) != "ELF-ish payload" {
		t.Fatalf("extracted %q, %v", b, err)
	}
}

// A path in the archive must not be able to steer where we write. The entry is
// written at a destination the CALLER chose, so the classic "././etc/cron.d"
// has nothing to traverse — this pins that the name is only ever matched, never
// joined.
func TestExtractBinaryIgnoresThePathInTheArchive(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "out")
	src := tgz(t, [2]string{"../../../../tmp/calabi", "payload"})
	if err := extractBinary(src, dest); err != nil {
		t.Fatalf("extractBinary: %v", err)
	}
	if _, err := os.Stat(dest); err != nil {
		t.Fatalf("the entry was not written where the caller asked: %v", err)
	}
	// And nothing appeared anywhere else under the temp root.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("wrote %d files, want exactly the one destination", len(entries))
	}
}

// Anything that is not the binary is skipped, not treated as it. A release
// archive that grows a README must not suddenly install the README.
func TestExtractBinarySkipsEverythingElse(t *testing.T) {
	src := tgz(t,
		[2]string{"README.md", "not the binary"},
		[2]string{"bin/calabi", "the real one"},
	)
	dest := filepath.Join(t.TempDir(), "out")
	if err := extractBinary(src, dest); err != nil {
		t.Fatalf("extractBinary: %v", err)
	}
	b, _ := os.ReadFile(dest)
	if string(b) != "the real one" {
		t.Errorf("extracted %q, want the calabi entry", b)
	}
}

func TestExtractBinaryRejectsAnArchiveWithoutCalabi(t *testing.T) {
	src := tgz(t, [2]string{"README.md", "nope"})
	dest := filepath.Join(t.TempDir(), "out")
	if err := extractBinary(src, dest); err == nil {
		t.Fatal("an archive with no calabi binary was accepted")
	}
	if _, err := os.Stat(dest); err == nil {
		t.Error("a destination file was left behind after a failed extract")
	}
}

// An empty entry would swap in a zero-byte "binary" and take the service down
// with nothing to look at. The hash and signature cannot catch it: an empty file
// hashes and signs perfectly well.
func TestExtractBinaryRejectsAnEmptyBinary(t *testing.T) {
	src := tgz(t, [2]string{"calabi", ""})
	dest := filepath.Join(t.TempDir(), "out")
	if err := extractBinary(src, dest); err == nil {
		t.Fatal("a zero-byte binary was accepted")
	}
}

func TestExtractBinaryRejectsNonGzip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "not.tar.gz")
	if err := os.WriteFile(p, []byte("this is not gzip"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := extractBinary(p, filepath.Join(t.TempDir(), "out")); err == nil {
		t.Fatal("a non-gzip file was accepted as an archive")
	}
}

// Linux servers default to "security only" rather than "automatic": the restart
// there drops live tunnels for something nobody asked for at that moment.
// Desktops default to automatic, where a few seconds of reconnect costs nothing.
func TestDefaultModeIsConservativeOnServers(t *testing.T) {
	p := DefaultPolicy()
	if err := p.Validate(); err != nil {
		t.Fatalf("the default policy does not validate: %v", err)
	}
	want := ModeAuto
	if runtime.GOOS == "linux" {
		want = ModeSecurity
	}
	if p.Mode != want {
		t.Errorf("default mode = %q, want %q on this platform", p.Mode, want)
	}
}
