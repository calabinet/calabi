//go:build linux

package selfupdate

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// script writes an executable shell script. Standing in for the release binary:
// what applyInstaller needs from it is that the kernel will execute it and that
// it answers `version` — a script does both, without a cross-compile in a test.
func script(t *testing.T, path, body string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// verifyRunnable is the gate that catches the one bad artifact a hash and a
// signature cannot: a correctly published tarball built for another
// architecture. Without it that failure shows up as a service that never comes
// back, with the old binary already gone.
func TestVerifyRunnableAcceptsOnlyAWorkingCalabi(t *testing.T) {
	dir := t.TempDir()
	ok := script(t, filepath.Join(dir, "good"), `echo "calabi 9.9.9"`)
	if err := verifyRunnable(context.Background(), ok); err != nil {
		t.Errorf("a working binary was rejected: %v", err)
	}

	// Runs, but is not us. A tarball that somehow carried the wrong program.
	wrong := script(t, filepath.Join(dir, "wrong"), `echo "some other tool 1.0"`)
	if err := verifyRunnable(context.Background(), wrong); err == nil {
		t.Error("a binary that does not identify itself as calabi was accepted")
	}

	// Does not run at all — the wrong-architecture case.
	broken := filepath.Join(dir, "broken")
	if err := os.WriteFile(broken, []byte("\x7fELF not really"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := verifyRunnable(context.Background(), broken); err == nil {
		t.Error("a binary that cannot execute here was accepted")
	}
}

// The claim the whole Linux path rests on: renaming a file over a RUNNING
// executable works, and the process holding the old one keeps running off the
// old inode. If this were false, applyInstaller would be replacing the binary of
// a live service with no way back.
func TestRenameOverAHeldBinaryKeepsTheOldInodeAlive(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "calabi")
	script(t, live, `echo "calabi 1.0.0"`)

	// Stand in for the running process: an open descriptor on the old inode.
	held, err := os.Open(live)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()

	newer := script(t, filepath.Join(dir, ".calabi-update.new"), `echo "calabi 2.0.0"`)

	// The backup link applyInstaller makes, so a human has something to move back.
	backup := live + ".old"
	if err := os.Link(live, backup); err != nil {
		t.Fatalf("hard link for the backup: %v", err)
	}
	if err := os.Rename(newer, live); err != nil {
		t.Fatalf("rename over a held binary: %v", err)
	}

	// The held descriptor still reads the OLD contents...
	buf := make([]byte, 64)
	n, _ := held.ReadAt(buf, 0)
	if !strings.Contains(string(buf[:n]), "1.0.0") {
		t.Errorf("the running process lost its binary: %q", buf[:n])
	}
	// ...the path now has the new one...
	b, _ := os.ReadFile(live)
	if !strings.Contains(string(b), "2.0.0") {
		t.Errorf("on-disk binary after swap: %q", b)
	}
	// ...and the backup is still the old one.
	ob, _ := os.ReadFile(backup)
	if !strings.Contains(string(ob), "1.0.0") {
		t.Errorf("backup after swap: %q", ob)
	}
}

// End to end over the real archive path: a published tarball goes in, a verified
// executable comes out where the caller asked.
func TestExtractThenVerifyOnLinux(t *testing.T) {
	src := tgz(t, [2]string{"calabi", "#!/bin/sh\necho \"calabi 9.9.9\"\n"})
	dest := filepath.Join(t.TempDir(), "calabi")
	if err := extractBinary(src, dest); err != nil {
		t.Fatalf("extractBinary: %v", err)
	}
	// extractBinary must leave it executable, or the verify below cannot run it
	// and neither could systemd.
	fi, err := os.Stat(dest)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o111 == 0 {
		t.Fatalf("extracted mode %v — not executable", fi.Mode().Perm())
	}
	if err := verifyRunnable(context.Background(), dest); err != nil {
		t.Errorf("verifyRunnable on a freshly extracted binary: %v", err)
	}
}
