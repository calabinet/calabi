package selfupdate

// Archive handling for the Linux update path, kept OUT of apply_linux.go on
// purpose: nothing in here is platform-specific, and behind a //go:build linux
// tag it could only be tested on Linux — which is to say, not on the machine
// where it is written. This is the part that parses attacker-shaped input.

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// maxBinaryBytes caps what we will write out of an archive. The archive itself
// is already size-capped and signature-checked, but a decompressor is a
// multiplier and this runs as root: a zip-bomb-shaped tarball that verified
// correctly would otherwise fill the disk the service lives on.
const maxBinaryBytes = 512 << 20

// extractBinary pulls the `calabi` executable out of a.tar.gz into dest.
func extractBinary(archivePath, dest string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("selfupdate: archive is not gzip: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("selfupdate: read archive: %w", err)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		// Match on the BASE NAME and ignore the rest of the path. The entry is
		// never written at the name the archive gives it, so a hostile "./."
		// in there cannot reach outside the destination — the classic tar
		// traversal simply has nothing to traverse.
		if filepath.Base(filepath.Clean(h.Name)) != "calabi" {
			continue
		}
		out, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
		if err != nil {
			return err
		}
		n, cerr := io.Copy(out, io.LimitReader(tr, maxBinaryBytes+1))
		if closeErr := out.Close(); cerr == nil {
			cerr = closeErr
		}
		if cerr != nil {
			return cerr
		}
		if n > maxBinaryBytes {
			return fmt.Errorf("selfupdate: binary in archive exceeds %d bytes — refusing", int64(maxBinaryBytes))
		}
		if n == 0 {
			return errors.New("selfupdate: archive contains an empty calabi binary")
		}
		return os.Chmod(dest, 0o755)
	}
	return errors.New("selfupdate: no `calabi` binary found in the archive")
}
