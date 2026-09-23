package main

import (
	"crypto/tls"
	"fmt"
	"os"
	"sync"
)

// fileCert serves a certificate held in a pair of files, and notices when they
// are replaced.
//
// Rotation happens under this process, not through it: a BYOI node's own leaf
// renews itself (bffedgeclient.RunCertRenewal writes the new PEM over the same
// path with 30 days left of 90), and a platform node's control certificate is
// replaced by whoever runs the box. Neither restarts the edge, so a listener
// that read the file once at boot goes on presenting the copy it happens to
// hold — and keeps doing so past the point where a valid certificate has been
// sitting next to it for a month.
//
// A stat per handshake pays for that. The control listener handshakes once per
// device SESSION (data streams are yamux-multiplexed over the same connection),
// so the rate is bounded by devices, not by traffic.
type fileCert struct {
	certPath, keyPath string

	mu    sync.RWMutex
	cur   *tls.Certificate
	stamp string // what the files looked like when cur was read
}

func newFileCert(certPath, keyPath string, loaded tls.Certificate) *fileCert {
	f := &fileCert{certPath: certPath, keyPath: keyPath, cur: &loaded}
	f.stamp = f.stampNow()
	return f
}

// get returns the current certificate, re-reading it first if the files have
// changed since the last read.
func (f *fileCert) get() (*tls.Certificate, error) {
	stamp := f.stampNow()
	f.mu.RLock()
	cur, cached := f.cur, f.stamp
	f.mu.RUnlock()
	if stamp != "" && stamp == cached {
		return cur, nil
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if stamp != "" && stamp == f.stamp { // another handshake got there first
		return f.cur, nil
	}
	next, err := tls.LoadX509KeyPair(f.certPath, f.keyPath)
	if err != nil {
		// A rotation is two files written a moment apart, so a handshake can
		// land on a cert that does not match its key yet. Keep serving what we
		// have and leave the stamp alone, so the next handshake tries again —
		// failing here would turn a transient mismatch into a refused device.
		if f.cur != nil {
			return f.cur, nil
		}
		return nil, fmt.Errorf("control certificate %s: %w", f.certPath, err)
	}
	f.cur, f.stamp = &next, stamp
	return f.cur, nil
}

// stampNow describes both files well enough to notice a replacement. Empty when
// either is unreadable, which get() treats as "nothing to compare" and leaves
// the loaded certificate in place.
func (f *fileCert) stampNow() string {
	c, err := os.Stat(f.certPath)
	if err != nil {
		return ""
	}
	k, err := os.Stat(f.keyPath)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%d:%d:%d:%d",
		c.ModTime().UnixNano(), c.Size(), k.ModTime().UnixNano(), k.Size())
}
