// renew.go — auto-renewal of the edge's OWN mTLS client cert (F1,
// byoi-seat-and-cert-lifecycle).
//
// The edge leaf is short-lived (cert-svc issues BYOI edges at 90 days). This
// loop calls bff-edge.RenewEdgeCert over the SAME mTLS conn before expiry,
// hot-swaps the in-memory cert (via the certHolder that backs the dialer's
// GetClientCertificate) so the running connection is never dropped, and
// persists the new PEMs to disk so a restart survives on the fresh cert.
//
// Only a BYOI edge (cert carries a SPIFFE org SAN) renews: a platform edge's
// cert is admin-managed and RenewEdgeCert is BYOI-only, so the loop exits early
// for it. A revoked cert can't reach RenewEdgeCert at all (bff-edge's CRL), and
// a de-entitled org is refused (PermissionDenied) — either way the short cert
// simply expires (soft landing / hard cut), and the operator re-issues manually.

package bffedgeclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	pb "github.com/calabi/calabi/pkg/edge-proto/edgepb"
)

const (
	// renewBefore starts renewal attempts once the leaf has less than this left.
	// 30 days of slack on a 90-day cert absorbs long edge downtime.
	renewBefore = 30 * 24 * time.Hour
	// renewRetry backs off between failed attempts (transient upstreams, or a
	// de-entitled org whose entitlement may later return).
	renewRetry = time.Hour
	// renewMaxSleep caps the idle wait so the loop re-evaluates at least daily
	// (robust to clock changes / a stuck-far NotAfter).
	renewMaxSleep = 24 * time.Hour
	// renewCallTimeout bounds a single RenewEdgeCert RPC.
	renewCallTimeout = 30 * time.Second
)

// certHolder is the swappable backing store for the dialer's
// GetClientCertificate callback. Read on every TLS handshake; written by
// RunCertRenewal on rotation.
type certHolder struct {
	mu   sync.RWMutex
	cert *tls.Certificate
}

func (h *certHolder) get() *tls.Certificate {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.cert
}

func (h *certHolder) set(c *tls.Certificate) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cert = c
}

func (h *certHolder) notAfter() time.Time {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.cert == nil || h.cert.Leaf == nil {
		return time.Time{}
	}
	return h.cert.Leaf.NotAfter
}

// isBYOI reports whether the current leaf carries a SPIFFE org SAN (a BYOI
// edge). Platform edges have no URI SAN.
func (h *certHolder) isBYOI() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.cert == nil || h.cert.Leaf == nil {
		return false
	}
	for _, u := range h.cert.Leaf.URIs {
		if u != nil && u.Scheme == "spiffe" {
			return true
		}
	}
	return false
}

// loadLeafKeyPair is tls.LoadX509KeyPair plus a parsed Leaf, so the holder can
// read NotAfter / the SPIFFE SAN without re-parsing on every check.
func loadLeafKeyPair(certPath, keyPath string) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	if len(cert.Certificate) > 0 {
		if leaf, perr := x509.ParseCertificate(cert.Certificate[0]); perr == nil {
			cert.Leaf = leaf
		}
	}
	return cert, nil
}

// RunCertRenewal keeps the edge's own mTLS client cert fresh until ctx is
// cancelled, then returns nil.
//
// It runs as a background namedRunner in main's errCh set, where ANY runner
// returning — even nil — trips the shutdown select and stops the whole edge
// (main.go: `case err := <-errCh` with err==nil falls through to `return nil`,
// silently). So this MUST NOT return before ctx is done: the platform-edge and
// no-holder skip paths block on ctx.Done() rather than returning immediately.
// A bare `return nil` on the skip path shut every PLATFORM edge (no org SAN,
// so nothing to renew) down ~1s after boot — booted clean, then vanished with
// no shutdown log. BYOI edges were unaffected (their loop blocks on ctx).
func (c *Conn) RunCertRenewal(ctx context.Context, logger *slog.Logger) error {
	logger = logger.With("component", "edge-cert-renewer")
	if c == nil || c.holder == nil {
		<-ctx.Done() // hold the runner slot open for the process lifetime
		return nil
	}
	if !c.holder.isBYOI() {
		logger.Info("platform edge cert (no org SAN) — auto-renew not applicable; skipping")
		<-ctx.Done() // NOT a bare return — that would shut the edge down (see above)
		return nil
	}
	logger.Info("edge cert auto-renewer started", "not_after", c.holder.notAfter(), "renew_before", renewBefore)
	for {
		na := c.holder.notAfter()
		wait := renewMaxSleep
		if !na.IsZero() {
			if d := time.Until(na.Add(-renewBefore)); d < wait {
				wait = d
			}
		}
		if wait > 0 {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(wait):
			}
			continue
		}
		// In the renewal window — attempt a rotation.
		if err := c.renewOnce(ctx, logger); err != nil {
			logger.Warn("edge cert renewal failed; will retry",
				"err", err, "not_after", na, "retry_in", renewRetry)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(renewRetry):
			}
		}
		// On success the holder now has a far-future NotAfter, so the next
		// iteration sleeps long.
	}
}

func (c *Conn) renewOnce(ctx context.Context, logger *slog.Logger) error {
	callCtx, cancel := context.WithTimeout(ctx, renewCallTimeout)
	defer cancel()
	resp, err := c.Client.RenewEdgeCert(callCtx, &pb.RenewEdgeCertRequest{})
	if err != nil {
		return err
	}
	newCert, err := tls.X509KeyPair(resp.GetCertPem(), resp.GetKeyPem())
	if err != nil {
		return fmt.Errorf("parse renewed keypair: %w", err)
	}
	if len(newCert.Certificate) > 0 {
		if leaf, perr := x509.ParseCertificate(newCert.Certificate[0]); perr == nil {
			newCert.Leaf = leaf
		}
	}
	// Persist first (a restart should land on the new cert), then hot-swap the
	// in-memory holder. A persist failure is non-fatal for the running process —
	// the swap still takes effect — but warn: a restart would revert to old files.
	if perr := c.persistCert(resp.GetCertPem(), resp.GetKeyPem(), resp.GetCaPem()); perr != nil {
		logger.Warn("persist renewed cert failed; in-memory swap only (a restart would use the old cert)", "err", perr)
	}
	c.holder.set(&newCert)
	logger.Info("edge cert renewed + hot-swapped",
		"serial", resp.GetSerialHex(), "not_after", resp.GetNotAfter().AsTime())
	return nil
}

// persistCert atomically writes the renewed PEMs back to the configured paths.
// Empty inputs / paths are skipped (the CA rarely changes but is written when
// returned, so a CA roll is picked up too).
func (c *Conn) persistCert(certPEM, keyPEM, caPEM []byte) error {
	if err := writeFileAtomic(c.cfg.ClientCertPath, certPEM, 0o644); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	if err := writeFileAtomic(c.cfg.ClientKeyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	if err := writeFileAtomic(c.cfg.CAPath, caPEM, 0o644); err != nil {
		return fmt.Errorf("write ca: %w", err)
	}
	return nil
}

// writeFileAtomic writes via a temp file + rename so a crash mid-write can't
// leave a truncated cert/key on disk. No-op for an empty path or payload.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	if path == "" || len(data) == 0 {
		return nil
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
