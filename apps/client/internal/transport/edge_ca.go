package transport

import (
	"crypto/x509"
	_ "embed"
	"errors"
	"fmt"
	"os"
)

// embeddedEdgeCA is the platform edge-CA root certificate, compiled into
// the binary. Production builds replace certs/edge-ca.pem with the real
// cert-svc edge-CA root (PUBLIC cert only — never the private key); the
// checked-in placeholder carries no certificate so OSS / dev builds still
// compile. Without a real embedded root, verification falls back to
// CALABI_EDGE_CA_FILE (dev), and fails closed if neither is present.
//
//go:embed certs/edge-ca.pem
var embeddedEdgeCA []byte

// EdgeRootCAs returns the trust pool for verifying any server certificate the
// platform edge CA signed: the edge :7443 control listener AND — since the mesh
// coordinator grew native TLS (R0′) — coord's public gRPC. It reads the embedded
// root plus the optional CALABI_EDGE_CA_FILE override, so the mesh datapath can
// dial coord with the exact trust root the edge control transport already uses;
// coord presents an edge-CA-signed server cert (calabi-coord CALABI_COORD_TLS_*), and
// this build needs no extra trust distribution to verify it.
func EdgeRootCAs() (*x509.CertPool, error) {
	return edgeRootCAs(os.Getenv("CALABI_EDGE_CA_FILE"))
}

// edgeRootCAs builds the trust pool used to verify the edge :7443 control
// listener: the embedded platform root plus an optional extra CA file
// (CALABI_EDGE_CA_FILE — a dev/override hook).
//
// The embedded root is the canonical trust now that the dev *and* release
// CAs are compiled in, so CALABI_EDGE_CA_FILE is redundant in normal use.
// A set-but-unreadable extra file is therefore NON-FATAL when the embedded
// root is present: a stale env var (e.g. a relative dev path that no longer
// resolves under the binary's cwd) must not break a binary that already has
// working trust. We only hard-fail on the extra file when it's the sole
// source of trust (an OSS placeholder build with no embedded cert), or when
// the file is actually present but malformed (no PEM certs) — that's a real
// misconfiguration worth surfacing.
//
// Fails closed overall: if nothing yields a usable certificate it errors
// rather than returning an empty pool (which TLS would treat as "verify
// against system roots" — wrong for an internally-signed edge cert).
func edgeRootCAs(extraFile string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	embedded := len(embeddedEdgeCA) > 0 && pool.AppendCertsFromPEM(embeddedEdgeCA)
	added := embedded
	if extraFile != "" {
		pem, err := os.ReadFile(extraFile)
		switch {
		case err != nil:
			// Unreadable extra file. Tolerate it only if the embedded root
			// already covers us; otherwise it was the only trust we had.
			if !embedded {
				return nil, fmt.Errorf("read CALABI_EDGE_CA_FILE %q: %w", extraFile, err)
			}
		case !pool.AppendCertsFromPEM(pem):
			return nil, fmt.Errorf("no PEM certificates found in %q", extraFile)
		default:
			added = true
		}
	}
	if !added {
		return nil, errors.New(
			"no edge CA root available — this build has no embedded root; " +
				"set CALABI_EDGE_CA_FILE to a CA PEM (dev: deploy/dev/certs/ca.crt), " +
				"or CALABI_INSECURE=1 to skip verification (unsafe)")
	}
	return pool, nil
}
