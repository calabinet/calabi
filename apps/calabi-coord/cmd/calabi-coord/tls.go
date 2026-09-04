package main

import (
	"log/slog"
	"os"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// coordServerCreds builds the gRPC server options that make coord's :7014 serve
// TLS (R0′ / hardening).
//
// Coord's gRPC is the ONE control-plane surface a client dials directly over the
// public internet — the daemon sends its tk_ auth key over it on every enroll —
// so it should not be plaintext in production. Rather than front it with a TLS
// proxy, coord terminates TLS itself with a server certificate signed by the
// platform EDGE CA: the daemon already embeds that CA root to verify the edge
// :7443 control listener, so it verifies coord with zero extra trust
// distribution (see the client's dialCoord / transport.EdgeRootCAs).
//
// Both CALABI_COORD_TLS_CERT_FILE and _KEY_FILE must be set together. Neither set =
// plaintext, warned loudly (correct for dev / smoke, and for a deployment that
// still terminates TLS in front). One-of-two set is a misconfiguration that
// would silently serve plaintext, so it aborts.
//
// IMPORTANT: give coord a SERVER-only certificate (serverAuth EKU, no clientAuth,
// no SPIFFE org SAN) — i.e. one from cert-svc's IssueServerCert, NOT an edge leaf.
// An edge leaf doubles as a control-plane CLIENT credential (mTLS into bff-edge),
// so handing coord's internet-facing listener one would widen the blast radius of
// a coord compromise. The edge CA signs both; only the EKU differs.
func coordServerCreds(logger *slog.Logger) []grpc.ServerOption {
	cert := strings.TrimSpace(os.Getenv("CALABI_COORD_TLS_CERT_FILE"))
	key := strings.TrimSpace(os.Getenv("CALABI_COORD_TLS_KEY_FILE"))

	if cert == "" && key == "" {
		logger.Warn("coord gRPC is PLAINTEXT — the daemon sends its auth key over it. Set CALABI_COORD_TLS_CERT_FILE/_KEY_FILE (an edge-CA server cert) before exposing :7014 publicly, or terminate TLS in front")
		return nil
	}
	if cert == "" || key == "" {
		logger.Error("coord: CALABI_COORD_TLS_CERT_FILE and _KEY_FILE must both be set or both empty; refusing to start half-configured (would silently serve plaintext)")
		os.Exit(1)
	}
	creds, err := credentials.NewServerTLSFromFile(cert, key)
	if err != nil {
		logger.Error("coord: cannot load the gRPC server certificate; refusing to start", "cert", cert, "err", err)
		os.Exit(1)
	}
	logger.Info("coord gRPC serving TLS", "cert", cert)
	return []grpc.ServerOption{grpc.Creds(creds)}
}
