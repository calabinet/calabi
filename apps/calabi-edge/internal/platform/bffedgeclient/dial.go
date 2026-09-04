// dial.go — open the long-lived mTLS gRPC connection to bff-edge.
//
// One connection. All edge → control-plane traffic flows through it.
// The edge presents an X.509 client cert signed by cert-svc's edge CA
//; bff-edge's auth interceptor extracts edge_id + region
// from the cert's CN and stamps them onto every RPC.
//
// We pin TLS 1.3 + ALPN "h2" to match bff-edge's server config and
// keep the wire envelope identical to what the edge already speaks
// over plaintext gRPC inside the cluster.

package bffedgeclient

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	pb "github.com/calabi/calabi/pkg/edge-proto/edgepb"
)

// Config bundles the input paths for Dial.
type Config struct {
	// Addr is bff-edge's public host:port, e.g. "bff-edge.calabi.net:443".
	Addr string
	// ClientCertPath / ClientKeyPath are the edge's mTLS leaf cert + key
	// (issued by cert-svc.IssueEdgeCert; CN = "edge-{id}-{region}").
	ClientCertPath string
	ClientKeyPath  string
	// CAPath is the bff-edge server CA bundle. May equal the calabi
	// internal CA if bff-edge's server cert is self-signed; otherwise
	// supply the public root chain.
	CAPath string
	// ServerName overrides the SNI hostname when the dial Addr is an
	// IP literal (e.g. for staging). Empty = use the host part of Addr.
	ServerName string
}

// Conn bundles the open gRPC connection with a typed BFFEdge client.
type Conn struct {
	GRPC   *grpc.ClientConn
	Client pb.BFFEdgeClient

	// holder backs the TLS GetClientCertificate callback so RunCertRenewal can
	// hot-swap the edge's own mTLS leaf without dropping the connection (F1).
	// cfg keeps the on-disk paths so a renewed cert is persisted for restart.
	holder *certHolder
	cfg    Config
}

// Close drops the underlying gRPC conn.
func (c *Conn) Close() error {
	if c == nil || c.GRPC == nil {
		return nil
	}
	return c.GRPC.Close()
}

// Dial constructs the mTLS gRPC connection. The connection is lazy
// (grpc.NewClient does NOT block on TCP), matching the rest of the
// edge code's "boot fast, dial when needed" posture.
func Dial(cfg Config) (*Conn, error) {
	if cfg.Addr == "" {
		return nil, fmt.Errorf("bffedgeclient: empty bff-edge addr")
	}
	if cfg.ClientCertPath == "" || cfg.ClientKeyPath == "" {
		return nil, fmt.Errorf("bffedgeclient: client cert/key paths are required for mTLS")
	}
	if cfg.CAPath == "" {
		return nil, fmt.Errorf("bffedgeclient: CA bundle path is required")
	}

	clientCert, err := loadLeafKeyPair(cfg.ClientCertPath, cfg.ClientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("bffedgeclient: load client cert/key: %w", err)
	}
	caPEM, err := os.ReadFile(cfg.CAPath)
	if err != nil {
		return nil, fmt.Errorf("bffedgeclient: read CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("bffedgeclient: CA bundle has no usable certs")
	}

	holder := &certHolder{cert: &clientCert}
	tlsCfg := &tls.Config{
		// GetClientCertificate (not a static Certificates slice) so RunCertRenewal
		// can hot-swap the leaf on rotation: the next handshake picks up the new
		// cert without a restart. The established conn keeps its session; reconnects
		// use whatever the holder currently has.
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return holder.get(), nil
		},
		RootCAs:    pool,
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h2"},
		ServerName: cfg.ServerName,
	}

	conn, err := grpc.NewClient(
		cfg.Addr,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			// Stream + RPC heartbeat: 30s ping is enough to keep
			// stateful SLBs from idling the conn while not adding
			// meaningful traffic.
			Time:                30 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("bffedgeclient: dial %s: %w", cfg.Addr, err)
	}

	return &Conn{GRPC: conn, Client: pb.NewBFFEdgeClient(conn), holder: holder, cfg: cfg}, nil
}
