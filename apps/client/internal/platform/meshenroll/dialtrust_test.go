package meshenroll

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/calabi/calabi/apps/client/internal/trust"
	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
	meshpb "github.com/calabi/calabi/pkg/mesh-proto/meshpb"
)

// selfSignedCoord runs a coordinator stand-in serving gRPC over TLS on a
// self-signed certificate, as calabi-coord does with no certificate files, and
// returns its address and the certificate's pin.
func selfSignedCoord(t *testing.T) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "calabi-coord"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(grpc.Creds(credentials.NewServerTLSFromCert(&cert)))
	meshpb.RegisterCoordinatorServer(srv, meshpb.UnimplementedCoordinatorServer{})
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)
	return ln.Addr().String(), meshproto.CertPin(leaf)
}

// call makes one RPC and returns its status code. The stand-in implements
// nothing, so a call that crossed TLS comes back Unimplemented; one refused at
// the handshake comes back Unavailable.
func call(t *testing.T, addr string, cfg trust.Config) (codes.Code, error) {
	t.Helper()
	tc, err := cfg.TLS(addr)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := DialCoord(addr, tc)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = meshpb.NewCoordinatorClient(conn).GetRegisterChallenge(ctx, &meshpb.GetRegisterChallengeRequest{})
	return status.Code(err), err
}

// The pin survives gRPC's own TLS plumbing: the right fingerprint gets a call
// through to a self-signed coordinator, a wrong one never gets past the
// handshake, and neither does the system trust store.
func TestDialCoordHonoursTheConnectionsTrust(t *testing.T) {
	addr, pin := selfSignedCoord(t)

	if code, err := call(t, addr, trust.Config{Mode: trust.Pin, Pins: []string{pin}}); code != codes.Unimplemented {
		t.Fatalf("pinned: %v (%v), want the call to reach the server", code, err)
	}
	wrong := "sha256:" + strings.Repeat("0", 64)
	if code, err := call(t, addr, trust.Config{Mode: trust.Pin, Pins: []string{wrong}}); code != codes.Unavailable || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("wrong pin: %v (%v), want the handshake refused over the fingerprint", code, err)
	}
	if code, err := call(t, addr, trust.Config{Mode: trust.System}); code != codes.Unavailable {
		t.Fatalf("system trust: %v (%v), want the handshake refused", code, err)
	}
}
