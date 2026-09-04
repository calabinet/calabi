package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	"github.com/calabi/calabi/apps/client/internal/transport"
)

// dialCoord opens the gRPC connection to the mesh coordinator.
//
// Coord's public gRPC is the one internal control-plane surface a client dials
// directly over the public internet, and the daemon sends its auth key over it,
// so it is dialed over TLS by default — verified against the embedded platform
// edge CA (the SAME root the edge :7443 control transport trusts). coord presents
// an edge-CA-signed server cert (calabi-coord CALABI_COORD_TLS_CERT_FILE/_KEY_FILE), so
// no extra trust root has to be shipped. The TLS ServerName is the host in addr,
// which must match the cert SAN (e.g. coord.calabi.net).
//
// CALABI_INSECURE=1 dials plaintext instead — for dev / smoke stacks whose coord
// serves no TLS. It mirrors the edge control transport's existing CALABI_INSECURE
// escape hatch, so one flag makes a whole dev stack plaintext.
// coordKeepalive makes a dead control-plane connection FAIL rather than hang.
//
// Without it the netmap stream can sit on a half-open TCP indefinitely: the
// daemon believes it is watching a stream that will never deliver another
// netmap, and the runner never gets the error it needs to reconnect. That is
// exactly the state a machine wakes up from standby in — the far side dropped
// the connection while this one was asleep and there is nobody left to send a
// RST. 30s + 10s puts a ceiling of about 40s on how long that can last.
//
// PermitWithoutStream keeps the connection proven between netmaps too. NOTE: this
// pings more often than a stock gRPC server's default enforcement policy allows
// (MinTime 5m), so calabi-coord sets a matching EnforcementPolicy — DEPLOY COORD-SVC
// FIRST. Against an un-upgraded coordinator these pings are tolerated only
// because the server resets its ping-strike counter whenever it sends data, and
// coord pushes netmaps regularly; a quiet stretch would earn a GOAWAY.
var coordKeepalive = grpc.WithKeepaliveParams(keepalive.ClientParameters{
	Time:                30 * time.Second,
	Timeout:             10 * time.Second,
	PermitWithoutStream: true,
})

func dialCoord(addr string) (*grpc.ClientConn, error) {
	if os.Getenv("CALABI_INSECURE") == "1" {
		return grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()), coordKeepalive)
	}
	pool, err := transport.EdgeRootCAs()
	if err != nil {
		return nil, fmt.Errorf("coord TLS trust root: %w (set CALABI_INSECURE=1 for a plaintext dev coordinator)", err)
	}
	host, _, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		host = addr // addr may already be a bare host
	}
	creds := credentials.NewTLS(&tls.Config{
		RootCAs:    pool,
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	})
	return grpc.NewClient(addr, grpc.WithTransportCredentials(creds), coordKeepalive)
}
