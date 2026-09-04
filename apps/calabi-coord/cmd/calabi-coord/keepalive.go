package main

import (
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

// coordKeepaliveOptions lets the daemon prove its control-plane connection is
// still alive, and lets coord notice a node that has silently gone away.
//
// The client half is what matters. A daemon watching netmaps holds one long-lived
// server stream, and if the path under it dies without a RST — the machine was
// suspended, a NAT dropped the mapping, a middlebox timed the flow out — that
// stream simply never delivers anything again. Nothing in gRPC surfaces an error
// on its own, so the daemon sits there believing it is enrolled while the
// coordinator has long since forgotten it. The client therefore pings every 30s
// and gives up after 10s of silence (see the client's dialCoord).
//
// That cadence is far more often than gRPC's DEFAULT server enforcement allows
// (keepalive.EnforcementPolicy zero value = MinTime 5 minutes, no pings without
// an active stream), and a server that considers a client too chatty answers with
// a GOAWAY carrying ENHANCE_YOUR_CALM — it kills the connection rather than
// ignoring the ping. Hence MinTime here, which must stay BELOW the client's ping
// interval with room to spare for jitter.
//
// ⚠ DEPLOY ORDER: calabi-coord before the client. A client with keepalive against an
// old coordinator survives only on an implementation detail (the server clears
// its ping-strike counter whenever it sends data, and coord pushes netmaps often
// enough); a quiet stretch of three pings would earn that GOAWAY.
//
// The server half (ServerParameters.Time) is the mirror image: coord pings an
// idle connection so a node whose machine vanished stops holding a netmap
// subscription open forever. MaxConnectionAge/Idle are deliberately left at
// infinity — recycling a healthy control connection on a timer would cost a
// re-enroll for nothing.
func coordKeepaliveOptions() []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             15 * time.Second,
			PermitWithoutStream: true,
		}),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    60 * time.Second,
			Timeout: 20 * time.Second,
		}),
	}
}
