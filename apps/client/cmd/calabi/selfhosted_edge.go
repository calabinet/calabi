package main

// How a device that joined a self-hosted server reaches its edge: the coordinator says which
// edge and which certificate, and signs the grant the edge takes as this
// device's sign-in. Nothing about the edge is configured on the device.

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/calabinet/calabi/apps/client/internal/mesh"
	"github.com/calabinet/calabi/apps/client/internal/selfhosted"
	"github.com/calabinet/calabi/apps/client/internal/session"
	"github.com/calabinet/calabi/apps/client/internal/transport"
	"github.com/calabinet/calabi/apps/client/internal/trust"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

// coordReader runs read against the coordinator this device joined: over its
// live mesh session, or a view session when the mesh is off (localMesh.read).
type coordReader func(ctx context.Context, read func(*mesh.CoordClient) error) error

var (
	errNoEdge  = errors.New("the self-hosted server names no edge for tunnels yet (CALABI_COORD_EDGE_ADDR on the coordinator; with no fingerprint given, it names the edge once it has read the edge's certificate)")
	errNoGrant = errors.New("the coordinator signs no grants for its edge")
)

// fetchEdgeAccess asks the coordinator for its edge and a fresh grant.
func fetchEdgeAccess(ctx context.Context, read coordReader) (mesh.EdgeAccess, error) {
	var acc mesh.EdgeAccess
	err := read(ctx, func(cc *mesh.CoordClient) error {
		var err error
		acc, err = cc.GetEdgeAccess(ctx)
		return err
	})
	if err != nil {
		return mesh.EdgeAccess{}, err
	}
	if len(acc.Grant) == 0 {
		return mesh.EdgeAccess{}, errNoGrant
	}
	return acc, nil
}

// edgeDialOptions is how the device dials the edge the coordinator named:
// pinned to the certificate the coordinator read from it, or checked against
// the system's roots when the coordinator says the edge has a public one. The
// trust in the edge comes from the trust in the coordinator.
func edgeDialOptions(e mesh.EdgeTarget) (transport.DialOptions, error) {
	t := trust.Config{Mode: trust.System}
	if e.Pin != "" {
		t = trust.Config{Mode: trust.Pin, Pins: []string{e.Pin}}
	}
	tlsCfg, err := t.TLS(e.Addr)
	if err != nil {
		return transport.DialOptions{}, err
	}
	return transport.DialOptions{Addr: e.Addr, TLSConfig: tlsCfg}, nil
}

// deviceCredential is the edge sign-in: the coordinator's grant, and the node
// key that answers the edge's challenge.
func deviceCredential(grant []byte, key mesh.PrivateKey) session.DeviceCredential {
	return session.DeviceCredential{Grant: grant, NodeKey: key.Public(), NodePriv: key}
}

// grantRenewDelay is when to renew a grant expiring at expiry: with a third of
// its life left (20 minutes of an hour's grant), so a coordinator that is
// briefly away does not cost the session. Never sooner than a second: a grant
// handed out already expired must not spin the loop.
func grantRenewDelay(now, expiry time.Time) time.Duration {
	left := expiry.Sub(now)
	return max(left-left/3, time.Second)
}

// grantRetryDelay is how soon to try again after a renewal failed: every
// minute, and more often as the grant nears its end.
func grantRetryDelay(now, expiry time.Time) time.Duration {
	return min(max(expiry.Sub(now)/2, time.Second), time.Minute)
}

// keepGrantFresh hands the edge a renewed grant before the one the session
// signed in with runs out; the edge ends a session whose grant expires
// unrenewed. It returns when ctx ends or the session can no longer take one.
func keepGrantFresh(ctx context.Context, logger *slog.Logger, cli *session.Client, read coordReader, expiry time.Time) {
	wait := grantRenewDelay(time.Now(), expiry)
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		fctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		acc, err := fetchEdgeAccess(fctx, read)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			wait = grantRetryDelay(time.Now(), expiry)
			logger.Warn("could not renew this device's grant for the edge; trying again",
				"err", err, "expires", expiry.UTC().Format(time.RFC3339), "retry_in", wait.String())
			continue
		}
		if err := cli.RefreshGrant(acc.Grant); err != nil {
			return // the session is gone; the reconnect loop takes it from here
		}
		expiry = acc.Expiry
		wait = grantRenewDelay(time.Now(), expiry)
		logger.Debug("renewed this device's grant for the edge", "expires", expiry.UTC().Format(time.RFC3339))
	}
}

// edgeProblem is why a device has no tunnels, in a word for the console, for
// an error from getting its edge access or signing in to the edge. "" when
// there is nothing more specific to say than the error.
func edgeProblem(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, errNoEdge), errors.Is(err, errNoGrant):
		return "no_edge"
	case errors.Is(err, errNoMesh):
		return "not_joined"
	case errors.Is(err, selfhosted.ErrCannotView):
		return "connecting"
	}
	switch grpcCode(err) {
	case codes.FailedPrecondition:
		if grpcMessage(err) == meshproto.AwaitingApproval {
			return "awaiting_approval"
		}
		return "needs_invite"
	case codes.NotFound, codes.Unauthenticated:
		return "needs_invite"
	case codes.PermissionDenied:
		return "disabled"
	}
	return ""
}

// grpcMessage is the message of the gRPC status somewhere in err's chain.
// status.Convert would give the whole wrapped error's text instead.
func grpcMessage(err error) string {
	var se interface{ GRPCStatus() *grpcstatus.Status }
	if errors.As(err, &se) {
		return se.GRPCStatus().Message()
	}
	return ""
}
