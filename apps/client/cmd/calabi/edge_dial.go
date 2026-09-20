package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/calabinet/calabi/apps/client/internal/mesh"
	"github.com/calabinet/calabi/apps/client/internal/selfhosted"
	"github.com/calabinet/calabi/apps/client/internal/session"
	"github.com/calabinet/calabi/apps/client/internal/transport"
)

// oneShotEdge is the edge a one-shot command (`calabi http|tcp|udp|sni`) dialled,
// and how its session signs in there.
type oneShotEdge struct {
	addr string
	mux  *transport.Mux
	// token signs in to a calabi.net edge; device, to the edge of the
	// self-hosted server this device joined.
	token  string
	device *session.DeviceCredential
	// read and expiry keep a self-hosted grant fresh while the session runs.
	read   coordReader
	expiry time.Time
	viewer *selfhosted.Viewer
}

// openOneShotEdge dials the edge for `calabi <cmd>`, or returns an exit code
// after telling the user why it cannot.
//
// On calabi.net: the edge requireEdgeAddr names, its certificate checked as it
// always was (the CA compiled into this client, plus CALABI_EDGE_CA_FILE for a
// development stack, or no check with CALABI_INSECURE=1), and the account's
// token.
//
// Standalone: the device's own identity on the self-hosted server it joined — the coordinator names the
// edge and its certificate and signs the grant the edge takes. There is nothing
// to set in the environment; a device that has not joined is told to.
func openOneShotEdge(logger *slog.Logger, cmd string) (*oneShotEdge, int) {
	if clientIsStandalone() {
		return openSelfHostedEdge(logger, cmd)
	}
	addr := requireEdgeAddr(logger, cmd)
	if addr == "" {
		return nil, 2
	}
	logger.Info("connecting", "server", addr)
	mux, err := transport.Dial(platformEdgeDialOptions(addr))
	if err != nil {
		fmt.Fprintln(os.Stderr, "calabi: dial:", err)
		return nil, 1
	}
	return &oneShotEdge{addr: addr, mux: mux, token: resolveToken()}, 0
}

// platformEdgeDialOptions is how a one-shot command checks a calabi.net edge:
// the CA compiled into this client, which transport adds CALABI_EDGE_CA_FILE to.
func platformEdgeDialOptions(addr string) transport.DialOptions {
	return transport.DialOptions{
		Addr:       addr,
		Insecure:   envBool("CALABI_INSECURE", defaultInsecure),
		CACertFile: envOr("CALABI_EDGE_CA_FILE", ""),
	}
}

// openSelfHostedEdge is openOneShotEdge for a standalone client.
func openSelfHostedEdge(logger *slog.Logger, cmd string) (*oneShotEdge, int) {
	path := envOr("CALABI_DAEMON_CONFIG", managedConfigPath())
	cfg, _, err := loadLocalConfigOrEmpty(path, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "calabi %s: %v\n", cmd, err)
		return nil, 1
	}
	if cfg.Mesh.Coord == "" {
		fmt.Fprintf(os.Stderr, "calabi %s: this device has not joined a self-hosted server.\n"+
			"  Join one with an invite its server prints (`calabi-coord invite`):\n"+
			"    calabi join 'calabi://join?…'\n"+
			"  (or run `calabi mode platform` if you meant to use calabi.net)\n", cmd)
		return nil, 2
	}
	viewer := &selfhosted.Viewer{}
	read := func(ctx context.Context, fn func(*mesh.CoordClient) error) error {
		return viewer.Read(ctx, nil, func() (selfhosted.Node, error) { return selfHostedNode(cfg.Mesh) }, fn)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	acc, err := fetchEdgeAccess(ctx, read)
	cancel()
	if err == nil && len(acc.Edges) == 0 {
		err = errNoEdge
	}
	if err != nil {
		viewer.Drop()
		fmt.Fprintf(os.Stderr, "calabi %s: %s\n", cmd, explainEdgeAccess(err, cfg.Mesh.Coord))
		return nil, 1
	}
	key, err := meshNodeKey(cfg.Mesh)
	if err != nil {
		viewer.Drop()
		fmt.Fprintf(os.Stderr, "calabi %s: device key: %v\n", cmd, err)
		return nil, 1
	}
	edge := acc.Edges[0]
	logger.Info("connecting", "server", edge.Addr, "coord", cfg.Mesh.Coord)
	opts, err := edgeDialOptions(edge)
	if err == nil {
		var mux *transport.Mux
		if mux, err = transport.Dial(opts); err == nil {
			cred := deviceCredential(acc.Grant, key)
			return &oneShotEdge{addr: edge.Addr, mux: mux, device: &cred, read: read, expiry: acc.Expiry, viewer: viewer}, 0
		}
	}
	viewer.Drop()
	fmt.Fprintln(os.Stderr, "calabi: dial:", err)
	return nil, 1
}

// explainEdgeAccess is what a person is told when the coordinator gave no way
// to the edge.
func explainEdgeAccess(err error, coord string) string {
	switch edgeProblem(err) {
	case "needs_invite":
		return "the server " + coord + " no longer takes this device (it was removed or signed out); join again with a new invite: calabi join <invite>"
	case "disabled":
		return "this device is disabled on " + coord
	case "awaiting_approval":
		return "this device is waiting for approval on " + coord + "; ask its administrator"
	case "connecting":
		return "cannot sign in to " + coord + " without the daemon: start it once (`calabi daemon`) so it joins, or join with `calabi join <invite>`"
	}
	return err.Error()
}

// newSession starts the session on this edge. Call keepFresh once it has
// signed in.
func (e *oneShotEdge) newSession(logger *slog.Logger, name string) *session.Client {
	cli := session.New(logger, e.mux, e.token, name)
	if e.device != nil {
		cli.SetDeviceCredential(*e.device)
	} else {
		cli.SetDeviceID(resolveDeviceID())
	}
	return cli
}

// keepFresh renews a self-hosted grant for as long as ctx lives; nothing on
// calabi.net, whose edge signs in with the account's token.
func (e *oneShotEdge) keepFresh(ctx context.Context, logger *slog.Logger, cli *session.Client) {
	if e.device != nil {
		go keepGrantFresh(ctx, logger, cli, e.read, e.expiry)
	}
}

// Close ends the connection and the view session it was fetched over.
func (e *oneShotEdge) Close() {
	if e.viewer != nil {
		e.viewer.Drop()
	}
	e.mux.Close()
}
