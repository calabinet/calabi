package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/calabi/calabi/apps/client/internal/session"
	"github.com/calabi/calabi/apps/client/internal/status"
	proto "github.com/calabi/calabi/pkg/protocol"
)

// runSNI implements `calabi sni <local-port> --domain example.com`.
//
// The local upstream is expected to be a TLS server (the user terminates
// TLS themselves with their own cert). The edge peeks ClientHello, routes
// by SNI server_name, and pipes raw TLS bytes through — no handshake is
// performed on the edge. Wire-protocol-wise this is identical to a TCP
// proxy from the client's perspective; the local upstream sees the
// original ClientHello bytes.
func runSNI(args []string) int {
	fs := flag.NewFlagSet("sni", flag.ContinueOnError)
	name := fs.String("name", "sni", "tunnel name shown in dashboard")
	domain := fs.String("domain", "", "SNI server_name to route on (required)")
	host := fs.String("host", "127.0.0.1", "local host to forward to")
	sec := registerSecurityFlags(fs, false)
	if err := fs.Parse(reorderArgs(args, valueFlagsOf(fs))); err != nil {
		return 2
	}
	secJSON, secErr := sec.buildConfigJSON()
	if secErr != nil {
		fmt.Fprintln(os.Stderr, "calabi sni:", secErr)
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "calabi sni: missing <local-port>")
		fs.Usage()
		return 2
	}
	if *domain == "" {
		fmt.Fprintln(os.Stderr, "calabi sni: --domain is required (the SNI server_name)")
		return 2
	}
	localPort, err := strconv.Atoi(fs.Arg(0))
	if err != nil || localPort <= 0 || localPort > 65535 {
		fmt.Fprintln(os.Stderr, "calabi sni: invalid <local-port>:", fs.Arg(0))
		return 2
	}
	localAddr := fmt.Sprintf("%s:%d", *host, localPort)
	if err := validateLocalUpstream(localAddr); err != nil {
		fmt.Fprintln(os.Stderr, "calabi sni:", err)
		return 1
	}

	logger := setupLogger()
	// Make this machine attributable before the tunnel exists: without a
	// device id the row is stored with client_id = 0 and the console can show
	// neither which machine it runs on nor whether that machine is up.
	ensureDeviceRegistered(logger)
	// calabi.net: CALABI_SERVER (or a baked default, if this build has one),
	// else the edge the control plane names — the same picker the daemon uses.
	// Self-hosted: the edge the coordinator this device joined names.
	edge, code := openOneShotEdge(logger, "sni")
	if edge == nil {
		return code
	}
	defer edge.Close()
	edgeAddr := edge.addr

	cli := edge.newSession(logger, *name)

	state := status.New(version, edgeAddr)
	cli.AttachTracker(state)
	startStatusPage(logger, state)

	ctx, cancel := withSignalContext()
	defer cancel()

	if err := cli.Handshake(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "calabi: handshake:", err)
		return 1
	}
	edge.keepFresh(ctx, logger, cli)

	tun := session.Tunnel{
		Name:               *name,
		Type:               proto.ProxyKindSNI,
		LocalAddr:          localAddr,
		Domain:             *domain,
		SecurityConfigJSON: secJSON,
	}
	assigned, err := cli.RegisterTunnel(ctx, tun)
	if err != nil {
		fmt.Fprintln(os.Stderr, "calabi: register tunnel:", err)
		return 1
	}
	// What the EDGE did with the policy we sent — not what we assumed it would.
	sec.NoteEdgePolicy(assigned.ClientPolicy)
	state.AddTunnel(status.TunnelInfo{
		ProxyID:    assigned.ProxyID,
		Name:       *name,
		Type:       "sni",
		LocalAddr:  localAddr,
		PublicAddr: "tls://" + assigned.Domain,
	})
	defer state.RemoveTunnel(assigned.ProxyID)

	proxies := map[string]session.Tunnel{assigned.ProxyID: tun}
	resolve := func(id string) (session.Tunnel, bool) {
		t, ok := proxies[id]
		return t, ok
	}

	fmt.Printf("\n  tunnel: tls://%s  ->  %s  (SNI passthrough; bring your own cert)\n\n",
		assigned.Domain, localAddr)
	fmt.Println("  Ctrl-C to quit.")

	if err := cli.Run(ctx, resolve); err != nil {
		logger.Info("session ended", "err", err)
	}
	return 0
}
