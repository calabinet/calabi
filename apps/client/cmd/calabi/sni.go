package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/calabi/calabi/apps/client/internal/session"
	"github.com/calabi/calabi/apps/client/internal/status"
	"github.com/calabi/calabi/apps/client/internal/transport"
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
	sec, secNames := registerSecurityFlags(fs, false)
	if err := fs.Parse(reorderArgs(args, append([]string{"name", "domain", "host"}, secNames...))); err != nil {
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
	logger.Info("connecting",
		"server", envOr("CALABI_SERVER", defaultServer),
		"local", localAddr, "domain", *domain)

	mux, err := transport.Dial(transport.DialOptions{
		Addr:       envOr("CALABI_SERVER", defaultServer),
		Insecure:   envBool("CALABI_INSECURE", defaultInsecure),
		CACertFile: envOr("CALABI_EDGE_CA_FILE", ""),
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "calabi: dial:", err)
		return 1
	}

	cli := session.New(logger, mux, resolveToken(), *name)
	cli.SetDeviceID(resolveDeviceID())

	state := status.New(version, envOr("CALABI_SERVER", defaultServer))
	cli.AttachTracker(state)
	startStatusPage(logger, state)

	ctx, cancel := withSignalContext()
	defer cancel()

	if err := cli.Handshake(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "calabi: handshake:", err)
		return 1
	}

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
