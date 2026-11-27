// Command calabi-stun is a standalone, zero-dependency RFC 5780 dual-IP
// dual-port STUN server for Calabi client NAT1–NAT4 diagnostics.
//
// Deploy on a host with two public IPv4 addresses (or two private NIC IPs
// 1:1 NAT-mapped to two cloud Elastic IPs via --public-ip1 / --public-ip2).
// Point DNS `stun.calabi.net` (A record) at the primary public IP so already
// installed platform clients discover it automatically without an upgrade.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/calabinet/calabi/pkg/stunserver"
)

func main() {
	var (
		ip1       = flag.String("ip1", os.Getenv("CALABI_STUN_IP1"), "Primary bind IPv4 address (required)")
		ip2       = flag.String("ip2", os.Getenv("CALABI_STUN_IP2"), "Secondary bind IPv4 address (required)")
		port1     = flag.Int("port1", envInt("CALABI_STUN_PORT1", 3490), "Primary UDP port (default 3490; avoids calabi-edge's 3478)")
		port2     = flag.Int("port2", envInt("CALABI_STUN_PORT2", 3491), "Secondary UDP port (default 3491)")
		publicIP1 = flag.String("public-ip1", os.Getenv("CALABI_STUN_PUBLIC_IP1"), "Optional advertised public IPv4 for ip1 (cloud EIP 1:1 NAT)")
		publicIP2 = flag.String("public-ip2", os.Getenv("CALABI_STUN_PUBLIC_IP2"), "Optional advertised public IPv4 for ip2 (cloud EIP 1:1 NAT)")
		logLevel  = flag.String("log-level", envOr("CALABI_STUN_LOG_LEVEL", "info"), "Log level: debug|info|warn|error")
	)
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: parseLevel(*logLevel)}))

	p1, err := parseIPv4Flag("ip1", *ip1)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	p2, err := parseIPv4Flag("ip2", *ip2)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if *port1 <= 0 || *port1 > 65535 || *port2 <= 0 || *port2 > 65535 {
		fmt.Fprintln(os.Stderr, "calabi-stun: --port1 and --port2 must be between 1 and 65535")
		os.Exit(2)
	}

	cfg := stunserver.RFC5780Config{
		PrimaryIP:     p1,
		SecondaryIP:   p2,
		PrimaryPort:   uint16(*port1),
		SecondaryPort: uint16(*port2),
		Logger:        logger,
	}
	if strings.TrimSpace(*publicIP1) != "" {
		a, err := parseIPv4Flag("public-ip1", *publicIP1)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		cfg.AdvertisePrimaryIP = a
	}
	if strings.TrimSpace(*publicIP2) != "" {
		a, err := parseIPv4Flag("public-ip2", *publicIP2)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		cfg.AdvertiseSecondaryIP = a
	}

	srv, err := stunserver.ListenRFC5780(cfg)
	if err != nil {
		logger.Error("calabi-stun failed to start", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.Info("calabi-stun listening (RFC 5780 dual-IP dual-port)",
		"primary", srv.PrimaryAddr().String(),
		"other_advertised", srv.OtherAddr().String(),
		"ports", fmt.Sprintf("%d,%d", *port1, *port2),
	)
	_ = srv.Serve(ctx)
	logger.Info("calabi-stun stopped")
}

func parseIPv4Flag(name, raw string) (netip.Addr, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return netip.Addr{}, fmt.Errorf("calabi-stun: --%s is required", name)
	}
	ip, err := netip.ParseAddr(raw)
	if err != nil || !ip.Unmap().Is4() {
		return netip.Addr{}, fmt.Errorf("calabi-stun: --%s must be a valid IPv4 address (got %q)", name, raw)
	}
	return ip.Unmap(), nil
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
