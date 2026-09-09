package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// --status-addr: where the daemon's local web console (:7400) binds.
//
// The address was reachable only through CALABI_STATUS_ADDR, which left the two
// ways of running a daemon inconsistent: a foreground daemon took an env var, an
// installed service took `daemon install --status-port N` — a flag that only
// accepts a port, always binds loopback, and appears in no --help because it is
// pulled out of the argv by hand. Both still work; this is the one that reads
// like the rest of the CLI.

// registerStatusAddrFlag wires --status-addr onto fs, defaulting to the
// environment so the flag OVERRIDES the env var rather than fighting it (the
// same shape as --edge-region / --advertise-routes).
func registerStatusAddrFlag(fs *flag.FlagSet) *string {
	return fs.String("status-addr", envOr("CALABI_STATUS_ADDR", defaultStatusAddr),
		// No "(default …)" here: flag prints the default itself, from the value
		// above — which is the ENV when one is set, so saying it twice would also
		// say it wrong.
		`local web console bind address "host:port", or "disabled" to turn it off`)
}

// applyStatusAddr validates v and makes it the address for this process.
//
// It works by setting CALABI_STATUS_ADDR rather than threading a parameter
// through: half a dozen places already read that variable (the console server,
// the URL the daemon prints, `calabi mesh status`, the service installer), and
// one of them silently keeping the old value is a worse failure than the
// impurity — you would get a console on one port and a banner naming another.
//
// Returns a warning to log when the bind is not loopback. Not an error: the
// published Docker image documents 0.0.0.0 with a port publish, so refusing it
// would break a supported deployment.
func applyStatusAddr(v string) (warning string, err error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", fmt.Errorf("--status-addr: empty (use host:port, or \"disabled\")")
	}
	if strings.EqualFold(v, "disabled") || strings.EqualFold(v, "off") {
		return "", os.Setenv("CALABI_STATUS_ADDR", v)
	}

	host, portStr, serr := net.SplitHostPort(v)
	if serr != nil {
		// The likely typo is a bare port. Say so, rather than letting it through
		// to a bind error that names something the user did not type.
		if _, aerr := strconv.Atoi(v); aerr == nil {
			return "", fmt.Errorf("--status-addr: %q is a port, not an address — use 127.0.0.1:%s", v, v)
		}
		return "", fmt.Errorf("--status-addr: %q is not host:port (%v)", v, serr)
	}
	port, perr := strconv.Atoi(portStr)
	if perr != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("--status-addr: %q has no valid port", v)
	}
	if err := os.Setenv("CALABI_STATUS_ADDR", v); err != nil {
		return "", err
	}
	if !isLoopbackHost(host) {
		// Deliberately blunt. The console has no authentication of its own: it
		// hands its write token to anything that can load the page, and the
		// loopback bind IS the boundary that makes that safe.
		warning = fmt.Sprintf("the local console will listen on %s, not just loopback — "+
			"it has no login of its own and hands its write token to anyone who can reach it, "+
			"so put it behind something that does (SSH forward, or publish the port to 127.0.0.1 only)", v)
	}
	return warning, nil
}

// isLoopbackHost reports whether binding to host reaches only this machine. An
// EMPTY host (":7400") is every interface, which is the case most likely to be
// typed by accident.
func isLoopbackHost(host string) bool {
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	// A name we cannot resolve here: assume it is not loopback and warn. Being
	// wrong costs one warning; the other way round costs silence on an exposed
	// console.
	return false
}
