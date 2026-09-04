//go:build linux

package mesh

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const resolvConfPath = "/etc/resolv.conf"

// setupOSResolver points the OS at the MagicDNS resolver on listenIP: it assigns
// listenIP/32 to loopback (so the resolver can bind it and queries to it stay
// local rather than routing into the tun), captures the current upstream
// nameserver (to forward non-mesh queries), and rewrites /etc/resolv.conf to use
// listenIP with `search <suffix>` so bare node names resolve. Returns the
// upstream (host:port) + a cleanup that restores resolv.conf and removes the
// address. Linux-only (Windows/macOS integration is deferred, like the tun route
// config).
func setupOSResolver(listenIP, suffix string) (upstream string, cleanup func(), err error) {
	prev, _ := os.ReadFile(resolvConfPath)
	upstream = firstNameserver(string(prev), listenIP)

	if out, e := exec.Command("ip", "address", "add", listenIP+"/32", "dev", "lo").CombinedOutput(); e != nil &&
		!strings.Contains(strings.ToLower(string(out)), "exists") {
		return "", nil, fmt.Errorf("assign %s to lo: %v: %s", listenIP, e, strings.TrimSpace(string(out)))
	}

	content := "nameserver " + listenIP + "\n"
	if suffix != "" {
		content += "search " + suffix + "\n"
	}
	if e := os.WriteFile(resolvConfPath, []byte(content), 0o644); e != nil {
		_ = exec.Command("ip", "address", "del", listenIP+"/32", "dev", "lo").Run()
		return "", nil, fmt.Errorf("write %s: %w", resolvConfPath, e)
	}

	cleanup = func() {
		if prev != nil {
			_ = os.WriteFile(resolvConfPath, prev, 0o644)
		}
		_ = exec.Command("ip", "address", "del", listenIP+"/32", "dev", "lo").Run()
	}
	return upstream, cleanup, nil
}

// firstNameserver returns the first "nameserver X" (as host:53) from resolv.conf
// content, skipping `skip` (our own MagicDNS IP, so a stale rewritten config
// can't make us forward to ourselves). "" if none.
func firstNameserver(content, skip string) string {
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 2 && f[0] == "nameserver" && f[1] != skip {
			return f[1] + ":53"
		}
	}
	return ""
}
