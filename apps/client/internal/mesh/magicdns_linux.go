//go:build linux

package mesh

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const (
	resolvConfPath   = "/etc/resolv.conf"
	resolvBackupPath = "/etc/resolv.conf.calabi-orig"
)

// setupOSResolver points the OS at the MagicDNS resolver on listenIP: it assigns
// listenIP/32 to loopback (so the resolver can bind it and queries to it stay
// local rather than routing into the tun), works out where to forward non-mesh
// queries, and rewrites /etc/resolv.conf to use listenIP with `search <suffix>`
// so bare node names resolve. Returns the upstream (host:port) + a cleanup that
// restores resolv.conf and removes the address. Linux-only (Windows/macOS
// integration is deferred, like the tun route config).
//
// The host's real config is copied to resolvBackupPath BEFORE the rewrite, and a
// resolv.conf that already points at us is recognised as our own leftover rather
// than mistaken for the host's config. Both exist because the restore can only
// run on a graceful stop: a kill, a crash or a reboot leaves the rewritten file
// in place, and without the backup the original is simply gone — the machine
// then has no DNS at all until someone writes one by hand.
// magicdns_plan.go, where the decision lives (and is tested).
func setupOSResolver(listenIP, suffix string) (upstream string, cleanup func(), err error) {
	current, _ := os.ReadFile(resolvConfPath)
	backup, _ := os.ReadFile(resolvBackupPath)

	plan, err := planResolvTakeover(current, backup, listenIP)
	if err != nil {
		return "", nil, err
	}
	if plan.Backup != nil {
		if e := os.WriteFile(resolvBackupPath, plan.Backup, 0o644); e != nil {
			// Without a backup the takeover is not reversible across a crash, so
			// don't do it at all. Losing MagicDNS costs node-name resolution;
			// losing the host's DNS costs everything.
			return "", nil, fmt.Errorf("save %s: %w", resolvBackupPath, e)
		}
	}

	if out, e := exec.Command("ip", "address", "add", listenIP+"/32", "dev", "lo").CombinedOutput(); e != nil &&
		!strings.Contains(strings.ToLower(string(out)), "exists") {
		return "", nil, fmt.Errorf("assign %s to lo: %v: %s", listenIP, e, strings.TrimSpace(string(out)))
	}

	if e := os.WriteFile(resolvConfPath, renderResolvConf(listenIP, suffix), 0o644); e != nil {
		_ = exec.Command("ip", "address", "del", listenIP+"/32", "dev", "lo").Run()
		return "", nil, fmt.Errorf("write %s: %w", resolvConfPath, e)
	}

	cleanup = func() {
		if plan.Restore != nil {
			_ = os.WriteFile(resolvConfPath, plan.Restore, 0o644)
		}
		// Only now: while the backup exists, an ungraceful exit is still
		// recoverable by the next start.
		_ = os.Remove(resolvBackupPath)
		_ = exec.Command("ip", "address", "del", listenIP+"/32", "dev", "lo").Run()
	}
	return plan.Upstream, cleanup, nil
}
