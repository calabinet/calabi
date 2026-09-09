package mesh

import (
	"bufio"
	"errors"
	"strings"
)

// Deciding what to do with /etc/resolv.conf before MagicDNS takes it over.
//
// Kept separate from the syscalls (magicdns_linux.go) and free of build tags, so
// the decision is tested on any machine. What it protects against is not
// hypothetical: taking this file over wrong leaves the HOST with no DNS at all,
// for everything, not just the mesh.
//
// Two ways the old code got there, both seen on one machine on 2026-09-06:
//
//  1. The restore only ran on a graceful stop. A SIGKILL, a crash or a reboot
//     left resolv.conf pointing at 100.100.100.100 with nothing listening on it.
//  2. On the NEXT start the file it read as "the previous config" was its own
//     rewritten one. The upstream scan skips our own address, so it found none —
//     the resolver then had nowhere to forward ordinary queries, and cleanup
//     "restored" the broken file. The damage carried itself forward.
//
// The fix is to keep the real config in a backup file and to treat "the current
// file is already ours" as the signal to read that instead.

// ErrNoUpstreamResolver is returned when neither the live resolv.conf nor the
// backup names a usable upstream. Taking the file over then guarantees total DNS
// loss for the host, so the caller must NOT proceed — mesh runs without MagicDNS,
// which costs node-name resolution and nothing else.
var ErrNoUpstreamResolver = errors.New("mesh: refusing to take over /etc/resolv.conf: no upstream nameserver to forward ordinary queries to")

// resolvPlan is what the caller should do, decided before anything is written.
type resolvPlan struct {
	// Upstream is where non-mesh queries go, as host:port.
	Upstream string
	// Restore is the exact bytes cleanup must write back to resolv.conf.
	Restore []byte
	// Backup, when non-nil, is what to write to the backup file first. Nil means
	// a usable backup already exists and must be left alone — overwriting it with
	// our own rewritten config is precisely how the original was lost.
	Backup []byte
}

// planResolvTakeover decides the takeover from the two files' current contents.
// backup may be nil (no backup file yet).
func planResolvTakeover(current, backup []byte, listenIP string) (resolvPlan, error) {
	if pointsAt(string(current), listenIP) {
		// A previous run is still in effect (it never restored). The live file is
		// ours, so the host's real config can only be the backup.
		up := firstNameserver(string(backup), listenIP)
		if up == "" {
			return resolvPlan{}, ErrNoUpstreamResolver
		}
		return resolvPlan{Upstream: up, Restore: backup}, nil
	}
	up := firstNameserver(string(current), listenIP)
	if up == "" {
		return resolvPlan{}, ErrNoUpstreamResolver
	}
	return resolvPlan{Upstream: up, Restore: current, Backup: current}, nil
}

// pointsAt reports whether resolv.conf content names ip as a nameserver — i.e.
// whether this file is one we wrote.
func pointsAt(content, ip string) bool {
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 2 && f[0] == "nameserver" && f[1] == ip {
			return true
		}
	}
	return false
}

// firstNameserver returns the first "nameserver X" (as host:53) from resolv.conf
// content, skipping `skip` (our own MagicDNS IP, so a config we wrote can't make
// us forward to ourselves). "" if none.
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

// renderResolvConf is the file we install while MagicDNS is up.
func renderResolvConf(listenIP, suffix string) []byte {
	b := "nameserver " + listenIP + "\n"
	if suffix != "" {
		b += "search " + suffix + "\n"
	}
	return []byte(b)
}
