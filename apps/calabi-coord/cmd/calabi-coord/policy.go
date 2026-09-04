package main

import (
	"log/slog"
	"os"
	"time"

	"github.com/calabi/calabi/apps/calabi-coord/internal/core"
)

// policyState holds the reloadable policy + its file path so the watcher (started
// from main after the notifier exists) can hot-reload it. nil path = no file
// policy (allow-all), no watcher.
var policyState struct {
	reloadable *core.ReloadablePolicy
	path       string
}

// policyStore builds the meshnet ACL PolicyStore, shared by both deployments.
//
//   - CALABI_COORD_POLICY_FILE unset → AllowAllPolicy: every node in a meshnet
//     reaches every other (the pre-ACL default; unchanged behavior).
//   - set → a ReloadablePolicy seeded from the file (hot-reloaded by
//     startPolicyWatcher). The INITIAL load failing FAILS CLOSED (deny-all) with
//     a loud error — never fail-open — but stays watched, so fixing the file
//     recovers live without a restart. (The platform build swaps a DB-backed
//     per-org policy in MESH.8.)
func policyStore(logger *slog.Logger) core.PolicyStore {
	path := env("POLICY_FILE")
	if path == "" {
		return core.AllowAllPolicy{}
	}
	rp := core.NewReloadablePolicy(core.ACLPolicy{}) // deny-all until a good load
	policyState.reloadable = rp
	policyState.path = path

	if p, err := core.LoadACLPolicy(path); err != nil {
		logger.Error("acl policy initial load failed — FAILING CLOSED (deny all); will hot-reload when fixed", "err", err)
	} else {
		rp.Set(*p)
		logger.Info("acl policy loaded", "path", path, "rules", len(p.ACLs), "groups", len(p.Groups))
	}
	return rp
}

// startPolicyWatcher polls the ACL policy file and, on change, hot-reloads it and
// re-pushes every node's netmap (notif.BumpAll) so ACL edits take effect without
// a node reconnect. No-op when no policy file is configured. A reload that fails
// to parse keeps the previous (good) policy — only the INITIAL load fails closed.
func startPolicyWatcher(logger *slog.Logger, notif *core.Notifier) {
	rp, path := policyState.reloadable, policyState.path
	if rp == nil || path == "" {
		return
	}
	go func() {
		last := fileModTime(path)
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			m := fileModTime(path)
			if m.Equal(last) {
				continue
			}
			last = m
			p, err := core.LoadACLPolicy(path)
			if err != nil {
				logger.Error("acl policy reload failed; keeping previous policy", "err", err)
				continue
			}
			rp.Set(*p)
			notif.BumpAll()
			logger.Info("acl policy reloaded; re-pushing netmaps", "rules", len(p.ACLs), "groups", len(p.Groups))
		}
	}()
}

func fileModTime(path string) time.Time {
	fi, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return fi.ModTime()
}
