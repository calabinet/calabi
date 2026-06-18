// spawn.go — fire-and-forget child-process helpers used by `calabi
// login --start-daemon`.
//
// The basic recipe:
//
//  1. Probe the local /healthz to see if a daemon is already up. If
//     yes, nothing to do.
//  2. Pick our own argv[0] (os.Executable) so the spawned child is
//     definitely the same binary.
//  3. Launch with stdin/out/err redirected to the rotated log file
//     (or os.DevNull as a fallback) so the parent process can exit
//     without dragging the child into the terminal-closed cascade.
//  4. Detach the child from the parent process group so Ctrl-C in
//     the parent terminal doesn't propagate. Platform-specific bits
//     live in spawn_windows.go / spawn_unix.go.
//
// We deliberately do NOT install the OS-level service here — that's a
// separate explicit `calabi daemon install` step. Spawn is the lighter
// alternative: a foreground-detached process suitable for "I just want
// the daemon running while I'm logged in."
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// daemonAlreadyRunning hits the local /healthz with a short timeout.
// Returns true if anything answered with a 2xx — we deliberately
// don't decode the body because an older daemon (plain-text
// healthz) is still a daemon.
func daemonAlreadyRunning(addr string) bool {
	if addr == "" {
		addr = defaultStatusAddr
	}
	cli := &http.Client{Timeout: 800 * time.Millisecond}
	resp, err := cli.Get("http://" + addr + "/healthz")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode >= 200 && resp.StatusCode < 500
}

// spawnDetachedDaemon launches `calabi daemon` as a backgrounded child
// process. Returns nil on successful spawn; an error only when the
// fork itself failed. We don't wait for the daemon to become Ready —
// the caller polls /healthz separately if it needs that.
// absolutizePathEnv returns env with each named variable rewritten to an
// absolute path (resolved against the CURRENT process's cwd) when its value is
// a non-empty relative path. Absolute values, empty values, and unnamed
// variables pass through untouched. Used before spawning the detached daemon,
// whose own cwd differs from the user's — without this, a relative
// CALABI_EDGE_CA_FILE / CALABI_CONFIG would resolve against the daemon's cwd
// and fail.
func absolutizePathEnv(env []string, keys ...string) []string {
	want := make(map[string]bool, len(keys))
	for _, k := range keys {
		want[k] = true
	}
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if i := strings.IndexByte(kv, '='); i > 0 {
			k, v := kv[:i], kv[i+1:]
			if want[k] && v != "" && !filepath.IsAbs(v) {
				if abs, err := filepath.Abs(v); err == nil {
					kv = k + "=" + abs
				}
			}
		}
		out = append(out, kv)
	}
	return out
}

func spawnDetachedDaemon() error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve self: %w", err)
	}

	cmd := exec.Command(self, "daemon")
	// The daemon's cwd is set to $HOME below (so it doesn't pin the user's
	// directory), but path env vars like CALABI_EDGE_CA_FILE are commonly
	// relative (e.g. "deploy/dev/certs/ca.crt"). Resolve them to absolute
	// paths against the PARENT's cwd now, so the daemon finds the same files
	// the foreground client did instead of failing with "path not found".
	cmd.Env = absolutizePathEnv(os.Environ(), "CALABI_EDGE_CA_FILE", "CALABI_CONFIG")

	// Redirect stdio. Logs go to the file sink via logging.Setup; we
	// don't need a terminal at all. /dev/null + nul keep the child
	// from inheriting our pipes.
	devnull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err == nil {
		cmd.Stdin = devnull
		cmd.Stdout = devnull
		cmd.Stderr = devnull
	}

	// Place the child's working dir somewhere stable — if the user ran
	// `calabi login` from a directory they later rm -rf, the daemon
	// keeps cwd open and prevents the delete on Windows.
	if home, err := os.UserHomeDir(); err == nil {
		cmd.Dir = home
	} else {
		cmd.Dir = filepath.Dir(self)
	}

	applyDetachAttr(cmd) // platform-specific (see spawn_*.go)

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("spawn daemon: %w", err)
	}
	// Release so the parent can exit; the child becomes init's problem
	// on Unix, or stays detached on Windows.
	_ = cmd.Process.Release()
	return nil
}

// waitForDaemonReady polls /healthz until it returns connected=true or
// the deadline expires. Used by the login flow to print a positive
// "daemon online" line instead of a blind "spawned".
func waitForDaemonReady(ctx context.Context, addr string, deadline time.Duration) error {
	if addr == "" {
		addr = defaultStatusAddr
	}
	cctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	cli := &http.Client{Timeout: 500 * time.Millisecond}
	tk := time.NewTicker(200 * time.Millisecond)
	defer tk.Stop()
	for {
		select {
		case <-cctx.Done():
			return errors.New("daemon did not become ready before deadline")
		case <-tk.C:
			req, _ := http.NewRequestWithContext(cctx, "GET", "http://"+addr+"/healthz", nil)
			resp, err := cli.Do(req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			// Older daemon (plain-text "ok") counts as ready; JSON gets
			// parsed for connected=true.
			var probe struct {
				State     string `json:"state"`
				Connected bool   `json:"connected"`
			}
			if err := json.Unmarshal(body, &probe); err == nil {
				if probe.Connected || probe.State == "connected" {
					return nil
				}
			} else if resp.StatusCode == 200 {
				return nil
			}
		}
	}
}
